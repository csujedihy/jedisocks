#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include "utils.h"
#include "local.h"
#include "socks5.h"
#include "c_map.h"

static void socks_handshake_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socks_handshake_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void socks_write_cb(uv_write_t* req, int status);
static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void write_cb(uv_write_t *req, int status);
static void socks_after_shutdown_cb(uv_shutdown_t* req, int status);
static void socks_after_close_cb(uv_handle_t* handle);

static void connect_to_remote_cb(uv_connect_t* req, int status);
static void accept_cb(uv_stream_t *server, int status);
int verbose = 0;
int total_read;
int total_written;
int s_id = 0;
uv_loop_t *loop;
FILE * logfile = NULL;
// remote in local means the connection between client and server
remote_ctx_t *remote_ctx_long;
queue_t* send_queue;

static void socks_after_close_cb(uv_handle_t* handle) {
    LOGD("socks_after_close_cb");
    socks_handshake *socks_hsctx = (socks_handshake *)handle->data;
    if (socks_hsctx != NULL) {
        remove_c_map(remote_ctx_long->idfd_map, &socks_hsctx->session_id, NULL);
        free(socks_hsctx);
    }
    else
        LOGD("socks_after_close_cb: socks_hsctx == NULL?");
}

static void socks_after_shutdown_cb(uv_shutdown_t* req, int status) {
    LOGD("socks_after_shutdown_cb");
    socks_handshake *socks_hsctx = (socks_handshake *)req->data;
    uv_close((uv_handle_t*)&socks_hsctx->server, socks_after_close_cb);
    free(req);
}
    
static void socks_write_cb(uv_write_t* req, int status) {
    write_req_t* wr = (write_req_t*)req;
    socks_handshake* socks_hsctx = (socks_handshake*)req->data;
    if (status) {
        if (!uv_is_closing((uv_handle_t*)&socks_hsctx->server)) {
                // the remote is closing, we tell js-local to stop sending and preparing close
                uv_read_stop((uv_stream_t *)&socks_hsctx->server);
                int offset = 0;
                char* pkt_buf = malloc(EXP_TO_RECV_LEN);
                uint32_t session_id = htonl((uint32_t)socks_hsctx->session_id);
                uint16_t datalen = 0;
                pkt_maker(pkt_buf, &session_id, ID_LEN, offset);
                //LOGD("session_id = %d session_idno = %d", ctx->session_id, session_id);
                char rsv = 0x04;
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen, DATALEN_LEN, offset);
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->req.data = socks_hsctx;
                wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
                uv_write(&wr->req, (uv_stream_t*)&remote_ctx_long->remote, &wr->buf, 1, socks_write_cb);

                // shutdown remote
                uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                req->data = socks_hsctx;
                uv_shutdown(req, (uv_stream_t*)&socks_hsctx->server, socks_after_shutdown_cb);
        }    
        LOGD("socks write error: maybe client is closing");
    }
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(remote_ctx_long->expect_to_recv), remote_ctx_long->expect_to_recv);
    assert(buf->base != NULL);
}

static void remote_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (verbose) LOGD("nread = %d\n", nread);
    if (nread == UV_EOF) {
        uv_close((uv_handle_t*) client, NULL);
    } else if (nread > 0) {
        remote_ctx_t* ctx = (remote_ctx_t*)client->data;
        if (!ctx->reset) {
            if (verbose)  LOGD("reset packet and buffer\n");
            ctx->reset = 1;
            ctx->buf_len = 0;
            ctx->offset = 0;
            memset(ctx->packet_buf, 0, MAX_PKT_SIZE);
            memset(&ctx->tmp_packet, 0, sizeof(tmp_packet_t));
            ctx->stage = 0;
            
        }
        if (verbose) LOGD("buf_len before = %d\n", ctx->buf_len);
        memcpy(ctx->packet_buf + ctx->buf_len, buf->base, nread);  // copy current buf to packet_buf
        ctx->buf_len += nread;  // record how much data we put in the packet_buf
        if (verbose) LOGD("buf_len after = %d\n", ctx->buf_len);

        // TODO: fix the expected to recv buffer size
        if (ctx->stage == 0) {
            if (ctx->buf_len == EXP_TO_RECV_LEN) {
                pkt_access(&ctx->tmp_packet.session_id, ctx->packet_buf, ID_LEN, ctx->offset);
                ctx->tmp_packet.session_id = ntohl((uint32_t)ctx->tmp_packet.session_id);
                LOGD("session_id = %d\n", ctx->tmp_packet.session_id);
                pkt_access(&ctx->tmp_packet.rsv, ctx->packet_buf, RSV_LEN, ctx->offset);
                pkt_access(&ctx->tmp_packet.datalen, ctx->packet_buf, DATALEN_LEN, ctx->offset);
                ctx->tmp_packet.datalen = ntohs((uint16_t)ctx->tmp_packet.datalen);
                if (verbose) LOGD("datalen = %d\n", ctx->tmp_packet.datalen);
                ctx->expect_to_recv = ctx->tmp_packet.datalen;
                ctx->stage = 1;
                if (ctx->tmp_packet.rsv == 0x04) {
                    ctx->reset = 0;
                    ctx->expect_to_recv = EXP_TO_RECV_LEN;
                    LOGD("received a 0x04 packet");
                    socks_handshake* exist_ctx = NULL;
                    if (find_c_map(ctx->idfd_map, &ctx->tmp_packet.session_id, &exist_ctx))
                    {
                        // remote is closing, so shutdown SOCKS5 socket
                        if (!uv_is_closing((uv_handle_t*)&exist_ctx->server)) {
                            uv_read_stop((uv_stream_t *)&exist_ctx->server);
                            uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                            req->data = exist_ctx;
                            uv_shutdown(req, (uv_stream_t*)&exist_ctx->server, socks_after_shutdown_cb);
                        }
                    
                    }
                }
            }
            else{
                LOGD("< header length... gather more");
                ctx->expect_to_recv = EXP_TO_RECV_LEN - ctx->buf_len;
                return;
            }
        
        } else if (ctx->stage == 1) {
            if (ctx->buf_len == EXP_TO_RECV_LEN + ctx->tmp_packet.datalen) {
                ctx->reset = 0;
                if (verbose)  LOGD("data enough\n");
                socks_handshake* socks = NULL;
                if (find_c_map(ctx->idfd_map, &ctx->tmp_packet.session_id, &socks))
                {
                    socks->response = malloc(ctx->tmp_packet.datalen);
                    pkt_access(socks->response, ctx->packet_buf, ctx->tmp_packet.datalen, ctx->offset);
                    write_req_t* wr = malloc(sizeof(write_req_t));
                    wr->req.data = socks;
                    wr->buf = uv_buf_init(socks->response, ctx->tmp_packet.datalen);
                    uv_write(&wr->req, (uv_stream_t*)&socks->server, &wr->buf, 1, socks_write_cb);
                   // LOGD("response\n");
                    
                }
                else {
                    LOGD("found nothing in the map\n");
                    //assert(0);
                }
                ctx->expect_to_recv = EXP_TO_RECV_LEN;
            } else if (ctx->buf_len < EXP_TO_RECV_LEN + ctx->tmp_packet.datalen) {
                LOGD("< datalen... gather more");
                ctx->expect_to_recv = EXP_TO_RECV_LEN + ctx->tmp_packet.datalen - ctx->buf_len;
                return;
            } else {
                LOGD("impossible! should never reach here (> datalen)\n");
            }
        }
        free(buf->base);
    }
}
// Init long connection to your server
static void connect_to_remote_cb(uv_connect_t* req, int status) {
    remote_ctx_t* ctx = (remote_ctx_t *)req->data;
    if (status) {
        uv_close((uv_handle_t*)&ctx->remote, NULL);
        free(req);
        return;
    }
    req->handle->data = ctx;
    struct clib_map* map = new_c_map (compare_id, NULL, NULL);
    ctx->idfd_map = map;
    uv_read_start(req->handle, remote_alloc_cb, remote_read_cb);
    fprintf(stderr, "Connected to remote\n");
    int r = uv_listen((uv_stream_t*) &remote_ctx_long->listen->server, 128 /*backlog*/, accept_cb);
    if (r) ERROR("listen error", r)
    fprintf(stderr, "Listening on localhost:7000\n");

}   

static void accept_cb(uv_stream_t *server, int status) {
    if (status) ERROR("async connect", status);
    socks_handshake *socks_hsctx = calloc(1, sizeof(socks_handshake));
    socks_hsctx->server.data = socks_hsctx;
    uv_tcp_init(loop, &socks_hsctx->server);    
    int r = uv_accept(server, (uv_stream_t*) &socks_hsctx->server);
    if (r) {
      fprintf(stderr, "error accepting connection %d", r);
      uv_close((uv_handle_t*) &socks_hsctx->server, NULL);
    } else {
      uv_read_start((uv_stream_t*) &socks_hsctx->server, socks_handshake_alloc_cb,
                  socks_handshake_read_cb);
    }
}

static void socks_handshake_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(size), size);
    assert(buf->base != NULL);
}

static void socks_handshake_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (verbose)  LOGD("nread = %d", nread);
    if (nread == UV_EOF) {
        socks_handshake *socks_hsctx = client->data;
        socks_hsctx->closing = 1;
        if (!uv_is_closing((uv_handle_t*)&socks_hsctx->server)) {
                // the remote is closing, we tell js-local to stop sending and preparing close
                uv_read_stop((uv_stream_t *)&socks_hsctx->server);
                int offset = 0;
                char* pkt_buf = malloc(EXP_TO_RECV_LEN);
                uint32_t session_id = htonl((uint32_t)socks_hsctx->session_id);
                uint16_t datalen = 0;
                pkt_maker(pkt_buf, &session_id, ID_LEN, offset);
                //LOGD("session_id = %d session_idno = %d", ctx->session_id, session_id);
                char rsv = 0x04;
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen, DATALEN_LEN, offset);
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->req.data = socks_hsctx;
                wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
                uv_write(&wr->req, (uv_stream_t*)&remote_ctx_long->remote, &wr->buf, 1, socks_write_cb);

                // shutdown remote
                uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                req->data = socks_hsctx;
                uv_shutdown(req, (uv_stream_t*)&socks_hsctx->server, socks_after_shutdown_cb);
        }        
        // for debug
        fprintf(stderr, "closed client connection\n");
    } else if (nread > 0) {
        socks_handshake *socks_hsctx = client->data;
        if (socks_hsctx->stage == 2) {
            if (!socks_hsctx->init) {
                socks_hsctx->init = 1;
                socks_hsctx->session_id = ++s_id;
                insert_c_map (remote_ctx_long->idfd_map, &socks_hsctx->session_id, sizeof(int), socks_hsctx, sizeof(int));
                if (s_id == INT_MAX)
                    s_id = 0;
                int offset = 0;
                char* pkt_buf = malloc(ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN + ADDRLEN_LEN \
                                        + socks_hsctx->addrlen + PORT_LEN + nread);
                packet_t* pkt = calloc(1, sizeof(packet_t));
                pkt->rawpacket = pkt_buf;
                char rsv = 0x01;
                uint32_t id_to_send = htonl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = htons((uint16_t)(ATYP_LEN + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread));
                pkt_maker(pkt_buf, &id_to_send, ID_LEN, offset);
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                pkt_maker(pkt_buf, &socks_hsctx->atyp, ATYP_LEN, offset);
                LOGD("pkt_maker atyp %d", (char)*(pkt_buf + offset - 1));
                pkt_maker(pkt_buf, &socks_hsctx->addrlen, ADDRLEN_LEN, offset);
                pkt_maker(pkt_buf, &socks_hsctx->host, socks_hsctx->addrlen, offset);
                pkt_maker(pkt_buf, &socks_hsctx->port, PORT_LEN, offset);
                pkt_maker(pkt_buf, buf->base, nread, offset);
                list_add_to_tail(send_queue, pkt);
                //SHOW_BUFFER(pkt_buf, nread);
                if (verbose) LOGD("now here is buf\n");
                if (verbose) SHOW_BUFFER(buf->base, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN \
                 + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread);  
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->buf = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN \
                 + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread);
                uv_write(&wr->req, (uv_stream_t*)&remote_ctx_long->remote, &wr->buf, 1, write_cb);
                // do not forget freeing buffers
            }
            else
            {
                if (socks_hsctx->closing == 1)
                {
                    free(buf->base);
                    return;
                }
                int offset = 0;
                char* pkt_buf = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
                packet_t* pkt = calloc(1, sizeof(packet_t));
                pkt->rawpacket = pkt_buf;
                char rsv = 0x00;
                uint32_t id_to_send = ntohl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = ntohs((uint16_t)nread);
                pkt_maker(pkt_buf, &id_to_send, ID_LEN, offset);
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                pkt_maker(pkt_buf, buf->base, nread, offset);
                list_add_to_tail(send_queue, pkt);
                if (verbose) SHOW_BUFFER(pkt_buf, nread);
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->req.data = socks_hsctx;
                wr->buf = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
                uv_write(&wr->req, (uv_stream_t*)&remote_ctx_long->remote, &wr->buf, 1, write_cb);
                // do not forget free buffers
            }
        }

        if (socks_hsctx->stage == 0){
            // received the first SOCKS5 request = in stage 0
            if (verbose)  LOGD("%ld bytes read\n", nread);
            total_read += nread;
            write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
            char socks_first_req[SOCKS5_FISRT_REQ_SIZE] = {0x05,0x01,0x00};
            method_select_response_t *socks_first_resp = malloc(sizeof(method_select_response_t));
            socks_first_resp->ver = SVERSION;
            socks_first_resp->method = HEXZERO;
            int r = memcmp(socks_first_req, buf->base, SOCKS5_FISRT_REQ_SIZE);
            if (r == 0)
                LOGD("Received a socks5 request");
            wr->buf =  uv_buf_init((char*)socks_first_resp, sizeof(method_select_response_t));
            uv_write(&wr->req, client, &wr->buf, 1 /*nbufs*/, write_cb);
            socks_hsctx->stage = 1;
            // sent the 1st response -> switch to the stage 1
            free(buf->base);
        } else if (socks_hsctx->stage == 1){
            // received 2nd request in stage 1
            // here we have to parse the requested domain or ip address, then we store it in hsctx
            socks5_req_or_resp_t* req = (socks5_req_or_resp_t*)buf->base;
            char* addr_ptr = &req->atyp + 1;
            if (req->atyp == 0x01) {
                
                // client requests a ipv4 address
                socks_hsctx->atyp = 1;
                socks_hsctx->addrlen = 4;
                memcpy(socks_hsctx->host, addr_ptr, 4);  // ipv4 copied
                addr_ptr += 4;
                memcpy(socks_hsctx->port, addr_ptr, 2);  // port copied in network order
                uint16_t p = ntohs(*(uint16_t *)(socks_hsctx->port));

            } else if (req->atyp == 3){
                if (verbose) LOGD("atyp == 3\n");
                socks_hsctx->atyp = 3;
                socks_hsctx->addrlen = *(addr_ptr++);
                memcpy(socks_hsctx->host, addr_ptr, socks_hsctx->addrlen);      // domain name copied
                addr_ptr += socks_hsctx->addrlen;
                memcpy(socks_hsctx->port, addr_ptr, 2);                         // port copied
                uint16_t p = ntohs(*(uint16_t *)(socks_hsctx->port));           //conv to host order
            } else
                LOGD("unexpected atyp");

            socks5_req_or_resp_t* resp = calloc(1, sizeof(socks5_req_or_resp_t));
            memcpy(resp, req, sizeof(socks5_req_or_resp_t) - 4);  // only copy the first 4 bytes to save time
            resp->cmd_or_resp = 0;
            resp->atyp = 1;
            write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
            wr->buf = uv_buf_init((char*)resp, sizeof(socks5_req_or_resp_t));
            uv_write(&wr->req, client, &wr->buf, 1, write_cb);
            socks_hsctx->stage = 2;
            free(buf->base);

        }

    }
    if (nread == 0) free(buf->base);
}

static void write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*) req;
    if (status) ERROR("async write", status);
    assert(wr->req.type == UV_WRITE);
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}


int main() {
    struct sockaddr_in bind_addr;
    struct sockaddr_in connect_addr;
    send_queue = calloc(1, sizeof(queue_t));
    list_init(send_queue);
    char* locallog = "/tmp/local.log";
    //USE_LOGFILE(locallog);
    loop = uv_default_loop();
    server_ctx *socks_ctx = calloc(1, sizeof(server_ctx));
    remote_ctx_long = calloc(1, sizeof(remote_ctx_t));
    remote_ctx_long->expect_to_recv = 7;
    uv_connect_t *req = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));
    req->data = remote_ctx_long;
    remote_ctx_long->remote.data = remote_ctx_long;
    remote_ctx_long->listen = socks_ctx;
    socks_ctx->server.data = socks_ctx;

    uv_tcp_init(loop, &socks_ctx->server);
    uv_tcp_init(loop, &remote_ctx_long->remote);
    
    int r = uv_ip4_addr("127.0.0.1", 7001, &connect_addr);
    r = uv_tcp_connect(req, &remote_ctx_long->remote, (struct sockaddr*)&connect_addr, connect_to_remote_cb);
    r = uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
    LOGD("r = %d",r);
    r = uv_tcp_bind(&socks_ctx->server, (struct sockaddr*)&bind_addr, 0);
    if(r < 0)
    	ERROR("bind error", r);
    
    uv_run(loop, UV_RUN_DEFAULT);
    CLOSE_LOGFILE;
    return 0;
}