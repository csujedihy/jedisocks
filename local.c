#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <uv.h>
#include "utils.h"
#include "local.h"
#include "socks5.h"


typedef struct {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

static void socks_handshake_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socks_handshake_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void write_cb(uv_write_t *req, int status);
static void connect_to_remote_cb(uv_connect_t* req, int status);
static void accept_cb(uv_stream_t *server, int status);

int total_read;
int total_written;
int s_id = 0;
uv_loop_t *loop;
remote_ctx_t *remote_ctx_long;
queue_t* send_queue;

// Init long connection to your server
static void connect_to_remote_cb(uv_connect_t* req, int status) {
    remote_ctx_t* ctx = (remote_ctx_t *)req->data;
    if (status) {
        uv_close((uv_handle_t*)&ctx->remote, NULL);
        free(req);
        return;
    }

    free(req);

    LOGD("Connected to remote");
    int r = uv_listen((uv_stream_t*) &remote_ctx_long->listen->server, 128 /*backlog*/, accept_cb);
    if (r) ERROR("listen error", r)
    LOGD("Listening on localhost:7000\n");

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
    if (nread == UV_EOF) {
        uv_close((uv_handle_t*) client, NULL);
        // for debug
        fprintf(stderr, "closed client connection\n");
        fprintf(stderr, "Total read:    %d\n", total_read);
        fprintf(stderr, "Total written: %d\n", total_written);
        total_read = total_written = 0;
    } else if (nread > 0) {
        socks_handshake *socks_hsctx = client->data;
        if (socks_hsctx->stage == 2) {
            // here we create a session to multiplex the long connection 
            /*

            if init == 0
                ~~~~~~~~~~________________________________________________________________________________________
                | IV_KEY  | ID, 4 | RSV, 1 | DATALEN, 2 | ATYP, 1 | ADDRLEN, 1 | ADDR, VAR | PORT, 2 | DATA, VAR |
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            else
                ___________________________________________
                | ID, 4 | RSV, 1 | DATALEN, 2 | DATA, VAR |
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            
            #define ID_LEN 4
            #define DATALEN_LEN 2
            #define ATYP_LEN 1
            #define ADDRLEN_LEN  
            #define PORT_LEN 2

            */

            #define ID_LEN 4
            #define RSV_LEN 1
            #define DATALEN_LEN 2
            #define ATYP_LEN 1
            #define ADDRLEN_LEN  2
            #define PORT_LEN 2

            
            if (!socks_hsctx->init) {
                socks_hsctx->init = 1;
                socks_hsctx->session_id = ++s_id;
                if (s_id == INT_MAX)
                    s_id = 0;
                int offset = 0;
                char* pkt_buf = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN + ADDRLEN_LEN \
                                        + socks_hsctx->addrlen + PORT_LEN + nread);
                packet_t* pkt = calloc(1, sizeof(packet_t));
                pkt->rawpacket = pkt_buf;
                char rsv = 0;
                uint32_t id_to_send = ntohl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = ntohs((uint16_t)nread);
                pkt_maker(pkt_buf, &id_to_send, ID_LEN, offset);
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                pkt_maker(pkt_buf, &socks_hsctx->atyp, ATYP_LEN, offset);
                pkt_maker(pkt_buf, &socks_hsctx->addrlen, ADDRLEN_LEN, offset);
                pkt_maker(pkt_buf, &socks_hsctx->host, socks_hsctx->addrlen, offset);
                pkt_maker(pkt_buf, &socks_hsctx->port, PORT_LEN, offset);
                pkt_maker(pkt_buf, buf, nread, offset);
                list_add_to_tail(send_queue, pkt);
            }
            else {

                int offset = 0;
                char* pkt_buf = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
                packet_t* pkt = calloc(1, sizeof(packet_t));
                pkt->rawpacket = pkt_buf;
                char rsv = 0;
                uint32_t id_to_send = ntohl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = ntohs((uint16_t)nread);
                pkt_maker(pkt_buf, &id_to_send, ID_LEN, offset);
                pkt_maker(pkt_buf, &rsv, RSV_LEN, offset);
                pkt_maker(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                pkt_maker(pkt_buf, buf, nread, offset);
                list_add_to_tail(send_queue, pkt);

                // LOGD("stage = 2");
                // printf("\n");
                // SHOW_BUFFER(buf->base, nread);
                // write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                // wr->buf = uv_buf_init((char*)buf->base, nread);
                // uv_write(&wr->req, (uv_stream_t*)&remote_ctx_long->remote, &wr->buf, 1, write_cb);

    
            }

        }

        if(socks_hsctx->stage == 0){
            // received the first SOCKS5 request = in stage 0
            LOGD("%ld bytes read\n", nread);
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

                printf("atyp == 3\n");
                socks_hsctx->atyp = 3;
                socks_hsctx->addrlen = *(addr_ptr++);
                memcpy(socks_hsctx->host, addr_ptr, socks_hsctx->addrlen);   // domain name copied
                addr_ptr += socks_hsctx->addrlen;
                memcpy(socks_hsctx->port, addr_ptr, 2);          // port copied
                uint16_t p = ntohs(*(uint16_t *)(socks_hsctx->port));    //conv to host order

            } else
                LOGD("unexpected atyp");

            //SHOW_BUFFER_IN_HEX(buf->base, nread);
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
    write_req_t* wr;
    wr = (write_req_t*) req;

    int written = wr->buf.len;
    if (status) ERROR("async write", status);
    assert(wr->req.type == UV_WRITE);
    fprintf(stderr, "%d bytes written\n", written);
    total_written += written;

    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

int main() {
    struct sockaddr_in bind_addr;
    struct sockaddr_in connect_addr;
    send_queue = calloc(1, sizeof(queue_t));
    list_init(send_queue);

    loop = uv_default_loop();
    server_ctx *socks_ctx = calloc(1, sizeof(server_ctx));
    remote_ctx_long = calloc(1, sizeof(remote_ctx_t));
    uv_connect_t *req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
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
    return 0;
}