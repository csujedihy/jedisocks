#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>
#include <getopt.h>
#include "jconf.h"
#include "local.h"
#include "utils.h"
#include "socks5.h"
#include "c_map.h"

// callback functions
static void socks_handshake_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socks_handshake_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void socks_write_cb(uv_write_t* req, int status);
static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void remote_write_cb(uv_write_t *req, int status);
static void socks_after_shutdown_cb(uv_shutdown_t* req, int status);
static void socks_after_close_cb(uv_handle_t* handle);
static void connect_to_remote_cb(uv_connect_t* req, int status);
static void socks_accept_cb(uv_stream_t *server, int status);
static void remote_after_close_cb(uv_handle_t* handle);
static void connect_to_remote_cb(uv_connect_t* req, int status);

// customized functions
static remote_ctx_t* create_new_long_connection(server_ctx_t* listener);
static void remote_exception(remote_ctx_t* remote_ctx);
static void send_EOF_packet(socks_handshake_t* socks_hsctx, remote_ctx_t* remote_ctx);

int verbose       = 0;
int log_to_file   = 1;
int total_read    = 0;
int total_written = 0;
FILE * logfile    = NULL;

conf_t conf;
uv_loop_t *loop;

static void remote_after_close_cb(uv_handle_t* handle) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*) handle->data;
    delete_c_map(remote_ctx->idfd_map);
    /*
    socks_handshake_t* curr = NULL;
    for (curr = list_get_start(&remote_ctx->managed_socks_list);
         !list_elem_is_end(&remote_ctx->managed_socks_list, curr);
         curr = curr->next) {
        if (curr != NULL) {
            if (!uv_is_closing((uv_handle_t*) &curr->server)) {
                curr->remote_long = NULL;
                uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                req->data = curr;
                uv_shutdown(req, (uv_stream_t*)&curr->server, socks_after_shutdown_cb);
            }
        }
    }
    */
    remote_ctx->listen->remote_long = NULL;
    free(remote_ctx);
}

static void send_EOF_packet(socks_handshake_t* socks_hsctx, remote_ctx_t* remote_ctx) {
    int offset = 0;
    char* pkt_buf = malloc(HDR_LEN);
    uint32_t session_id = htonl((uint32_t)socks_hsctx->session_id);
    uint16_t datalen    = 0;
    char rsv = CTL_CLOSE;
    
    set_header(pkt_buf, &session_id, ID_LEN, offset);
    set_header(pkt_buf, &rsv, RSV_LEN, offset);
    set_header(pkt_buf, &datalen, DATALEN_LEN, offset);
    
    //LOGD("session_id = %d session_idno = %d", ctx->session_id, session_id);

    write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
    wr->req.data = socks_hsctx;
    wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
    uv_write(&wr->req, (uv_stream_t*)&remote_ctx->remote, &wr->buf, 1, remote_write_cb);
}

// this will cause corruption because remote_ctx_long is not existed.
static void socks_after_close_cb(uv_handle_t* handle) {
    LOGD("socks_after_close_cb");
    socks_handshake_t *socks_hsctx = (socks_handshake_t *)handle->data;
    if (socks_hsctx != NULL) {
        if (socks_hsctx->remote_long != NULL)
            send_EOF_packet(socks_hsctx, socks_hsctx->remote_long);
        socks_hsctx->closed++;
        if (socks_hsctx->closed == 2) {
            LOGD("session %d is removed from session map and ctx is freed", socks_hsctx->session_id);
            // add a comment
            if (socks_hsctx->remote_long != NULL)
                remove_c_map(socks_hsctx->remote_long->idfd_map, &socks_hsctx->session_id, NULL);
            free(socks_hsctx);
        }
    }
    else
        LOGD("socks_after_close_cb: socks_hsctx == NULL?");
}

static void socks_after_shutdown_cb(uv_shutdown_t* req, int status) {
    LOGD("socks_after_shutdown_cb");
    socks_handshake_t *socks_hsctx = (socks_handshake_t *)req->data;
    uv_close((uv_handle_t*)&socks_hsctx->server, socks_after_close_cb);
    free(req);
}
    
static void socks_write_cb(uv_write_t* req, int status) {
    fprintf(stderr, "socks write\n");
    write_req_t* wr = (write_req_t*)req;
    socks_handshake_t* socks_hsctx = (socks_handshake_t*)req->data;
    if (status) {
        if (!uv_is_closing((uv_handle_t*)&socks_hsctx->server)) {
            // the remote is closing, we tell js-local to stop sending and preparing close
            uv_read_stop((uv_stream_t *)&socks_hsctx->server);

            // shutdown remote
            uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
            req->data          = socks_hsctx;
            uv_shutdown(req, (uv_stream_t*)&socks_hsctx->server, socks_after_shutdown_cb);
        }    
        LOGD("socks write error: maybe client is closing");
    }
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    remote_ctx_t* ctx = (remote_ctx_t*)handle->data;
    *buf = uv_buf_init(ctx->recv_buffer, ctx->expect_to_recv);
    assert(buf->base != NULL);
}

static void remote_exception(remote_ctx_t* remote_ctx) {
    fprintf(stderr, "remote_exception captured\n");
    uv_read_stop((uv_stream_t *)&remote_ctx->remote);
    if (!uv_is_closing((uv_handle_t*)&remote_ctx->remote)) {
        struct clib_iterator *socks_map_itr = NULL;
        struct clib_object *elem            = NULL;
        socks_handshake_t* socks_hsctx      = NULL;
        
        /* traverse the whole map to stop SOCKS5 reading bufs*/
        socks_map_itr = new_iterator_c_map (remote_ctx->idfd_map);
        elem = socks_map_itr->get_next(socks_map_itr);
        while (elem) {
            socks_hsctx = (socks_handshake_t*)socks_map_itr->get_value(elem);
            elem = socks_map_itr->get_next(socks_map_itr);
            if (socks_hsctx != NULL) {
                uv_read_stop((uv_stream_t*) &socks_hsctx->server);
                socks_hsctx->remote_long = NULL;
                uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                req->data = socks_hsctx;
                uv_shutdown(req, (uv_stream_t*)&socks_hsctx->server, socks_after_shutdown_cb);
            }
        }
        delete_iterator_c_map(socks_map_itr);
        uv_close((uv_handle_t*) &remote_ctx->remote, remote_after_close_cb);
    }
}

static void remote_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    fprintf(stderr, "remote_read_cb called\n");
    remote_ctx_t* ctx = (remote_ctx_t*)client->data;
//    struct timeval _tv_start = GetTimeStamp();
    if (verbose) LOGD("nread = %d\n", nread);
    if (nread < 0) {
        if (!uv_is_closing((uv_handle_t*)client)) {
            fprintf(stderr, "remote long connection is closed or error\n");
            remote_exception(ctx);
        }

    } else if (nread > 0) {
        if (!ctx->reset) {
            if (verbose)  LOGD("reset packet and buffer\n");
            ctx->reset   = 1;
            ctx->buf_len = 0;
            ctx->offset  = 0;
//            struct timeval _tv_start = GetTimeStamp();
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
            if (ctx->buf_len == HDR_LEN) {
                get_header(&ctx->tmp_packet.session_id, ctx->packet_buf, ID_LEN, ctx->offset);
                ctx->tmp_packet.session_id = ntohl((uint32_t)ctx->tmp_packet.session_id);
                LOGD("session_id = %d\n", ctx->tmp_packet.session_id);
                get_header(&ctx->tmp_packet.rsv, ctx->packet_buf, RSV_LEN, ctx->offset);
                get_header(&ctx->tmp_packet.datalen, ctx->packet_buf, DATALEN_LEN, ctx->offset);
                ctx->tmp_packet.datalen = ntohs((uint16_t)ctx->tmp_packet.datalen);
                if (verbose) LOGD("datalen = %d\n", ctx->tmp_packet.datalen);
                ctx->expect_to_recv = ctx->tmp_packet.datalen;
                ctx->stage = 1;
                if (ctx->tmp_packet.rsv == CTL_CLOSE) {
                    ctx->reset = 0;
                    ctx->expect_to_recv = HDR_LEN;
                    LOGD("received a CTL_CLOSE(0x04) packet -- session in js-server is closed");
                    socks_handshake_t* exist_ctx = NULL;

                    if (find_c_map(ctx->idfd_map, &ctx->tmp_packet.session_id, &exist_ctx))
                    {
                        exist_ctx->closed++;
                        if (exist_ctx->closed == 2) {
                            // client passively removes and frees session
                            LOGD("session %d is removed from session map and ctx is freed", exist_ctx->session_id);
                            if (exist_ctx->remote_long != NULL)
                                remove_c_map(exist_ctx->remote_long->idfd_map, &exist_ctx->session_id, NULL);
                                free(exist_ctx);
                            // add session id to idle session id list
                        }
                        
                        // remote is closing, so shutdown SOCKS5 socket
                        if (!uv_is_closing((uv_handle_t*)&exist_ctx->server)) {
                            uv_read_stop((uv_stream_t *)&exist_ctx->server);
                            uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
                            req->data          = exist_ctx;
                            uv_shutdown(req, (uv_stream_t*)&exist_ctx->server, socks_after_shutdown_cb);
                        }
                    
                    }
                }
            }
            else{
                LOGD("< header length... gather more");
                ctx->expect_to_recv = HDR_LEN - ctx->buf_len;
                return;
            }
        
        } else if (ctx->stage == 1) {
            if (ctx->buf_len == HDR_LEN + ctx->tmp_packet.datalen) {
                ctx->reset = 0;
                if (verbose)  LOGD("data enough\n");
                fprintf(stderr, "stage = 1, remote_read_cb\n");
                socks_handshake_t* socks = NULL;
                if (find_c_map(ctx->idfd_map, &ctx->tmp_packet.session_id, &socks))
                {
                    fprintf(stderr, "remote_read_ready_to_write\n");
                    socks->response = malloc(ctx->tmp_packet.datalen);
                    get_payload(socks->response, ctx->packet_buf, ctx->tmp_packet.datalen, ctx->offset);
                    write_req_t* wr = malloc(sizeof(write_req_t));
                    wr->req.data    = socks;
                    wr->buf         = uv_buf_init(socks->response, ctx->tmp_packet.datalen);
                    uv_write(&wr->req, (uv_stream_t*)&socks->server, &wr->buf, 1, socks_write_cb);
                }
                else {
                    LOGD("found nothing in the map\n");
                }
                ctx->expect_to_recv = HDR_LEN;
            } else if (ctx->buf_len < HDR_LEN + ctx->tmp_packet.datalen) {
                LOGD("< datalen... gather more");
                ctx->expect_to_recv = HDR_LEN + ctx->tmp_packet.datalen - ctx->buf_len;
                return;
            } else {
                LOGD("impossible! should never reach here (> datalen)\n");
            }
        }
    }

}

// Init a long connection to your server
static void connect_to_remote_cb(uv_connect_t* req, int status) {
    remote_ctx_t* ctx = (remote_ctx_t *)req->data;
    req->handle->data = ctx;
    if (status) {
        fprintf(stderr, "connect error\n");
        remote_exception(ctx);
        free(req);
        return;
    }
    uv_read_start(req->handle, remote_alloc_cb, remote_read_cb);
    /* visit all SOCKS5 context and tell them to start reading bufs*/
    socks_handshake_t* curr = NULL;
    for (curr = list_get_start(&ctx->managed_socks_list);
         !list_elem_is_end(&ctx->managed_socks_list, curr);
         curr = curr->next) {
        if (curr != NULL)
        {
            uv_read_start((uv_stream_t*) &curr->server, socks_handshake_alloc_cb,
                          socks_handshake_read_cb);
            fprintf(stderr, "read start\n");
        }
    }
    ctx->connected = RC_OK;
    fprintf(stderr, "Connected to remote\n");
}   

static int try_to_connect_remote(remote_ctx_t* ctx) {
    fprintf(stderr, "try to connect to remote\n");
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    int r = uv_ip4_addr(conf.server_address, conf.serverport, &remote_addr);
    if (r)
        FATAL("wrong address!");
    ctx->connected = RC_ESTABLISHING;
    uv_connect_t* remote_conn_req = (uv_connect_t*) malloc(sizeof(uv_connect_t));
    remote_conn_req->data = ctx;
    return uv_tcp_connect(remote_conn_req, &ctx->remote, (struct sockaddr*)&remote_addr, connect_to_remote_cb);
}

// socks accept callback
static void socks_accept_cb(uv_stream_t *server, int status) {
    if (status)
        ERROR("async connect", status);
    server_ctx_t *listener = (server_ctx_t*)server->data;
    socks_handshake_t *socks_hsctx = calloc(1, sizeof(socks_handshake_t));
    socks_hsctx->server.data = socks_hsctx;
    
    /* set central gateway address */
    socks_hsctx->stage   = 2;
    socks_hsctx->atyp    = ATYP_DOMAIN;
    socks_hsctx->addrlen = conf.centralgw_address_len;
    memcpy(socks_hsctx->host, conf.centralgw_address, socks_hsctx->addrlen);      // domain name copied
    uint16_t gateway_port_n = htons(conf.gatewayport);
    memcpy(socks_hsctx->port, &gateway_port_n, sizeof(gateway_port_n));
    /* set central gateway address */
    
    uv_tcp_init(loop, &socks_hsctx->server);
    uv_tcp_nodelay(&socks_hsctx->server, 1);
    int r = uv_accept(server, (uv_stream_t*) &socks_hsctx->server);
    if (r) {
        fprintf(stderr, "accepting connection failed %d", r);
        uv_close((uv_handle_t*) &socks_hsctx->server, NULL);
    }
    if (listener->remote_long != NULL) {
        remote_ctx_t* remote_ctx = listener->remote_long;
        list_add_to_tail(&remote_ctx->managed_socks_list, socks_hsctx);
        socks_hsctx->remote_long = remote_ctx;
        
        switch (remote_ctx->connected) {
            case RC_OFF:
                try_to_connect_remote(remote_ctx);
                break;
            case RC_OK:
                uv_read_start((uv_stream_t*) &socks_hsctx->server, socks_handshake_alloc_cb,
                                  socks_handshake_read_cb);
                break;
            case RC_ESTABLISHING:
                break;
        }
    }
    else {
        listener->remote_long = create_new_long_connection(listener);
        list_add_to_tail(&listener->remote_long->managed_socks_list, socks_hsctx);
        try_to_connect_remote(listener->remote_long);
        socks_hsctx->remote_long = listener->remote_long;
    }
    socks_hsctx->session_id = ++socks_hsctx->remote_long->sid;
    insert_c_map (socks_hsctx->remote_long->idfd_map, &socks_hsctx->session_id, sizeof(int), socks_hsctx, sizeof(int));
    if (socks_hsctx->remote_long->sid == INT_MAX)
        socks_hsctx->remote_long->sid = 0;
}

static void socks_handshake_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

static void socks_handshake_read_cb(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (verbose)  LOGD("nread = %d", nread);
    if (nread == UV_EOF) {
        socks_handshake_t *socks_hsctx = client->data;
        socks_hsctx->closing = 1;
        if (!uv_is_closing((uv_handle_t*)&socks_hsctx->server)) {
            // the remote is closing, we tell js-local to stop sending and preparing close
            uv_read_stop((uv_stream_t *)&socks_hsctx->server);

            // shutdown remote
            uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
            req->data = socks_hsctx;
            uv_shutdown(req, (uv_stream_t*)&socks_hsctx->server, socks_after_shutdown_cb);
        }        
        // for debug
        LOGD("A socks5 connection is closed\n");
    } else if (nread > 0) {
        socks_handshake_t *socks_hsctx = client->data;
        if (socks_hsctx->stage == 2) {
            if (!socks_hsctx->init) {
                socks_hsctx->init = 1;
                int offset = 0;
                char* pkt_buf = malloc(ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN + ADDRLEN_LEN \
                                        + socks_hsctx->addrlen + PORT_LEN + nread);
                packet_t* pkt = calloc(1, sizeof(packet_t));
                pkt->rawpacket = pkt_buf;
                char rsv = CTL_INIT;
                uint32_t id_to_send = htonl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = htons((uint16_t)(ATYP_LEN + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread));
                set_header(pkt_buf, &id_to_send, ID_LEN, offset);
                set_header(pkt_buf, &rsv, RSV_LEN, offset);
                set_header(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                set_header(pkt_buf, &socks_hsctx->atyp, ATYP_LEN, offset);
                LOGD("pkt_maker atyp %d", socks_hsctx->atyp);
                set_header(pkt_buf, &socks_hsctx->addrlen, ADDRLEN_LEN, offset);
                set_header(pkt_buf, &socks_hsctx->host, socks_hsctx->addrlen, offset);
                set_header(pkt_buf, &socks_hsctx->port, PORT_LEN, offset);
                set_payload(pkt_buf, buf->base, nread, offset);
                //SHOW_BUFFER(pkt_buf, nread);
                if (verbose) LOGD("now here is buf\n");
                if (verbose) SHOW_BUFFER(buf->base, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN \
                 + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread);
                
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->req.data    = socks_hsctx->remote_long;
                wr->buf         = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN \
                 + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread);
                uv_write(&wr->req, (uv_stream_t*)&socks_hsctx->remote_long->remote, &wr->buf, 1, remote_write_cb);
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
                char rsv = CTL_NORMAL;
                uint32_t id_to_send      = ntohl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = ntohs((uint16_t)nread);
                set_header(pkt_buf, &id_to_send, ID_LEN, offset);
                set_header(pkt_buf, &rsv, RSV_LEN, offset);
                set_header(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                set_header(pkt_buf, buf->base, nread, offset);
                if (verbose) SHOW_BUFFER(pkt_buf, nread);
                
                // to add a pointer to refer to long remote connection
                write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                wr->req.data    = socks_hsctx->remote_long;
                wr->buf = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
                uv_write(&wr->req, (uv_stream_t*)&socks_hsctx->remote_long->remote, &wr->buf, 1, remote_write_cb);
                // do not forget free buffers
            }
        }
        
        free(buf->base);
    }
    
    if (nread == 0) free(buf->base);
}

static void remote_write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*) req;
    remote_ctx_t* remote_ctx = req->data;
    if (status) {
        if (!uv_is_closing((uv_handle_t*)&remote_ctx->remote)) {
            LOGD("async write, maybe long remote connection is broken %d", status);
            remote_exception(remote_ctx);
        }
    }
    assert(wr->req.type == UV_WRITE);
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

static remote_ctx_t* create_new_long_connection(server_ctx_t* listener){
    remote_ctx_t* remote_ctx_long;
    remote_ctx_long = calloc(1, sizeof(remote_ctx_t));
    if (remote_ctx_long == NULL) {
        FATAL("Not enough memory");
    }
    remote_ctx_long->expect_to_recv = HDR_LEN;
//    uv_connect_t *req = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));
//    req->data = remote_ctx_long;
    remote_ctx_long->remote.data    = remote_ctx_long;
    remote_ctx_long->listen         = listener;
    remote_ctx_long->connected      = RC_OFF;
    struct clib_map* map = new_c_map(compare_id, NULL, NULL);
    remote_ctx_long->idfd_map        = map;
    uv_tcp_init(loop, &remote_ctx_long->remote);
    list_init(&remote_ctx_long->managed_socks_list);
    uv_tcp_nodelay(&remote_ctx_long->remote, 1);
    return remote_ctx_long;
}

int main(int argc, char **argv) {
    memset(&conf, '\0', sizeof(conf));
#ifndef DEBUGX
    int c, option_index = 0;
    char* configfile = NULL;
    opterr = 0;
    static struct option long_options[] =
    {
        {0, 0, 0, 0}
    };
    
    while ((c = getopt_long(argc, argv, "c:r:l:p:P:V",
                            long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                configfile = optarg;
                break;
            case 'p':
                conf.localport = atoi(optarg);
                break;
            case 'P':
                conf.serverport = atoi(optarg);
                break;
            case 'r':
                conf.local_address = optarg;
                break;
            case 'l':
                conf.server_address = optarg;
                break;
            case 'V':
                verbose = 1;
                break;
            default:
                opterr = 1;
                break;
        }
    }

    if (configfile != NULL) {
        read_conf(configfile, &conf);
    }

    if (opterr || argc == 1 || conf.serverport == NULL || conf.server_address == NULL || conf.localport == NULL || conf.local_address == NULL) {
        printf("Error: 1) pass wrong or null args to the program.\n");
        printf("       2) parse config file failed.\n");
        usage();
        exit(EXIT_FAILURE);
    }
    
    //USE_LOGFILE(locallog);
#else
    conf.localport      = 7000;
    conf.serverport     = 7001;
    conf.server_address = "127.0.0.1";
    conf.local_address  = "0.0.0.0";
#endif

    struct sockaddr_in bind_addr;
    struct sockaddr_in connect_addr;
    
    loop = uv_default_loop();
    char* locallog = "/tmp/local.log";
    
    if (log_to_file)
        USE_LOGFILE(locallog);
    
    server_ctx_t *listener      = calloc(1, sizeof(server_ctx_t));
    server_ctx_t *listener_http = calloc(1, sizeof(server_ctx_t));
    listener->server.data       = listener;
    listener_http->server.data  = listener_http;
    listener->remote_long       = create_new_long_connection(listener);
    listener_http->remote_long  = create_new_long_connection(listener_http);
    
    uv_tcp_init(loop, &listener_http->server);
    uv_tcp_nodelay(&listener_http->server, 1);
    uv_tcp_init(loop, &listener->server);
    uv_tcp_nodelay(&listener->server, 1);
    
    int r = 0;
    r = uv_ip4_addr(conf.local_address, conf.localport, &bind_addr);
    if (r)
        ERROR("address error", r);
    LOGD("Ready to connect to remote server");
    r = uv_tcp_bind(&listener->server, (struct sockaddr*)&bind_addr, 0);
    if (r)
    	ERROR("bind error", r);
    r = uv_listen((uv_stream_t*) &listener->server, 128 /*backlog*/, socks_accept_cb);
    if (r)
        ERROR("listen error port", r);
    fprintf(stderr, "Listening on localhost:7000\n");
    uv_run(loop, UV_RUN_DEFAULT);
    CLOSE_LOGFILE;
    return 0;
}