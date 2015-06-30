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

//TODO: change write_cb status code handling (UV_ECANCELED)

// callback functions
static void socks_handshake_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf);
static void socks_handshake_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void socks_write_cb(uv_write_t* req, int status);
static void remote_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf);
static void remote_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void remote_write_cb(uv_write_t* req, int status);
static void socks_after_shutdown_cb(uv_shutdown_t* req, int status);
static void socks_after_close_cb(uv_handle_t* handle);
static void connect_to_remote_cb(uv_connect_t* req, int status);
static void socks_accept_cb(uv_stream_t* server, int status);
static void remote_after_close_cb(uv_handle_t* handle);
static void connect_to_remote_cb(uv_connect_t* req, int status);

// customized functions
static remote_ctx_t* create_new_long_connection(server_ctx_t* listener, int);
static void remote_exception(remote_ctx_t* remote_ctx);
static void send_EOF_packet(socks_handshake_t* socks_hsctx, remote_ctx_t* remote_ctx);

int verbose = 0;
int log_to_file = 1;
int total_read = 0;
int total_written = 0;
FILE* logfile = NULL;

conf_t conf;
uv_loop_t* loop;

static inline int
session_cmp(const socks_handshake_t* tree_a, const socks_handshake_t* tree_b)
{
    if (tree_a->session_id == tree_b->session_id)
        return 0;
    return tree_a->session_id < tree_b->session_id ? -1 : 1;
}

RB_PROTOTYPE(socks_map_tree, socks_handshake, rb_link, session_cmp);
RB_GENERATE(socks_map_tree, socks_handshake, rb_link, session_cmp);

static void remote_after_close_cb(uv_handle_t* handle)
{
    remote_ctx_t* remote_ctx = (remote_ctx_t*)handle->data;
    remote_ctx->listen->remote_long[remote_ctx->rc_index] = create_new_long_connection(remote_ctx->listen, remote_ctx->rc_index);
    free(remote_ctx);
}

static void send_EOF_packet(socks_handshake_t* socks_hsctx, remote_ctx_t* remote_ctx)
{
    int offset = 0;
    char* pkt_buf = malloc(HDR_LEN);
    uint32_t session_id = htonl((uint32_t)socks_hsctx->session_id);
    uint16_t datalen = 0;
    char rsv = CTL_CLOSE;

    set_header(pkt_buf, &session_id, ID_LEN, offset);
    set_header(pkt_buf, &rsv, RSV_LEN, offset);
    set_header(pkt_buf, &datalen, DATALEN_LEN, offset);

    //LOGD("session_id = %d session_idno = %d", ctx->session_id, session_id);

    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
    wr->req.data = remote_ctx;
    wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
    int r = uv_write(&wr->req, (uv_stream_t*)&remote_ctx->remote, &wr->buf, 1, remote_write_cb);
    if (r) {
        free(wr->buf.base);
        free(wr);
        HANDLECLOSE_RC(&remote_ctx->remote, remote_ctx);
    }
}

// this will cause corruption because remote_ctx_long is not existed.
static void socks_after_close_cb(uv_handle_t* handle)
{
    LOGD("socks_after_close_cb");
    socks_handshake_t* socks_hsctx = (socks_handshake_t*)handle->data;
    if (likely(socks_hsctx != NULL)) {
        if (socks_hsctx->remote_long != NULL) {
            send_EOF_packet(socks_hsctx, socks_hsctx->remote_long);
            RB_REMOVE(socks_map_tree, &socks_hsctx->remote_long->socks_map, socks_hsctx);
        }
        // add a comment
        free(socks_hsctx);
    }
    else
        LOGD("socks_after_close_cb: socks_hsctx == NULL?");
}

static void socks_after_shutdown_cb(uv_shutdown_t* req, int status)
{
    LOGD("socks_after_shutdown_cb");
    socks_handshake_t* socks_hsctx = (socks_handshake_t*)req->data;
    uv_close((uv_handle_t*)&socks_hsctx->server, socks_after_close_cb);
    free(req);
}

static void socks_write_cb(uv_write_t* req, int status)
{
    write_req_t* wr = (write_req_t*)req;
    socks_handshake_t* socks_hsctx = (socks_handshake_t*)req->data;
    if (status) {
        if (status != UV_ECANCELED) {
            HANDLECLOSE(&socks_hsctx->server, socks_after_close_cb);
            LOGW("socks write error status: %s", uv_err_name(status));
        }
        else
            LOGW("socks write canceled due to closing connection");
    }
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

static void remote_exception(remote_ctx_t* remote_ctx)
{
    LOGW("Freeing remote long connection...");
    uv_read_stop((uv_stream_t*)&remote_ctx->remote);
    if (!uv_is_closing((uv_handle_t*)&remote_ctx->remote)) {
        socks_handshake_t* socks_hsctx = NULL;

        /* traverse the whole map to stop SOCKS5 reading bufs*/
        RB_FOREACH(socks_hsctx, socks_map_tree, &remote_ctx->socks_map)
        {
            if (socks_hsctx != NULL) {
                uv_read_stop((uv_stream_t*)&socks_hsctx->server);
                socks_hsctx->remote_long = NULL;
                HANDLECLOSE(&socks_hsctx->server, socks_after_close_cb);
            }
        }
        uv_close((uv_handle_t*)&remote_ctx->remote, remote_after_close_cb);
    }
}

static void remote_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    remote_ctx_t* ctx = (remote_ctx_t*)handle->data;
    *buf = uv_buf_init(ctx->recv_buffer, ctx->expect_to_recv);
    assert(buf->base != NULL);
}

static void remote_read_cb(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
    remote_ctx_t* ctx = (remote_ctx_t*)client->data;
    if (verbose)
        LOGD("nread = %d\n", nread);
    if (unlikely(nread <= 0)) {
        if (nread == 0)
            return;
        HANDLECLOSE_RC(client, ctx);
    }
    else {
        if (!ctx->reset) {
            if (verbose)
                LOGD("reset packet and buffer\n");
            ctx->reset = 1;
            ctx->buf_len = 0;
            ctx->offset = 0;
            memset(&ctx->tmp_packet, 0, sizeof(tmp_packet_t));
            ctx->stage = 0;
        }

        if (verbose)
            LOGD("buf_len before = %d\n", ctx->buf_len);
        memcpy(ctx->packet_buf + ctx->buf_len, buf->base, nread); // copy current buf to packet_buf
        ctx->buf_len += nread; // record how much data we put in the packet_buf
        if (verbose)
            LOGD("buf_len after = %d\n", ctx->buf_len);

        if (ctx->stage == 0) {
            if (likely(ctx->buf_len == HDR_LEN)) {
                get_header(&ctx->tmp_packet.session_id, ctx->packet_buf, ID_LEN, ctx->offset);
                ctx->tmp_packet.session_id = ntohl((uint32_t)ctx->tmp_packet.session_id);
                LOGD("session_id = %d\n", ctx->tmp_packet.session_id);
                get_header(&ctx->tmp_packet.rsv, ctx->packet_buf, RSV_LEN, ctx->offset);
                get_header(&ctx->tmp_packet.datalen, ctx->packet_buf, DATALEN_LEN, ctx->offset);
                ctx->tmp_packet.datalen = ntohs((uint16_t)ctx->tmp_packet.datalen);
                if (verbose)
                    LOGD("datalen = %d\n", ctx->tmp_packet.datalen);
                ctx->expect_to_recv = ctx->tmp_packet.datalen;
                ctx->stage = 1;

                if (ctx->tmp_packet.rsv != CTL_NORMAL) {
                    ctx->reset = 0;
                    ctx->expect_to_recv = HDR_LEN;
                    if (CTL_CLOSE == ctx->tmp_packet.rsv) {
                        LOGD("received a CTL_CLOSE(0x04) packet -- session in js-server is closed");
                        socks_handshake_t* exist_ctx = NULL;
                        socks_handshake_t find_ctx;
                        find_ctx.session_id = ctx->tmp_packet.session_id;

                        /* using Apple's map (rb-tree) structure */
                        exist_ctx = RB_FIND(socks_map_tree, &ctx->socks_map, &find_ctx);
                        if (exist_ctx != NULL) {
                            HANDLECLOSE(&exist_ctx->server, socks_after_close_cb);
                        }
                    }
                    else if (CTL_CLOSE_ACK == ctx->tmp_packet.rsv) {
                        // add this session id to available session list
                        LOGW("Received a CTL_CLOSE_ACK packet");
                        session_t* avl_session = calloc(1, sizeof(session_t));
                        avl_session->session_id = ctx->tmp_packet.session_id;
                        list_add_to_tail(&ctx->avl_session_list, avl_session);
                    }
                }
            }
            else {
                LOGD("< header length... gather more");
                ctx->expect_to_recv = HDR_LEN - ctx->buf_len;
                return;
            }
        }
        else if (ctx->stage == 1) {
            if (ctx->buf_len == HDR_LEN + ctx->tmp_packet.datalen) {
                ctx->reset = 0;
                socks_handshake_t* socks = NULL;
                socks_handshake_t find_ctx;
                find_ctx.session_id = ctx->tmp_packet.session_id;
                socks = RB_FIND(socks_map_tree, &ctx->socks_map, &find_ctx);
                if (socks != NULL) {
                    char* response = malloc(ctx->tmp_packet.datalen);
                    get_payload(response, ctx->packet_buf, ctx->tmp_packet.datalen, ctx->offset);
                    write_req_t* wr = malloc(sizeof(write_req_t));
                    wr->req.data = socks;
                    wr->buf = uv_buf_init(response, ctx->tmp_packet.datalen);
                    int r = uv_write(&wr->req, (uv_stream_t*)&socks->server, &wr->buf, 1, socks_write_cb);
                    UV_WRITE_CHECK(r, wr, &socks->server, socks_after_close_cb);
                }
                else {
                    LOGW("remote_read_cb found nothing in the map\n");
                }
                ctx->expect_to_recv = HDR_LEN;
            }
            else if (ctx->buf_len < HDR_LEN + ctx->tmp_packet.datalen) {
                LOGD("< datalen... gather more");
                ctx->expect_to_recv = HDR_LEN + ctx->tmp_packet.datalen - ctx->buf_len;
                return;
            }
            else {
                LOGD("impossible! should never reach here (> datalen)\n");
            }
        }
    }
}

// Init a long connection to your server
static void connect_to_remote_cb(uv_connect_t* req, int status)
{
    remote_ctx_t* ctx = (remote_ctx_t*)req->data;
    req->handle->data = ctx;
    if (status) {
        LOGW("Failed to connect to remote gateway");
        HANDLECLOSE_RC(&ctx->remote, ctx);
        free(req);
        return;
    }
    uv_read_start(req->handle, remote_alloc_cb, remote_read_cb);
    ctx->connected = RC_OK;
    LOGI("Connected to gateway (pool connection id: %d)", ctx->rc_index);
    free(req);
}

static int try_to_connect_remote(remote_ctx_t* ctx)
{
    LOGI("Try to connect to remote (pool connection id: %d)", ctx->rc_index);
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    int r = uv_ip4_addr(conf.server_address, conf.serverport, &remote_addr);
    if (r)
        FATAL("wrong address!");
    ctx->connected = RC_ESTABLISHING;
    uv_connect_t* remote_conn_req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    remote_conn_req->data = ctx;
    return uv_tcp_connect(remote_conn_req, &ctx->remote, (struct sockaddr*)&remote_addr, connect_to_remote_cb);
}

// socks accept callback
static void socks_accept_cb(uv_stream_t* server, int status)
{
    static int round_robin_index = 0;
    if (status) {
        LOGW("async connect error %d", status);
        return;
    }

    server_ctx_t* listener = (server_ctx_t*)server->data;
    socks_handshake_t* socks_hsctx = calloc(1, sizeof(socks_handshake_t));
    socks_hsctx->server.data = socks_hsctx;

    /* set central gateway address */
    if (conf.backend_mode) {
        struct sockaddr_in remote_addr;
        uv_ip4_addr(conf.centralgw_address, conf.gatewayport, &remote_addr);
        socks_hsctx->stage = 2;
        socks_hsctx->atyp = ATYP_IPV4;
        socks_hsctx->addrlen = 4;
        memcpy(socks_hsctx->host, &remote_addr.sin_addr.s_addr, socks_hsctx->addrlen);
        uint16_t gateway_port_n = htons(conf.gatewayport);
        memcpy(socks_hsctx->port, &gateway_port_n, sizeof(gateway_port_n));
    }
    /* set central gateway address */

    uv_tcp_init(loop, &socks_hsctx->server);
    uv_tcp_nodelay(&socks_hsctx->server, 1);
    int r = uv_accept(server, (uv_stream_t*)&socks_hsctx->server);
    if (r) {
        LOGW("accepting connection failed %d", r);
        uv_close((uv_handle_t*)&socks_hsctx->server, NULL);
        free(socks_hsctx);
        return;
    }

    if (likely(listener->remote_long[round_robin_index] != NULL)) {

        remote_ctx_t* remote_ctx = listener->remote_long[round_robin_index];
        socks_hsctx->remote_long = remote_ctx;

        switch (remote_ctx->connected) {
        case RC_OFF:
            socks_hsctx->remote_long = NULL;
            uv_close((uv_handle_t*)&socks_hsctx->server, socks_after_close_cb);
            try_to_connect_remote(remote_ctx);
            return;
            break;
        case RC_OK:
            uv_read_start((uv_stream_t*)&socks_hsctx->server, socks_handshake_alloc_cb,
                socks_handshake_read_cb);
            break;
        case RC_ESTABLISHING:
            socks_hsctx->remote_long = NULL;
            uv_close((uv_handle_t*)&socks_hsctx->server, socks_after_close_cb);
            return;
            break;
        }

        session_t* avl_session = list_get_head_elem(&socks_hsctx->remote_long->avl_session_list);
        if (NULL != avl_session) {
            socks_hsctx->session_id = avl_session->session_id;
            list_remove_elem(avl_session);
            free(avl_session);
            avl_session = NULL;
        }
        else {
            socks_hsctx->session_id = ++socks_hsctx->remote_long->sid;
            if (socks_hsctx->remote_long->sid == INT_MAX)
                socks_hsctx->remote_long->sid = 0;
        }

        socks_handshake_t* cr = RB_INSERT(socks_map_tree, &socks_hsctx->remote_long->socks_map, socks_hsctx);
        if (cr) {
            LOGW("long id = %d RB_INSERT FAILED", socks_hsctx->remote_long->rc_index);
            assert(0);
        }
        LOGW("Insert session id = %d into map", socks_hsctx->session_id);
    }

    if (++round_robin_index == listener->rc_pool_size)
        round_robin_index = 0;
}

static void socks_handshake_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    *buf = uv_buf_init((char*)malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

static void socks_handshake_read_cb(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
    if (verbose)
        LOGD("nread = %d", nread);
    if (unlikely(nread <= 0)) {
        if (buf->len)
            free(buf->base);
        if (nread == 0)
            return;
        socks_handshake_t* socks_hsctx = client->data;
        HANDLECLOSE(&socks_hsctx->server, socks_after_close_cb);
        // for debug
        LOGD("A socks5 connection is closed\n");
    }
    else {
        socks_handshake_t* socks_hsctx = client->data;
        if (likely(socks_hsctx->stage == 2)) {
            if (!socks_hsctx->init) {
                socks_hsctx->init = 1;
                LOGW("Init with session id = %d", socks_hsctx->session_id);
                int offset = 0;
                char* pkt_buf = malloc(ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN + ADDRLEN_LEN
                    + socks_hsctx->addrlen + PORT_LEN + nread);
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
                if (verbose)
                    LOGD("now here is buf\n");
                if (verbose)
                    SHOW_BUFFER(buf->base, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN
                            + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + nread);
                if (socks_hsctx->remote_long != NULL) {
                    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
                    wr->req.data = socks_hsctx->remote_long;
                    wr->buf = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + ATYP_LEN
                            + ADDRLEN_LEN + socks_hsctx->addrlen + PORT_LEN + (unsigned int)nread);
                    int r = uv_write(&wr->req, (uv_stream_t*)&socks_hsctx->remote_long->remote, &wr->buf, 1, remote_write_cb);
                    if (r) {
                        free(wr->buf.base);
                        free(wr);
                        HANDLECLOSE_RC(&socks_hsctx->remote_long->remote, socks_hsctx->remote_long);
                    }
                }
                // do not forget freeing buffers
            }
            else {
                // redundant?
                if (socks_hsctx->closing == 1) {
                    free(buf->base);
                    return;
                }
                int offset = 0;
                char* pkt_buf = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
                char rsv = CTL_NORMAL;
                uint32_t id_to_send = ntohl((uint32_t)(socks_hsctx->session_id));
                uint16_t datalen_to_send = ntohs((uint16_t)nread);
                set_header(pkt_buf, &id_to_send, ID_LEN, offset);
                set_header(pkt_buf, &rsv, RSV_LEN, offset);
                set_header(pkt_buf, &datalen_to_send, DATALEN_LEN, offset);
                set_header(pkt_buf, buf->base, nread, offset);
                if (verbose)
                    SHOW_BUFFER(pkt_buf, nread);

                // to add a pointer to refer to long remote connection
                if (socks_hsctx->remote_long != NULL) {
                    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
                    wr->req.data = socks_hsctx->remote_long;
                    wr->buf = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + (unsigned int)nread);
                    int r = uv_write(&wr->req, (uv_stream_t*)&socks_hsctx->remote_long->remote, &wr->buf, 1, remote_write_cb);
                    if (r) {
                        free(wr->buf.base);
                        free(wr);
                        HANDLECLOSE_RC(&socks_hsctx->remote_long->remote, socks_hsctx->remote_long);
                    }
                }
                // do not forget free buffers
            }
        }

        if (socks_hsctx->stage == 0) {
            // received the first SOCKS5 request = in stage 0
            if (verbose)
                LOGD("%ld bytes read\n", nread);
            total_read += nread;
            char socks_first_req[SOCKS5_FISRT_REQ_SIZE] = { 0x05, 0x01, 0x00 }; // refer to SOCKS5 protocol
            method_select_response_t* socks_first_resp = malloc(sizeof(method_select_response_t));
            socks_first_resp->ver = SVERSION;
            socks_first_resp->method = HEXZERO;
            int r = memcmp(socks_first_req, buf->base, SOCKS5_FISRT_REQ_SIZE);
            if (r)
                LOGD("Not a SOCKS5 request, drop n close");

            write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
            wr->req.data = socks_hsctx;
            wr->buf = uv_buf_init((char*)socks_first_resp, sizeof(method_select_response_t));
            uv_write(&wr->req, client, &wr->buf, 1 /*nbufs*/, socks_write_cb);
            UV_WRITE_CHECK(r, wr, client, socks_after_close_cb);
            socks_hsctx->stage = 1;
            // sent the 1st response -> switch to the stage 1
        }
        else if (socks_hsctx->stage == 1) {
            // received 2nd request in stage 1
            // here we have to parse the requested domain or ip address, then we store it in hsctx
            socks5_req_or_resp_t* req = (socks5_req_or_resp_t*)buf->base;
            char* addr_ptr = &req->atyp + 1;
            if (req->atyp == ATYP_IPV4) {

                // client requests a ipv4 address
                socks_hsctx->atyp = ATYP_IPV4;
                socks_hsctx->addrlen = 4;
                memcpy(socks_hsctx->host, addr_ptr, 4); // ipv4 copied
                addr_ptr += 4;
                memcpy(socks_hsctx->port, addr_ptr, 2); // port copied in network order
                //                uint16_t p = ntohs(*(uint16_t *)(socks_hsctx->port));
            }
            else if (req->atyp == ATYP_DOMAIN) {
                if (verbose)
                    LOGD("atyp == 3\n");
                socks_hsctx->atyp = ATYP_DOMAIN;
                socks_hsctx->addrlen = *(addr_ptr++);
                memcpy(socks_hsctx->host, addr_ptr, socks_hsctx->addrlen); // domain name copied
                addr_ptr += socks_hsctx->addrlen;
                memcpy(socks_hsctx->port, addr_ptr, 2); // port copied
            }
            else
                LOGD("ERROR: unexpected atyp");

            socks5_req_or_resp_t* resp = calloc(1, sizeof(socks5_req_or_resp_t));
            memcpy(resp, req, sizeof(socks5_req_or_resp_t) - 4);
            // only copy the first 4 bytes to save time

            resp->cmd_or_resp = REP_OK;
            resp->atyp = ATYP_OK;

            write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
            wr->req.data = socks_hsctx;
            wr->buf = uv_buf_init((char*)resp, sizeof(socks5_req_or_resp_t));
            int r = uv_write(&wr->req, client, &wr->buf, 1, socks_write_cb);
            UV_WRITE_CHECK(r, wr, client, socks_after_close_cb);
            socks_hsctx->stage = 2;
        }

        free(buf->base);
    }
}

static void remote_write_cb(uv_write_t* req, int status)
{
    write_req_t* wr = (write_req_t*)req;
    remote_ctx_t* remote_ctx = req->data;
    if (status) {
        HANDLECLOSE_RC(&remote_ctx->remote, remote_ctx);
    }
    assert(wr->req.type == UV_WRITE);
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

static remote_ctx_t* create_new_long_connection(server_ctx_t* listener, int index)
{
    remote_ctx_t* remote_ctx_long = calloc(1, sizeof(remote_ctx_t));
    if (remote_ctx_long == NULL) {
        FATAL("Not enough memory");
    }
    remote_ctx_long->rc_index = index;
    remote_ctx_long->expect_to_recv = HDR_LEN;
    remote_ctx_long->remote.data = remote_ctx_long;
    remote_ctx_long->listen = listener;
    remote_ctx_long->connected = RC_OFF;

    RB_INIT(&remote_ctx_long->socks_map);
    uv_tcp_init(loop, &remote_ctx_long->remote);
    list_init(&remote_ctx_long->avl_session_list);
    uv_tcp_nodelay(&remote_ctx_long->remote, 1);
    return remote_ctx_long;
}

int main(int argc, char** argv)
{
    memset(&conf, '\0', sizeof(conf));
    conf.pool_size = 5; // default pool size = 5
    int c, option_index = 0, daemon = 0;
    char* configfile = NULL;
    opterr = 0;
    static struct option long_options[] = {
        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "c:r:l:p:P:V:n:d",
                long_options, &option_index)) != -1) {
        switch (c) {
        case 'n':
            conf.pool_size = atoi(optarg);
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
        case 'd':
            daemon = 1;
            break;
        default:
            opterr = 1;
            break;
        }
    }

    if (configfile != NULL) {
        read_conf(configfile, &conf);
    }

    LOGI("Backend mode = %d (1 = ON, 0 = OFF)", conf.backend_mode);
    LOGI("Connection Pool size = %d", conf.pool_size);

    if (opterr || argc == 1 || conf.serverport == 0 || conf.server_address == NULL || conf.localport == 0 || conf.local_address == NULL) {
        printf("Error: 1) pass wrong or null args to the program.\n");
        printf("       2) parse config file failed.\n");
        usage();
        exit(EXIT_FAILURE);
    }

#ifndef XCODE_DEBUG
    if (daemon == 1) {
        LOGI("js-local is working as deamon.");
        init_daemon();
    }
#endif

    struct sockaddr_in bind_addr;

    loop = malloc(sizeof *loop);
    uv_loop_init(loop);

    char* locallog = "/tmp/local.log";

    if (log_to_file)
        USE_LOGFILE(locallog);
    server_ctx_t* listener = calloc(1, sizeof(server_ctx_t));
    listener->server.data = listener;
    listener->rc_pool_size = conf.pool_size;
    if (listener->rc_pool_size > MAX_RC_NUM)
        ERROR("too large pool size!");
    for (int i = 0; i < listener->rc_pool_size; ++i) {
        listener->remote_long[i] = create_new_long_connection(listener, i);
        try_to_connect_remote(listener->remote_long[i]);
    }

    uv_tcp_init(loop, &listener->server);
    uv_tcp_nodelay(&listener->server, 1);

    int r = 0;
    r = uv_ip4_addr(conf.local_address, conf.localport, &bind_addr);
    if (r)
        ERROR_UV("address error", r);
    LOGD("Ready to connect to remote server");
    r = uv_tcp_bind(&listener->server, (struct sockaddr*)&bind_addr, 0);
    if (r)
        ERROR_UV("bind error", r);
    r = uv_listen((uv_stream_t*)&listener->server, 128 /*backlog*/, socks_accept_cb);
    if (r)
        ERROR_UV("listen error port", r);
    LOGI("Listening on localhost:7000");

    signal(SIGPIPE, SIG_IGN);
    uv_signal_t sigint;
    sigint.data = loop;
    int n = uv_signal_init(loop, &sigint);
    n = uv_signal_start(&sigint, signal_handler, SIGINT);

    uv_run(loop, UV_RUN_DEFAULT);
    CLOSE_LOGFILE;
    return 0;
}