#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include "utils.h"
#include "server.h"
#include "c_map.h"
#include "jconf.h"

uv_loop_t *loop = NULL;
FILE * logfile  = NULL;
int verbose     = 0;
int log_to_file = 1;
conf_t  conf;

// callback functions
static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void server_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void server_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void remote_write_cb(uv_write_t *req, int status);
static void remote_after_shutdown_cb(uv_shutdown_t* req, int status);
static void remote_after_close_cb(uv_handle_t* handle);
static void remote_addr_resolved_cb(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res);
static void remote_on_connect_cb(uv_connect_t* req, int status);
static void server_write_cb(uv_write_t *req, int status);
static void remote_timeout_cb(uv_timer_t* handle);

// customized functions
static int try_to_connect_remote(remote_ctx_t* remote_ctx);
static void send_EOF_packet(remote_ctx_t* remote_ctx, int cmd);
static void server_exception(server_ctx_t* server_ctx);

static void remote_timeout_cb(uv_timer_t* handle) {
    LOGW("remote timeout, ready to close remote connection");
    remote_ctx_t* remote_ctx = handle->data;
        if (!uv_is_closing((uv_handle_t*)&remote_ctx->handle)) {
        if (remote_ctx->resolved == 1)
            uv_close((uv_handle_t*)&remote_ctx->handle, remote_after_close_cb);
        else
            remote_ctx->closing = 1;
    }
}

static void server_after_close_cb(uv_handle_t* handle) {
    server_ctx_t* server_ctx = (server_ctx_t*) handle->data;
    delete_c_map(server_ctx->idfd_map);
    free(server_ctx);
    fprintf(stderr, "server_ctx freed\n");
}

static void server_exception(server_ctx_t* server_ctx) {
    if (server_ctx == NULL)
        assert(0);
    LOGW("Freeing remote long connection...");
    uv_read_stop((uv_stream_t *)&server_ctx->handle);
    if (!uv_is_closing((uv_handle_t*)&server_ctx->handle)) {
        struct clib_iterator *remote_map_itr = NULL;
        struct clib_object *elem = NULL;
        remote_ctx_t* remote_ctx = NULL;
        
        /* traverse the whole map to stop remote connections reading bufs */
        remote_map_itr = new_iterator_c_map (server_ctx->idfd_map);
        elem = remote_map_itr->get_next(remote_map_itr);
        while (elem) {
            remote_ctx = (remote_ctx_t*)remote_map_itr->get_value(elem);
            elem = remote_map_itr->get_next(remote_map_itr);
            if (remote_ctx != NULL) {
                uv_read_stop((uv_stream_t*) &remote_ctx->handle);
                remote_ctx->server_ctx = NULL;
                if (!uv_is_closing((uv_handle_t*) &remote_ctx->handle) && (remote_ctx->resolved == 1)) {
                    LOGW("server_exception remote_ctx = %x session_id = %d type = %d", remote_ctx, remote_ctx->session_id,remote_ctx->handle.type);
                    uv_close((uv_handle_t*) &remote_ctx->handle, remote_after_close_cb);
                }
            }
        }
        delete_iterator_c_map(remote_map_itr);
        uv_close((uv_handle_t*) &server_ctx->handle, server_after_close_cb);
    }
}

static void send_EOF_packet(remote_ctx_t* ctx, int cmd){
    int offset = 0;
    char* pkt_buf       = malloc(HDRLEN);
    uint32_t session_id = htonl((uint32_t)ctx->session_id);
    uint16_t datalen    = 0;
    uint8_t rsv            = cmd;
    LOGW("send_EOF_packet session id = %d",ctx->session_id);
    LOGD("the session id of the closing session is %d", ctx->session_id);

    set_header(pkt_buf, &session_id, ID_LEN, offset);
    set_header(pkt_buf, &rsv, RSV_LEN, offset);
    set_header(pkt_buf, &datalen, DATALEN_LEN, offset);

    write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
    wr->req.data = ctx->server_ctx;
    wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
    uv_write(&wr->req, (uv_stream_t*)&ctx->server_ctx->handle, &wr->buf, 1, server_write_cb);
}

static void remote_after_close_cb(uv_handle_t* handle) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*)handle->data;
    LOGW("remote_close_cb remote_ctx = %x session_id = %d", remote_ctx, remote_ctx->session_id);
    if (remote_ctx != NULL) {
        uv_timer_stop(&remote_ctx->http_timeout);
        if ((remote_ctx->server_ctx != NULL)) {
            remove_c_map(remote_ctx->server_ctx->idfd_map, &remote_ctx->session_id, NULL);
            if (CTL_CLOSE == remote_ctx->ctl_cmd)
                send_EOF_packet(remote_ctx, CTL_CLOSE_ACK);
            else if (CTL_NORMAL == remote_ctx->ctl_cmd)
                send_EOF_packet(remote_ctx, CTL_CLOSE);
        }
        packet_t* packet_to_free = NULL;
        while ((packet_to_free = list_get_head_elem(&remote_ctx->send_queue))) {
            list_remove_elem(packet_to_free);
            free(packet_to_free);
        }
        free(remote_ctx);
    }
}

static void remote_after_shutdown_cb(uv_shutdown_t* req, int status) {
    if (status) {
        LOGD("error remote_after_shutdown_cb status %d", status);
    }
    remote_ctx_t *remote_ctx = (remote_ctx_t *) req->data;
    LOGW("remote_after_shutdown_cb remote_ctx = %x session_id = %d\n", remote_ctx, remote_ctx->session_id);
    uv_close((uv_handle_t*) &remote_ctx->handle, remote_after_close_cb);
    free(req);  
}

// Notice: watch out each callback function, inappropriate free() leads to disaster
static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*)stream->data;
    //uv_timer_again(&remote_ctx->http_timeout);
    if (unlikely(nread <= 0)) {
        LOGD("remote_read_cb: nread <= 0");
        if (buf->len)
            free(buf->base);
        if (nread == 0)
            return;
        remote_ctx->connected = 0;
        if (!uv_is_closing((uv_handle_t*)&remote_ctx->handle)) {
            // the remote is closing, we tell js-local to stop sending and preparing close
            uv_read_stop((uv_stream_t *)&remote_ctx->handle);
            uv_close((uv_handle_t*)&remote_ctx->handle, remote_after_close_cb);
            
        }
    } else {
        server_ctx_t* server_ctx = remote_ctx->server_ctx;
        if (server_ctx == NULL) {
            free(buf->base);
            return;
        }
        
        int offset = 0;
        char* pkt_buf       = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
        uint32_t session_id = htonl((uint32_t)remote_ctx->session_id);
        uint16_t datalen    = htons((uint16_t)nread);
        set_header(pkt_buf, &session_id, ID_LEN, offset);
        uint8_t rsv = CTL_NORMAL;
        set_header(pkt_buf, &rsv, RSV_LEN, offset);
        set_header(pkt_buf, &datalen, DATALEN_LEN, offset);
        set_payload(pkt_buf, buf->base, nread, offset);
        write_req_t* req = calloc(1,sizeof(write_req_t));
        req->req.data    = server_ctx;
        req->buf         = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
        uv_write(&req->req, (uv_stream_t*)&remote_ctx->server_ctx->handle, &req->buf, 1, server_write_cb);
        LOGW("remote_read_cb remote_ctx = %x session_id = %d type = %d", remote_ctx, remote_ctx->session_id,remote_ctx->handle.type);
        free(buf->base);
    }
}

static void server_write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*)req;
    server_ctx_t* server_ctx = (server_ctx_t*) req->data;
    if (status) {
        if (!uv_is_closing((uv_handle_t*)&server_ctx->handle)) {
            LOGW("async write, maybe long remote connection is broken %d", status);
            server_exception(server_ctx);
        }
        // allow below lines to be executed to free bufs
    }
    assert(wr->req.type == UV_WRITE);
    
    if (wr->buf.base != NULL) {
        free(wr->buf.base);
    }
    free(wr);
}

static void remote_write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*)req;
    remote_ctx_t* remote_ctx = (remote_ctx_t*)req->data;
    if (status)
    {
        LOGW("remote_write_cb error session id = %d", remote_ctx->session_id);
        remote_ctx->connected = 0;
        if (status != UV_ECANCELED) {
            HANDLECLOSE(&remote_ctx->handle, remote_after_close_cb);
        }
        
        free(wr->buf.base);
        free(wr);
        LOGD("remote write failed!");
        return;
    }
    
    assert(wr->req.type == UV_WRITE);
    //LOGD("send in remote_write_cb data = \n%s\n", wr->buf.base);
    LOGW("uv_timer_again remote_ctx = %x", remote_ctx);
    uv_timer_again(&remote_ctx->http_timeout);
    packet_t* packet = list_get_head_elem(&remote_ctx->send_queue);
    if (packet) {
        write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
        wr->req.data    = remote_ctx;
        wr->buf         = uv_buf_init(packet->data, packet->payloadlen);
        int r = uv_write(&wr->req, (uv_stream_t*) &remote_ctx->handle, &wr->buf, 1, remote_write_cb);
        UV_WRITE_CHECK(r, wr, &remote_ctx->handle, remote_after_close_cb);
        list_remove_elem(packet);
        free(packet);
    }
    else {
        if (verbose)
            LOGD("got nothing to send");
    }
    
    free(wr->buf.base);
    free(wr);
    LOGW("remote_write_cb remote_ctx = %x session_id = %d type = %d", remote_ctx, remote_ctx->session_id,remote_ctx->handle.type);
}

// TODO: add timer to watch remote connection in case of TCP or HTTP timeout
static void remote_on_connect_cb(uv_connect_t* req, int status) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*)req->data;
    if (status) {
        LOGD("error in remote_on_connect");
        HANDLECLOSE(&remote_ctx->handle, remote_after_close_cb);
        free(req);
        return;
    }
    if (verbose) LOGD("domain resovled");
    remote_ctx->connected = 1;
    uv_read_start((uv_stream_t*)&remote_ctx->handle, remote_alloc_cb, remote_read_cb);
    
    packet_t* packet = list_get_head_elem(&remote_ctx->send_queue);
    if (packet) {
        LOGD("sent something in remote_on_connect");
        write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
        wr->req.data    = remote_ctx;
        wr->buf         = uv_buf_init(packet->data, packet->payloadlen);
        int r = uv_write(&wr->req, (uv_stream_t*) &remote_ctx->handle, &wr->buf, 1, remote_write_cb);
        UV_WRITE_CHECK(r, wr, &remote_ctx->handle, remote_after_close_cb);
        list_remove_elem(packet);
        free(packet);
    }
    else{
        if (verbose) LOGD("got nothing to send");
    }
    free(req);
}

static int try_to_connect_remote(remote_ctx_t* remote_ctx) {
    LOGW("try to connect to remote");
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    memcpy(&remote_addr.sin_addr.s_addr, remote_ctx->host, 4);
    remote_addr.sin_port = *(uint16_t*)remote_ctx->port; // notice: packet.port is in network order
    uv_connect_t* remote_conn_req = (uv_connect_t*) malloc(sizeof(uv_connect_t));
    uv_tcp_nodelay(&remote_ctx->handle, 1);
    remote_conn_req->data = remote_ctx;
    return uv_tcp_connect(remote_conn_req, &remote_ctx->handle, (struct sockaddr*)&remote_addr, remote_on_connect_cb);
}

static void remote_addr_resolved_cb(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*) resolver->data;
    if (status) {
        LOGD("error DNS resolve ");
        remote_ctx->resolved = 0;
        freeaddrinfo(res);
        HANDLECLOSE(&remote_ctx->handle, remote_after_close_cb);
        return;
    }
    
    if (remote_ctx->closing == 1) {
        remote_ctx->resolved = 0;
        HANDLECLOSE(&remote_ctx->handle, remote_after_close_cb);
        uv_freeaddrinfo(res);
        free(resolver);
        return;
    }
    
    remote_ctx->resolved = 1;
    if (res->ai_family == AF_INET) {
        memcpy(remote_ctx->host, &((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr, 4);
        remote_ctx->addrlen = 4;
    } else if (res->ai_family == AF_INET6) {
        memcpy(remote_ctx->host, &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr.s6_addr, 16);
        remote_ctx->addrlen = 16;
    } else {
        LOGD("DNS ai_family unrecognized");
    }
    LOGD("ip when resovled: %d.%d.%d.%d \n", (unsigned char)ctx->host[0], (unsigned char)ctx->host[1], (unsigned char)ctx->host[2], (unsigned char)ctx->host[3]);
    LOGW("remote_addr_resolved_cb remote_ctx = %x session_id = %d", remote_ctx, remote_ctx->session_id);
    int r = try_to_connect_remote(remote_ctx);
    if (r)
        HANDLECLOSE(&remote_ctx->handle, remote_after_close_cb);
    uv_freeaddrinfo(res);
    free(resolver);
}

static void server_accept_cb(uv_stream_t *server, int status) {
	if (status) ERROR_UV("async connect", status);
	server_ctx_t* ctx = calloc(1, sizeof(server_ctx_t));
    ctx->handle.data = ctx;
    ctx->expect_to_recv = HDRLEN;
	uv_tcp_init(loop, &ctx->handle);
    uv_tcp_nodelay(&ctx->handle, 1);

	int r = uv_accept(server, (uv_stream_t*)&ctx->handle);
	if (r) {
		LOGD("error accepting connection %d", r);
		uv_close((uv_handle_t*)&ctx->handle, NULL);
	} else	{
        struct clib_map* map = new_c_map(compare_id, NULL, NULL);
        ctx->idfd_map        = map;
		uv_read_start((uv_stream_t*)&ctx->handle, server_alloc_cb, server_read_cb);
	}
}

static void server_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    server_ctx_t* server_ctx = (server_ctx_t*)handle->data;
    *buf = uv_buf_init(server_ctx->recv_buffer, server_ctx->expect_to_recv);
    assert(buf->base != NULL);
}

// complex! de-multiplexing the long connection
static void server_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    server_ctx_t* ctx = (server_ctx_t*)stream->data;
    // TODO: optimize long remote connection handling logic
    LOGD("hehe nread = %d", nread);
    LOGD("server_read_cb: ==============================start============================");
	if (unlikely(nread <= 0)) {
        if (nread == 0)
            return;
        if (!uv_is_closing((uv_handle_t*) stream)) {
            LOGW("remote long connection is closed or error when reading");
            server_exception(ctx);
        }
        
	} else if (nread > 0) {

        // one packet finished, reset!
        LOGD("1: buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);

        if (!ctx->reset) {
            LOGD("reset!");
            packetnbuf_reset(ctx);
            ctx->packet.offset = 0;
        }
        
        LOGD("2: buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);

        memcpy(ctx->packet_buf + ctx->buf_len, buf->base, nread);  // copy current buf to packet_buf
        ctx->buf_len += nread;  // record how much data we put in the packet_buf

        if (ctx->stage == 0) {
            if (ctx->buf_len >= EXP_TO_RECV_LEN) {
                LOGD("stage = 0");
                LOGD("3: buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);
                get_id(ctx, &ctx->packet.session_id, ctx->packet_buf, ID_LEN, ctx->packet.offset);
                LOGW("Received packet with session id = %d", ctx->packet.session_id);
                get_header(&ctx->packet.rsv, ctx->packet_buf, RSV_LEN, ctx->packet.offset);
                get_header(&ctx->packet.datalen, ctx->packet_buf, DATALEN_LEN, ctx->packet.offset);
                ctx->packet.datalen = ntohs((uint16_t)ctx->packet.datalen);
                ctx->expect_to_recv = ctx->packet.datalen;
                LOGD("session id = %d RSV = %d", ctx->packet.session_id, ctx->packet.rsv);
                ctx->stage = 1; 
                // check packet's RSV, see if this packet has control info.
                // CTL_CLOSE means peer wanted to close this session -> FIN
                // peer has to make sure no more data issued on this session 
                if (ctx->packet.rsv == CTL_CLOSE) {
                    LOGW("received a packet with CTL_CLOSE (0x04) session id = %d", ctx->packet.session_id);
                    remote_ctx_t* exist_ctx = NULL;
                    if (find_c_map(ctx->idfd_map, &ctx->packet.session_id, &exist_ctx)){
                        if (exist_ctx != NULL) {
                            // stop watching read I/O
                            // elegantly close
                            // closing == 4, peer closing in charge, just close remote
                            exist_ctx->ctl_cmd = CTL_CLOSE;
                            LOGW("exist session close remote_ctx = %x\n", exist_ctx);
                            uv_read_stop((uv_stream_t *)&exist_ctx->handle);
                            if (!uv_is_closing((uv_handle_t*)&exist_ctx->handle)) {
                                if (exist_ctx->resolved == 1)
                                    uv_close((uv_handle_t*)&exist_ctx->handle, remote_after_close_cb);
                                else
                                    exist_ctx->closing = 1;
                            }
                        }
                        else
                            LOGW("found a NULL remote_ctx to free");
                    }
                    else {
                        LOGW("warning: closing an non-existent remote_ctx which means this session id is safe to be reused in local-side");
                        remote_ctx_t tmp_remote_ctx;
                        tmp_remote_ctx.session_id = ctx->packet.session_id;
                        tmp_remote_ctx.server_ctx = ctx;
                        send_EOF_packet(&tmp_remote_ctx, CTL_CLOSE_ACK);
                        
                    }
                    
                    ctx->reset = 0;
                    ctx->expect_to_recv = EXP_TO_RECV_LEN;
                }
                LOGD("4: buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);

            }
            else {
                if (verbose) LOGD("< header length ... gather more");
                ctx->expect_to_recv = EXP_TO_RECV_LEN - ctx->buf_len;
                LOGD("ctx->expect_to_recv %d", ctx->expect_to_recv);
                return;
            }
        } else if (ctx->stage == 1) {
            if (ctx->buf_len == ctx->packet.datalen + EXP_TO_RECV_LEN) {
                // after processing this packet, we have to handle the next packet so reset all stuffs
                ctx->reset = 0;
                ctx->expect_to_recv = EXP_TO_RECV_LEN;
                remote_ctx_t* exist_ctx = NULL;
                if (find_c_map(ctx->idfd_map, &ctx->packet.session_id, &exist_ctx))
                {
                    if (exist_ctx == NULL)
                        LOGD("exist_ctx == NULL");
                    LOGD("server_read_cb: exist_ctx in session_id = %d, RSV = %d datalen = %d\n", ctx->packet.session_id, ctx->packet.rsv, ctx->packet.datalen);
                    if (ctx->packet.rsv == CTL_INIT)
                        assert(0);
                    ctx->packet.payloadlen = ctx->packet.datalen;
                    packet_t* pkt_to_send = malloc(sizeof(packet_t));
                    memcpy(pkt_to_send, &ctx->packet, sizeof(packet_t));
                    pkt_to_send->data = malloc(ctx->packet.payloadlen);
                    get_header(pkt_to_send->data, ctx->packet_buf, ctx->packet.payloadlen, ctx->packet.offset);
                    LOGD("server_read_cb: (request)packet.data = \n%s\n",pkt_to_send->data);
                    //LOG_SHOW_BUFFER(pkt_to_send->data, pkt_to_send->payloadlen);
                    list_add_to_tail(&exist_ctx->send_queue, pkt_to_send);
                    LOGD("server_read_cb: ip: %d.%d.%d.%d", (unsigned char)exist_ctx->host[0], (unsigned char)exist_ctx->host[1], (unsigned char)exist_ctx->host[2], (unsigned char)exist_ctx->host[3]);
                    LOGD("server_read_cb: resovled = %d connected = %d", exist_ctx->resolved, exist_ctx->connected);
                    if (exist_ctx->resolved == 1 && exist_ctx->connected == 1) {
                        packet_t* packet = list_get_head_elem(&exist_ctx->send_queue);
                        if (packet) {
                            write_req_t *wr = (write_req_t*) malloc(sizeof(write_req_t));
                            wr->req.data = exist_ctx;
                            wr->buf      = uv_buf_init(packet->data, packet->payloadlen);
                            int r = uv_write(&wr->req, (uv_stream_t*)(void *)&exist_ctx->handle, &wr->buf, 1, remote_write_cb);
                            UV_WRITE_CHECK(r, wr, &exist_ctx->handle, remote_after_close_cb);
                            list_remove_elem(packet);
                            free(packet);
                        }
                        else
                            LOGD("server_read_cb: got nothing to send");
                    }
                    else if (exist_ctx->connected == 0) {
                        LOGD("remote is closing");
                        //try_to_connect_remote(exist_ctx);
                    }
                    LOGD("buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);
                    LOGW("server_read_cb:2 remote_ctx = %x session_id = %d type = %d", exist_ctx, exist_ctx->session_id,exist_ctx->handle.type);
                }
                else
                {
                    if (ctx->packet.rsv == CTL_NORMAL)
                    {
                        LOGW("Received packet from freed session");
                        return;
                    }
                    remote_ctx_t* remote_ctx = calloc(1, sizeof(remote_ctx_t));
                    remote_ctx->ctl_cmd = CTL_NORMAL;
                    remote_ctx->server_ctx  = ctx;
                    remote_ctx->handle.data = remote_ctx;
                    remote_ctx->http_timeout.data = remote_ctx;
                    uv_tcp_init(loop, &remote_ctx->handle);
                    uv_timer_init(loop, &remote_ctx->http_timeout);
                    LOGW("uv_timer_start remote_ctx = %x http_timeout = %x", remote_ctx, &remote_ctx->http_timeout);
                    uv_timer_start(&remote_ctx->http_timeout, remote_timeout_cb, conf.timeout, conf.timeout);
                    list_init(&remote_ctx->send_queue);
                    get_header(&ctx->packet.atyp, ctx->packet_buf, ATYP_LEN, ctx->packet.offset);
                    get_header(&ctx->packet.addrlen, ctx->packet_buf, ADDRLEN_LEN, ctx->packet.offset);
                    remote_ctx->addrlen = ctx->packet.addrlen;
                    get_header(remote_ctx->host, ctx->packet_buf, ctx->packet.addrlen, ctx->packet.offset);
                    get_header(remote_ctx->port, ctx->packet_buf, PORT_LEN, ctx->packet.offset);
//                  packet_payload_alloc(ctx->packet, FULLPKT);
                    ctx->packet.payloadlen = ctx->packet.datalen - (ATYP_LEN + ADDRLEN_LEN + ctx->packet.addrlen + PORT_LEN);
                    packet_t* pkt_to_send = malloc(sizeof(packet_t));
                    memcpy(pkt_to_send, &ctx->packet, sizeof(packet_t));
                    pkt_to_send->data = malloc(ctx->packet.payloadlen);
                    get_payload(pkt_to_send->data, ctx->packet_buf, ctx->packet.payloadlen, ctx->packet.offset);
                    //LOGD("(request)packet.data =\n%s", pkt_to_send->data);
                    remote_ctx->host[remote_ctx->addrlen] = '\0';// put a EOF on domain name
                    remote_ctx->session_id = ctx->packet.session_id;
                    LOGW("server_read_cb remote_ctx = %x create session id = %d", remote_ctx, remote_ctx->session_id);
                    insert_c_map (ctx->idfd_map, &remote_ctx->session_id, sizeof(int), remote_ctx, sizeof(int));
                    list_add_to_tail(&remote_ctx->send_queue, pkt_to_send);
                    //SHOWPKTDEBUGWODATA(remote_ctx);
                    if (ctx->packet.atyp == 0x03) {
                        uv_getaddrinfo_t* resolver = malloc(sizeof(uv_getaddrinfo_t));
                        // have to resolve domain name first
                        resolver->data = remote_ctx;
                        int r = uv_getaddrinfo(loop, resolver, remote_addr_resolved_cb, remote_ctx->host, NULL, NULL);
                    }
                    else if (ctx->packet.atyp == 0x01)  // do not have to resolve ipv4 address
                    {
                        int r = try_to_connect_remote(remote_ctx);
                        if (r)
                            LOGW("Received packet with atyp 0x01");
                    }
                    else if (ctx->packet.atyp == 0x04){
                        // TODO: ipv6 temporarily unsupported
                    }
                    LOGW("server_read_cb:1 remote_ctx = %x session_id = %d type = %d", remote_ctx,  remote_ctx->session_id, remote_ctx->handle.type);
                }
            } else if (ctx->buf_len < ctx->packet.datalen + EXP_TO_RECV_LEN) {
                if (verbose) LOGD("< datalen gather more");
                ctx->expect_to_recv = EXP_TO_RECV_LEN + ctx->packet.datalen - ctx->buf_len;
                return;
            } else{
                assert(0);
                LOGD("impossible! should never reach here (> datalen)\n");
            }
        }
        else {
            LOGD("strange stage %d\n", ctx->stage);
            assert(0);
        }
	}
    LOGD("server_read_cb: ==============================end==============================\n");

}



int main(int argc, char **argv)
{
    memset(&conf, 0, sizeof(conf_t));
    int c, option_index = 0, daemon = 0;
    char* configfile = NULL;
    opterr = 0;
    static struct option long_options[] = {{0, 0, 0, 0}};
    while ((c = getopt_long(argc, argv, "c:r:l:p:P:V:d",
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

    if (opterr || argc == 1 || conf.serverport == NULL) {
        printf("Error: 1)passed wrong or null args to the program.\n");
        printf("       2)parsing config file failed.\n");
        usage();
        exit(EXIT_FAILURE);
    }
    
    server_validate_conf(&conf);
    
#ifndef XCODE_DEBUG
    if (daemon == 1) {
        LOGI("js-server is working as deamon.");
        init_daemon();
    }
#endif
        
    loop = uv_default_loop();
    char* serverlog = "/tmp/server.log";
    if (log_to_file)
        USE_LOGFILE(serverlog);
    
    listener_t* listener = malloc(sizeof(listener_t));
	uv_tcp_init(loop, &listener->handle);
    uv_tcp_nodelay(&listener->handle, 1);
	struct sockaddr_in bind_addr;
	int r = uv_ip4_addr(conf.server_address, conf.serverport, &bind_addr);
    r = uv_tcp_bind(&listener->handle, (struct sockaddr*)&bind_addr, 0);
	if (r < 0)
        ERROR_UV("js-server: bind error", r);
	r = uv_listen((uv_stream_t*)&listener->handle, 128, server_accept_cb);
	if (r)
        ERROR_UV("js-server: listen error", r);
	LOGI("js-server: listen on %s:%d", conf.server_address, conf.serverport);
    //setup_signal_handler(loop);
	uv_run(loop, UV_RUN_DEFAULT);
    uv_close((uv_handle_t*) &listener->handle, NULL);
    uv_loop_delete(loop);
    free(listener);
    CLOSE_LOGFILE;
}
