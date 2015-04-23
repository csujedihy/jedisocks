#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>
#include <getopt.h>
#include "utils.h"
#include "server.h"
#include "c_map.h"
#include "jconf.h"

uv_loop_t *loop;
int verbose     = 0;
FILE * logfile  = NULL;
int log_to_file = 1;

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

// customized functions
static int try_to_connect_remote(remote_ctx_t* ctx);
static void send_EOF_packet(remote_ctx_t* ctx);

#ifdef MEMDEBUG
void* jmalloc(size_t size) {
    static int malloc_count = 0;
    malloc_count++;
    return malloc(size);
}

void jfree(void * ptr) {
    static int free_count = 0;
    free_count++;
    free(ptr);
}
#else
#define jmalloc malloc
#define jfree free
#endif

static void send_EOF_packet(remote_ctx_t* ctx){
    int offset = 0;
    char* pkt_buf       = jmalloc(HDRLEN);
    uint32_t session_id = htonl((uint32_t)ctx->session_id);
    uint16_t datalen    = 0;
    char rsv            = CTL_CLOSE;
    LOGD("the session id of the closing session is %d", ctx->session_id);

    set_header(pkt_buf, &session_id, ID_LEN, offset);
    set_header(pkt_buf, &rsv, RSV_LEN, offset);
    set_header(pkt_buf, &datalen, DATALEN_LEN, offset);
    
    //LOGD("session_id = %d session_idno = %d", ctx->session_id, session_id);

    write_req_t *wr = (write_req_t*) jmalloc(sizeof(write_req_t));
    wr->req.data = ctx;
    wr->buf = uv_buf_init(pkt_buf, EXP_TO_RECV_LEN);
    uv_write(&wr->req, (uv_stream_t*)&ctx->server_ctx->server, &wr->buf, 1, server_write_cb);
}

static void remote_after_close_cb(uv_handle_t* handle) {
    remote_ctx_t* remote_ctx = (remote_ctx_t*)handle->data;
    if (remote_ctx != NULL) {
        remove_c_map(remote_ctx->server_ctx->idfd_map, &remote_ctx->session_id, NULL);
        send_EOF_packet(remote_ctx);
        packet_t* packet_to_free = NULL;
        while ((packet_to_free = list_get_head_elem(&remote_ctx->send_queue))) {
            list_remove_elem(packet_to_free);
            jfree(packet_to_free);
        }
        jfree(remote_ctx);
    }
}

static void remote_after_shutdown_cb(uv_shutdown_t* req, int status) {
    if (status) {
        LOGD("error remote_after_shutdown_cb status %d", status);
    }
        
    LOGD("remote_after_shutdown_cb");
    remote_ctx_t *remote_ctx = (remote_ctx_t *)req->data;
    uv_close((uv_handle_t*)&remote_ctx->remote, remote_after_close_cb);
    jfree(req);  
}

// Notice: watch out each callback function, inappropriate jfree() leads to disaster
static void remote_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) jmalloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

static void remote_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    remote_ctx_t* ctx = (remote_ctx_t*)stream->data;
    if (nread == UV_EOF) {
        LOGD("remote_read_cb: UV_EOF");
        //uv_close((uv_handle_t*) stream, NULL);
        ctx->connected = 0;
        if (!uv_is_closing((uv_handle_t*)&ctx->remote)) {
            // the remote is closing, we tell js-local to stop sending and preparing close
            uv_read_stop((uv_stream_t *)&ctx->remote);

            // shutdown remote
            uv_shutdown_t *req = jmalloc(sizeof(uv_shutdown_t));
            req->data = ctx;
            uv_shutdown(req, (uv_stream_t*)&ctx->remote, remote_after_shutdown_cb);
        }
        //now handle remote close
        // for debug
    } else if (nread > 0) {
        server_ctx_t* server_ctx = ctx->server_ctx;
        int offset = 0;
        char* pkt_buf       = calloc(1, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
        uint32_t session_id = htonl((uint32_t)ctx->session_id);
        uint16_t datalen    = htons((uint16_t)nread);
        set_header(pkt_buf, &session_id, ID_LEN, offset);
        char rsv = CTL_NORMAL;
        
        set_header(pkt_buf, &rsv, RSV_LEN, offset);
        set_header(pkt_buf, &datalen, DATALEN_LEN, offset);
        set_payload(pkt_buf, buf->base, nread, offset);
        
        //LOGD("datalen(nread) = %d datalenno = %d", nread, datalen);

        write_req_t* req = calloc(1,sizeof(write_req_t));
        req->req.data    = ctx;
        req->buf         = uv_buf_init(pkt_buf, ID_LEN + RSV_LEN + DATALEN_LEN + nread);
//        req->packet = ctx->packet;
        req->pkt_buf     = pkt_buf;
//        jfree(ctx->packet);
        uv_write(&req->req, (uv_stream_t*)&ctx->server_ctx->server, &req->buf, 1, server_write_cb);
        jfree(buf->base);
    }
    if (nread == 0) jfree(buf->base);
}

static void server_write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*)req;
    if (status) {
        LOGD("error in server_write_cb");
    }
    assert(wr->req.type == UV_WRITE);
    
    if (wr->buf.base != NULL) {
        jfree(wr->buf.base);
    }

    jfree(wr);
}

static void remote_write_cb(uv_write_t *req, int status) {
    write_req_t* wr = (write_req_t*)req;
    remote_ctx_t* ctx = (remote_ctx_t*)req->data;
    if (status)
    {
        ctx->connected = 0;
        if (status != UV_ECANCELED) {
            if (!uv_is_closing((uv_handle_t*)&ctx->remote)) {
                // the remote is closing, we tell js-local to stop sending and preparing close
                uv_read_stop((uv_stream_t *)&ctx->remote);
                ctx->closing = 1;
                
                // shutdown remote
                uv_shutdown_t *req = jmalloc(sizeof(uv_shutdown_t));
                req->data = ctx;
                uv_shutdown(req, (uv_stream_t*)&ctx->remote, remote_after_shutdown_cb);
            }
        }

        jfree(wr->buf.base);
        jfree(wr);
        LOGD("remote write failed!");
        return;
    }
    assert(wr->req.type == UV_WRITE);
    //LOGD("send in remote_write_cb data = \n%s\n", wr->buf.base);
    packet_t* packet = list_get_head_elem(&ctx->send_queue);
    if (packet) {
        write_req_t *wr = (write_req_t*) jmalloc(sizeof(write_req_t));
        wr->req.data    = ctx;
        wr->buf         = uv_buf_init(packet->data, packet->payloadlen);
        wr->packet      = packet;
        uv_write(&wr->req, req->handle, &wr->buf, 1, remote_write_cb);
        list_remove_elem(packet);
        jfree(packet);
    }
    else {
        if (verbose)
            LOGD("got nothing to send");
    }
    
    jfree(wr->buf.base);
    jfree(wr);
}

// TODO: add timer to watch remote connection in case of TCP or HTTP timeout
static void remote_on_connect_cb(uv_connect_t* req, int status) {
    remote_ctx_t* ctx = (remote_ctx_t*)req->data;
    if (status) {
        LOGD("error in remote_on_connect");
        uv_close((uv_handle_t*)&ctx->remote, NULL);
        jfree(req);
        return;
    }
    if (verbose) LOGD("domain resovled");
    ctx->connected = 1;
    uv_read_start((uv_stream_t*)&ctx->remote, remote_alloc_cb, remote_read_cb);
    
    packet_t* packet = list_get_head_elem(&ctx->send_queue);
    if (packet) {
        LOGD("sent something in remote_on_connect");
        write_req_t *wr = (write_req_t*) jmalloc(sizeof(write_req_t));
        wr->req.data    = ctx;
        wr->buf         = uv_buf_init(packet->data, packet->payloadlen);
        wr->packet      = packet;
        uv_write(&wr->req, req->handle, &wr->buf, 1, remote_write_cb);
        list_remove_elem(packet);
        jfree(packet);
    }
    else{
        if (verbose) LOGD("got nothing to send");
    }
    jfree(req); //2.28 added
}

static int try_to_connect_remote(remote_ctx_t* ctx) {
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    memcpy(&remote_addr.sin_addr.s_addr, ctx->host, 4);
    remote_addr.sin_port = *(uint16_t*)ctx->port; // notice: packet.port is in network order
    uv_connect_t* remote_conn_req = (uv_connect_t*) jmalloc(sizeof(uv_connect_t));
    uv_tcp_init(loop, &ctx->remote);
    uv_tcp_nodelay(&ctx->remote, 1);
    ctx->remote.data = ctx; // is redundant?
    remote_conn_req->data = ctx;
    return uv_tcp_connect(remote_conn_req, &ctx->remote, (struct sockaddr*)&remote_addr, remote_on_connect_cb);
}

static void remote_addr_resolved_cb(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    remote_ctx_t* ctx = (remote_ctx_t*) resolver->data;
    if (status) {
        LOGD("error DNS resolve ");
        ctx->resolved = 0;
        // TODO:
        // more exceptions to handle?
        return;
    }
    if (verbose) LOGD("remote_addr_resolve");
    ctx->resolved = 1;
    if (res->ai_family == AF_INET) {
        memcpy(ctx->host, &((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr, 4);
        ctx->addrlen = 4; //fix
    } else if (res->ai_family == AF_INET6) {
        memcpy(ctx->host, &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr.s6_addr, 16);
        ctx->addrlen = 16; //fix
    } else {
        LOGD("DNS resolve failed!");
    }
    LOGD("ip when resovled: %d.%d.%d.%d \n", (unsigned char)ctx->host[0], (unsigned char)ctx->host[1], (unsigned char)ctx->host[2], (unsigned char)ctx->host[3]);

    int r = try_to_connect_remote(ctx);
    if (r)
        LOGD("error in connect to remote");
    uv_freeaddrinfo(res);
    jfree(resolver);
}

static void server_accept_cb(uv_stream_t *server, int status) {
	if (status) ERROR("async connect", status);
	server_ctx_t* ctx = server->data;
    ctx->server.data = ctx;
	uv_tcp_init(loop, &ctx->server);
    uv_tcp_nodelay(&ctx->server, 1);

	int r = uv_accept(server, (uv_stream_t*)&ctx->server);
	if (r) {
		LOGD("error accepting connection %d", r);
		uv_close((uv_handle_t*)&ctx->server, NULL);
	} else	{
        struct clib_map* map = new_c_map(compare_id, NULL, NULL);
        ctx->idfd_map        = map;
		uv_read_start((uv_stream_t*)&ctx->server, server_alloc_cb, server_read_cb);
	}
}

static void server_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    server_ctx_t* server_ctx = (server_ctx_t*)handle->data;
    *buf = uv_buf_init(server_ctx->recv_buffer, server_ctx->expect_to_recv);
    assert(buf->base != NULL);
}

// complex! de-multiplexing the long connection
static void server_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
//    struct timeval _tv_start = GetTimeStamp();
    LOGD("hehe nread = %d", nread);
    
//    LOGD("server_read_cb: ==============================start============================");
	if (nread == UV_EOF) {
		uv_close((uv_handle_t*) stream, NULL);
	} else if (nread > 0) {
        server_ctx_t* ctx = (server_ctx_t*)stream->data;
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
                    LOGD("received a packet with CTL_CLOSE (0x04)");
                    LOGD("session id = %d", ctx->packet.session_id);
                    remote_ctx_t* exist_ctx = NULL;
                    if (remove_c_map(ctx->idfd_map, &ctx->packet.session_id, &exist_ctx)) {
                        // stop watching read I/O
                        // elegantly close
                        // closing == 4, peer closing in charge, just close remote
                        uv_read_stop((uv_stream_t *)&exist_ctx->remote);
                        if (!uv_is_closing((uv_handle_t*)&exist_ctx->remote)) {
                            uv_shutdown_t *req = jmalloc(sizeof(uv_shutdown_t));
                            req->data = exist_ctx;
                            uv_shutdown(req, (uv_stream_t*)&exist_ctx->remote, remote_after_shutdown_cb);
                        }

                    } else
                        LOGD("warning: closing an non-existent remote_ctx");
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
                    packet_t* pkt_to_send = jmalloc(sizeof(packet_t));
                    memcpy(pkt_to_send, &ctx->packet, sizeof(packet_t));
                    pkt_to_send->data = jmalloc(ctx->packet.payloadlen);
                    get_header(pkt_to_send->data, ctx->packet_buf, ctx->packet.payloadlen, ctx->packet.offset);
                    LOGD("server_read_cb: (request)packet.data = \n%s\n",pkt_to_send->data);
                    LOG_SHOW_BUFFER(pkt_to_send->data, pkt_to_send->payloadlen);
                    list_add_to_tail(&exist_ctx->send_queue, pkt_to_send);
                    LOGD("server_read_cb: ip: %d.%d.%d.%d", (unsigned char)exist_ctx->host[0], (unsigned char)exist_ctx->host[1], (unsigned char)exist_ctx->host[2], (unsigned char)exist_ctx->host[3]);
                    LOGD("server_read_cb: resovled = %d connected = %d", exist_ctx->resolved, exist_ctx->connected);
                    if (exist_ctx->resolved == 1 && exist_ctx->connected == 1) {
                        packet_t* packet = list_get_head_elem(&exist_ctx->send_queue);
                        if (packet) {
                            write_req_t *wr = (write_req_t*) jmalloc(sizeof(write_req_t));
                            wr->req.data = exist_ctx;
                            wr->buf      = uv_buf_init(packet->data, packet->payloadlen);
                            wr->packet   = packet;
                            //LOGD("send in (exist_ctx) server_read_cb len = %d data = \n%s\n",packet->payloadlen, wr->buf.base);
                            // TODO: debug here
                            uv_write(&wr->req, (uv_stream_t*)(void *)&exist_ctx->remote, &wr->buf, 1, remote_write_cb);
                            list_remove_elem(packet);
                            jfree(packet);
                        }
                        else
                            LOGD("server_read_cb: got nothing to send");
                    }
                    else if (exist_ctx->connected == 0) {
                        LOGD("remote is closing");
                        //try_to_connect_remote(exist_ctx);
                    }
                    LOGD("buf_len = %d, reset = %d, stage = %d, expect_to_recv %d", ctx->buf_len, ctx->reset, ctx->stage, ctx->expect_to_recv);
                }
                else
                {
                    if (ctx->packet.rsv == CTL_NORMAL)
                    {
                        LOGD("385 return");
                        return;
                    }
                    remote_ctx_t* remote_ctx = calloc(1, sizeof(remote_ctx_t));
                    remote_ctx->server_ctx  = ctx;
                    remote_ctx->remote.data = ctx;
                    list_init(&remote_ctx->send_queue);
                    get_header(&ctx->packet.atyp, ctx->packet_buf, ATYP_LEN, ctx->packet.offset);
                    get_header(&ctx->packet.addrlen, ctx->packet_buf, ADDRLEN_LEN, ctx->packet.offset);
                    remote_ctx->addrlen = ctx->packet.addrlen;
                    get_header(remote_ctx->host, ctx->packet_buf, ctx->packet.addrlen, ctx->packet.offset);
                    get_header(remote_ctx->port, ctx->packet_buf, PORT_LEN, ctx->packet.offset);
//                  packet_payload_alloc(ctx->packet, FULLPKT);
                    ctx->packet.payloadlen = ctx->packet.datalen - (ATYP_LEN + ADDRLEN_LEN + ctx->packet.addrlen + PORT_LEN);
                    packet_t* pkt_to_send = jmalloc(sizeof(packet_t));
                    memcpy(pkt_to_send, &ctx->packet, sizeof(packet_t));
                    pkt_to_send->data = jmalloc(ctx->packet.payloadlen);
                    get_payload(pkt_to_send->data, ctx->packet_buf, ctx->packet.payloadlen, ctx->packet.offset);
                    //LOGD("(request)packet.data =\n%s", pkt_to_send->data);
                    remote_ctx->host[remote_ctx->addrlen] = '\0';// put a EOF on domain name
                    remote_ctx->session_id                = ctx->packet.session_id;
                    insert_c_map (ctx->idfd_map, &remote_ctx->session_id, sizeof(int), remote_ctx, sizeof(int));
                    list_add_to_tail(&remote_ctx->send_queue, pkt_to_send);
                    //SHOWPKTDEBUGWODATA(remote_ctx);
                    if (ctx->packet.atyp == 0x03) {
                        uv_getaddrinfo_t* resolver = jmalloc(sizeof(uv_getaddrinfo_t));
                        // have to resolve domain name first
                        resolver->data = remote_ctx;
                        int r = uv_getaddrinfo(loop, resolver, remote_addr_resolved_cb, remote_ctx->host, NULL, NULL);
                    }
                    else if (ctx->packet.atyp == 0x01)  // do not have to resolve ipv4 address
                    {
                        int r = try_to_connect_remote(remote_ctx);
                        if (r)
                            LOGD("warning: atyp = 0x01");
                    }
                    else if (ctx->packet.atyp == 0x04){
                        // TODO: ipv6 temporarily unsupported
                    }
                    
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
//    struct timeval _tv_end = GetTimeStamp();
//    fprintf(stderr, "Time cost =  %ldus\n",((_tv_end.tv_sec*1000000 + _tv_end.tv_usec) - (_tv_start.tv_sec*1000000 + _tv_start.tv_usec)));
}

int main(int argc, char **argv)
{
    conf_t  conf;
    memset(&conf, 0, sizeof(conf_t));
    int c, option_index = 0;
    char* configfile = NULL;
    opterr = 0;
    static struct option long_options[] =
    {
        { 0, 0, 0, 0 }
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
                printf("default error\n");
                break;
        }
    }
    
    if (configfile != NULL) {
        read_conf(configfile, &conf);
    }
    printf("ra = %s\n", conf.server_address);

    if (opterr || argc == 1 || conf.serverport == NULL) {
        printf("Error: 1)passed wrong or null args to the program.\n");
        printf("       2)parsing config file failed.\n");
        usage();
        exit(EXIT_FAILURE);
    }
    
    server_validate_conf(&conf);
    loop = uv_default_loop();
    char* serverlog = "/tmp/server.log";
    if (log_to_file)
        USE_LOGFILE(serverlog);
    
    server_ctx_t* ctx   = calloc(1, sizeof(server_ctx_t));
    ctx->expect_to_recv = HDRLEN;
    ctx->listen.data    = ctx;
	uv_tcp_init(loop, &ctx->listen);
    uv_tcp_nodelay(&ctx->listen, 1);
	struct sockaddr_in bind_addr;
	int r = uv_ip4_addr(conf.server_address, conf.serverport, &bind_addr);
    // TODO: parse json
    r = uv_tcp_bind(&ctx->listen, (struct sockaddr*)&bind_addr, 0);
	if (r < 0)
        ERROR("js-server: bind error", r);
	r = uv_listen((uv_stream_t*)&ctx->listen, 128, server_accept_cb);
	if (r)
        ERROR("js-server: listen error", r);
	fprintf(stderr, "js-server: listen on %s:%d\n", conf.server_address, conf.serverport);
	uv_run(loop, UV_RUN_DEFAULT);
    CLOSE_LOGFILE;
}
