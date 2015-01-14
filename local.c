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

int total_read;
int total_written;

uv_loop_t *loop;

static void connect_to_remote_cb(uv_connect_t* req, int status) {
    remote_ctx_t* ctx = (remote_ctx_t *)req->data;
    if (status) {
        uv_close((uv_handle_t*)&ctx->remote, NULL);
        free(req);
        return;
    }

    free(req);
    LOGD("Connected to remote");

}   

static void accept_cb(uv_stream_t *server, int status) {
    if (status) ERROR("async connect", status);
    socks_handshake *socks_hsctx = calloc(1,sizeof(socks_handshake));
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
            LOGD("stage = 2");
            SHOW_BUFFER(buf->base,nread);
            free(buf->base);
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
            uv_write(&wr->req, client, &wr->buf, 1/*nbufs*/, write_cb);
            socks_hsctx->stage = 1;
            // sent the 1st response -> switch to the stage 1
            free(buf->base);
        } else if (socks_hsctx->stage == 1){
            // received 2nd request in stage 1
            // here we have to parse the requested domain or ip address
            socks5_req_or_resp_t* req = (socks5_req_or_resp_t*)buf->base;
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

    loop = uv_default_loop();
    server_ctx *socks_ctx = calloc(1, sizeof(server_ctx));
    remote_ctx_t *remote_ctx = calloc(1, sizeof(remote_ctx_t));
    uv_connect_t *req = (uv_connect_t *)malloc(sizeof(uv_connect_t));

    socks_ctx->server.data = socks_ctx;
    socks_ctx->remote_ctx = remote_ctx;

    uv_tcp_init(loop, &socks_ctx->server);
    uv_tcp_init(loop, &remote_ctx->remote);
    
    int r = uv_ip4_addr("127.0.0.1", 7001, &connect_addr);
    r = uv_tcp_connect(req, &remote_ctx->remote, connect_addr, connect_to_remote_cb);
    r = uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
    LOGD("r = %d",r);
    r = uv_tcp_bind(&socks_ctx->server, (struct sockaddr*)&bind_addr, 0);
    if(r < 0)
    	ERROR("bind error", r);
    r = uv_listen((uv_stream_t*) &socks_ctx->server, 128 /*backlog*/, accept_cb);
    if (r) ERROR("listen error", r)

    fprintf(stderr, "Listening on localhost:7000\n");

    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}