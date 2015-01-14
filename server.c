#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <uv.h>
#include "utils.h"
#include "server.h"

uv_loop_t *loop;

void server_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void server_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void write_cb(uv_write_t *req, int status);

void accept_cb(uv_stream_t *server, int status) {
	if (status) ERROR("async connect", status);
	server_ctx_t* ctx = server->data;
	uv_tcp_init(loop, &ctx->server);
	int r = uv_accept(server, (uv_stream_t*)&ctx->server);
	if (r) {
		fprintf(stderr, "error accepting connection %d", r);
		uv_close((uv_handle_t*)&ctx->server, NULL);
	} else	{
		uv_read_start((uv_stream_t*)&ctx->server, server_alloc_cb, server_read_cb);
	}
}

void server_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    *buf = uv_buf_init((char*) malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

void server_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	if (nread == UV_EOF) {
		uv_close((uv_handle_t*) stream, NULL);
	} else if (nread > 0) {
		SHOW_BUFFER(buf->base, nread);
		free(buf->base);
	}
	if(nread == 0) free(buf->base);
}

int main()
{
	loop = uv_default_loop();
	server_ctx_t* ctx = calloc(1, sizeof(server_ctx_t));
	ctx->listen.data = ctx;
	uv_tcp_init(loop, &ctx->listen);
	struct sockaddr_in bind_addr;
	int r = uv_ip4_addr("0.0.0.0", 7001, &bind_addr);
	r = uv_tcp_bind(&ctx->listen, (struct sockaddr*)&bind_addr, 0);
	if (r < 0)	ERROR("js-server: bind error", r);
	r = uv_listen((uv_stream_t*)&ctx->listen, 128, accept_cb);
	if (r)	ERROR("js-server: listen error", r);
	LOGD("js-server: listen on port 8888");
	uv_run(loop, UV_RUN_DEFAULT);
}
