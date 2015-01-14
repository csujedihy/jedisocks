#ifndef SERVER_H_
#define SERVER_H_
#define BUF_SIZE 2048
typedef struct {
	uv_tcp_t listen;
	uv_tcp_t server;
	uv_tcp_t remote;
	int stage;

} server_ctx_t;

#endif