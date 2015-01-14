#ifndef LOCAL_H_
#define LOCAL_H_

#define SOCKS5_FISRT_REQ_SIZE 3
#define SOCKS5_FISRT_RESP_SIZE 2

typedef struct
{
	uv_tcp_t remote;
	int stage;
	size_t buffer_len;
} remote_ctx_t;

typedef struct
{
	uv_tcp_t server;
	size_t buffer_len; // Also use as pending cound after handshake
	int stage;
	remote_ctx_t* remote_ctx;
} server_ctx;

typedef struct 
{
	uv_tcp_t server;
	int stage;
} socks_handshake;

typedef struct 
{
	uv_tcp_t pool;
	int stage;
} pool_ctx;

#endif