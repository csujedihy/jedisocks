#ifndef LOCAL_H_
#define LOCAL_H_
#include "c_map.h"
#include "tree.h"

#define INT_MAX 2147483647
#define BUF_SIZE 2048
#define CTL_CLOSE 0x04
#define CTL_INIT 0x01
#define CTL_NORMAL 0
#define CTL_CLOSE_ACK 0x03

// packet related MACROs
#define MAX_PKT_SIZE 8192
#define ID_LEN 4
#define PKT_LEN 2
#define RSV_LEN 1
#define DATALEN_LEN 2
#define ATYP_LEN 1
#define ADDRLEN_LEN 1
#define PORT_LEN 2
#define HDR_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)
#define EXP_TO_RECV_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)

// remote connection status MACROs
#define RC_OFF 0
#define RC_ESTABLISHING 1
#define RC_OK 2
#define MAX_RC_NUM 100

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct server_ctx {
    uv_tcp_t server;
    int stage;
    int rc_pool_size;
    struct remote_ctx* remote_long[MAX_RC_NUM];
} server_ctx_t;

typedef struct packet {
    char* rawpacket;
    int pktsize;
    struct packet* prev;
    struct packet* next;
} packet_t;

typedef struct send_queue {
    packet_t head;
} queue_t;

typedef struct tmp_packet {
    int session_id;
    char rsv;
    uint16_t datalen;
    char* data;
} tmp_packet_t;

typedef struct socks_handshake {
    RB_ENTRY(socks_handshake) rb_link;
    uv_tcp_t server;
    int stage;
    char atyp;
    int init;
    int session_id;
    int closing;
    int closed;
    char addrlen;
    char host[256]; // to support ipv6
    char port[16];
    struct remote_ctx* remote_long;
    struct socks_handshake* prev;
    struct socks_handshake* next;
} socks_handshake_t;

RB_HEAD(socks_map_tree, socks_handshake);

typedef struct socks_connection_list {
    socks_handshake_t head;
} socks_connection_list_t;

typedef struct session {
    int session_id;
    struct session* prev;
    struct session* next;
} session_t;

typedef struct avl_session_list {
    session_t head;
} avl_session_list_t;

typedef struct remote_ctx {
    uv_tcp_t remote;
    int stage;
    int run;
    size_t buffer_len;
    struct socks_map_tree socks_map;
    server_ctx_t* listen;
    char packet_buf[MAX_PKT_SIZE];
    char recv_buffer[MAX_PKT_SIZE];
    tmp_packet_t tmp_packet;
    int buf_len;
    int reset;
    int offset;
    int expect_to_recv;
    uint32_t sid;
    avl_session_list_t avl_session_list;
    int connected;
    int rc_index;
} remote_ctx_t;

#endif