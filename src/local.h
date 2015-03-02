#ifndef LOCAL_H_
#define LOCAL_H_
#include "c_map.h"

#define SOCKS5_FISRT_REQ_SIZE 3
#define SOCKS5_FISRT_RESP_SIZE 2
#define INT_MAX 2147483647
#define BUF_SIZE 2048
#define MAX_PKT_SIZE 81920
#define ID_LEN 4
#define PKT_LEN 2
#define RSV_LEN 1
#define DATALEN_LEN 2
#define ATYP_LEN 1
#define ADDRLEN_LEN  1
#define PORT_LEN 2

#define EXP_TO_RECV_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)

// built-in link list MACROs, modified from libcork
#define list_init(list) \
do { \
(list)->head.next = &(list)->head; \
(list)->head.prev = &(list)->head; \
} while (0)

#define list_add_after(prev, elem) \
do { \
(elem)->prev = (prev); \
(elem)->next = (prev)->next; \
(prev)->next->prev = (elem); \
(prev)->next = (elem); \
} while (0)

#define list_add_before(succ, elem) \
do { \
(elem)->prev = (succ)->prev; \
(elem)->next = (succ); \
(succ)->prev->next = (elem); \
(succ)->prev = (elem); \
} while (0)

#define list_add_to_tail(list, elem) \
list_add_before(&(list)->head, elem);

#define list_add_to_head(list, elem) \
list_add_after(&(list)->head, elem);

#define list_get_head_elem(list) \
(((list)->head.next == &(list)->head)? NULL: (list)->head.next)

#define list_remove_elem(elem) \
do { \
    (elem)->prev->next = (elem)->next; \
    (elem)->next->prev = (elem)->prev; \
} while (0)

int compare_id (void* left, void* right) {
    if (*(uint32_t*)left == *(uint32_t*)right)
        return 0;
    return *(uint32_t*)left < *(uint32_t*)right? -1:1;
}

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct
{
	uv_tcp_t server;
	size_t buffer_len; // Also use as pending cound after handshake
	int stage;
} server_ctx;

typedef struct packet{
	char* rawpacket;
	int pktsize;
	struct packet* prev;
	struct packet* next;
} packet_t;

typedef struct send_queue{
	packet_t head;
} queue_t;

typedef struct tmp_packet {
    int session_id;
    char rsv;
    uint16_t datalen;
    char * data;
} tmp_packet_t;

typedef struct socks_handshake
{
    uv_tcp_t server;
    int stage;
    char atyp;
    int init;
    int session_id;
    int closing;
    int closed;
    char addrlen;
    char host[256];	// to support ipv6
    char port[16];
    char* response;
    struct socks_handshake* prev;
    struct socks_handshake* next;
} socks_handshake_t;

typedef struct socks_connection_list{
    socks_handshake_t head;
} socks_connection_list_t;

typedef struct
{
	uv_tcp_t remote;
	int stage;
	int run;
	size_t buffer_len;
    struct clib_map* idfd_map;  // for mapping session id with remote fd
	server_ctx* listen;
    char packet_buf[MAX_PKT_SIZE];
    char recv_buffer[MAX_PKT_SIZE];
    tmp_packet_t tmp_packet;
    int buf_len;
    int reset;
    int offset;
    int expect_to_recv;
    uint32_t sid;
    socks_connection_list_t managed_socks_list; // SOCKS5 connections managed by this remote_ctx
    int connected;
} remote_ctx_t;




#endif