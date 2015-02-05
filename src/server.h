#ifndef SERVER_H_
#define SERVER_H_
#define BUF_SIZE 2048
#include "c_map.h"

#define MAX_PKT_SIZE 8192
#define EXP_TO_RECV_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)
#define ID_LEN 4
#define RSV_LEN 1
#define DATALEN_LEN 2
#define ATYP_LEN 1
#define ADDRLEN_LEN  1
#define PORT_LEN 2
#define FULLPKT 1
#define SMALLPKT 0

#define packet_payload_alloc(packet, flag) \
do { \
if (flag) \
    packet.payloadlen = packet.datalen - ATYP_LEN + ADDRLEN_LEN + packet.addrlen + PORT_LEN; \
else \
    packet.payloadlen = packet.datalen; \
packet.data = calloc(1, packet.payloadlen); \
} while(0)

#define addrinfo_hints_init(hints) \
do { \
hints.ai_family = PF_INET; \
hints.ai_socktype = SOCK_STREAM; \
hints.ai_protocol = IPPROTO_TCP; \
hints.ai_flags = 0; \
} while(0)

// reset packet buf
// reset packet structure
#define packetnbuf_reset(ctx) \
do { \
ctx->buf_len = 0; \
ctx->stage = 0; \
memset(ctx->packet_buf, 0, MAX_PKT_SIZE); \
memset(&ctx->packet, 0, sizeof(packet_t)); \
ctx->reset = 1; \
} while(0)

// debug
#define SHOWPKTDEBUG(remote_ctx) LOGD("session_id=%d, rsv=%d, datalen=%d, atyp=%d, addrlen=%d, host=%s, port=%d, data=\n%s",remote_ctx->packet->session_id, remote_ctx->packet->rsv, remote_ctx->packet->datalen, remote_ctx->packet->atyp, remote_ctx->packet->addrlen, remote_ctx->packet->host, ntohs(*(uint16_t*)remote_ctx->packet->port), remote_ctx->packet->data)

#define SHOWPKTDEBUGWODATA(remote_ctx) LOGD("session_id=%d, rsv=%d, datalen=%d, atyp=%d, addrlen=%d, host=%s, port=%d",remote_ctx->packet->session_id, remote_ctx->packet->rsv, remote_ctx->packet->datalen, remote_ctx->packet->atyp, remote_ctx->packet->addrlen, remote_ctx->packet->host, ntohs(*(uint16_t*)remote_ctx->packet->port))

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



typedef struct packet {
    uint32_t session_id;
    char rsv;
    uint16_t datalen;
    uint16_t payloadlen;
    char atyp;
    char addrlen;
    char host[257];
    char port[2];
    char* data;
    int offset;
    struct packet *prev;
    struct packet *next;
} packet_t;

typedef struct send_queue{
    packet_t head;
} queue_t;

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
    packet_t* packet;
    char* pkt_buf;
} write_req_t;

typedef struct {

	uv_tcp_t listen;
	uv_tcp_t server;
    struct clib_map* idfd_map;  // for mapping session id with remote fd
    packet_t packet;
    queue_t send_queue;
    char packet_buf[MAX_PKT_SIZE];
    int buf_len;
    int reset;
	int stage;
    int expect_to_recv;
} server_ctx_t;


typedef struct {
    int session_id;
    uv_tcp_t remote;
    server_ctx_t* server_ctx;
    char host[257];
    char port[2];
    packet_t* packet;
    queue_t send_queue;
    int resolved;
    int connected;
    char addrlen;
    
//    char dnsed_ipv4[16];    // reserved for ipv6 addr
//    char port[2];
//    int session_id;
    int stage;
} remote_ctx_t;

#endif