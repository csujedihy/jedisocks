#ifndef LOCAL_H_
#define LOCAL_H_

#define SOCKS5_FISRT_REQ_SIZE 3
#define SOCKS5_FISRT_RESP_SIZE 2
#define INT_MAX 2147483647

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

//packet related operations
#define pkt_maker(dest, src, len, offset) \
do { \
    memcpy(dest + offset, src, len); \
    offset += len; \
}  while(0)

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


typedef struct
{
	uv_tcp_t remote;
	int stage;
	int run;
	size_t buffer_len;
	server_ctx* listen;
} remote_ctx_t;


typedef struct 
{
	uv_tcp_t server;
	int stage;
	char atyp;
	int init;
	int session_id;
	char addrlen;
	char host[256];	// to support ipv6
	char port[16];	
} socks_handshake;

typedef struct 
{
	uv_tcp_t pool;
	int stage;
} pool_ctx;

#endif