#ifndef _UTILS_H
#define _UTILS_H
#include <stdio.h>
#include <string.h>
#include <time.h>
extern FILE * logfile;

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define COLORDEF_GREEM \e[01;32m
#define COLORDEF_WHITE \e[0m
#define USE_LOGFILE(ident)                                     \
    do {                                                       \
        if (ident != NULL) { logfile = fopen(ident, "w+"); } } \
    while (0)

#define CLOSE_LOGFILE                               \
    do {                                            \
        if (logfile != NULL) { fclose(logfile); } } \
    while (0)
#define ERROR(msg, code) do {                                                         \
  fprintf(stderr, "%s: [%s: %s]\n", msg, uv_err_name((code)), uv_strerror((code)));   \
  assert(0);                                                                          \
} while (0)

#define LOGD(format, ...)   \
    do {    \
            if (logfile != NULL) {  \
                time_t now = time(NULL);    \
                char timestr[20];   \
                strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
                fprintf(logfile, " %s INFO: " format "\n", timestr,  \
                        ## __VA_ARGS__);    \
                fflush(logfile);    \
            }   \
            else { \
                time_t now = time(NULL);    \
                char timestr[20];   \
                strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
                fprintf(stderr, " %s INFO: " format "\n", timestr,  \
                ## __VA_ARGS__);    \
                fflush(stderr);    \
            } \
        } \
    while (0)

#define __LOGD(format, ...)   \
do {    \
} \
while (0)

#define FATAL(format, ...)   \
do {    \
    if (logfile != NULL) {  \
        time_t now = time(NULL);    \
        char timestr[20];   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
        fprintf(logfile, " %s INFO: " format "\n", timestr,  \
        ## __VA_ARGS__);    \
        fflush(logfile);    \
    }   \
    else { \
        time_t now = time(NULL);    \
        char timestr[20];   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
        fprintf(stderr, " %s INFO: " format "\n", timestr,  \
        ## __VA_ARGS__);    \
        fflush(stderr);    \
    } \
    exit(EXIT_FAILURE); \
} \
while (0)

#define LOGE(format, ...)                                                     \
    do {                                                                      \
                                                                                \
            time_t now = time(NULL);                                          \
            char timestr[20];                                                 \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));              \
            fprintf(stderr, " %s ERROR: " format "\n", timestr, \
                    ## __VA_ARGS__);                                          \
        }                                                                      \
    while (0)

#define SHOW_BUFFER(buf, len) do {\
                              for (int i=0; i<len; i++)\
                                putchar(buf[i]);\
                              } while (0)

#define LOG_SHOW_BUFFER(buf, len) do {\
                                if (logfile != NULL) {  \
                                  for (int i=0; i<len; i++)\
                                    fprintf(logfile, "%c", buf[i]);\
                                  fflush(logfile);    \
                                  } \
                              } while (0)                              

#define SHOW_BUFFER_IN_HEX(buf, len) do {\
                              for (int i=0; i<len; i++)\
                                printf("%x_",buf[i]);\
                              } while (0)

//packet related operations
#define set_header pkt_maker
#define set_payload pkt_maker
#define get_header pkt_access
#define get_payload pkt_access
#define get_id pkt_access_sid
#define pkt_maker(dest, src, len, offset) \
do { \
memcpy(dest + offset, src, len); \
offset += len; \
}  while(0)

#define pkt_access(dest, src, len, offset) \
do { \
memcpy(dest, src + offset, len); \
offset += len; \
}  while(0)

#define pkt_access_sid(ctx, dest, src, len, offset) \
do { \
pkt_access((dest), (src), (len), (offset)); \
(ctx)->packet.session_id = ntohl((uint32_t)ctx->packet.session_id); \
} while(0)

// built-in link list MACROs, originated from libcork
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

#define list_get_start(list) \
((list)->head.next)

#define list_elem_is_end(list, element) \
((element) == &(list)->head)

#define HTTP_SPACE_LEN 1
#define HTTP_CHRCTR_LEN 9
#define HTTP_LF_OFFSET 10
#define HTTP_SUBVER_POS 7
#define HEADER_HOST_STR_LEN 6
#define HTTPS_SYMBOL_LEN 7


void usage();

int kmp_search(char* dest_str, int dest_str_len, char* src_str, int src_str_len);

#endif