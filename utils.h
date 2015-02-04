#ifndef _UTILS_H
#define _UTILS_H
#include <uv.h>
#include <stdio.h>
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
} while(0);

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
        }   \
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

#endif