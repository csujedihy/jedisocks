#ifndef _UTILS_H
#define _UTILS_H
#include <uv.h>
#include <stdio.h>
#include <time.h>
    
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

#define ERROR(msg, code) do {                                                         \
  fprintf(stderr, "%s: [%s: %s]\n", msg, uv_err_name((code)), uv_strerror((code)));   \
  assert(0);                                                                          \
} while(0);

#define LOGD(format, ...)                                                    \
    do {                                                                     \
                                                                            \
            time_t now = time(NULL);                                         \
            char timestr[20];                                                \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));             \
            fprintf(stderr, "\e[01;32m %s INFO: \e[0m" format "\n", timestr, \
                    ## __VA_ARGS__);                                         \
        }                                                                   \
    while (0)

#define LOGE(format, ...)                                                     \
    do {                                                                      \
                                                                                \
            time_t now = time(NULL);                                          \
            char timestr[20];                                                 \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));              \
            fprintf(stderr, "\e[01;35m %s ERROR: \e[0m" format "\n", timestr, \
                    ## __VA_ARGS__);                                          \
        }                                                                      \
    while (0)

#define SHOW_BUFFER(buf, len) do {\
                              for (int i=0; i<len; i++)\
                                putchar(buf[i]);\
                              } while (0)

#define SHOW_BUFFER_IN_HEX(buf, len) do {\
                              for (int i=0; i<len; i++)\
                                printf("%x_",buf[i]);\
                              } while (0)

#endif