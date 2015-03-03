//
//  main.c
//  gzip-test
//
//  Created by jedihy on 15-3-3.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#define MAXTHREAD 8
#define REQUESTNUM 1000
char* path = "/tmp/index.html";
char* text = NULL;
char* buf = NULL;
uLong blen;
uLong tlen;
int completed_task = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct timeval tv_end;
struct timeval tv_start;

struct timeval GetTimeStamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv;
}

char* readhtml(char* path, uLong* tlen) {
    static char* filebuf;
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("Invalid config path.");
    }
    
    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);
    *tlen = pos;
    filebuf = malloc(pos);
    if (filebuf == NULL) {
        printf("No enough memory.\n");
    }
    
    int nread = fread(filebuf, pos, 1, f);
    if (!nread) {
        printf("Failed to read the config file.\n");
    }
    fclose(f);

    return filebuf;
}

void *thread_for_uncompr(void *arg)
{
    
    for (int i =0; i < REQUESTNUM/MAXTHREAD; ++i) {
        char* uncompressed = malloc(tlen);
        /* 解压缩 */
        if(uncompress(uncompressed, &tlen, buf, blen) != Z_OK)
        {
            printf("uncompress failed!\n");
            return -1;
        }
        free(uncompressed);
    }
   
    return NULL;
}


int main(int argc, const char * argv[]) {
    void* status;
    //= strlen(text) + 1;  /* 需要把字符串的结束符'\0'也一并处理 */
    text = readhtml(path, &tlen);
    pthread_t pid[MAXTHREAD];

    /* 计算缓冲区大小，并为其分配内存 */
    blen = compressBound(tlen); /* 压缩后的长度是不会超过blen的 */
    if((buf = (char*)malloc(sizeof(char) * blen)) == NULL)
    {
        printf("no enough memory!\n");
        return -1;
    }
    
    /* 压缩 */
    if(compress(buf, &blen, text, tlen) != Z_OK)
    {
        printf("compress failed!\n");
        return -1;
    }
    
    struct timeval _tv_start = GetTimeStamp();
    int j = 0;
    for (int i = 0; i < 32; ) {
        i += 1;
        if (i%50==5)
            j++;
    }
    struct timeval _tv_end = GetTimeStamp();
    
    printf("Time cost =  %ldms\n",((_tv_end.tv_sec*1000000 + _tv_end.tv_usec) - (_tv_start.tv_sec*1000000 + _tv_start.tv_usec))/1000);
    if(buf != NULL)
    {
        free(buf);
        buf = NULL;
    }
    
    return 0;
}
