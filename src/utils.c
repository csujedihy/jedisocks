//
//  utils.c
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

void usage() {
    printf("\
Jedisocks v1.0\n\
  developed by Jedihy\n\
  usage:\n\
  js-[local|server]\n\
    -c <config_file> Path of configuration file that is written in JSON\n\
    -r <server_host> Ip address of your remote server\n\
    -l <local_host> Ip address of your local server\n\
    -p <local_port> Port number of your local server\n\
    -P <remote_port> Port number of your remote server\n\
    ");
}

int kmp_search(char* dest_str, int dest_str_len, char* src_str, int src_str_len) {
    
    if (dest_str_len <= 0 || src_str_len <= 0 || dest_str == NULL || src_str == NULL)
        return -1;
    
    int dest_pos = 0, src_pos = 0, k = -1, j = 0;
    
    // construct Partial Match Table
    int* mcss_table = malloc(strlen(src_str) * sizeof(int));
    mcss_table[0] = -1;
    
    while (j < src_str_len - 1) {
        if (k == -1 || src_str[j] == src_str[k]) {
            ++j, ++k;
            mcss_table[j] = k;
        } else {
            k = mcss_table[k];
        }
    }
    
    while (dest_pos < dest_str_len && src_pos < src_str_len) {
        if (dest_str[dest_pos] == src_str[src_pos]) {
            dest_pos++;
            src_pos++;
        } else {
            if (src_pos > 0)
                src_pos = mcss_table[src_pos];
            else
                dest_pos++;
        }
    }
    
    free(mcss_table);
    if (src_pos == src_str_len)
        return dest_pos - src_pos;
    else
        return -1;
}