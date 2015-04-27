//
//  utils.c
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
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

// for performance tunning
struct timeval GetTimeStamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv;
}