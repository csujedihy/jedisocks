//
//  jconf.h
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#ifndef jedisocks_jconf_h
#define jedisocks_jconf_h
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

typedef struct {
    uint16_t localport;
    uint16_t serverport;
    uint16_t gatewayport;
    char* server_address;
    char* local_address;
    char* centralgw_address;
    uint32_t centralgw_address_len;
    int backend_mode;
    int pool_size;
} conf_t;

extern void read_conf(char* configfile, conf_t* conf);
extern int server_validate_conf(conf_t* conf);
extern int local_validate_conf(conf_t* conf);
#endif
