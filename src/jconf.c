//
//  jconf.c
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "js0n.h"
#include "utils.h"
#include "jconf.h"
char* four0addr = "0.0.0.0";
int local_validate_conf(conf_t* conf) {
    if (conf->local_address == NULL) {
        conf->local_address = four0addr;
    }
    if (conf->server_address == NULL)
        return 1;
    return 0;
}

int server_validate_conf(conf_t* conf) {
    if (conf->server_address == NULL) {
        conf->server_address = four0addr;
    }
    return 0;
}

void read_conf(char* configfile, conf_t* conf) {

    conf_t* config = conf;
    char* aaa = "127.0.0.1";
    char* val = NULL;
    char* configbuf = NULL;
    char localportbuf[6] = {0};
    char serverportbuf[6] = {0};
    int vlen = 0;
    FILE *f = fopen(configfile, "rb");
    if (f == NULL) {
        FATAL("Invalid config path.");
    }
    
    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    configbuf = malloc(pos + 1);
    if (configbuf == NULL) {
        FATAL("No enough memory.");
    }
    
    int nread = fread(configbuf, pos, 1, f);
    if (!nread) {
        FATAL("Failed to read the config file.");
    }
    fclose(f);
    
    configbuf[pos] = '\0'; // end of string

    val = js0n("server_port", strlen("server_port"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(serverportbuf, val, vlen);
        conf->serverport = atoi(serverportbuf);
    }
    
    val = js0n("local_port", strlen("local_port"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(localportbuf, val, vlen);
        conf->localport = atoi(localportbuf);
    }
    
    val = js0n("server", 6, configbuf, (int)pos, &vlen);
    if (val != NULL) {
        
        conf->server_address = (char*)malloc(vlen + 1);
        memcpy(conf->server_address, val, vlen);
        conf->server_address[vlen] = '\0';
    }
    
    val = js0n("local_address", 13, configbuf, (int)pos, &vlen);
    if (val != NULL) {
        conf->local_address = (char*)malloc(vlen + 1);
        memcpy(conf->local_address, val, vlen);
        conf->local_address[vlen] = '\0';
    }
}