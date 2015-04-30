//
//  jconf.c
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

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
    char* val = NULL;
    char* configbuf = NULL;
    char localport_buf[6]    = {0};
    char serverport_buf[6]   = {0};
    char gatewayport_buf[6]  = {0};
    char backend_mode_buf[6] = {0};
    char pool_size_buf[6]    = {0};
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
    
#define JSONPARSE(str)                                    \
val = js0n(str, strlen(str), configbuf, (int)pos, &vlen); \
if (val != NULL)

    JSONPARSE("server_port") {
        memcpy(serverport_buf, val, vlen);
        conf->serverport = atoi(serverport_buf);
    }
    
    JSONPARSE("local_port") {
        memcpy(localport_buf, val, vlen);
        conf->localport = atoi(localport_buf);
    }
    
    JSONPARSE("server"){
        conf->server_address = (char*)malloc(vlen + 1);
        memcpy(conf->server_address, val, vlen);
        conf->server_address[vlen] = '\0';
    }
    
    JSONPARSE("local_address"){
        conf->local_address = (char*)malloc(vlen + 1);
        memcpy(conf->local_address, val, vlen);
        conf->local_address[vlen] = '\0';
    }
    
    JSONPARSE("pool_size"){
        memcpy(pool_size_buf, val, vlen);
        conf->pool_size = atoi(pool_size_buf);
    }
    
    JSONPARSE("backend_mode"){
        memcpy(backend_mode_buf, val, vlen);
        conf->backend_mode = atoi(backend_mode_buf);
        if (!conf->backend_mode)
            return;
    }
    
    JSONPARSE("gateway_address"){
        conf->centralgw_address = (char*)malloc(vlen);
        memcpy(conf->centralgw_address, val, vlen);
        conf->centralgw_address_len = vlen;
    }
    
    JSONPARSE("gateway_port"){
        memcpy(gatewayport_buf, val, vlen);
        conf->gatewayport = atoi(gatewayport_buf);
        fprintf(stderr, "Forward to gateway:%d\n", conf->gatewayport);
    }
    
#undef JSONPARSE
}