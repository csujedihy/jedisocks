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
    char* aaa = "127.0.0.1";
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

    val = js0n("server_port", strlen("server_port"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(serverport_buf, val, vlen);
        conf->serverport = atoi(serverport_buf);
    }
    
    val = js0n("local_port", strlen("local_port"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(localport_buf, val, vlen);
        conf->localport = atoi(localport_buf);
    }
    
    val = js0n("server", strlen("server"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        conf->server_address = (char*)malloc(vlen + 1);
        memcpy(conf->server_address, val, vlen);
        conf->server_address[vlen] = '\0';
    }
    
    val = js0n("local_address", strlen("local_address"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        conf->local_address = (char*)malloc(vlen + 1);
        memcpy(conf->local_address, val, vlen);
        conf->local_address[vlen] = '\0';
    }
    
    val = js0n("pool_size", strlen("pool_size"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(pool_size_buf, val, vlen);
        conf->pool_size = atoi(pool_size_buf);
    }
    
    val = js0n("backend_mode", strlen("backend_mode"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(backend_mode_buf, val, vlen);
        conf->backend_mode = atoi(backend_mode_buf);
        if (!conf->backend_mode)
            return;
    }
    
    val = js0n("gateway_address", strlen("gateway_address"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        conf->centralgw_address = (char*)malloc(vlen);
        memcpy(conf->centralgw_address, val, vlen);
        conf->centralgw_address_len = vlen;
    }
    
    val = js0n("gateway_port", strlen("gateway_port"), configbuf, (int)pos, &vlen);
    if (val != NULL) {
        memcpy(gatewayport_buf, val, vlen);
        conf->gatewayport = atoi(gatewayport_buf);
        fprintf(stderr, "Forward to gateway:%d\n", conf->gatewayport);
    }
    
}