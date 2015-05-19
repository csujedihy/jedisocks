//
//  utils.c
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <stdio.h>
#include <uv.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils.h"

void usage()
{
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

void init_daemon()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("./");
}

void signal_handler(uv_signal_t* handle, int signum)
{
    printf("Ctrl+C pressed %d\n", signum);
    uv_loop_t* loop = handle->data;
    uv_signal_stop(handle);
    uv_stop(loop);
    uv_loop_delete(loop);
    exit(0);
}

void setup_signal_handler(uv_loop_t* loop)
{
    signal(SIGPIPE, SIG_IGN);
    uv_signal_t sigint;
    sigint.data = loop;
    int n = uv_signal_init(loop, &sigint);
    n = uv_signal_start(&sigint, signal_handler, SIGINT);
}