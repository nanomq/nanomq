#ifndef ZMQ_PROXY_H
#define ZMQ_PROXY_H

#include <nng/mqtt/mqtt_client.h>
#include <nng/supplemental/util/platform.h>
#include <nng/nng.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

typedef struct {
    const char *zmq_conn_url;
    const char *zmq_listen_url;
    const char *mqtt_url;
    const char *sub_topic;
    const char *pub_topic;
    void       *zmq_sender; 
    enum {PUB_SUB, REQ_REP} type;
} zmq_proxy_conf;

int  zmq_gateway(zmq_proxy_conf *conf);

extern int gateway_start(int argc, char **argv);
extern int gateway_dflt(int argc, char **argv);
#endif