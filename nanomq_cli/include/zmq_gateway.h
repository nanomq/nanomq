#ifndef ZMQ_PROXY_H
#define ZMQ_PROXY_H

#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/conf.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

extern int zmq_gateway(zmq_gateway_conf *conf);
extern int gateway_start(int argc, char **argv);
extern int gateway_dflt(int argc, char **argv);

#endif