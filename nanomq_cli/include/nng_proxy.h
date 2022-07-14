#ifndef NANOMQ_NNG_CLIENT_H
#define NANOMQ_NNG_CLIENT_H

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum nng_proto { PUB0, SUB0, CONN, REQ, REP, PAIR0, PAIR1 };

typedef struct nng_proxy_opts nng_proxy_opts;

extern int nng_pub0_dflt(int argc, char **argv);
extern int nng_sub0_dflt(int argc, char **argv);
// extern int conn_dflt(int argc, char **argv);
extern int nng_pub0_start(int argc, char **argv);
extern int nng_sub0_start(int argc, char **argv);
// extern int nng_conn_start(int argc, char **argv);
extern int nng_client0_stop(int argc, char **argv);
extern int nng_proxy_start(int argc, char **argv);
extern int nng_client_parse_opts(int argc, char **argv, nng_proxy_opts *nng_opts);
#endif // NANOMQ_NNG_CLIENT_H
