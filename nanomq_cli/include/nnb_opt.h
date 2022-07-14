#ifndef NNB_OPT_H
#define NNB_OPT_H

#if !defined(NANO_PLATFORM_WINDOWS) && defined(SUPP_BENCH)
// TODO support windows later

#include <assert.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

typedef struct {
	bool  enable;
	char *cacert;
	char *cert;
	char *key;
	char *keypass;
} tls_opt;

typedef struct {
	char *  host;
	char *  username;
	char *  password;
	int     port;
	int     version;
	int     count;
	int     startnumber;
	int     interval;
	int     keepalive;
	bool    clean;
	tls_opt tls;
	// TODO future
	// char	ifaddr[64];
	// char	prefix[64];
} nnb_conn_opt;

typedef struct {
	char *  host;
	char *  username;
	char *  password;
	char *  topic;
	int     port;
	int     version;
	int     count;
	int     startnumber;
	int     interval;
	int     keepalive;
	int     qos;
	bool    clean;
	tls_opt tls;
	// TODO future
	// bool	ws;
	// char	ifaddr[64];
	// char	prefix[64];
} nnb_sub_opt;

typedef struct {
	char *  host;
	char *  username;
	char *  password;
	char *  topic;
	int     port;
	int     version;
	int     count;
	int     startnumber;
	int     interval;
	int     interval_of_msg;
	int     size;
	int     limit;
	int     keepalive;
	int     qos;
	bool    retain;
	bool    clean;
	tls_opt tls;
	// TODO future
	// bool	ws;
	// char	ifaddr[64];
	// char	prefix[64];
} nnb_pub_opt;

static struct option long_options[] = {

	{ "host", required_argument, NULL, 0 },
	{ "port", required_argument, NULL, 0 },
	{ "topic", required_argument, NULL, 0 },
	{ "version", required_argument, NULL, 0 },
	{ "count", required_argument, NULL, 0 },
	{ "startnumber", required_argument, NULL, 0 },
	{ "interval", required_argument, NULL, 0 },
	{ "username", required_argument, NULL, 0 },
	{ "password", required_argument, NULL, 0 },
	{ "keepalive", required_argument, NULL, 0 },
	{ "clean", required_argument, NULL, 0 },
	{ "limit", required_argument, NULL, 0 },
	{ "qos", required_argument, NULL, 0 },
	{ "size", required_argument, NULL, 0 },
	{ "retain", required_argument, NULL, 0 },
	{ "interval_of_msg", required_argument, NULL, 0 },
	{ "ssl", no_argument, NULL, 0 },
	{ "cafile", required_argument, NULL, 0 },
	{ "certfile", required_argument, NULL, 0 },
	{ "keyfile", required_argument, NULL, 0 },
	{ "keypass", required_argument, NULL, 0 },

	//  { "ifaddr", 	required_argument, NULL, 0 },
	//  { "prefix", 	required_argument, NULL, 0 },
	{ "help", no_argument, NULL, 0 }, { NULL, 0, NULL, 0 }
};

extern nnb_conn_opt *nnb_conn_opt_init(int argc, char **argv);
extern void          nnb_conn_opt_destory(nnb_conn_opt *opt);
extern nnb_sub_opt * nnb_sub_opt_init(int argc, char **argv);
extern void          nnb_sub_opt_destory(nnb_sub_opt *opt);
extern nnb_pub_opt * nnb_pub_opt_init(int argc, char **argv);
extern void          nnb_pub_opt_destory(nnb_pub_opt *opt);

#endif

#endif