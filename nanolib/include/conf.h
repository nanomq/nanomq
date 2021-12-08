#ifndef CONF_H
#define CONF_H

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zmalloc.h"

#define USAGE                                                                 \
	"Usage: nanomq broker {"                                              \
	"{start|restart [-conf <path>] [-url <url>] [-daemon] [-tq_thread "   \
	"<num>] [-max_tq_thread <num>] [-parallel <num>] [-qos_duration "     \
	"<num>]}|stop}\n"                                                     \
	"  -conf <path>          the path of a specified nanomq "             \
	"configuration file "                                                 \
	"\n"                                                                  \
	"  -bridge <path>        the path of a specified bridge "             \
	"configuration file \n"                                               \
	"  -url <url>            the format of 'tcp://ip_addr:host'\n"        \
	"  -tq_thread <num>      the number of taskq threads used, `num` "    \
	"greater than 0 and less than 256\n"                                  \
	"  -max_tq_thread <num>  the maximum number of taskq threads used, "  \
	"`num` greater than 0 and less than 256\n"                            \
	"  -parallel <num>       the maximum number of outstanding requests " \
	"we can handle\n"                                                     \
	"  -property_size <num>  the max size for a MQTT user property\n"     \
	"  -msq_len <num>        the queue length for resending messages\n"   \
	"  -qos_duration <num>   the interval of the qos timer\n"             \
	"  -http                 enable http server (default: disable)\n"     \
	"  -port <num>           the port of http server (default: 8081)\n"

#define CONF_READ_RECORD "Conf_file: %s read as %s\n"

#define PID_PATH_NAME "/tmp/nanomq/nanomq.pid"
#define CONF_PATH_NAME "/etc/nanomq.conf"
#define CONF_AUTH_PATH_NAME "/etc/nanomq_auth_username.conf"
#define CONF_BRIDGE_PATH_NAME "/etc/nanomq_bridge.conf"

#define CONF_URL_DEFAULT "broker+tcp://0.0.0.0:1883"

struct conf_auth {
	int    count;
	char **usernames;
	char **passwords;
};
typedef struct conf_auth conf_auth;

struct conf_http_server {
	bool     enable;
	uint16_t port;
	char *   username;
	char *   password;
};

typedef struct conf_http_server conf_http_server;

struct conf_websocket {
	bool  enable;
	char *url;
};

typedef struct conf_websocket conf_websocket;

typedef struct {
	char *   topic;
	uint32_t topic_len;
	uint8_t  qos;
} subscribe;

struct conf_bridge {
	bool       bridge_mode;
	char *     address;
	uint8_t    proto_ver;
	char *     clientid;
	bool       clean_start;
	char *     username;
	char *     password;
	uint16_t   keepalive;
	size_t     forwards_count;
	char **    forwards;
	size_t     sub_count;
	subscribe *sub_list;
};

typedef struct conf_bridge conf_bridge;

struct conf {
	char *   url;
	int      num_taskq_thread;
	int      max_taskq_thread;
	uint64_t parallel;
	int      property_size;
	int      msq_len;
	int      qos_duration;
	void *   db_root;
	bool     allow_anonymous;
	bool     daemon;

	conf_http_server http_server;
	conf_websocket   websocket;
	conf_bridge      bridge;

	conf_auth auths;
};

typedef struct conf conf;

extern bool conf_parser(conf **nanomq_conf, const char *path);
extern bool conf_bridge_parse(conf *nanomq_conf, const char *path);
extern void print_bridge_conf(conf_bridge *bridge);
extern void conf_init(conf **nanomq_conf);
extern void print_conf(conf *nanomq_conf);
extern void conf_fini(conf *nanomq_conf);

extern void conf_auth_parser(conf *);

extern int string_trim(char **dst, char *str);

#endif
