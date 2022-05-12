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


#define PID_PATH_NAME "/tmp/nanomq/nanomq.pid"
#define CONF_PATH_NAME "/etc/nanomq.conf"
#define CONF_AUTH_PATH_NAME "/etc/nanomq_auth_username.conf"
#define CONF_BRIDGE_PATH_NAME "/etc/nanomq_bridge.conf"
#define CONF_GATEWAY_PATH_NAME "/etc/nanomq_gateway.conf"
#define CONF_RULE_ENGINE_PATH_NAME "/etc/nanomq_rule_engine.conf"
#define CONF_WEB_HOOK_PATH_NAME "/etc/nanomq_web_hook.conf"
#define CONF_AUTH_HTTP_PATH_NAME "/etc/nanomq_auth_http.conf"

#define CONF_TCP_URL_DEFAULT "nmq-tcp://0.0.0.0:1883"
#define CONF_TLS_URL_DEFAULT "tls+nmq-tcp://0.0.0.0:8883"
#define CONF_WS_URL_DEFAULT "nmq-ws://0.0.0.0:8083/mqtt"
#define CONF_WSS_URL_DEFAULT "nmq-wss://0.0.0.0:8084/mqtt"

#define BROKER_NMQ_TCP_URL_PREFIX "nmq-tcp"
#define BROKER_NMQ_TCP_TLS_URL_PREFIX "tls+nmq-tcp"
#define BROKER_NMQ_WS_URL_PREFIX "nmq-ws"
#define BROKER_NMQ_WSS_URL_PREFIX "nmq-wss"

#define BROKER_TCP_URL_PREFIX "broker+tcp"
#define BROKER_WS_URL_PREFIX "nmq+ws"
#define BROKER_WSS_URL_PREFIX "nmq+wss"

#define FREE_NONULL(p)    \
	if (p) {          \
		free(p);  \
		p = NULL; \
	}

struct conf_auth {
	int    count;
	char **usernames;
	char **passwords;
};
typedef struct conf_auth conf_auth;

struct conf_tls {
	bool  enable;
	char *url; // "tls+nmq-tcp://addr:port"
	char *cafile;
	char *certfile;
	char *keyfile;
	char *ca;
	char *cert;
	char *key;
	char *key_password;
	bool  verify_peer;
	bool  set_fail; // fail_if_no_peer_cert
};

typedef struct conf_tls conf_tls;

struct conf_http_header {
	char *key;
	char *value;
};

typedef struct conf_http_header conf_http_header;

typedef enum {
	ACCESS,
	USERNAME,
	CLIENTID,
	IPADDRESS,
	PROTOCOL,
	PASSWORD,
	SOCKPORT,    // sockport of server accepted
	COMMON_NAME, // common name of client TLS cert
	SUBJECT,     // subject of client TLS cert
	TOPIC,
} http_param_type;

struct conf_http_param {
	char *          name;
	http_param_type type;
};

typedef struct conf_http_param conf_http_param;

struct conf_auth_http_req {
	char *url;
	char *method;
	size_t header_count;
	conf_http_header **headers;
	size_t param_count;
	conf_http_param **params;
};

typedef struct conf_auth_http_req conf_auth_http_req;

struct conf_auth_http {
	bool               enable;
	conf_auth_http_req auth_req;
	conf_auth_http_req super_req;
	conf_auth_http_req acl_req;
	uint64_t           timeout;         // seconds
	uint64_t           connect_timeout; // seconds
	size_t             pool_size;
	// TODO not support yet
	conf_tls tls;
};

typedef struct conf_auth_http conf_auth_http;

struct conf_jwt {
	char *iss;
	char *public_keyfile;
	char *private_keyfile;
	char *public_key;
	char *private_key;
	size_t public_key_len;
	size_t private_key_len;
};

typedef struct conf_jwt conf_jwt;

struct conf_http_server {
	bool     enable;
	uint16_t port;
	char *   username;
	char *   password;
	enum { BASIC, JWT, NONE_AUTH } auth_type;
	conf_jwt jwt;
};

typedef struct conf_http_server conf_http_server;

struct conf_websocket {
	bool  enable;
	char *url;     // "nmq-ws://addr:port/path"
	char *tls_url; // "nmq-wss://addr:port/path"
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
	uint64_t   parallel;
	conf_tls   tls;
};

typedef struct {
    const char *zmq_sub_url;
    const char *zmq_pub_url;
    const char *mqtt_url;
    const char *sub_topic;
    const char *pub_topic;
    const char *zmq_sub_pre;
    const char *zmq_pub_pre;
	const char *path;
	const char *username;
	const char *password;
    void       *zmq_sender; 
	int 		proto_ver;
	int			keepalive;
	bool		clean_start;
	int			parallel;
    enum {PUB_SUB, REQ_REP} type;
} zmq_gateway_conf;

static char *rule_engine_key_arr[] = {
		"qos",
		"id",
		"topic",
		"clientid",
		"username",
		"password",
		"timestamp",
		"payload",
		"*",
		NULL
};


// typedef struct {
// 	const char *key;
// 	const char *value;
// } rule_engine_filter;

typedef struct {
	bool		flag[8];
	const char 	*topic; 	
	char 		**filter;
} rule_engine_info;

typedef struct conf_bridge conf_bridge;

typedef enum {
	CLIENT_CONNECT,
	CLIENT_CONNACK,
	CLIENT_CONNECTED,
	CLIENT_DISCONNECTED,
	CLIENT_SUBSCRIBE,
	CLIENT_UNSUBSCRIBE,
	SESSION_SUBSCRIBED,
	SESSION_UNSUBSCRIBED,
	SESSION_TERMINATED,
	MESSAGE_PUBLISH,
	MESSAGE_DELIVERED,
	MESSAGE_ACKED,
	UNKNOWN_EVENT,
} webhook_event;

typedef enum {
	plain,
	base64,
	base62
} hook_payload_type;

struct conf_web_hook_rule {
	uint16_t      rule_num;
	webhook_event event;
	char *        action;
	char *        topic;
};

typedef struct conf_web_hook_rule conf_web_hook_rule;

struct conf_web_hook {
	bool   enable;
	char * url;
	size_t pool_size;
	hook_payload_type encode_payload;
	size_t header_count;
	conf_http_header **headers;

	uint16_t            rule_count;
	conf_web_hook_rule **rules;

	// TODO not support yet
	conf_tls tls;
};

typedef struct conf_web_hook  conf_web_hook;

struct conf {
	char *   conf_file;
	char *   bridge_file;
	char *   rule_engine_file;
	char * 	 web_hook_file;
	char *   auth_file;
	char *   auth_http_file;
	char *   url; // "nmq-tcp://addr:port"
	int      num_taskq_thread;
	int      max_taskq_thread;
	uint64_t parallel;
	int      property_size;
	int      msq_len;
	int      qos_duration;
	void *   db_root;
	bool     allow_anonymous;
	bool     daemon;

	conf_tls         tls;
	conf_http_server http_server;
	conf_websocket   websocket;
	conf_bridge      bridge;
	conf_web_hook    web_hook;
	rule_engine_info *rule_engine;

	conf_auth      auths;
	conf_auth_http auth_http;
};

typedef struct conf conf;

extern bool conf_parser(conf *nanomq_conf);
extern bool conf_bridge_parse(conf *nanomq_conf);
extern bool conf_gateway_parse(zmq_gateway_conf *g_conf);
extern bool conf_web_hook_parse(conf *nanomq_conf);
extern bool conf_rule_engine_parse(conf *nanomq_conf);
extern bool conf_auth_http_parse(conf *nanomq_conf);
extern void print_bridge_conf(conf_bridge *bridge);
extern void conf_init(conf *nanomq_conf);
extern void print_conf(conf *nanomq_conf);
extern void conf_fini(conf *nanomq_conf);
extern void conf_auth_parser(conf *);
extern void conf_update(const char *fpath, const char *key, char *value);
extern void conf_update_var(
    const char *fpath, const char *key, uint8_t type, void *var);

#define conf_update_int(path, key, var) \
	conf_update_var(path, key, 0, (void *) &(var))
#define conf_update_u8(path, key, var) \
	conf_update_var(path, key, 1, (void *) &(var))
#define conf_update_u16(path, key, var) \
	conf_update_var(path, key, 2, (void *) &(var))
#define conf_update_u32(path, key, var) \
	conf_update_var(path, key, 3, (void *) &(var))
#define conf_update_u64(path, key, var) \
	conf_update_var(path, key, 4, (void *) &(var))
#define conf_update_long(path, key, var) \
	conf_update_var(path, key, 5, (void *) &(var))
#define conf_update_double(path, key, var) \
	conf_update_var(path, key, 6, (void *) &(var))
#define conf_update_bool(path, key, var) \
	conf_update_var(path, key, 7, (void *) &(var))

extern int string_trim(char **dst, char *str);

#endif
