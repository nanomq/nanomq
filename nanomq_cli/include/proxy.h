#ifndef __NANOMQ_CLI_PROXY_H__
#define __NANOMQ_CLI_PROXY_H__

#include "nng/supplemental/nanolib/conf.h"

typedef struct {
	int    argc;
	char **argv;
} cmd_args;

typedef struct {
	void *            conf;
	const char *      conf_path;
	const char *      proxy_name;
	conf_http_server *http_server;
	cmd_args          args;
} proxy_info;

#endif
