#ifndef __NANOMQ_CLI_PROXY_H__
#define __NANOMQ_CLI_PROXY_H__

#include "nng/supplemental/nanolib/conf.h"

typedef struct {
	void *            conf;
	const char *      conf_path;
	const char *      proxy_name;
	conf_http_server *http_server;
} proxy_info;

#endif
