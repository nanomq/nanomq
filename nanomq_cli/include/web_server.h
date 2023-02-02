#ifndef __NANOMQ_CLI_WEB_SERVER_H__
#define __NANOMQ_CLI_WEB_SERVER_H__

#include <ctype.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_DEFAULT_USER "admin"
#define HTTP_DEFAULT_PASSWORD "public"
#define HTTP_DEFAULT_PORT 8082

extern int  start_rest_server(conf_http_server *conf);
extern void stop_rest_server(void);

#endif // __NANOMQ_CLI_WEB_SERVER_H__