#ifndef __NANOMQ_CLI_REST_API_H__
#define __NANOMQ_CLI_REST_API_H__

#include <ctype.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nng/supplemental/nanolib/conf.h"
#include "proxy.h"

#define REST_URI_ROOT "/api/v4/proxy"
#define REST_HOST "http://0.0.0.0:%u"
#define REST_URL REST_HOST REST_URI_ROOT

enum result_code {
	SUCCEED                        = 0,
	RPC_ERROR                      = 101,
	UNKNOWN_MISTAKE                = 102,
	WRONG_USERNAME_OR_PASSWORD     = 103,
	EMPTY_USERNAME_OR_PASSWORD     = 104,
	USER_DOES_NOT_EXIST            = 105,
	ADMIN_CANNOT_BE_DELETED        = 106,
	MISSING_KEY_REQUEST_PARAMES    = 107,
	REQ_PARAM_ERROR                = 108,
	REQ_PARAMS_JSON_FORMAT_ILLEGAL = 109,
	PLUGIN_IS_ENABLED              = 110,
	PLUGIN_IS_CLOSED               = 111,
	CLIENT_IS_OFFLINE              = 112,
	USER_ALREADY_EXISTS            = 113,
	OLD_PASSWORD_IS_WRONG          = 114,
	ILLEGAL_SUBJECT                = 115,
	TOKEN_EXPIRED                  = 116,
};

typedef struct http_msg {
	uint16_t status;
	int      request;
	size_t   content_type_len;
	char *   content_type;
	size_t   method_len;
	char *   method;
	size_t   uri_len;
	char *   uri;
	size_t   token_len;
	char *   token;
	size_t   data_len;
	char *   data;
	bool     encrypt_data;
} http_msg;

extern void     put_http_msg(http_msg *msg, const char *content_type,
        const char *method, const char *uri, const char *token, const char *data,
        size_t data_sz);
extern void     destory_http_msg(http_msg *msg);
extern http_msg process_request_cli(http_msg *msg, proxy_info *proxy);

#define GET_METHOD "GET"
#define POST_METHOD "POST"
#define PUT_METHOD "PUT"
#define DELETE_METHOD "DELETE"


#endif
