//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "rest_api.h"
#include "libs/base64.h"
// #include "utils/log.h"
#include "include/broker.h"
#include "include/nanomq.h"
#include "libs/cJSON.h"

#include <nng/supplemental/http/http.h>

static http_msg get_endpoints(http_msg *msg);
static http_msg get_broker(http_msg *msg);
static http_msg get_subscriptions(http_msg *msg);
static http_msg get_clients(http_msg *msg);
static http_msg post_ctrl(http_msg *msg);

typedef struct {
	const char *method;
	const char *request;
	http_msg (*handler)(http_msg *);
} request_handler;

request_handler request_handlers[] = {

	{ GET_METHOD, REQ_BROKERS, get_broker },
	{ GET_METHOD, REQ_SUBSCRIPTIONS, get_subscriptions },
	{ GET_METHOD, REQ_CLIENTS, get_clients },
	{ POST_METHOD, REQ_CTRL, post_ctrl },

};

void
put_http_msg(http_msg *msg, const char *method, const char *uri,
    const char *token, const char *data, size_t data_sz)
{
	if (method != NULL) {
		msg->method_len = strlen(method);
		msg->method     = nng_strdup(method);
	}

	if (uri != NULL) {
		msg->uri_len = strlen(uri);
		msg->uri     = nng_strdup(uri);
	}

	if (token != NULL) {
		msg->token_len = strlen(token);
		msg->token     = nng_strdup(token);
	}

	if (data != NULL) {
		msg->data_len = data_sz;
		msg->data     = nng_alloc(msg->data_len);
		memcpy(msg->data, data, msg->data_len);
	}
}

void
destory_http_msg(http_msg *msg)
{
	if (msg->method_len > 0) {
		nng_strfree(msg->method);
		msg->method_len = 0;
	}

	if (msg->token_len > 0) {
		nng_strfree(msg->token);
		msg->token_len = 0;
	}
	if (msg->data_len > 0) {
		nng_free(msg->data, msg->data_len);
		msg->data_len = 0;
	}
	if (msg->uri_len > 0) {
		nng_strfree(msg->uri);
		msg->uri_len = 0;
	}
}

static bool
authorize(http_msg *msg)
{

	bool result = false;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Basic %s", msg->token) != 1) {
		return false;
	}

	size_t token_len = strlen(msg->token);
	debug_msg("token: %.*s", token_len, msg->token);

	uint8_t *decode = nng_alloc(token_len);

	base64_decode(msg->token, token_len, decode);

	debug_msg("decode token: %s", decode);

	// TODO Authorize username:password

	nng_free(decode, msg->token_len);

	// return result;
	return true;
}

http_msg
process_request(http_msg *msg)
{

	http_msg res = { 0 };

	if (!authorize(msg)) {
		res.status = NNG_HTTP_STATUS_UNAUTHORIZED;
		goto exit;
	}

	char  request[255]  = "";
	char  response[255] = "";
	char *param         = strrchr(msg->uri, '?');
	debug_msg("param: %s", param);
	if (param == NULL) {
		return get_endpoints(msg);
	}
	int rv = sscanf(param + 1, "req=%s", request);
	debug_msg("%d, request: %s", rv, request);

	if (rv < 1) {
		res.status = NNG_HTTP_STATUS_BAD_REQUEST;
		goto exit;
	}

	for (size_t i = 0;
	     i < sizeof(request_handlers) / sizeof(request_handlers[0]); i++) {
		if (strcmp(msg->method, request_handlers[i].method) == 0 &&
		    strcmp(request_handlers[i].request, request) == 0) {
			debug_msg(
			    "found handler: %s", request_handlers[i].request);
			return request_handlers[i].handler(msg);
		}
	}

	res.status = NNG_HTTP_STATUS_METHOD_NOT_ALLOWED;

exit:
	memset(response, 0, 255);
	sprintf(response, "ERROR: %d", res.status);
	put_http_msg(&res, NULL, NULL, NULL, response, strlen(response));

	return res;
}

static http_msg
get_endpoints(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	return res;
}

static http_msg
get_broker(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	return res;
}

static http_msg
get_subscriptions(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	return res;
}

static http_msg
get_clients(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	db_tree *db = get_broker_db();

	print_db_tree(db);

	return res;
}

static http_msg
post_ctrl(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	cJSON *object = cJSON_Parse(msg->data);

	cJSON *action = cJSON_GetObjectItem(object, "action");

	char *value = cJSON_GetStringValue(action);

	debug_msg("get action: %s", value);

	if (strcasecmp(value, "stop") == 0) {
		broker_stop(0, NULL);
	} else if (strcasecmp(value, "restart") == 0) {
		// TODO not support yet
	}

	cJSON_Delete(object);

	return res;
}
