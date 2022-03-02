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
#include "include/sub_handler.h"
#include "libs/cJSON.h"

#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <stdint.h>
#include <string.h>

static http_msg error_response(
    http_msg *msg, uint16_t status, enum result_code code, uint64_t sequence);

static http_msg get_endpoints(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_broker(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_subscriptions(
    cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_clients(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg post_ctrl(cJSON *data, http_msg *msg, uint64_t sequence);

typedef struct {
	int request;
	http_msg (*handler)(cJSON *, http_msg *, uint64_t);
} request_handler;

request_handler request_handlers[] = {

	{ REQ_BROKERS, get_broker },
	{ REQ_SUBSCRIPTIONS, get_subscriptions },
	{ REQ_CLIENTS, get_clients },
	{ REQ_CTRL, post_ctrl },

};

void
put_http_msg(http_msg *msg, const char *content_type, const char *method,
    const char *uri, const char *token, const char *data, size_t data_sz)
{
	if (content_type != NULL) {
		msg->content_type_len = strlen(content_type);
		msg->content_type     = nng_strdup(content_type);
	}

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
	if (msg->content_type_len > 0) {
		nng_strfree(msg->content_type);
		msg->content_type_len = 0;
	}

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

static enum result_code
authorize(http_msg *msg)
{

	enum result_code result = SUCCEED;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Basic %s", msg->token) != 1) {
		return EMPTY_USERNAME_OR_PASSWORD;
	}

	size_t token_len = strlen(msg->token);

	uint8_t *decode = nng_alloc(token_len);

	base64_decode(msg->token, token_len, decode);

	// Authorize username:password
	conf_http_server *server = get_http_server_conf();

	size_t auth_len =
	    strlen(server->username) + strlen(server->password) + 2;
	char *auth = nng_alloc(auth_len);
	snprintf(auth, auth_len, "%s:%s", server->username, server->password);

	if (strncmp(auth, decode, auth_len) != 0) {
		result = WRONG_USERNAME_OR_PASSWORD;
	}

	nng_free(auth, auth_len);
	nng_free(decode, msg->token_len);

	return result;
}

http_msg
process_request(http_msg *msg)
{
	http_msg         ret           = { 0 };
	uint16_t         status        = NNG_HTTP_STATUS_OK;
	enum result_code code          = SUCCEED;
	char             response[255] = "";
	uint64_t         sequence      = 0UL;

	cJSON *req;
	if ((code = authorize(msg)) != SUCCEED) {
		status = NNG_HTTP_STATUS_UNAUTHORIZED;

		goto exit;
	}

	cJSON *object = cJSON_Parse(msg->data);

	if (!cJSON_IsObject(object)) {
		status = NNG_HTTP_STATUS_BAD_REQUEST;
		code   = REQ_PARAMS_JSON_FORMAT_ILLEGAL;
		goto exit;
	}

	req          = cJSON_GetObjectItem(object, "req");
	msg->request = (int) cJSON_GetNumberValue(req);

	cJSON *seq = cJSON_GetObjectItem(object, "seq");
	sequence   = (uint64_t) cJSON_GetNumberValue(seq);

	bool found = false;

	for (size_t i = 0;
	     i < sizeof(request_handlers) / sizeof(request_handlers[0]); i++) {
		if (request_handlers[i].request == msg->request) {
			debug_msg(
			    "found handler: %d", request_handlers[i].request);
			ret =
			    request_handlers[i].handler(object, msg, sequence);
			found = true;
			break;
		}
	}
	cJSON_Delete(object);

	if (found) {
		return ret;
	} else {
		status = NNG_HTTP_STATUS_NOT_FOUND;
		code   = UNKNOWN_MISTAKE;
	}

exit:
	ret = error_response(msg, status, code, sequence);
	return ret;
}

static http_msg
error_response(
    http_msg *msg, uint16_t status, enum result_code code, uint64_t sequence)
{
	http_msg ret = { 0 };

	ret.status = status;

	cJSON *res_obj;
	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);

	uint64_t seq = sequence ? sequence : 0UL;

	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);

	if (msg->request > 0) {
		cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	}
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &ret, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);

	return ret;
}

static http_msg
get_endpoints(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);
	// TODO not impelement yet
	return res;
}

static http_msg
get_broker(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	res_obj          = cJSON_CreateObject();
	data_info        = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
	cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	cJSON_AddItemToObject(res_obj, "data", data_info);

	uint64_t msg_in = nanomq_get_message_in();
	uint64_t msg_out = nanomq_get_message_out();
	cJSON_AddNumberToObject(data_info, "message_in", msg_in);
	cJSON_AddNumberToObject(data_info, "message_out", msg_out);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
get_subscriptions(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	data_info        = cJSON_CreateArray();
	res_obj          = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
	cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	cJSON_AddItemToObject(res_obj, "data", data_info);

	dbtree *          db   = get_broker_db();
	dbhash_ptpair_t **pt   = dbhash_get_ptpair_all();
	size_t            size = cvector_size(pt);
	for (size_t i = 0; i < size; i++) {
		client_ctx *ctxt = (client_ctx *) dbtree_find_client(
		    db, pt[i]->topic, pt[i]->pipe);

		cJSON *data_info_elem;
		data_info_elem = cJSON_CreateObject();
		cJSON_AddItemToArray(data_info, data_info_elem);
		const uint8_t *cid = conn_param_get_clientid(ctxt->cparam);
		cJSON_AddStringToObject(data_info_elem, "client_id", cid);
		cJSON *topics = cJSON_CreateArray();
		cJSON_AddItemToObject(data_info_elem, "subscriptions", topics);

		topic_node *tn = ctxt->sub_pkt->node;
		while (tn) {
			cJSON *topic_with_opt = cJSON_CreateObject();
			cJSON_AddStringToObject(topic_with_opt, "topic",
			    tn->it->topic_filter.body);
			cJSON_AddNumberToObject(
			    topic_with_opt, "qos", tn->it->qos);
			cJSON_AddItemToArray(topics, topic_with_opt);
			tn = tn->next;
		}

		dbhash_ptpair_free(pt[i]);
	}
	cvector_free(pt);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
get_clients(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *data_info;
	data_info = cJSON_CreateArray();

	dbtree *          db   = get_broker_db();
	dbhash_ptpair_t **pt   = dbhash_get_ptpair_all();
	size_t            size = cvector_size(pt);
	for (size_t i = 0; i < size; i++) {
		client_ctx *ctxt = (client_ctx *) dbtree_find_client(
		    db, pt[i]->topic, pt[i]->pipe);
		const uint8_t *cid = conn_param_get_clientid(ctxt->cparam);
		const uint8_t *user_name =
		    conn_param_get_username(ctxt->cparam);
		uint16_t keep_alive = conn_param_get_keepalive(ctxt->cparam);
		const uint8_t proto_ver =
		    conn_param_get_protover(ctxt->cparam);

#ifdef STATISTICS
		uint32_t recv_cnt = ctxt->recv_cnt;
#endif

		cJSON *data_info_elem;
		data_info_elem = cJSON_CreateObject();
		cJSON_AddStringToObject(data_info_elem, "client_id", cid);
		cJSON_AddStringToObject(data_info_elem, "username",
		    user_name == NULL ? "" : (char *) user_name);
		cJSON_AddNumberToObject(
		    data_info_elem, "keepalive", keep_alive);
		cJSON_AddNumberToObject(data_info_elem, "protocol", proto_ver);
		cJSON_AddNumberToObject(data_info_elem, "connect_status", 1);
#ifdef STATISTICS
		cJSON_AddNumberToObject(
		    data_info_elem, "message_receive", recv_cnt);
#endif
		cJSON_AddItemToArray(data_info, data_info_elem);

		topic_node *tn = ctxt->sub_pkt->node;

		dbhash_ptpair_free(pt[i]);
	}
	cvector_free(pt);

	cJSON *res_obj;

	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
	cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	cJSON_AddItemToObject(res_obj, "data", data_info);
	char *dest = cJSON_PrintUnformatted(res_obj);
	cJSON_Delete(res_obj);

	put_http_msg(
	    &res, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);

	return res;
}

static http_msg
post_ctrl(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;
	res.data     = strdup(__FUNCTION__);
	res.data_len = strlen(__FUNCTION__);

	cJSON *action = cJSON_GetObjectItem(data, "action");

	char *value = cJSON_GetStringValue(action);

	debug_msg("get action: %s", value);

	// TODO not impelement yet
	if (strcasecmp(value, "stop") == 0) {
		broker_stop(0, NULL);
	} else if (strcasecmp(value, "restart") == 0) {
		// TODO not support yet
	}

	return res;
}
