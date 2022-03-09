//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/rest_api.h"
#include "include/broker.h"
#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "libs/base64.h"
#include "libs/cJSON.h"

#include <file.h>
#include <nng/nng.h>
#include <nng/supplemental/http/http.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static http_msg error_response(
    http_msg *msg, uint16_t status, enum result_code code, uint64_t sequence);

static http_msg get_endpoints(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_broker(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_subscriptions(
    cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_clients(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg post_ctrl(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg post_config(cJSON *data, http_msg *msg, uint64_t sequence);
static http_msg get_config(cJSON *data, http_msg *msg, uint64_t sequence);

static int getStringValue(cJSON *obj, const char *key, char **value);
static int getLongValue(cJSON *obj, const char *key, long *value);
static int getBoolValue(cJSON *obj, const char *key, bool *value);
static void update_main_conf(cJSON *json, conf *config);
static void update_bridge_conf(cJSON *json, conf *config);

typedef struct {
	int request;
	http_msg (*handler)(cJSON *, http_msg *, uint64_t);
} request_handler;

request_handler request_handlers[] = {
	// clang-format off
	{ REQ_BROKERS, get_broker },
	{ REQ_SUBSCRIPTIONS, get_subscriptions }, 
	{ REQ_CLIENTS, get_clients },
	{ REQ_CTRL, post_ctrl },
	{ REQ_GET_CONFIG, get_config },
	{ REQ_SET_CONFIG, post_config }
	// clang-format on
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

	size_t   token_len = strlen(msg->token);
	uint8_t *token     = nng_alloc(token_len + 1);
	memcpy(token, msg->token, token_len);
	token[token_len] = '\0';

	// Authorize username:password
	conf_http_server *server = get_http_server_conf();

	size_t auth_len =
	    strlen(server->username) + strlen(server->password) + 2;
	char *auth = nng_alloc(auth_len);
	snprintf(auth, auth_len, "%s:%s", server->username, server->password);

	uint8_t *decode      = nng_alloc(auth_len);
	decode[auth_len - 1] = '\0';

	base64_decode((const char *) token, token_len, decode);

	if (strncmp(auth, (const char *) decode, auth_len) != 0) {
		result = WRONG_USERNAME_OR_PASSWORD;
	}

	nng_free(auth, auth_len);
	nng_free(decode, msg->token_len);
	nng_free(token, token_len);

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

	char *data = nng_alloc(sizeof(char) * (msg->data_len + 1));
	memcpy(data, msg->data, msg->data_len);
	data[msg->data_len] = '\0';

	cJSON *object = cJSON_Parse(data);
	nng_free(data, msg->data_len + 1);

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
	http_msg res     = { 0 };
	res.status       = NNG_HTTP_STATUS_OK;
	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	res_obj          = cJSON_CreateObject();
	data_info        = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
	cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	cJSON_AddItemToObject(res_obj, "data", data_info);

	size_t   client_size = dbhash_get_pipe_cnt();
	uint64_t msg_in      = nanomq_get_message_in();
	uint64_t msg_out     = nanomq_get_message_out();
	uint64_t msg_drop    = nanomq_get_message_drop();
	cJSON_AddNumberToObject(data_info, "client_size", client_size);
	cJSON_AddNumberToObject(data_info, "message_in", msg_in);
	cJSON_AddNumberToObject(data_info, "message_out", msg_out);
	cJSON_AddNumberToObject(data_info, "message_drop", msg_drop);
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
		cJSON_AddStringToObject(
		    data_info_elem, "client_id", (char *) cid);
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
		cJSON_AddStringToObject(
		    data_info_elem, "client_id", (char *) cid);
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

static int
getStringValue(cJSON *obj, const char *key, char **value)
{
	cJSON *item = cJSON_GetObjectItem(obj, key);
	if (cJSON_IsString(item)) {
		*value = cJSON_GetStringValue(item);
		debug_msg("%s: %s", key, *value);
		return 0;
	}
	return -1;
}

static int
getLongValue(cJSON *obj, const char *key, long *value)
{
	cJSON *item = cJSON_GetObjectItem(obj, key);
	if (cJSON_IsNumber(item)) {
		*value = cJSON_GetNumberValue(item);
		debug_msg("%s: %ld", key, *value);
		return 0;
	}
	return -1;
}

static int
getBoolValue(cJSON *obj, const char *key, bool *value)
{
	cJSON *item = cJSON_GetObjectItem(obj, key);
	if (cJSON_IsBool(item)) {
		*value = cJSON_IsTrue(item);
		debug_msg("%s: %s", key, *value == true ? "true" : "false");
		return 0;
	}
	return -1;
}

static http_msg
get_config(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	conf * config   = get_global_conf();
	cJSON *conf_obj = cJSON_CreateObject();

	cJSON_AddStringToObject(conf_obj, "url", config->url);
	cJSON_AddNumberToObject(
	    conf_obj, "num_taskq_thread", config->num_taskq_thread);
	cJSON_AddNumberToObject(
	    conf_obj, "max_taskq_thread", config->max_taskq_thread);
	cJSON_AddNumberToObject(conf_obj, "parallel", config->parallel);
	cJSON_AddNumberToObject(
	    conf_obj, "property_size", config->property_size);
	cJSON_AddNumberToObject(conf_obj, "msq_len", config->msq_len);
	cJSON_AddBoolToObject(
	    conf_obj, "allow_anonymous", config->allow_anonymous);
	cJSON_AddBoolToObject(conf_obj, "daemon", config->daemon);

	cJSON *tls_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(tls_obj, "enable", config->tls.enable);
	cJSON_AddStringToObject(tls_obj, "url", config->tls.url);
	if (config->tls.key_password) {
		cJSON_AddStringToObject(
		    tls_obj, "key_password", config->tls.key_password);
	} else {
		cJSON_AddNullToObject(tls_obj, "key_password");
	}
	if (config->tls.key) {
		cJSON_AddStringToObject(tls_obj, "key", config->tls.key);
	} else {
		cJSON_AddNullToObject(tls_obj, "key");
	}
	if (config->tls.cert) {
		cJSON_AddStringToObject(tls_obj, "cert", config->tls.cert);
	} else {
		cJSON_AddNullToObject(tls_obj, "cert");
	}
	if (config->tls.ca) {
		cJSON_AddStringToObject(tls_obj, "cacert", config->tls.ca);
	} else {
		cJSON_AddNullToObject(tls_obj, "cacert");
	}
	cJSON_AddBoolToObject(tls_obj, "verify_peer", config->tls.verify_peer);
	cJSON_AddBoolToObject(
	    tls_obj, "fail_if_no_peer_cert", config->tls.set_fail);

	cJSON *ws_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(ws_obj, "enable", config->websocket.enable);
	cJSON_AddStringToObject(ws_obj, "url", config->websocket.url);
	cJSON_AddStringToObject(ws_obj, "tls_url", config->websocket.tls_url);

	cJSON *http_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(http_obj, "enable", config->http_server.enable);
	cJSON_AddNumberToObject(http_obj, "port", config->http_server.port);
	cJSON_AddStringToObject(
	    http_obj, "username", config->http_server.username);
	cJSON_AddStringToObject(
	    http_obj, "password", config->http_server.password);

	cJSON *bridge_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(
	    bridge_obj, "bridge_mode", config->bridge.bridge_mode);
	if (config->bridge.bridge_mode) {
		cJSON_AddStringToObject(
		    bridge_obj, "address", config->bridge.address);
		cJSON_AddNumberToObject(
		    bridge_obj, "proto_ver", config->bridge.proto_ver);
		cJSON_AddStringToObject(
		    bridge_obj, "clientid", config->bridge.clientid);
		cJSON_AddBoolToObject(
		    bridge_obj, "clean_start", config->bridge.clean_start);
		cJSON_AddStringToObject(
		    bridge_obj, "username", config->bridge.username);
		cJSON_AddStringToObject(
		    bridge_obj, "password", config->bridge.password);
		cJSON_AddNumberToObject(
		    bridge_obj, "keepalive", config->bridge.keepalive);
		cJSON_AddNumberToObject(
		    bridge_obj, "parallel", config->bridge.parallel);

		cJSON *pub_topics = cJSON_CreateArray();
		for (size_t i = 0; i < config->bridge.forwards_count; i++) {
			cJSON *topic =
			    cJSON_CreateString(config->bridge.forwards[i]);
			cJSON_AddItemToArray(pub_topics, topic);
		}
		cJSON_AddItemToObject(bridge_obj, "forwards", pub_topics);

		cJSON *sub_infos = cJSON_CreateArray();
		for (size_t j = 0; j < config->bridge.sub_count; j++) {
			cJSON *   sub_obj = cJSON_CreateObject();
			subscribe sub     = config->bridge.sub_list[j];
			cJSON_AddStringToObject(sub_obj, "topic", sub.topic);
			cJSON_AddNumberToObject(sub_obj, "qos", sub.qos);
			cJSON_AddItemToArray(sub_infos, sub_obj);
		}

		cJSON_AddItemToObject(bridge_obj, "subscription", sub_infos);
	}

	cJSON_AddItemToObject(conf_obj, "tls", tls_obj);
	cJSON_AddItemToObject(conf_obj, "websocket", ws_obj);
	cJSON_AddItemToObject(conf_obj, "http_server", http_obj);
	cJSON_AddItemToObject(conf_obj, "bridge", bridge_obj);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
	cJSON_AddNumberToObject(res_obj, "rep", msg->request);
	cJSON_AddItemToObject(res_obj, "data", conf_obj);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static void
update_main_conf(cJSON *json, conf *config)
{
	char *   url = NULL;
	bool     daemon;
	int      num_taskq_thread;
	int      max_taskq_thread;
	uint64_t parallel;
	int      property_size;
	int      msq_len;
	int      qos_duration;
	bool     allow_anonymous;

	if (getStringValue(json, "url", &url) == 0) {
		conf_update(config->conf_file, "url", url);
	}
	if (getBoolValue(json, "daemon", &daemon) == 0) {
		conf_update_bool(config->conf_file, "daemon", daemon);
	}
	if (getLongValue(json, "num_taskq_thread", &num_taskq_thread) == 0) {
		conf_update_long(
		    config->conf_file, "num_taskq_thread", num_taskq_thread);
	}
	if (getLongValue(json, "max_taskq_thread", &max_taskq_thread) == 0) {
		conf_update_long(
		    config->conf_file, "max_taskq_thread", max_taskq_thread);
	}
	if (getLongValue(json, "parallel", &parallel) == 0) {
		conf_update_long(config->conf_file, "parallel", parallel);
	}
	if (getLongValue(json, "property_size", &property_size) == 0) {
		conf_update_long(
		    config->conf_file, "property_size", property_size);
	}
	if (getLongValue(json, "msq_len", &msq_len) == 0) {
		conf_update_long(config->conf_file, "msq_len", msq_len);
	}
	if (getLongValue(json, "qos_duration", &qos_duration) == 0) {
		conf_update_long(
		    config->conf_file, "qos_duration", qos_duration);
	}
	if (getBoolValue(json, "allow_anonymous", &allow_anonymous) == 0) {
		conf_update_bool(
		    config->conf_file, "allow_anonymous", allow_anonymous);
	}

	cJSON *tls = cJSON_GetObjectItem(json, "tls");
	if (cJSON_IsObject(tls)) {
		bool  tls_enable;
		char *tls_url;
		char *tls_keypass;
		char *tls_key;
		char *tls_cert;
		char *tls_cacert;
		bool  tls_verify_peer;
		bool  tls_fail_if_no_peer_cert;

		if (getBoolValue(tls, "enable", &tls_enable) == 0) {
			conf_update_bool(
			    config->conf_file, "tls.enable", tls_enable);
		}
		if (getStringValue(tls, "url", &tls_url) == 0) {
			conf_update(config->conf_file, "tls.url", tls_url);
		}
		if (getStringValue(tls, "keypass", &tls_keypass) == 0) {
			conf_update(
			    config->conf_file, "tls.keypass", tls_keypass);
		}
		if (getStringValue(tls, "key", &tls_key) == 0) {
			file_write_string(config->tls.keyfile, tls_key);
		}
		if (getStringValue(tls, "cert", &tls_cert) == 0) {
			file_write_string(config->tls.certfile, tls_cert);
		}
		if (getStringValue(tls, "cacert", &tls_cacert) == 0) {
			file_write_string(config->tls.cafile, tls_cacert);
		}
		if (getBoolValue(tls, "verify_peer", &tls_verify_peer) == 0) {
			conf_update_bool(config->conf_file, "tls.verify_peer",
			    tls_verify_peer);
		}
		if (getBoolValue(tls, "fail_if_no_peer_cert",
		        &tls_fail_if_no_peer_cert) == 0) {
			conf_update_bool(config->conf_file,
			    "tls.fail_if_no_peer_cert",
			    tls_fail_if_no_peer_cert);
		}
	}

	cJSON *websocket = cJSON_GetObjectItem(json, "websocket");
	if (cJSON_IsObject(websocket)) {
		bool  ws_enable;
		char *ws_url;
		char *ws_tls_url;

		if (getBoolValue(websocket, "enable", &ws_enable) == 0) {
			conf_update_bool(
			    config->conf_file, "websocket.enable", ws_enable);
		}
		if (getStringValue(websocket, "url", &ws_url) == 0) {
			conf_update(
			    config->conf_file, "websocket.url", ws_url);
		}
		if (getStringValue(websocket, "tls_url", &ws_tls_url) == 0) {
			conf_update(config->conf_file, "websocket.tls_url",
			    ws_tls_url);
		}
	}

	cJSON *http_server = cJSON_GetObjectItem(json, "http_server");
	if (cJSON_IsObject(http_server)) {
		bool     http_enable;
		uint16_t http_port;
		char *   http_username;
		char *   http_password;
		if (getBoolValue(http_server, "enable", &http_enable) == 0) {
			conf_update_bool(config->conf_file,
			    "http_server.enable", http_enable);
		}
		if (getLongValue(http_server, "port", &http_port) == 0) {
			conf_update_long(
			    config->conf_file, "http_server.port", http_port);
		}
		if (getStringValue(http_server, "username", &http_username) ==
		    0) {
			conf_update(config->conf_file, "http_server.username",
			    http_username);
		}
		if (getStringValue(http_server, "password", &http_password) ==
		    0) {
			conf_update(config->conf_file, "http_server.password",
			    http_password);
		}
	}
}

static void
update_bridge_conf(cJSON *json, conf *config)
{
	conf_bridge bridge_ct = { 0 };
	if (getBoolValue(json, "bridge_mode", &bridge_ct.bridge_mode) == 0) {
		conf_update_bool(config->bridge_file,
		    "bridge.mqtt.bridge_mode", bridge_ct.bridge_mode);
	}
	if (getStringValue(json, "address", &bridge_ct.address) == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.address",
		    bridge_ct.address);
	}
	if (getLongValue(json, "proto_ver", &bridge_ct.proto_ver) == 0) {
		conf_update_bool(config->bridge_file, "bridge.mqtt.proto_ver",
		    bridge_ct.proto_ver);
	}
	if (getStringValue(json, "clientid", &bridge_ct.clientid) == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.clientid",
		    bridge_ct.clientid);
	}
	if (getLongValue(json, "keepalive", &bridge_ct.keepalive) == 0) {
		conf_update_bool(config->bridge_file, "bridge.mqtt.keepalive",
		    bridge_ct.keepalive);
	}
	if (getBoolValue(json, "clean_start", &bridge_ct.clean_start) == 0) {
		conf_update_bool(config->bridge_file,
		    "bridge.mqtt.clean_start", bridge_ct.clean_start);
	}
	if (getStringValue(json, "username", &bridge_ct.username) == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.username",
		    bridge_ct.username);
	}
	if (getStringValue(json, "password", &bridge_ct.password) == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.password",
		    bridge_ct.password);
	}
	if (getLongValue(json, "parallel", &bridge_ct.parallel) == 0) {
		conf_update_bool(config->bridge_file, "bridge.mqtt.parallel",
		    bridge_ct.parallel);
	}
	cJSON *pub_topics = cJSON_GetObjectItem(json, "forwards");

	if (cJSON_IsArray(pub_topics)) {
		int    topic_count = cJSON_GetArraySize(pub_topics);
		size_t length      = 0;
		for (size_t i = 0; i < topic_count; i++) {
			cJSON *item = cJSON_GetArrayItem(pub_topics, i);
			char * str  = cJSON_GetStringValue(item);
			length += strlen(str) + 1;
		}
		char *topic_str = nng_zalloc(length);
		for (size_t j = 0; j < topic_count; j++) {
			cJSON *item = cJSON_GetArrayItem(pub_topics, j);
			char * str  = cJSON_GetStringValue(item);
			strcat(topic_str, str);
			if (j < topic_count - 1) {
				strcat(topic_str, ",");
			}
		}
		conf_update(
		    config->bridge_file, "bridge.mqtt.forwards", topic_str);
		nng_free(topic_str, length);
	}

	cJSON *sub_infos = cJSON_GetObjectItem(json, "subscription");
	if (cJSON_IsArray(sub_infos)) {
		int  sub_count        = cJSON_GetArraySize(sub_infos);
		char sub_keyname[100] = { 0 };

		for (int i = 0; i < sub_count; i++) {
			cJSON *item = cJSON_GetArrayItem(sub_infos, i);

			char *sub_topic;
			int   sub_qos;
			if (getStringValue(item, "topic", &sub_topic) == 0) {
				memset(sub_keyname, 0, 100);
				sprintf(sub_keyname,
				    "bridge.mqtt.subscription."
				    "%d."
				    "topic",
				    i + 1);
				conf_update(config->bridge_file, sub_keyname,
				    sub_topic);
			}
			if (getLongValue(item, "qos", &sub_qos) == 0) {
				memset(sub_keyname, 0, 100);
				sprintf(sub_keyname,
				    "bridge.mqtt.subscription."
				    "%d."
				    "qos",
				    i + 1);
				conf_update_long(
				    config->bridge_file, sub_keyname, sub_qos);
			}
		}
	}
}

static http_msg
post_config(cJSON *data, http_msg *msg, uint64_t sequence)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *conf_data = cJSON_GetObjectItem(data, "data");
	conf * config    = get_global_conf();

	if (cJSON_IsObject(conf_data)) {
		update_main_conf(conf_data, config);

		cJSON *bridge = cJSON_GetObjectItem(conf_data, "bridge");
		if (cJSON_IsObject(bridge)) {
			update_bridge_conf(bridge, config);
		}

		cJSON *res_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
		cJSON_AddNumberToObject(res_obj, "seq", (uint64_t) sequence);
		cJSON_AddNumberToObject(res_obj, "rep", msg->request);
		char *dest = cJSON_PrintUnformatted(res_obj);

		put_http_msg(&res, msg->content_type, NULL, NULL, NULL, dest,
		    strlen(dest));

		cJSON_free(dest);
		cJSON_Delete(res_obj);

		return res;
	}
}