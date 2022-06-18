//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/rest_api.h"
#include "base64.h"
#include "cJSON.h"
#include "include/broker.h"
#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "include/version.h"

#include "file.h"
#include "nng/nng.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/util/platform.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef SUPP_JWT
#include "l8w8jwt/decode.h"
#include "l8w8jwt/encode.h"
#endif

typedef struct {
	char *key;
	char *value;
} kv;

typedef struct {
	char *node;
	bool  end;
} tree;

struct uri_content {
	size_t sub_count;
	tree **sub_tree;
	size_t params_count;
	kv **  params;
};

typedef struct uri_content uri_content;

typedef struct {
	const char *path;
	const char *name;
	const char *method;
	const char *descr;
} endpoints;

static endpoints api_ep[] = {
	{
	    .path   = "/brokers/",
	    .name   = "list_brokers",
	    .method = "GET",
	    .descr  = "A list of brokers in the cluster",
	},
	{
	    .path   = "/nodes/",
	    .name   = "list_nodes",
	    .method = "GET",
	    .descr  = "A list of nodes in the cluster",
	},
	{
	    .path   = "/clients/",
	    .name   = "list_clients",
	    .method = "GET",
	    .descr  = "A list of clients on current node",
	},
	{
	    .path   = "/clients/:clientid",
	    .name   = "lookup_client",
	    .method = "GET",
	    .descr  = "Lookup a client in the cluster",
	},
	{
	    .path   = "/clients/username/:username",
	    .name   = "lookup_client_via_username",
	    .method = "GET",
	    .descr  = "Lookup a client via username in the cluster",
	},
	{
	    .path   = "/subscriptions/",
	    .name   = "list_subscriptions",
	    .method = "GET",
	    .descr  = "A list of subscriptions in the cluster",
	},
	{
	    .path   = "/subscriptions/:clientid",
	    .name   = "lookup_client_subscriptions",
	    .method = "GET",
	    .descr  = "A list of subscriptions of a client",
	},
	{
	    .path   = "/topic-tree/",
	    .name   = "list_topic-tree",
	    .method = "GET",
	    .descr  = "A list of topic-tree in the cluster",
	},
	{
	    .path   = "/configuration/",
	    .name   = "get_broker_configuration",
	    .method = "GET",
	    .descr  = "show broker configuration",
	},
	{
	    .path   = "/configuration/",
	    .name   = "set_broker_configuration",
	    .method = "POST",
	    .descr  = "set broker configuration",
	},
	{
	    .path   = "/ctrl/:action",
	    .name   = "ctrl_broker",
	    .method = "POST",
	    .descr  = "Control broker stop or restart",
	},
};

static tree **      uri_parse_tree(const char *path, size_t *count);
static void         uri_tree_free(uri_content *ct);
static kv **        uri_param_parse(const char *path, size_t *count);
static void         uri_param_free(uri_content *ct);
static uri_content *uri_parse(const char *uri);
static void         uri_free(uri_content *ct);

static http_msg error_response(
    http_msg *msg, uint16_t status, enum result_code code);

static http_msg get_endpoints(http_msg *msg);
static http_msg get_brokers(http_msg *msg);
static http_msg get_nodes(http_msg *msg);
static http_msg get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username);
static http_msg get_subscriptions(
    http_msg *msg, kv **params, size_t param_num, const char *client_id);
static http_msg get_tree(http_msg *msg);
static http_msg post_ctrl(http_msg *msg, const char *type);
static http_msg get_config(http_msg *msg);
static http_msg post_config(http_msg *msg);

static void update_main_conf(cJSON *json, conf *config);
static void update_bridge_conf(cJSON *json, conf *config);

#define getNumberValue(obj, item, key, value, rv)           \
	{                                                   \
		item = cJSON_GetObjectItem(obj, key);       \
		if (cJSON_IsNumber(item)) {                 \
			value = cJSON_GetNumberValue(item); \
			rv    = (0);                        \
		} else {                                    \
			rv = (-1);                          \
		}                                           \
	}

#define getBoolValue(obj, item, key, value, rv)       \
	{                                             \
		item = cJSON_GetObjectItem(obj, key); \
		if (cJSON_IsBool(item)) {             \
			value = cJSON_IsTrue(item);   \
			rv    = (0);                  \
		} else {                              \
			rv = (-1);                    \
		}                                     \
	}

#define getStringValue(obj, item, key, value, rv)           \
	{                                                   \
		item = cJSON_GetObjectItem(obj, key);       \
		if (cJSON_IsString(item)) {                 \
			value = cJSON_GetStringValue(item); \
			rv    = (0);                        \
		} else {                                    \
			rv = (-1);                          \
		}                                           \
	}

static void
get_time_str(char *str, size_t str_len)
{
	if (str == NULL) {
		return;
	}
	const time_t now_seconds = time(NULL);
	struct tm    now;
	struct tm *  tmp_time = localtime_r(&now_seconds, &now);
	strftime(str, str_len, "%Y-%m-%d %H:%M:%S", tmp_time);
}

static tree **
uri_parse_tree(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = strstr(path, REST_URI_ROOT);

	size_t num  = 0;
	tree **root = NULL;
	int    len  = 0;

	if (str) {
		str += strlen(REST_URI_ROOT);
		while (NULL != (ret = strchr(str, '/'))) {
			num++;
			root      = realloc(root, sizeof(tree *) * num);
			len       = ret - str + 1;
			tree *sub = nng_zalloc(sizeof(tree));
			sub->node = nng_zalloc(len);
			strncpy(sub->node, str, len - 1);
			sub->end      = false;
			root[num - 1] = sub;
			str           = ret + 1;
		}
		if (num > 0) {
			if (strlen(str) > 0) {
				num++;
				root = realloc(root, sizeof(char *) * num);
				tree *sub     = nng_zalloc(sizeof(tree));
				sub->node     = nng_strdup(str);
				sub->end      = true;
				root[num - 1] = sub;
			} else {
				tree *sub = root[num - 1];
				sub->end  = true;
			}
		}
	}

	*count = num;
	return root;
}

static void
uri_tree_free(uri_content *ct)
{
	if (ct->sub_count > 0) {
		tree **node = ct->sub_tree;
		for (size_t i = 0; i < ct->sub_count; i++) {
			tree *sub = node[i];
			nng_strfree(sub->node);
			nng_free(sub, sizeof(tree));
		}
		nng_free(node, ct->sub_count * sizeof(tree *));
		ct->sub_count = 0;
	}
}

static kv **
uri_param_parse(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = (char *) path;

	size_t num    = 0;
	char **kv_str = NULL;
	int    len    = 0;

	while (NULL != (ret = strchr(str, '&'))) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		len             = ret - str + 1;
		kv_str[num - 1] = nng_zalloc(len);
		memcpy(kv_str[num - 1], str, len - 1);
		str = ret + 1;
	}
	if (num > 0) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		kv_str[num - 1] = nng_strdup(str);
	} else {
		return NULL;
	}

	kv **  params      = calloc(num, sizeof(kv *));
	size_t param_count = 0;

	for (size_t i = 0; i < num; i++) {
		char *key   = nng_zalloc(strlen(kv_str[i]));
		char *value = nng_zalloc(strlen(kv_str[i]));
		if (2 == sscanf(kv_str[i], "%[^=]=%s", key, value)) {
			params[i]        = nng_zalloc(sizeof(kv));
			params[i]->key   = key;
			params[i]->value = value;
			param_count++;
		} else {
			if (key) {
				free(key);
			}
			if (value) {
				free(value);
			}
		}
		free(kv_str[i]);
		kv_str[i] = NULL;
	}

	*count = param_count;
	return params;
}

static void
uri_param_free(uri_content *ct)
{
	if (ct->params_count > 0) {
		kv **params = ct->params;
		for (size_t i = 0; i < ct->params_count; i++) {
			nng_strfree(params[i]->key);
			nng_strfree(params[i]->value);
			nng_free(params[i], sizeof(kv));
		}
		nng_free(params, ct->params_count * sizeof(kv *));
		ct->params_count = 0;
	}
}

static uri_content *
uri_parse(const char *uri)
{
	uri_content *uri_ct  = nng_zalloc(sizeof(uri_content));
	uri_ct->params_count = 0;
	uri_ct->params       = NULL;
	char *path           = NULL;
	char *param          = NULL;
	int   len            = 0;

	if (strcmp(uri, REST_URI_ROOT) == 0 ||
	    strcmp(uri, REST_URI_ROOT "/") == 0) {
		return uri_ct;
	}

	char *p = strchr(uri, '?');
	if (p) {
		// Have parameters
		param = p + 1;
		if (strlen(param) >= 3) {
			uri_ct->params =
			    uri_param_parse(param, &uri_ct->params_count);
		}
		len  = p - uri + 1;
		path = nng_zalloc(len);
		memcpy(path, uri, len - 1);
	} else {
		path = nng_strdup(uri);
	}

	uri_ct->sub_tree = uri_parse_tree(path, &uri_ct->sub_count);
	nng_strfree(path);
	return uri_ct;
}

static void
uri_free(uri_content *ct)
{
	if (ct) {
		uri_tree_free(ct);
		uri_param_free(ct);
		nng_free(ct, sizeof(uri_content));
		ct = NULL;
	}
}

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

#ifdef SUPP_JWT

static enum result_code
jwt_authorize(http_msg *msg)
{
	enum result_code result = SUCCEED;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Bearer %s", msg->token) != 1) {
		return EMPTY_USERNAME_OR_PASSWORD;
	}

	conf_http_server *server = get_http_server_conf();

	struct l8w8jwt_decoding_params params;
	l8w8jwt_decoding_params_init(&params);

	params.alg        = L8W8JWT_ALG_RS256;
	params.jwt        = msg->token;
	params.jwt_length = strlen(msg->token);

	if (server->jwt.iss) {
		params.validate_iss        = server->jwt.iss;
		params.validate_iss_length = strlen(server->jwt.iss);
	}

	params.verification_key        = (uint8_t *) server->jwt.public_key;
	params.verification_key_length = server->jwt.public_key_len;

	params.validate_exp          = 1;
	params.exp_tolerance_seconds = 200;

	enum l8w8jwt_validation_result validation_result = 0;

	struct l8w8jwt_claim *claim       = NULL;
	size_t                claim_count = 0;

	int rv =
	    l8w8jwt_decode(&params, &validation_result, &claim, &claim_count);

	if (rv == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID) {
		struct l8w8jwt_claim *body_claim = l8w8jwt_get_claim(
		    claim, claim_count, "bodyEncode", strlen("bodyEncode"));
		if (body_claim) {
			if (body_claim->type == 1) {
				msg->encrypt_data = true;
			} else {
				msg->encrypt_data = false;
			}
		}
	} else {
		debug_msg("decode jwt token failed: return %d, result: %d", rv,
		    validation_result);
		if (validation_result == L8W8JWT_EXP_FAILURE) {
			result = TOKEN_EXPIRED;
		} else {
			result = WRONG_USERNAME_OR_PASSWORD;
		}
	}

	if (claim_count > 0) {
		l8w8jwt_free_claims(claim, claim_count);
	}

	return result;
}
#else

static enum result_code
jwt_authorize(http_msg *msg)
{
	return REQ_PARAM_ERROR;
}
#endif

static enum result_code
basic_authorize(http_msg *msg)
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
process_request(http_msg *msg, conf_http_server *config)
{
	http_msg         ret    = { 0 };
	uint16_t         status = NNG_HTTP_STATUS_OK;
	enum result_code code   = SUCCEED;
	uri_content *    uri_ct = NULL;
	switch (config->auth_type) {
	case BASIC:
		if ((code = basic_authorize(msg)) != SUCCEED) {
			status = NNG_HTTP_STATUS_UNAUTHORIZED;
			goto exit;
		}
		break;

	case JWT:
		if ((code = jwt_authorize(msg)) != SUCCEED) {
			status = NNG_HTTP_STATUS_UNAUTHORIZED;
			goto exit;
		}

	default:
		break;
	}

	uri_ct = uri_parse(msg->uri);
	if (strcasecmp(msg->method, "GET") == 0) {
		if (uri_ct->sub_count == 0) {
			ret = get_endpoints(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "brokers") == 0) {
			ret = get_brokers(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "nodes") == 0) {
			ret = get_nodes(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node,
			    NULL);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "username") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL,
			    uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "subscriptions") == 0) {
			ret = get_subscriptions(
			    msg, uri_ct->params, uri_ct->params_count, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "subscriptions") == 0) {
			ret = get_subscriptions(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "topic-tree") == 0) {
			ret = get_tree(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = get_config(msg);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (strcasecmp(msg->method, "POST") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "ctrl") == 0) {
			ret = post_ctrl(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = post_config(msg);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else {
		status = NNG_HTTP_STATUS_METHOD_NOT_ALLOWED;
		code   = UNKNOWN_MISTAKE;
		goto exit;
	}

	uri_free(uri_ct);
	return ret;

exit:
	uri_free(uri_ct);
	ret = error_response(msg, status, code);
	return ret;
}

static http_msg
error_response(http_msg *msg, uint16_t status, enum result_code code)
{
	http_msg ret = { 0 };

	ret.status = status;

	cJSON *res_obj;
	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &ret, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);

	return ret;
}

static http_msg
get_endpoints(http_msg *msg)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	cJSON *array = cJSON_CreateArray();

	size_t ep_count = sizeof(api_ep) / sizeof(api_ep[0]);

	for (size_t i = 0; i < ep_count; i++) {
		cJSON *item = cJSON_CreateObject();
		cJSON_AddStringToObject(item, "path", api_ep[i].path);
		cJSON_AddStringToObject(item, "name", api_ep[i].name);
		cJSON_AddStringToObject(item, "method", api_ep[i].method);
		cJSON_AddStringToObject(item, "descr", api_ep[i].descr);
		cJSON_AddItemToArray(array, item);
	}
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);

	return res;
}

static void
get_uptime(char *str, size_t str_len)
{
	nng_time uptime = nng_clock() - get_boot_time();
	nng_time hours  = uptime / 1000 / 3600;
	nng_time mins   = uptime / 1000 / 60 % 60;
	nng_time secs   = uptime / 1000 % 60;

	snprintf(str, str_len, "%ld Hours, %ld minutes, %ld seconds", hours,
	    mins, secs);
}

static void
get_version(char *str, size_t str_len)
{
	snprintf(str, str_len, "%d.%d.%d-%s", FW_EV_VER_MAJOR, FW_EV_VER_MINOR,
	    FW_EV_VER_PATCH, FW_EV_VER_ID_SHORT);
}

static http_msg
get_brokers(http_msg *msg)
{
	http_msg res     = { .status = NNG_HTTP_STATUS_OK };
	cJSON *  res_obj = cJSON_CreateObject();

	char time_str[100] = { 0 };
	get_time_str(time_str, 100);

	char runtime[100] = { 0 };
	get_uptime(runtime, 100);

	char version[100] = { 0 };
	get_version(version, 100);

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	cJSON *array = cJSON_CreateArray();
	cJSON *item  = cJSON_CreateObject();
	cJSON_AddStringToObject(item, "datetime", time_str);
	cJSON_AddStringToObject(item, "node_status", "Running");
	cJSON_AddStringToObject(item, "sysdescr", "NanoMQ Broker");
	cJSON_AddStringToObject(item, "uptime", runtime);
	cJSON_AddStringToObject(item, "version", version);
	cJSON_AddItemToArray(array, item);
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);

	return res;
}

static http_msg
get_nodes(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	char runtime[100] = { 0 };
	get_uptime(runtime, 100);

	char version[100] = { 0 };
	get_version(version, 100);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON *array = cJSON_CreateArray();
	cJSON *item  = cJSON_CreateObject();

	cJSON_AddNumberToObject(item, "connections", dbhash_get_pipe_cnt());
	cJSON_AddStringToObject(item, "node_status", "Running");
	cJSON_AddStringToObject(item, "uptime", runtime);
	cJSON_AddStringToObject(item, "version", version);

	cJSON_AddItemToArray(array, item);
	cJSON_AddItemToObject(res_obj, "data", array);

	char *json = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	cJSON_free(json);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *data_info;
	data_info = cJSON_CreateArray();

	dbtree *          db   = get_broker_db();
	dbhash_ptpair_t **pt   = dbhash_get_ptpair_all();
	size_t            size = cvector_size(pt);
	for (size_t i = 0; i < size; i++) {
		dbtree_ctxt *db_ctxt = (dbtree_ctxt *) dbtree_find_client(
		    db, pt[i]->topic, pt[i]->pipe);
		if (db_ctxt == NULL) {
			continue;
		}
		client_ctx *   ctxt = db_ctxt->ctx;
		const uint8_t *cid  = conn_param_get_clientid(ctxt->cparam);
		if (client_id != NULL) {
			if (strcmp(client_id, cid) != 0) {
				goto skip;
			}
		}
		const uint8_t *user_name =
		    conn_param_get_username(ctxt->cparam);
		if (username != NULL) {
			if (strcmp(username, user_name) != 0) {
				goto skip;
			}
		}
		uint16_t keep_alive = conn_param_get_keepalive(ctxt->cparam);
		const uint8_t proto_ver =
		    conn_param_get_protover(ctxt->cparam);
		const char *proto_name = conn_param_get_pro_name(ctxt->cparam);
		const bool  clean_start =
		    conn_param_get_clean_start(ctxt->cparam);

		cJSON *data_info_elem;
		data_info_elem = cJSON_CreateObject();
		cJSON_AddStringToObject(
		    data_info_elem, "client_id", (char *) cid);
		cJSON_AddStringToObject(data_info_elem, "username",
		    user_name == NULL ? "" : (char *) user_name);
		cJSON_AddNumberToObject(
		    data_info_elem, "keepalive", keep_alive);
		cJSON_AddStringToObject(
		    data_info_elem, "conn_state", "connected");
		cJSON_AddBoolToObject(
		    data_info_elem, "clean_start", clean_start);
		cJSON_AddStringToObject(
		    data_info_elem, "proto_name", proto_name);
		cJSON_AddNumberToObject(
		    data_info_elem, "proto_ver", proto_ver);
#ifdef STATISTICS
		cJSON_AddNumberToObject(data_info_elem, "recv_msg",
		    ctxt->recv_cnt != NULL ? nng_atomic_get64(ctxt->recv_cnt)
		                           : 0);
#endif
		cJSON_AddItemToArray(data_info, data_info_elem);

		topic_node *tn = ctxt->sub_pkt->node;

	skip:
		dbhash_ptpair_free(pt[i]);
		if (0 == dbtree_ctxt_free(db_ctxt)) {
			client_ctx *ctx = dbtree_ctxt_delete(db_ctxt);
			if (ctx) {
				del_sub_ctx(ctx, pt[i]->topic);
			}
		}

	}
	cvector_free(pt);

	cJSON *res_obj;

	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	// cJSON *meta = cJSON_CreateObject();

	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
	cJSON_AddItemToObject(res_obj, "data", data_info);
	char *dest = cJSON_PrintUnformatted(res_obj);
	cJSON_Delete(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);

	return res;
}

static http_msg
get_subscriptions(
    http_msg *msg, kv **params, size_t param_num, const char *client_id)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	data_info        = cJSON_CreateArray();
	res_obj          = cJSON_CreateObject();

	dbtree *          db   = get_broker_db();
	dbhash_ptpair_t **pt   = dbhash_get_ptpair_all();
	size_t            size = cvector_size(pt);
	for (size_t i = 0; i < size; i++) {
		const char * cid     = NULL;
		dbtree_ctxt *db_ctxt = (dbtree_ctxt *) dbtree_find_client(
		    db, pt[i]->topic, pt[i]->pipe);
		if (db_ctxt == NULL) {
			continue;
		}
		client_ctx *ctxt = db_ctxt->ctx;
		if (ctxt->cparam) {
			cid = (const char *) conn_param_get_clientid(
			    ctxt->cparam);
			if (client_id) {
				if (strcmp(client_id, cid) != 0) {
					goto skip;
				}
			}
		}

		topic_node *tn = ctxt->sub_pkt->node;
		while (tn) {
			cJSON *subscribe = cJSON_CreateObject();
			if (cid) {
				cJSON_AddStringToObject(
				    subscribe, "clientid", cid);
			} else {
				cJSON_AddStringToObject(
				    subscribe, "clientid", "");
			}
			cJSON_AddStringToObject(
			    subscribe, "topic", tn->it->topic_filter.body);
			cJSON_AddNumberToObject(subscribe, "qos", tn->it->qos);
			cJSON_AddItemToArray(data_info, subscribe);
			tn = tn->next;
		}
	skip:
		if (0 == dbtree_ctxt_free(db_ctxt)) {
			client_ctx *ctx = dbtree_ctxt_delete(db_ctxt);
			if (ctx) {
				del_sub_ctx(ctx, pt[i]->topic);
			}
		}
		dbhash_ptpair_free(pt[i]);
	}
	cvector_free(pt);

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	// cJSON *meta = cJSON_CreateObject();
	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
	cJSON_AddItemToObject(res_obj, "data", data_info);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static void *
get_client_info_cb(void *ctxt)
{
	if (NULL == ctxt) {
		return NULL;
	}

	dbtree_ctxt *dctxt = (dbtree_ctxt *) ctxt;
	client_ctx * cctxt = dctxt->ctx;
	if (NULL == cctxt) {
		return NULL;
	}

	conn_param *cp = cctxt->cparam;
	return (void *) conn_param_get_clientid(cp);
}

static http_msg
get_tree(http_msg *msg)
{
	http_msg res     = { 0 };
	res.status       = NNG_HTTP_STATUS_OK;
	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	res_obj          = cJSON_CreateObject();
	data_info        = cJSON_CreateArray();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", data_info);

	dbtree *       db = get_broker_db();
	dbtree_info ***vn = (dbtree_info ***) dbtree_get_tree(
	    db, get_client_info_cb);

	for (int i = 0; i < cvector_size(vn); i++) {
		cJSON *data_info_elem = cJSON_CreateArray();
		cJSON_AddItemToArray(data_info, data_info_elem);
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			cJSON *elem = cJSON_CreateObject();
			cJSON_AddItemToArray(data_info_elem, elem);
			cJSON_AddStringToObject(
			    elem, "topic", vn[i][j]->topic);
			zfree(vn[i][j]->topic);
			cJSON_AddNumberToObject(
			    elem, "cld_cnt", vn[i][j]->cld_cnt);
			cJSON *clients = cJSON_CreateStringArray(
			    (const char *const *) vn[i][j]->clients,
			    cvector_size(vn[i][j]->clients));
			cvector_free(vn[i][j]->clients);
			zfree(vn[i][j]);
			cJSON_AddItemToObject(elem, "clientid", clients);
		}
		cvector_free(vn[i]);
	}
	cvector_free(vn);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static char *
mk_str(int n, char **str_arr, char *seperator)
{
	size_t len = 0;
	char * str = NULL;
	for (size_t i = 0; i < n; i++) {
		len += strlen(str_arr[i]) + strlen(seperator) + 2;
	}
	str = calloc(1, len);
	for (size_t i = 0; i < n; i++) {
		strcat(str, str_arr[i]);
		strcat(str, seperator);
	}
	return str;
}

#ifndef NANO_PLATFORM_WINDOWS
static void
ctrl_cb(void *arg)
{
	char * action = arg;
	int    argc   = get_cache_argc();
	char **argv   = get_cache_argv();
	char * cmd    = NULL;

	nng_msleep(2000);

	if (strcasecmp(action, "stop") == 0) {
		argv[2] = "stop";
		cmd     = mk_str(3, argv, " ");
	} else if (strcasecmp(action, "restart") == 0) {
		argv[2] = "restart";
		cmd     = mk_str(argc, argv, " ");
	}
	nng_strfree(action);
	if (cmd) {
		system(cmd);
		free(cmd);
	}
}
#endif

static http_msg
post_ctrl(http_msg *msg, const char *type)
{
	http_msg    res = { 0 };
	nng_thread *thread;
	int         code = SUCCEED;

	if (strcasecmp(type, "stop") == 0 ||
	    strcasecmp(type, "restart") == 0) {
#ifndef NANO_PLATFORM_WINDOWS
		char *arg = nng_strdup(type);
		nng_thread_create(&thread, ctrl_cb, arg);
		res.status = NNG_HTTP_STATUS_OK;
#else
		res.status = NNG_HTTP_STATUS_NOT_ACCEPTABLE;
		code       = RPC_ERROR;
#endif
	} else {
		res.status = NNG_HTTP_STATUS_NOT_FOUND;
		code       = RPC_ERROR;
	}
	cJSON *res_obj;

	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	char *dest = cJSON_PrintUnformatted(res_obj);
	cJSON_Delete(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);

	return res;
}

static http_msg
get_config(http_msg *msg)
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
	cJSON_AddStringToObject(http_obj, "auth_type",
	    config->http_server.auth_type == JWT ? "jwt" : "basic");

	cJSON *bridge_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(
	    bridge_obj, "bridge_mode", config->bridge.bridge_mode);

	cJSON_AddStringToObject(bridge_obj, "address", config->bridge.address);
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
		cJSON *topic = cJSON_CreateString(config->bridge.forwards[i]);
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

	cJSON_AddItemToObject(conf_obj, "tls", tls_obj);
	cJSON_AddItemToObject(conf_obj, "websocket", ws_obj);
	cJSON_AddItemToObject(conf_obj, "http_server", http_obj);
	cJSON_AddItemToObject(conf_obj, "bridge", bridge_obj);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", conf_obj);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
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

	cJSON *item;
	int    rv;
	getStringValue(json, item, "url", url, rv);
	if (rv == 0) {
		conf_update(config->conf_file, "url", url);
	}
	getBoolValue(json, item, "daemon", daemon, rv);
	if (rv == 0) {
		conf_update_bool(config->conf_file, "daemon", daemon);
	}
	getNumberValue(json, item, "num_taskq_thread", num_taskq_thread, rv);
	if (rv == 0) {
		conf_update_int(
		    config->conf_file, "num_taskq_thread", num_taskq_thread);
	}
	getNumberValue(json, item, "max_taskq_thread", max_taskq_thread, rv);
	if (rv == 0) {
		conf_update_int(
		    config->conf_file, "max_taskq_thread", max_taskq_thread);
	}
	getNumberValue(json, item, "parallel", parallel, rv);
	if (rv == 0) {
		conf_update_u64(config->conf_file, "parallel", parallel);
	}
	getNumberValue(json, item, "property_size", property_size, rv);
	if (rv == 0) {
		conf_update_int(
		    config->conf_file, "property_size", property_size);
	}
	getNumberValue(json, item, "msq_len", msq_len, rv);
	if (rv == 0) {
		conf_update_int(config->conf_file, "msq_len", msq_len);
	}
	getNumberValue(json, item, "qos_duration", qos_duration, rv);
	if (rv == 0) {
		conf_update_int(
		    config->conf_file, "qos_duration", qos_duration);
	}
	getBoolValue(json, item, "allow_anonymous", allow_anonymous, rv);
	if (rv == 0) {
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

		char   dir[1024] = { 0 };
		size_t path_len  = 0;

		getBoolValue(tls, item, "enable", tls_enable, rv);
		if (rv == 0) {
			conf_update_bool(
			    config->conf_file, "tls.enable", tls_enable);
		}
		getStringValue(tls, item, "url", tls_url, rv);
		if (rv == 0) {
			conf_update(config->conf_file, "tls.url", tls_url);
		}
		getStringValue(tls, item, "keypass", tls_keypass, rv);
		if (rv == 0) {
			conf_update(
			    config->conf_file, "tls.keypass", tls_keypass);
		}
		getStringValue(tls, item, "key", tls_key, rv);
		if (rv == 0) {
			if (config->tls.keyfile == NULL) {
				memset(dir, 0, 1024);
				if (getcwd(dir, sizeof(dir)) != NULL) {
					path_len = strlen(dir) +
					    strlen("/key.pem") + 1;
					config->tls.keyfile =
					    nng_zalloc(path_len);
					strcat(config->tls.keyfile, dir);
					strcat(
					    config->tls.keyfile, "/key.pem");
					conf_update(config->conf_file,
					    "tls.keyfile",
					    config->tls.keyfile);
				}
			}
			file_write_string(config->tls.keyfile, tls_key);
		}
		getStringValue(tls, item, "cert", tls_cert, rv);
		if (rv == 0) {
			if (config->tls.certfile == NULL) {
				memset(dir, 0, 1024);
				if (getcwd(dir, sizeof(dir)) != NULL) {
					path_len = strlen(dir) +
					    strlen("/cert.pem") + 1;
					config->tls.certfile =
					    nng_zalloc(path_len);
					strcat(config->tls.certfile, dir);
					strcat(
					    config->tls.certfile, "/cert.pem");
					conf_update(config->conf_file,
					    "tls.certfile",
					    config->tls.certfile);
				}
			}
			file_write_string(config->tls.certfile, tls_cert);
		}
		getStringValue(tls, item, "cacert", tls_cacert, rv);
		if (rv == 0) {
			if (config->tls.cafile == NULL) {
				memset(dir, 0, 1024);
				if (getcwd(dir, sizeof(dir)) != NULL) {
					path_len = strlen(dir) +
					    strlen("/cacert.pem") + 1;
					config->tls.cafile =
					    nng_zalloc(path_len);
					strcat(config->tls.cafile, dir);
					strcat(
					    config->tls.cafile, "/cacert.pem");
					conf_update(config->conf_file,
					    "tls.cacertfile",
					    config->tls.cafile);
				}
			}
			file_write_string(config->tls.cafile, tls_cacert);
		}
		getBoolValue(tls, item, "verify_peer", tls_verify_peer, rv);
		if (rv == 0) {
			conf_update_bool(config->conf_file, "tls.verify_peer",
			    tls_verify_peer);
		}
		getBoolValue(tls, item, "fail_if_no_peer_cert",
		    tls_fail_if_no_peer_cert, rv);
		if (rv == 0) {
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

		getBoolValue(websocket, item, "enable", ws_enable, rv);
		if (rv == 0) {
			conf_update_bool(
			    config->conf_file, "websocket.enable", ws_enable);
		}
		getStringValue(websocket, item, "url", ws_url, rv);
		if (rv == 0) {
			conf_update(
			    config->conf_file, "websocket.url", ws_url);
		}
		getStringValue(websocket, item, "tls_url", ws_tls_url, rv);
		if (rv == 0) {
			conf_update(config->conf_file, "websocket.tls_url",
			    ws_tls_url);
		}
	}

	cJSON *http_server = cJSON_GetObjectItem(json, "http_server");
	if (cJSON_IsObject(http_server)) {
		bool     http_enable;
		uint16_t http_port;
		char *   http_username = NULL;
		char *   http_password = NULL;
		char *   auth_type     = NULL;
		getBoolValue(http_server, item, "enable", http_enable, rv);
		if (rv == 0) {
			conf_update_bool(config->conf_file,
			    "http_server.enable", http_enable);
		}
		getNumberValue(http_server, item, "port", http_port, rv);
		if (rv == 0) {
			conf_update_u16(
			    config->conf_file, "http_server.port", http_port);
		}
		getStringValue(
		    http_server, item, "username", http_username, rv);
		if (rv == 0) {
			conf_update(config->conf_file, "http_server.username",
			    http_username);
		}
		getStringValue(
		    http_server, item, "password", http_password, rv);
		if (rv == 0) {
			conf_update(config->conf_file, "http_server.password",
			    http_password);
		}
		getStringValue(http_server, item, "auth_type", auth_type, rv);
		if (rv == 0) {
			if (strcmp("basic", auth_type) == 0 ||
			    strcmp("jwt", auth_type) == 0) {
				conf_update(config->conf_file,
				    "http_server.auth_type", auth_type);
			}
		}
	}
}

static void
update_bridge_conf(cJSON *json, conf *config)
{
	int         rv;
	cJSON *     item;
	conf_bridge bridge_ct = { 0 };
	getBoolValue(json, item, "bridge_mode", bridge_ct.bridge_mode, rv);
	if (rv == 0) {
		conf_update_bool(config->bridge_file,
		    "bridge.mqtt.bridge_mode", bridge_ct.bridge_mode);
	}
	getStringValue(json, item, "address", bridge_ct.address, rv);
	if (rv == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.address",
		    bridge_ct.address);
	}
	getNumberValue(json, item, "proto_ver", bridge_ct.proto_ver, rv);
	if (rv == 0) {
		conf_update_u8(config->bridge_file, "bridge.mqtt.proto_ver",
		    bridge_ct.proto_ver);
	}
	getStringValue(json, item, "clientid", bridge_ct.clientid, rv);
	if (rv == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.clientid",
		    bridge_ct.clientid);
	}
	getNumberValue(json, item, "keepalive", bridge_ct.keepalive, rv);
	if (rv == 0) {
		conf_update_u16(config->bridge_file, "bridge.mqtt.keepalive",
		    bridge_ct.keepalive);
	}
	getBoolValue(json, item, "clean_start", bridge_ct.clean_start, rv);
	if (rv == 0) {
		conf_update_bool(config->bridge_file,
		    "bridge.mqtt.clean_start", bridge_ct.clean_start);
	}
	getStringValue(json, item, "username", bridge_ct.username, rv);
	if (rv == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.username",
		    bridge_ct.username);
	}
	getStringValue(json, item, "password", bridge_ct.password, rv);
	if (rv == 0) {
		conf_update(config->bridge_file, "bridge.mqtt.password",
		    bridge_ct.password);
	}
	getNumberValue(json, item, "parallel", bridge_ct.parallel, rv);
	if (rv == 0) {
		conf_update_u64(config->bridge_file, "bridge.mqtt.parallel",
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
			cJSON * sub_item = cJSON_GetArrayItem(sub_infos, i);
			char *  sub_topic;
			uint8_t sub_qos;
			getStringValue(sub_item, item, "topic", sub_topic, rv);
			if (rv == 0) {
				memset(sub_keyname, 0, 100);
				sprintf(sub_keyname,
				    "bridge.mqtt.subscription."
				    "%d."
				    "topic",
				    i + 1);
				conf_update(config->bridge_file, sub_keyname,
				    sub_topic);
			}
			getNumberValue(sub_item, item, "qos", sub_qos, rv);
			if (rv == 0) {
				memset(sub_keyname, 0, 100);
				sprintf(sub_keyname,
				    "bridge.mqtt.subscription."
				    "%d."
				    "qos",
				    i + 1);
				conf_update_u8(
				    config->bridge_file, sub_keyname, sub_qos);
			}
		}
	}
}

static http_msg
post_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *conf_data = cJSON_GetObjectItem(req, "data");
	conf * config    = get_global_conf();

	if (cJSON_IsObject(conf_data)) {
		update_main_conf(conf_data, config);

		cJSON *bridge = cJSON_GetObjectItem(conf_data, "bridge");
		if (cJSON_IsObject(bridge)) {
			update_bridge_conf(bridge, config);
		}
	}
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}
