//
// Copyright 2025 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if NANO_PLATFORM_LINUX
#define _GNU_SOURCE
#endif
#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/protocol/mqtt/nmq_mqtt.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/util/idhash.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/file.h"
#include "nng/supplemental/nanolib/parquet.h"
#include "nng/supplemental/nanolib/cmd.h"

#include "include/rest_api.h"
#include "include/bridge.h"
#include "include/conf_api.h"
#include "include/broker.h"
#include "include/nanomq.h"
#include "include/nanomq_rule.h"
#include "include/sub_handler.h"
#include "include/version.h"
#include "include/mqtt_api.h"

#if defined(SUPP_LICENSE_STD) || defined(SUPP_PARQUET)
#include "aes_gcm.h"
#endif

#if defined(SUPP_LICENSE_STD)
#include "include/license_std.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>

#ifdef SUPP_JWT
#include "l8w8jwt/decode.h"
#include "l8w8jwt/encode.h"
#endif

#if NANO_PLATFORM_WINDOWS
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <share.h>
#define nano_localtime(t, pTm) localtime_s(pTm, t)
#define nano_strtok strtok_s
#else
#define nano_localtime(t, pTm) localtime_r(t, pTm)
#define nano_strtok strtok_r
#endif

#if NANO_PLATFORM_LINUX
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif

typedef int (handle_mqtt_msg_cb) (cJSON *, nng_socket *);
#define BROKER_DATA_SIZE 2048
#define BRIDGE_DATA_SIZE 1024

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
	    .path   = "/brokers/connections",
	    .name   = "get_active_connections_number",
	    .method = "GET",
	    .descr  = "Get number of active connections in all brokers",
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
	    .path   = "/retains",
	    .name   = "list all retain messages",
	    .method = "GET",
	    .descr  = "A list of retain messages",
	},
	{
	    .path   = "/rules/",
	    .name   = "list_rules",
	    .method = "GET",
	    .descr  = "Get rule list",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "get_rule_details",
	    .method = "GET",
	    .descr  = "Get the details of a rule",
	},
	{
	    .path   = "/rules/",
	    .name   = "create_rule",
	    .method = "POST",
	    .descr  = "Create a rule and return the rule ID",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "update_rule",
	    .method = "PUT",
	    .descr  = "Update the rule and return the rule ID",
	},
	{
	    .path   = "/rules/:ruleid",
	    .name   = "delete_rule",
	    .method = "DELETE",
	    .descr  = "Delete the rule",
	},
	{
	    .path   = "/mqtt/subscribe",
	    .name   = "mqtt_subscribe",
	    .method = "POST",
	    .descr  = "Subscribe a topic",
	},
	{
		.path = "/bridges/:bridge_name",
		.name = "get_mqtt_bridges",
		.method = "GET",
		.descr = "Get the details of bridge",
	},
	// { TODO not supported
	// 	.path = "/bridges/",
	// 	.name = "post_mqtt_bridge",
	// 	.method = "POST",
	// 	.descr = "Create a bridge client",
	// },
	{
		.path = "/bridges/:bridge_name",
		.name = "put_mqtt_bridge",
		.method = "PUT",
		.descr = "Edit a bridge client",
	},
	{
		.path = "/bridges/switch/:bridge_name",
		.name = "put_mqtt_bridge_switch",
		.method = "POST",
		.descr = "trun on or off a bridge channel",
	},
	{
		.path = "/bridges/:bridge_name",
		.name = "delete_mqtt_bridge",
		.method = "DELETE",
		.descr = "DELETE a bridge client",
	},
	{
	    .path   = "/mqtt/publish",
	    .name   = "mqtt_publish",
	    .method = "POST",
	    .descr  = "Publish a MQTT message",
	},
	{
	    .path   = "/mqtt/unsubscribe",
	    .name   = "mqtt_unsubscribe",
	    .method = "POST",
	    .descr  = "Unsubscribe a topic",
	},
	{
	    .path   = "/mqtt/subscribe_batch",
	    .name   = "mqtt_subscribe_batch",
	    .method = "POST",
	    .descr  = "Batch subscribes topics",
	},
	{
	    .path   = "/mqtt/publish_batch",
	    .name   = "mqtt_publish_batch",
	    .method = "POST",
	    .descr  = "Batch publish MQTT messages",
	},
	{
	    .path   = "/mqtt/unsubscribe_batch",
	    .name   = "mqtt_unsubscribe_batch",
	    .method = "POST",
	    .descr  = "Batch unsubscribes topics",
	},
	{
	    .path   = "/write_file",
	    .name   = "overwrite config file",
	    .method = "POST",
	    .descr  = "wirte content to specific file path",
	},
	{
	    .path   = "/topic-tree/",
	    .name   = "list_topic-tree",
	    .method = "GET",
	    .descr  = "A list of topic-tree in the cluster",
	},
	{
	    .path   = "/reload/",
	    .name   = "get_hot_updatable_configuration",
	    .method = "GET",
	    .descr  = "show the configuration that can be hot updated",
	},
	{
	    .path   = "/reload/",
	    .name   = "set_hot_updatable_configuration",
	    .method = "POST",
	    .descr  = "set the configuration that can be hot updated",
	},
	{
	    .path   = "/configuration/",
	    .name   = "get_broker_configuration",
	    .method = "GET",
	    .descr  = "show all configuration of broker",
	},
	{
	    .path   = "/configuration/basic",
	    .name   = "get_basic_configuration",
	    .method = "GET",
	    .descr  = "set broker basic configuration",
	},
	{
	    .path   = "/configuration/tls",
	    .name   = "get_tls_configuration",
	    .method = "GET",
	    .descr  = "show broker tls configuration",
	},
	{
	    .path   = "/configuration/http_server",
	    .name   = "get_http_server_configuration",
	    .method = "GET",
	    .descr  = "show broker http_server configuration",
	},
	{
	    .path   = "/configuration/websocket",
	    .name   = "get_websocket_configuration",
	    .method = "GET",
	    .descr  = "show broker websocket configuration",
	},
	{
	    .path   = "/configuration/webhook",
	    .name   = "get_webhook_configuration",
	    .method = "GET",
	    .descr  = "show broker webhook configuration",
	},
	{
	    .path   = "/configuration/auth",
	    .name   = "get_auth_configuration",
	    .method = "GET",
	    .descr  = "show broker authorization configuration",
	},
	{
	    .path   = "/configuration/auth_http",
	    .name   = "get_auth_http_configuration",
	    .method = "GET",
	    .descr  = "show broker authorization by http configuration",
	},
	{
	    .path   = "/configuration/sqlite",
	    .name   = "get_sqlite_configuration",
	    .method = "GET",
	    .descr  = "show broker sqlite configuration",
	},
	{
	    .path   = "/configuration/bridge",
	    .name   = "get_bridge_configuration",
	    .method = "GET",
	    .descr  = "show broker bridge configuration",
	},
	{
	    .path   = "/configuration/aws_bridge",
	    .name   = "get_aws_bridge_configuration",
	    .method = "GET",
	    .descr  = "show broker aws_bridge configuration",
	},
	{
	    .path   = "/get_file",
	    .name   = "get file content from path",
	    .method = "GET",
	    .descr  = "To get config file content",
	},
	{
	    .path   = "/configuration/",
	    .name   = "set_broker_configuration",
	    .method = "POST",
	    .descr  = "set broker configuration",
	},
	{
	    .path   = "/config_update",
	    .name   = "update_configuration_file",
	    .method = "POST",
	    .descr  = "update configuration file",
	},
	{
	    .path   = "/ctrl/:action",
	    .name   = "ctrl_broker",
	    .method = "POST",
	    .descr  = "Control broker stop or restart",
	},
	{
	    .path   = "/metrics",
	    .name   = "metrics",
	    .method = "GET",
	    .descr  = "Returns all statistical metrics",
	},
	{
	    .path   = "/prometheus",
	    .name   = "prometheus",
	    .method = "GET",
	    .descr  = "Returns all prometheus data",
	},
	{
	    .path   = "/can_span",
	    .name   = "can_data_span",
	    .method = "GET",
	    .descr  = "Return can data span",
	},
	{
	    .path   = "/license/update",
	    .name   = "update_license",
	    .method = "POST",
	    .descr  = "Update license",
	},
	{
	    .path   = "/license/info",
	    .name   = "get_license_info",
	    .method = "GET",
	    .descr  = "Return license information",
	},
	{
	    .path   = "/tools/aes_enc",
	    .name   = "post_tools_aes_enc",
	    .method = "POST",
	    .descr  = "Return aes encrypted data",
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
static http_msg get_brokers_connections(http_msg *msg);
static http_msg get_nodes(http_msg *msg, nng_socket *broker_sock);
static http_msg get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_prometheus(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_can_data_span(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_metrics(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_retains(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock);
static http_msg get_license_info(http_msg *msg);
static http_msg get_subscriptions(
    http_msg *msg, kv **params, size_t param_num, const char *client_id);
static http_msg  get_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg  put_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg  delete_rules(
    http_msg *msg, kv **params, size_t param_num, const char *rule_id);
static http_msg post_rules(http_msg *msg);
static http_msg get_tree(http_msg *msg);
static http_msg post_ctrl(http_msg *msg, const char *type);
static http_msg show_reload_config(http_msg *msg);
static http_msg post_reload_config(http_msg *msg);
static http_msg get_config(http_msg *msg, const char *type);
static http_msg update_config(http_msg *msg);
static http_msg post_config(http_msg *msg, const char *type);
static http_msg post_mqtt_msg(
    http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb);
static http_msg post_mqtt_msg_batch(
    http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb);
static http_msg post_tools_aes_enc(http_msg *msg);

static http_msg write_file(http_msg *msg);
static http_msg get_file_content(http_msg *msg, char *path);
static http_msg get_mqtt_bridge(http_msg *msg, const char *name);
static http_msg put_mqtt_bridge(http_msg *msg, const char *name);
static http_msg put_mqtt_bridge_switch(http_msg *msg, const char *name);
static http_msg post_mqtt_bridge_sub(http_msg *msg, const char *name);
static http_msg post_mqtt_bridge_unsub(http_msg *msg, const char *name);
static http_msg post_license_update(http_msg *msg);
static http_msg get_logs_latest(http_msg *msg, kv **params, size_t param_num);
static http_msg get_logs_full(http_msg *msg, kv **params, size_t param_num);
static int properties_parse(property **properties, cJSON *json);
static int handle_publish_msg(cJSON *pub_obj, nng_socket *sock);
static int handle_subscribe_msg(cJSON *sub_obj, nng_socket *sock);
static int handle_unsubscribe_msg(cJSON *sub_obj, nng_socket *sock);

static void
get_time_str(char *str, size_t str_len)
{
	if (str == NULL) {
		return;
	}
	const time_t now_seconds = time(NULL);
	struct tm    now;
	nano_localtime(&now_seconds, &now);
	strftime(str, str_len, "%Y-%m-%d %H:%M:%S", &now);
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
			tree **new_root;
			new_root = realloc(root, sizeof(tree *) * num);
			if (new_root == NULL) {
				if (root != NULL) {
					free(root);
				}
				return NULL;
			}
			root      = new_root;
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
				tree **new_root;
				new_root = realloc(root, sizeof(tree *) * num);
				if (new_root == NULL) {
					if (root != NULL) {
						free(root);
					}
					return NULL;
				}
				root          = new_root;
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
		char **new_kv_str;
		new_kv_str = realloc(kv_str, sizeof(char *) * num);
		if (new_kv_str == NULL) {
			if (kv_str != NULL) {
				free(kv_str);
			}
			return NULL;
		}
		kv_str = new_kv_str;
		len             = ret - str + 1;
		kv_str[num - 1] = nng_zalloc(len);
		memcpy(kv_str[num - 1], str, len - 1);
		str = ret + 1;
	}
	if (num > 0 || strchr(str, '=')) {
		num++;
		char **new_kv_str;
		new_kv_str = realloc(kv_str, sizeof(char *) * num);
		if (new_kv_str == NULL) {
			if (kv_str != NULL) {
				free(kv_str);
			}
			return NULL;
		}
		kv_str          = new_kv_str;
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
	free(kv_str);

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
		msg->uri = NULL;
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

	params.validate_aud        = NULL;
	params.validate_aud_length = 0;

	params.validate_iat          = 0;
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
		log_error("decode jwt token failed: return %d, result: %d", rv,
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

	size_t decode_len    = token_len * 6 / 8 + 1;
	uint8_t *decode      = nng_alloc(decode_len);
	// No more than 3 '=' placeholders in token
	decode[decode_len - 1] = '\0';
	decode[decode_len - 2] = '\0';
	decode[decode_len - 3] = '\0';

	base64_decode((const char *) token, token_len, decode);

	if (strcmp(auth, (const char *) decode) != 0) {
		result = WRONG_USERNAME_OR_PASSWORD;
	}

	nng_free(auth, auth_len);
	nng_free(decode, msg->token_len);
	nng_free(token, token_len);

	return result;
}

static
int HexadecimalToDecimal(char* hex, int len)
{
	int hexLength = len;
	double dec = 0;

	for (int i = 0; i < hexLength; ++i)
	{
		char b = hex[i];

		if (b >= 48 && b <= 57)
			b -= 48;
		else if (b >= 65 && b <= 70)
			b -= 55;

		dec += b * pow(16, ((hexLength - i) - 1));
	}

	return (int)dec;
}

static
char* URLDecoding(char* data, unsigned int count) {
	char* result = nng_zalloc(count);
	int j = 0;

	for (int i = 0; i < count; ++i, ++j)
	{
		if (data[i] == '%')
		{
			char h[] = { data[i + 1], data[i + 2] };
			result[j] = (char)HexadecimalToDecimal(h, 2);
			i += 2;
		}
		else
		{
			result[j] = data[i];
		}
	}

	result[j] = '\0';

	return result;
}

http_msg
process_request(http_msg *msg, conf_http_server *hconfig, nng_socket *sock)
{
	http_msg         ret    = { 0 };
	uint16_t         status = NNG_HTTP_STATUS_OK;
	enum result_code code   = SUCCEED;
	uri_content *    uri_ct = NULL;
	switch (hconfig->auth_type) {
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
	if (msg->uri == NULL)	//Probably due to HTTP resend
		goto exit;
	uri_ct = uri_parse(msg->uri);

	if (nng_strcasecmp(msg->method, "GET") == 0) {
		if (uri_ct->sub_count == 0) {
			ret = get_endpoints(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "brokers") == 0) {
			ret = get_brokers(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "brokers") == 0 &&
			strcmp(uri_ct->sub_tree[2]->node, "connections") == 0) {
			ret = get_brokers_connections(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "nodes") == 0) {
			ret = get_nodes(msg, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "data_span") == 0) {
			ret = get_can_data_span(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "prometheus") == 0) {
			ret = get_prometheus(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "metrics") == 0) {
			ret = get_metrics(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "retains") == 0) {
			ret = get_retains(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "license") == 0 &&
			strcmp(uri_ct->sub_tree[2]->node, "info") == 0) {
			ret = get_license_info(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "logs") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "latest") == 0) {
			ret = get_logs_latest(msg, uri_ct->params, uri_ct->params_count);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "logs") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "full") == 0) {
			ret = get_logs_full(msg, uri_ct->params, uri_ct->params_count);

		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL, NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node,
			    NULL, hconfig->broker_sock);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "clients") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "username") == 0) {
			ret = get_clients(msg, uri_ct->params,
			    uri_ct->params_count, NULL,
			    uri_ct->sub_tree[3]->node, hconfig->broker_sock);
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
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = get_rules(
			    msg, uri_ct->params, uri_ct->params_count, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = get_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "topic-tree") == 0) {
			ret = get_tree(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "reload") == 0) {
			ret = show_reload_config(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = get_config(msg, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = get_config(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = get_mqtt_bridge(msg, NULL);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = get_mqtt_bridge(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "get_file") == 0) {
			size_t count = 0;
			while (count < uri_ct->params_count) {
				if (strcmp(uri_ct->params[count]->key, "default") == 0) {
					if (strcmp(uri_ct->params[count]->value, "true") == 0) {
						ret = get_file_content(msg, NULL);
						break;
					}
				} else if (strncmp(uri_ct->params[count]->key, "path", 4) == 0) {
					size_t path_len = strlen(uri_ct->params[count]->value);
					char *path = URLDecoding(uri_ct->params[count]->value, path_len);
					log_debug("decoded path: %s", path);
					ret = get_file_content(msg, path);
					nng_free(path, path_len);
					break;
				}
				count ++;
			}
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "POST") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "ctrl") == 0) {
			ret = post_ctrl(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "reload") == 0) {
			ret = post_reload_config(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = post_config(msg, NULL);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "config_update") == 0) {
			ret = update_config(msg);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "write_file") == 0) {
			ret = write_file(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration") == 0) {
			ret = post_config(msg, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 2 &&
		    uri_ct->sub_tree[1]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = post_rules(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "publish") == 0) {
			ret = post_mqtt_msg(msg, sock, handle_publish_msg);
		}  else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0 &&
			strcmp(uri_ct->sub_tree[2]->node, "sub") == 0) {
			ret = post_mqtt_bridge_sub(
			    msg, uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsub") == 0) {
			ret = post_mqtt_bridge_unsub(
			    msg, uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "publish_batch") == 0) {
			ret = post_mqtt_msg_batch(msg, sock, handle_publish_msg);
		} else if (uri_ct->sub_count == 4 &&
		    uri_ct->sub_tree[3]->end &&
			strcmp(uri_ct->sub_tree[2]->node, "switch") == 0 &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = put_mqtt_bridge_switch(msg, uri_ct->sub_tree[3]->node);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "license") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "update") == 0) {
			ret = post_license_update(msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "tools") == 0 &&
			strcmp(uri_ct->sub_tree[2]->node, "aes_enc") == 0) {
			ret = post_tools_aes_enc(msg);
		}

		/* else if (uri_ct->sub_count == 3 &&
		     uri_ct->sub_tree[2]->end &&
		     strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		     strcmp(uri_ct->sub_tree[2]->node, "subscribe") == 0) {
		         ret = post_mqtt_msg(msg, sock, handle_subscribe_msg);
		 }
		else if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "subscribe_batch") ==
		        0) {
		        ret = post_mqtt_msg_batch(
		            msg, sock, handle_subscribe_msg);
		}
		else if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsubscribe") == 0) {
		        ret = post_mqtt_msg(msg, sock, handle_unsubscribe_msg);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "mqtt") == 0 &&
		    strcmp(uri_ct->sub_tree[2]->node, "unsubscribe_batch") ==
		        0) {
		        ret = post_mqtt_msg_batch(
		            msg, sock, handle_unsubscribe_msg);
		} */
		else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "PUT") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = put_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
		} else if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "bridges") == 0) {
			ret = put_mqtt_bridge(msg, uri_ct->sub_tree[2]->node);
		} else {
			status = NNG_HTTP_STATUS_NOT_FOUND;
			code   = UNKNOWN_MISTAKE;
			goto exit;
		}
	} else if (nng_strcasecmp(msg->method, "DELETE") == 0) {
		if (uri_ct->sub_count == 3 &&
		    uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "rules") == 0) {
			ret = delete_rules(msg, uri_ct->params,
			    uri_ct->params_count, uri_ct->sub_tree[2]->node);
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

	snprintf(str, str_len, "%lu Hours, %lu minutes, %lu seconds", hours,
	    mins, secs);
}

static void
get_version(char *str, size_t str_len)
{
	snprintf(str, str_len, "%d.%d.%d-%s", NANO_VER_MAJOR, NANO_VER_MINOR,
	    NANO_VER_PATCH, NANO_VER_ID_SHORT);
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
get_brokers_connections(http_msg *msg)
{
	http_msg res    = { .status = NNG_HTTP_STATUS_OK };
	conf   * config = get_global_conf();

	char json[128];
#if defined(SUPP_LICENSE_DK) || defined(SUPP_LICENSE_STD)
	sprintf(json, "{\"connections\":%d}",
		 nng_atomic_get(config->lc));
#else
	sprintf(json, "{\"connections\":%d}", 0);
#endif
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, json, strlen(json));
	return res;
}

static void
get_conn_count_cb(void *key, void *value, void *arg)
{
	uint32_t count = *(uint32_t *) arg;
	count++;
	*(uint32_t *) arg = count;
}

static http_msg
get_nodes(http_msg *msg, nng_socket *broker_sock)
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

	uint32_t conn_count = 0;

	nng_id_map *pipe_id_map;

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) == 0) {
		nng_id_map_foreach2(
		    pipe_id_map, get_conn_count_cb, &conn_count);
	}

	cJSON_AddNumberToObject(item, "connections", conn_count);
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

typedef struct {
	cJSON *array;
	char * client_id;
	char * username;
} client_info;

typedef struct {
	uint32_t connections;
	uint32_t sessions;
	uint32_t topics;
	uint32_t subscribers;
	uint32_t message_received;
	uint32_t message_sent;
	uint32_t message_dropped;
	uint64_t memory;
	float    cpu_percent;
} client_stats;

typedef struct {
	const char *name;
	uint32_t    reconnections;
	uint32_t    message_received;
	uint32_t    message_sent;
	uint32_t    uplink_message_dropped;
	uint32_t    downlink_message_dropped;
	uint64_t    bytes_cached;
	uint64_t    bytes_sent;
	uint64_t    bytes_received;
} bridge_stats;


static void
get_client_cb(void *key, void *value, void *json_obj)
{
	client_info   *info    = json_obj;
	uint32_t       pipe_id = *(uint32_t *) key;
	nng_pipe       pipe    = { .id = pipe_id };
	bool           status  = nng_pipe_status(pipe);
	conn_param    *cp      = nng_pipe_cparam(pipe);
	const uint8_t *cid     = conn_param_get_clientid(cp);
	if (info->client_id != NULL) {
		if (strcmp(info->client_id, (const char *) cid) != 0) {
			conn_param_free(cp);
			return;
		}
	}
	const uint8_t *user_name = conn_param_get_username(cp);
	if (info->username != NULL) {
		if (user_name == NULL ||
		    strcmp(info->username, (const char *) user_name) != 0) {
			conn_param_free(cp);
			return;
		}
	}

	uint16_t      keep_alive  = conn_param_get_keepalive(cp);
	const uint8_t proto_ver   = conn_param_get_protover(cp);
	const char   *proto_name  = (const char *) conn_param_get_pro_name(cp);
	const char   *ipv4        = (const char *) conn_param_get_ip_addr_v4(cp);
	const bool    clean_start = conn_param_get_clean_start(cp);
	const mqtt_string *will_topic = (const mqtt_string *) conn_param_get_will_topic(cp);
	const mqtt_string *will_msg   = (const mqtt_string *) conn_param_get_will_msg(cp);

	cJSON *data_info_elem;
	data_info_elem = cJSON_CreateObject();
	cJSON_AddStringToObject(data_info_elem, "client_id", (char *) cid);
	cJSON_AddStringToObject(data_info_elem, "username",
	    user_name == NULL ? "" : (char *) user_name);
	cJSON_AddNumberToObject(data_info_elem, "keepalive", keep_alive);
	cJSON_AddStringToObject(data_info_elem, "ipv4",
		ipv4 == NULL ? "" : ipv4);
	if (status)
		cJSON_AddStringToObject(data_info_elem, "conn_state", "disconnected");
	else
		cJSON_AddStringToObject(data_info_elem, "conn_state", "connected");
	cJSON_AddBoolToObject(data_info_elem, "clean_start", clean_start);
	cJSON_AddStringToObject(data_info_elem, "proto_name", proto_name);
	cJSON_AddNumberToObject(data_info_elem, "proto_ver", proto_ver);
	if(will_topic != NULL) {
		cJSON_AddStringToObject(data_info_elem, "will_topic", will_topic->body);
	}
	if(will_msg != NULL) {
		cJSON_AddStringToObject(data_info_elem, "will_msg", will_msg->body);
	}

	// #ifdef STATISTICS
	// 		cJSON_AddNumberToObject(data_info_elem, "recv_msg",
	// 		    ctxt->recv_cnt != NULL ?
	// nng_atomic_get64(ctxt->recv_cnt) : 0); #endif
	cJSON_AddItemToArray(info->array, data_info_elem);

	conn_param_free(cp);
}

static void
get_metric_cb(void *key, void *value, void *stats)
{
	client_stats *s = (client_stats *) stats;
	s->sessions++;
	uint32_t       pipe_id = *(uint32_t *) key;
	nng_pipe       pipe    = { .id = pipe_id };
	bool           status  = nng_pipe_status(pipe);

	conn_param    *cp      = nng_pipe_cparam(pipe);
	const uint8_t *cid     = conn_param_get_clientid(cp);
	if (!status) s->connections++;

	conn_param_free(cp);

	// #ifdef STATISTICS
	// 		cJSON_AddNumberToObject(data_info_elem, "recv_msg",
	// 		    ctxt->recv_cnt != NULL ?
	// nng_atomic_get64(ctxt->recv_cnt) : 0); #endif
}

static http_msg
get_clients(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

 	cJSON *data_info;
	cJSON *res_obj;
	data_info = cJSON_CreateArray();

	nng_id_map *pipe_id_map;

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) != 0) {
		goto out;
	}


	client_info info = {
		.array     = data_info,
		.client_id = (char *) client_id,
		.username  = (char *) username,
	};

	nng_id_map_foreach2(pipe_id_map, get_client_cb, &info);

 out:

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


static void
compose_bridge_metrics(char *ret, bridge_stats *s)
{
	const char *name = s->name;
	char fmt[] = "# TYPE bridge_%s_reconnections counter"
	             "\n# HELP bridge_%s_reconnections counter"
	             "\nbridge_%s_reconnections %d"
	             "\n# TYPE bridge_%s_uplink_messages_dropped counter"
	             "\n# HELP bridge_%s_uplink_messages_dropped"
	             "\nbridge_%s_uplink_messages_dropped %d"
	             "\n# TYPE bridge_%s_downlink_messages_dropped counter"
	             "\n# HELP bridge_%s_downlink_messages_dropped"
	             "\nbridge_%s_downlink_messages_dropped %d"
	             "\n# TYPE bridge_%s_messages_received counter"
	             "\n# HELP bridge_%s_messages_received"
	             "\nbridge_%s_messages_received %d"
	             "\n# TYPE bridge_%s_messages_sent counter"
	             "\n# HELP bridge_%s_messages_sent"
	             "\nbridge_%s_messages_sent %d"
	             "\n# TYPE bridge_%s_bytes_sent counter"
	             "\n# HELP bridge_%s_bytes_sent (b)"
	             "\nbridge_%s_bytes_sent %ld"
	             "\n# TYPE bridge_%s_bytes_received counter"
	             "\n# HELP bridge_%s_bytes_received (b)"
	             "\nbridge_%s_bytes_received %d\n";

	snprintf(ret, BRIDGE_DATA_SIZE, fmt,
		name, name, name, s->reconnections,
		name, name, name, s->uplink_message_dropped,
		name, name, name, s->downlink_message_dropped,
		name, name, name, s->message_sent,
		name, name, name, s->message_received,
		name, name, name, s->bytes_sent,
		name, name, name, s->bytes_received
	);
}

static void
compose_metrics(char *ret, client_stats *ms, client_stats *s)
{
	char fmt[] = "# TYPE nanomq_connections_count gauge"
	             "\n# HELP nanomq_connections_count"
	             "\nnanomq_connections_count %d"
	             "\n# TYPE nanomq_connections_max gauge"
	             "\n# HELP nanomq_connections_max"
	             "\nnanomq_connections_max %d"
	             "\n# TYPE nanomq_sessions_count gauge"
	             "\n# HELP nanomq_sessions_count"
	             "\nnanomq_sessions_count %d"
	             "\n# TYPE nanomq_sessions_max gauge"
	             "\n# HELP nanomq_sessions_max"
	             "\nnanomq_sessions_max %d"
	             "\n# TYPE nanomq_topics_count gauge"
	             "\n# HELP nanomq_topics_count"
	             "\nnanomq_topics_count %d"
	             "\n# TYPE nanomq_topics_max gauge"
	             "\n# HELP nanomq_topics_max"
	             "\nnanomq_topics_max %d"
	             "\n# TYPE nanomq_subscribers_count gauge"
	             "\n# HELP nanomq_subscribers_count"
	             "\nnanomq_subscribers_count %d"
	             "\n# TYPE nanomq_subscribers_max gauge"
	             "\n# HELP nanomq_subscribers_max"
	             "\nnanomq_subscribers_max %d"
	             "\n# TYPE nanomq_messages_received counter"
	             "\n# HELP nanomq_messages_received"
	             "\nnanomq_messages_received %d"
	             "\n# TYPE nanomq_messages_sent counter"
	             "\n# HELP nanomq_messages_sent"
	             "\nnanomq_messages_sent %d"
	             "\n# TYPE nanomq_messages_dropped counter"
	             "\n# HELP nanomq_messages_dropped"
	             "\nnanomq_messages_dropped %d"
	             "\n# TYPE nanomq_memory_usage gauge"
	             "\n# HELP nanomq_memory_usage (b)"
	             "\nnanomq_memory_usage %ld"
	             "\n# TYPE nanomq_memory_usage_max gauge"
	             "\n# HELP nanomq_memory_usage_max (b)"
	             "\nnanomq_memory_usage_max %ld"
	             "\n# TYPE nanomq_cpu_usage gauge"
	             "\n# HELP nanomq_cpu_usage (%%)"
	             "\nnanomq_cpu_usage %.2f"
	             "\n# TYPE nanomq_cpu_usage_max gauge"
	             "\n# HELP nanomq_cpu_usage_max (%%)"
	             "\nnanomq_cpu_usage_max %.2f\n";

	snprintf(ret, BROKER_DATA_SIZE, fmt, s->connections, ms->connections,
		s->sessions, ms->sessions, s->topics, ms->topics, s->subscribers,
	    ms->subscribers, s->message_received, s->message_sent, s->message_dropped,
		s->memory, ms->memory, s->cpu_percent, ms->cpu_percent);
}

#define max_stats(s, ms, field) ms->field > s->field ? ms->field : s->field

static void
update_max_stats(client_stats *ms, client_stats *s)
{
	// TODO not strictly the maximum value.
	ms->topics      = max_stats(s, ms, topics);
	ms->sessions    = max_stats(s, ms, sessions);
	ms->connections = max_stats(s, ms, connections);
	ms->subscribers = max_stats(s, ms, subscribers);
	ms->memory      = max_stats(s, ms, memory);
	ms->cpu_percent = max_stats(s, ms, cpu_percent);
}

static void *
get_client_exist_cb(uint32_t pid)
{
	return (void*) (long long) pid;
}

static size_t
get_topics_count()
{
	dbtree        *db = get_broker_db();
	dbtree_info ***vn =
	    (dbtree_info ***) dbtree_get_tree(db, get_client_exist_cb);
	size_t counter = 0;

	for (int i = 0; i < cvector_size(vn); i++) {
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			nng_free(vn[i][j]->topic, strlen(vn[i][j]->topic));
			if (vn[i][j]->clients) {
				counter++;
			}
			cvector_free(vn[i][j]->clients);
			nng_free(vn[i][j], sizeof(dbtree_info));
		}
		cvector_free(vn[i]);
	}
	cvector_free(vn);
	return counter;
}

static long
get_cpu_time()
{
	FILE *fd;
	char  buff[256];

	fd = fopen("/proc/stat", "r");
	if (fd == NULL) {
		log_error("open /proc/stat failed!");
		return -1;
	}

	fgets(buff, sizeof(buff), fd);
	uint32_t user, nice, sys, idle, iowait, irq, sirq, steal;

	int rc = sscanf(buff, "%*s %u %u %u %u %u %u %u %u", &user, &nice, &sys, &idle,
	    &iowait, &irq, &sirq, &steal);

	fclose(fd);

	if (rc != 8) {
		log_error("scanf error!");
		return -1;
	}
	long ret = user + nice + sys + idle + iowait + irq + sirq + steal;
	return ret;
}

#if NANO_PLATFORM_WINDOWS
static ULARGE_INTEGER win_lastCPU, win_lastSysCPU, win_lastUserCPU;
static int win_get_cpu_is_init = 0;
static int win_num_processors = 8;
static HANDLE win_nanomq_handle;

static void win_get_cpu_init() {
    SYSTEM_INFO sysInfo;
    FILETIME ftime, fsys, fuser;

    GetSystemInfo(&sysInfo);
    win_num_processors = sysInfo.dwNumberOfProcessors;
	if (win_num_processors <= 0 || win_num_processors > 256) {
		log_warn("Failed to get processors. Use 8 as default. Cpu usage might be wrong");
		win_num_processors = 8;
	}

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&win_lastCPU, &ftime, sizeof(FILETIME));

    win_nanomq_handle = GetCurrentProcess();
    GetProcessTimes(win_nanomq_handle, &ftime, &ftime, &fsys, &fuser);
    memcpy(&win_lastSysCPU, &fsys, sizeof(FILETIME));
    memcpy(&win_lastUserCPU, &fuser, sizeof(FILETIME));
}
#endif

static long
update_process_info(client_stats *s)
{
#if NANO_PLATFORM_LINUX
	static long last_cpu_time  = 0;
	static long last_proc_time = 0;

	long cpu_time = get_cpu_time();
	if (cpu_time == -1) {
		s->cpu_percent = -1;
		return -1;
	}

	int  pid = getpid();
	char stat_file[256];
	snprintf(stat_file, sizeof(stat_file), "/proc/%d/stat", pid);

	FILE *fp = fopen(stat_file, "r");
	if (fp == NULL) {
		perror("Error opening file");
		return -1;
	}

	long utime, stime, cutime, cstime, rss;
	if (fscanf(fp,
	        "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu "
	        "%lu %ld %ld %*d %*d %*d %*d %*u %*u %ld",
	        &utime, &stime, &cutime, &cstime, &rss) != 5) {
		perror("Error reading file");
		fclose(fp);
		return -1;
	}
	fclose(fp);

	s->memory = rss * getpagesize();

	long   proc_time   = utime + stime + cutime + cstime;
	double cpu_percent = 100.0 *
	    ((double) (proc_time - last_proc_time) /
	        (cpu_time - last_cpu_time == 0 ? -1
	                                       : cpu_time - last_cpu_time));
	s->cpu_percent = cpu_percent <= 0 ? 0 : cpu_percent;
	log_debug("NanoMQ memory usage: %ld\n", s->memory);
	log_debug("NanoMQ cpu usage: %.2f %\n", s->cpu_percent);

	last_proc_time = proc_time;
	last_cpu_time  = cpu_time;

#elif NANO_PLATFORM_WINDOWS
	HANDLE handle = GetCurrentProcess();

	// --- Memory usage ---
	PROCESS_MEMORY_COUNTERS pmc;
	if (GetProcessMemoryInfo(handle, &pmc, sizeof(pmc))) {
		// Working set size is close to RES memory in linux
		s->memory = pmc.WorkingSetSize;
		log_debug("Memory Usage (WorkingSetSize): %zu KB", pmc.WorkingSetSize / 1024);
		log_debug("Peak Working Set Size: %zu KB", pmc.PeakWorkingSetSize / 1024);
		log_debug("Private Bytes: %zu KB", pmc.PagefileUsage / 1024);
	} else {
		log_warn("GetProcessMemoryInfo failed.");
		return -1;
	}

	// --- CPU usage ---
	// refer. https://stackoverflow.com/questions/63166/how-to-determine-cpu-and-memory-consumption-from-inside-a-process
	if (win_get_cpu_is_init == 0) {
		win_get_cpu_is_init = 1;
		win_get_cpu_init();
		// First time, just init. It will return right value at second times.
		return 0;
	}

	FILETIME       ftime, fsys, fuser;
	ULARGE_INTEGER now, sys, user;
	double         percent;

	GetSystemTimeAsFileTime(&ftime);
	memcpy(&now, &ftime, sizeof(FILETIME));

	GetProcessTimes(win_nanomq_handle, &ftime, &ftime, &fsys, &fuser);
	memcpy(&sys, &fsys, sizeof(FILETIME));
	memcpy(&user, &fuser, sizeof(FILETIME));
	percent = (sys.QuadPart - win_lastSysCPU.QuadPart) +
	    (user.QuadPart - win_lastUserCPU.QuadPart);
	percent /= (now.QuadPart - win_lastCPU.QuadPart);
	percent /= win_num_processors;
	win_lastCPU     = now;
	win_lastUserCPU = user;
	win_lastSysCPU  = sys;

	// Normalize by number of CPUs
	s->cpu_percent = 100.0 * percent;
	log_debug("NanoMQ cpu (%dcores) usage: %.2f %\n", win_num_processors, s->cpu_percent);
#else
	log_warn("Unsupported platform to get process info");
#endif

	return 0;
}

static http_msg
get_can_data_span(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg  res       = { .status = NNG_HTTP_STATUS_OK };
	cJSON    *res_obj   = cJSON_CreateObject();
	uint64_t *data_span = NULL;
	uint64_t *sums      = NULL;

	conf *conf = get_global_conf();
	conf_exchange *ex_conf = &conf->exchange;
	if (ex_conf->count <= 0) {
		return error_response(msg, NNG_HTTP_STATUS_NO_CONTENT,
		    CONTENT_NOT_AVAILABLE);
	}
	char **topicl = nng_zalloc(sizeof(char*) * ex_conf->count);
	for (size_t i = 0; i < ex_conf->count; i++) {
		topicl[i] = nng_strdup(ex_conf->nodes[i]->topic);
		log_info("got topic %s", topicl[i]);
	}

#ifdef SUPP_PARQUET
	parquet_get_key_span((const char**)topicl, ex_conf->count, &data_span, &sums);
#else
	log_error("Parquet is't compiled!");
#endif
	if (NULL == data_span) {
		cJSON_AddNumberToObject(res_obj, "code", PLUGIN_IS_CLOSED);
	} else {
		char topickey[16];
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
		cJSON *datajo = cJSON_CreateObject();
		for (int i=0; i<ex_conf->count; ++i) {
			cJSON *topicjo = cJSON_CreateObject();
			sprintf(topickey, "%ld", data_span[2*i]);
			cJSON_AddStringToObject(topicjo, "start", topickey);
			sprintf(topickey, "%ld", data_span[2*i+1]);
			cJSON_AddStringToObject(topicjo, "end", topickey);
			uint64_t sum = sums[i]/1024;
			cJSON_AddNumberToObject(topicjo, "space", sum);
			cJSON_AddItemToObject(datajo, topicl[i], topicjo);
		}
		cJSON_AddItemToObject(res_obj, "data", datajo);
#ifdef SUPP_PARQUET
		parquet_free_key_span(data_span, sums, ex_conf->count);
#endif
	}

	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	for (size_t i = 0; i < ex_conf->count; i++) {
		nng_free(topicl[i], strlen(topicl[i]));
	}
	nng_free(topicl, sizeof(char*) * ex_conf->count);
	cJSON_free(dest);
	cJSON_Delete(res_obj);

	return res;
}

static http_msg
get_prometheus(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	client_stats stats = { 0 };
	static client_stats max_stats = { 0 };
	nng_id_map *pipe_id_map;
	conf       *config = get_global_conf();
	int data_size = BROKER_DATA_SIZE + config->bridge.count*BRIDGE_DATA_SIZE;

	char *dest = nng_alloc(sizeof(char) * data_size);

	if (nng_socket_get_ptr(*broker_sock, NMQ_OPT_MQTT_PIPES,
	        (void **) &pipe_id_map) != 0) {
		goto out;
	}

	nng_id_map_foreach2(pipe_id_map, get_metric_cb, &stats);
	stats.subscribers      = dbhash_get_pipe_cnt();
	stats.topics           = get_topics_count();
#ifdef STATISTICS
	stats.message_received = nanomq_get_message_in();
	stats.message_sent     = nanomq_get_message_out();
	stats.message_dropped  = nanomq_get_message_drop();
#endif

	update_process_info(&stats);

	memset(dest, 0, data_size);
	update_max_stats(&max_stats, &stats);
	compose_metrics(dest, &max_stats, &stats);
	nng_socket *socket = NULL;
	nng_stat   *nng_stats;
	nng_stats_get(&nng_stats);
	for (size_t t = 0; t < config->bridge.count; t++) {
		conf_bridge_node *node = config->bridge.nodes[t];
		if (node->enable) {
			socket = node->sock;
			nng_stat *st1;
			nng_stat *st2;
			bridge_stats bs = { 0 };
			st1 = nng_stat_find_socket(nng_stats, *socket);
			uint64_t pipe;
			int      rv2 = nng_socket_get_uint64(
                            *socket, NNG_OPT_MQTT_CLIENT_PIPEID, &pipe);
			nng_stat *child = NULL;
			child              = nng_stat_find(st1, "name");
			if (child) {
				bs.name = nng_stat_string(child);
			}
			child = nng_stat_find(st1, "tx_msgs");
			if (child) {
				bs.message_sent = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "rx_msgs");
			if (child) {
				bs.message_received = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "tx_bytes");
			if (child) {
				bs.bytes_sent = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "rx_bytes");
			if (child) {
				bs.bytes_received = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "mqtt_client_reconnect");
			if (child) {
				bs.reconnections = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "mqtt_msg_send_drop");
			if (child) {
				bs.uplink_message_dropped = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "mqtt_msg_recv_drop");
			if (child) {
				bs.downlink_message_dropped = nng_stat_value(child);
			}
			child = nng_stat_find(st1, "mqtt_msg_bytes_cached");
			if (child) {
				bs.bytes_cached = nng_stat_value(child);
			}
			char bridge_metric_ret[BRIDGE_DATA_SIZE] = { 0 };
			compose_bridge_metrics(bridge_metric_ret, &bs);

			size_t len = strlen(dest);
			if (len < data_size) {
				snprintf(dest + len, data_size - len, "%s", bridge_metric_ret);
			}
		}
	}
	nng_stats_free(nng_stats);

out:
	put_http_msg(&res, "text/plain", NULL, NULL, NULL, dest, strlen(dest));
	nng_free(dest, data_size);

	return res;
}

static char *bin2hex(const uint8_t *s, uint32_t len)
{
	char *hex = nng_alloc(sizeof(char) * 2 * len + 1);
	for (uint32_t i=0; i<len; ++i) {
		sprintf(hex + 2*i, "%02x", s[i]);
	}
	hex[2*len] = '\0';
	return hex;
}

static void *
get_retain_info_cb(nng_msg *retain)
{
	nng_msg_clone(retain);
	return (void *) retain;
}

static http_msg
get_retains(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	(void)msg;
	http_msg res     = { .status = NNG_HTTP_STATUS_OK };
	cJSON *res_obj   = NULL;
	cJSON *data_info = NULL;
	res_obj          = cJSON_CreateObject();
	data_info        = cJSON_CreateArray();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", data_info);
#ifdef NNG_SUPP_SQLITE
	log_warn("get_retain API is disabled while SQLite enabled");
#else
	conf       *config = get_global_conf();
	nng_socket *socket = NULL;

	dbtree        *db_ret = get_broker_retain_db();
	dbtree_info ***vn =
	    (dbtree_info ***) dbtree_get_retain_tree(db_ret, get_retain_info_cb);
	for (int i = 0; i < cvector_size(vn); i++) {
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			if (cvector_size(vn[i][j]->clients) == 0) {
				nng_free(vn[i][j], sizeof(dbtree_info));
				continue;
			} else if (cvector_size(vn[i][j]->clients) != 3) {
				log_error("each topic should only have one "
				          "retain msg %d", cvector_size(vn[i][j]->clients));
			}
			cJSON *elem = cJSON_CreateObject();

			nng_msg *retain = (nng_msg *) vn[i][j]->clients[0];
			char    *cid    = (char *) vn[i][j]->clients[1];
			char    *ts     = (char *) vn[i][j]->clients[2];
			cvector_free(vn[i][j]->clients);
			cJSON_AddStringToObject(elem, "clientid", cid);
			cJSON_AddStringToObject(elem, "ts", ts);
			nng_free(cid, 0);
			nng_free(ts, 0);

			uint8_t qos = nng_mqtt_msg_get_publish_qos(retain);
			cJSON_AddNumberToObject(elem, "qos", qos);

			uint32_t    topicsz;
			const char *topic =
			    nng_mqtt_msg_get_publish_topic(retain, &topicsz);
			if (topicsz != 0 && topic) {
				char *pubtopic = nng_strndup(topic, topicsz);
				cJSON_AddStringToObject(
				    elem, "topic", pubtopic);
				free(pubtopic);
			}

			uint32_t pldsz;
			char    *pld =
			    nng_mqtt_msg_get_publish_payload(retain, &pldsz);
			if (pldsz != 0 && pld) {
				char *hex = bin2hex(pld, pldsz);
				cJSON_AddStringToObject(elem, "hexpld", hex);
				nng_free(hex, 0);
			}

			nng_msg_free(retain); // Cloned at get_retain_info_cb
			nng_free(vn[i][j], sizeof(dbtree_info));
			cJSON_AddItemToArray(data_info, elem);
		}
		cvector_free(vn[i]);
	}
	cvector_free(vn);
#endif
	char *dest = cJSON_PrintUnformatted(res_obj);
	cJSON_Delete(res_obj);

	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	nng_free(dest, 0);

	return res;
}

static http_msg
get_metrics(http_msg *msg, kv **params, size_t param_num,
    const char *client_id, const char *username, nng_socket *broker_sock)
{
	http_msg res     = { .status = NNG_HTTP_STATUS_OK };
	cJSON   *res_obj = cJSON_CreateObject();
	cJSON   *metrics = cJSON_CreateArray();

	client_stats stats = { 0 };

	update_process_info(&stats);

	conf       *config = get_global_conf();
	nng_socket *socket = NULL;
	nng_stat   *nng_stats;
	nng_stats_get(&nng_stats);
	for (size_t t = 0; t < config->bridge.count; t++) {
		conf_bridge_node *node = config->bridge.nodes[t];
		if (node->enable) {
			socket = node->sock;
			nng_stat *st1;
			nng_stat *st2;
			st1 = nng_stat_find_socket(nng_stats, *socket);
			uint64_t pipe;
			int      rv2 = nng_socket_get_uint64(
                            *socket, NNG_OPT_MQTT_CLIENT_PIPEID, &pipe);
			if (rv2 == 0) {
				st2 = nng_stat_find_pipe(nng_stats, pipe);
				nng_stats_dump(st2);
			}
			bool br = false;
			nng_socket_get_bool(
			    *socket, NNG_OPT_MQTT_CLIENT_CONNECT_BOOL, &br);
			nng_stat *child = NULL;
			cJSON *bridge_info = cJSON_CreateObject();
			cJSON_AddBoolToObject(bridge_info, "bridge connected", br);

			child              = nng_stat_find(st1, "name");
			if (child) {
				cJSON_AddStringToObject(bridge_info,
				    "bridge name",
				    nng_stat_string(child));
			}
			child = nng_stat_find(st1, "tx_msgs");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "rx_msgs");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "tx_bytes");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "rx_bytes");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "mqtt_client_reconnect");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "mqtt_msg_send_drop");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "mqtt_msg_recv_drop");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "mqtt_msg_sqlite_cached");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			child = nng_stat_find(st1, "mqtt_msg_bytes_cached");
			if (child) {
				cJSON_AddNumberToObject(bridge_info,
				    nng_stat_desc(child),
				    nng_stat_value(child));
			}
			cJSON_AddItemToArray(metrics, bridge_info);
		}
	}
	nng_stats_free(nng_stats);
	char cpu[16] = { 0 };
	char mem[64] = { 0 };
	snprintf(cpu, 16, "%.2f%%", stats.cpu_percent);
	snprintf(mem, 64, "%ld", stats.memory);

	cJSON_AddItemToObject(res_obj, "metrics", metrics);
	cJSON_AddStringToObject(res_obj, "cpuinfo", cpu);
	cJSON_AddStringToObject(res_obj, "memory", mem);

	// cJSON *meta = cJSON_CreateObject();
	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);

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
		nng_pipe p = { .id = pt[i]->pipe };
		conn_param *cp = nng_pipe_cparam(p);

 		if (cp) {
 			cid = (const char *) conn_param_get_clientid(
 			    cp);
			conn_param_free(cp);
			if (client_id) {
				if (strcmp(client_id, cid) != 0) {
 					goto skip;
 				}
			}
		}

 		// topic_queue *tn = pt[i]->topic;
		topic_queue *tq = dbhash_copy_topic_queue(pt[i]->pipe);
		topic_queue *reap_node = tq;
 		while (tq) {
 			cJSON *subscribe = cJSON_CreateObject();
 			if (cid) {
 				cJSON_AddStringToObject(
 				    subscribe, "clientid", cid);
 			} else {
 				cJSON_AddStringToObject(
 				    subscribe, "clientid", "");
 			}
 			cJSON_AddStringToObject(
 			    subscribe, "topic", tq->topic);
 			cJSON_AddNumberToObject(subscribe, "qos", tq->qos);
 			cJSON_AddItemToArray(data_info, subscribe);
 			tq = tq->next;
			nng_free(reap_node->topic, strlen(reap_node->topic));
			nng_free(reap_node, sizeof(topic_queue));
			reap_node = tq;
 		}
 	skip:
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

static http_msg
get_license_info(http_msg *msg)
{
	(void) msg;
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	char *dest = NULL;
#if defined(SUPP_LICENSE_STD)
	if (0 != lic_std_info(&dest)) {
		log_error("license not found");
		dest = nng_strdup("{\"code\":102}");
	}
#else
	dest = nng_strdup("{}");
	log_error("license is disabled");
	res.status = NNG_HTTP_STATUS_NOT_FOUND;
#endif
	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	return res;
}

#if defined(NNG_SUPP_SQLITE)  && defined(SUPP_RULE_ENGINE)

static bool
sqlite_table_exist(conf_rule *cr, char *name)
{
	for (size_t i = 0; i < cvector_size(cr->rules); i++) {
		if (cr->rules[i].forword_type == RULE_FORWORD_SQLITE) {
			if (nng_strcasecmp(cr->rules[i].sqlite_table, name) ==
			    0) {
				return true;
			}
		}
	}
	return false;
}

static int
post_rules_sqlite(conf_rule *cr, cJSON *jso_params, char *rawsql)
{
	cJSON *jso_param = NULL;
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				if (sqlite_table_exist(
				        cr, jso_param->valuestring)) {
					log_error("Sqlite table %s "
					          "is "
					          "exist!",
					    jso_param->valuestring);
					return REQ_PARAM_ERROR;
				}
				log_debug(
				    "table: %s\n", jso_param->valuestring);
				rule_sql_parse(cr, rawsql);
				cr->rules[cvector_size(cr->rules) - 1]
				    .forword_type = RULE_FORWORD_SQLITE;
				cr->rules[cvector_size(cr->rules) - 1]
				    .sqlite_table =
				    nng_strdup(jso_param->valuestring);
				cr->rules[cvector_size(cr->rules) - 1]
				    .raw_sql = nng_strdup(rawsql);
				cr->rules[cvector_size(cr->rules) - 1]
				    .enabled = true;
				cr->rules[cvector_size(cr->rules) - 1]
				    .rule_id = rule_generate_rule_id();
				if (1 == nanomq_client_sqlite(cr, true)) {
					log_error("Sqlite post error!");
					rule_free(&cr->rules[cvector_size(
					                         cr->rules) -
					    1]);
					cvector_pop_back(cr->rules);
					return PLUGIN_IS_CLOSED;
				}
			}
		}
	}

	cr->option |= RULE_ENG_SDB;
	return SUCCEED;
}
#endif

#if defined(SUPP_TIMESCALEDB) && defined(SUPP_RULE_ENGINE)
static int
post_rules_timescaledb(conf_rule *cr, cJSON *jso_params, char *rawsql)
{
	cJSON *jso_param = NULL;
	rule_timescaledb *timescaledb = rule_timescaledb_init();
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				timescaledb->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				timescaledb->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				timescaledb->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				timescaledb->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				rule_timescaledb_free(timescaledb);
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	if (false == rule_timescaledb_check(timescaledb)) {
		rule_timescaledb_free(timescaledb);
		return MISSING_KEY_REQUEST_PARAMES;
	}

	rule_sql_parse(cr, rawsql);
	cr->rules[cvector_size(cr->rules) - 1].forword_type =
	    RULE_FORWORD_TIMESCALEDB;
	cr->rules[cvector_size(cr->rules) - 1].timescaledb   = timescaledb;
	cr->rules[cvector_size(cr->rules) - 1].raw_sql = nng_strdup(rawsql);
	cr->rules[cvector_size(cr->rules) - 1].enabled = true;
	cr->rules[cvector_size(cr->rules) - 1].rule_id =
	    rule_generate_rule_id();
	if (-1 == nanomq_client_timescaledb(cr, true)) {
		return REQ_PARAM_ERROR;
	}

	cr->option |= RULE_ENG_TDB;
	return SUCCEED;
}
#endif

#if defined(SUPP_POSTGRESQL) && defined(SUPP_RULE_ENGINE)
static int
post_rules_postgresql(conf_rule *cr, cJSON *jso_params, char *rawsql)
{
	cJSON *jso_param = NULL;
	rule_postgresql *postgresql = rule_postgresql_init();
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				postgresql->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				postgresql->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				postgresql->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				postgresql->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				rule_postgresql_free(postgresql);
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	if (false == rule_postgresql_check(postgresql)) {
		rule_postgresql_free(postgresql);
		return MISSING_KEY_REQUEST_PARAMES;
	}

	rule_sql_parse(cr, rawsql);
	cr->rules[cvector_size(cr->rules) - 1].forword_type =
	    RULE_FORWORD_POSTGRESQL;
	cr->rules[cvector_size(cr->rules) - 1].postgresql   = postgresql;
	cr->rules[cvector_size(cr->rules) - 1].raw_sql = nng_strdup(rawsql);
	cr->rules[cvector_size(cr->rules) - 1].enabled = true;
	cr->rules[cvector_size(cr->rules) - 1].rule_id =
	    rule_generate_rule_id();
	if (-1 == nanomq_client_postgresql(cr, true)) {
		return REQ_PARAM_ERROR;
	}

	cr->option |= RULE_ENG_PDB;
	return SUCCEED;
}
#endif

#if defined(SUPP_MYSQL) && defined(SUPP_RULE_ENGINE)
static int
post_rules_mysql(conf_rule *cr, cJSON *jso_params, char *rawsql)
{
	cJSON *jso_param = NULL;
	rule_mysql *mysql = rule_mysql_init();
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				mysql->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				mysql->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				mysql->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				mysql->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				rule_mysql_free(mysql);
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	if (false == rule_mysql_check(mysql)) {
		rule_mysql_free(mysql);
		return MISSING_KEY_REQUEST_PARAMES;
	}

	rule_sql_parse(cr, rawsql);
	cr->rules[cvector_size(cr->rules) - 1].forword_type =
	    RULE_FORWORD_MYSQL;
	cr->rules[cvector_size(cr->rules) - 1].mysql   = mysql;
	cr->rules[cvector_size(cr->rules) - 1].raw_sql = nng_strdup(rawsql);
	cr->rules[cvector_size(cr->rules) - 1].enabled = true;
	cr->rules[cvector_size(cr->rules) - 1].rule_id =
	    rule_generate_rule_id();
	if (-1 == nanomq_client_mysql(cr, true)) {
		return REQ_PARAM_ERROR;
	}

	cr->option |= RULE_ENG_MDB;
	return SUCCEED;
}
#endif

#if defined(SUPP_RULE_ENGINE)
static int
post_rules_repub(conf_rule *cr, cJSON *jso_params, char *rawsql)
{
	cJSON   *jso_param = NULL;
	repub_t *repub     = rule_repub_init();

	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "topic")) {
				repub->topic =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "topic: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "address")) {
				repub->address =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "address: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "proto_ver")) {
				repub->proto_ver = jso_param->valueint;
				log_debug(
				    "proto_ver: %d\n", jso_param->valueint);
			} else if (!nng_strcasecmp(
			               jso_param->string, "keepalive")) {
				repub->keepalive = jso_param->valueint;
				log_debug(
				    "keepalive: %d\n", jso_param->valueint);
			} else if (!nng_strcasecmp(
			               jso_param->string, "clientid")) {
				repub->clientid =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "clientid: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				repub->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				repub->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "clean_start")) {
				repub->clean_start =
				    !nng_strcasecmp(jso_param->string, "true");
				log_debug("clean_start: %s\n",
				    jso_param->valuestring);
			} else {
				puts("Unsupport key word!");
			}
		}
	}
	if (NULL == repub->address || NULL == repub->topic) {
		rule_repub_free(repub);
		return MISSING_KEY_REQUEST_PARAMES;
	}

	nng_socket *sock = (nng_socket *) nng_alloc(sizeof(nng_socket));
	if (nano_client(sock, repub) != 0) {
		rule_repub_free(repub);
		nng_free(sock, sizeof(nng_socket));
		return MISSING_KEY_REQUEST_PARAMES;
	}

	rule_sql_parse(cr, rawsql);
	cr->rules[cvector_size(cr->rules) - 1].forword_type =
	    RULE_FORWORD_REPUB;

	cr->rules[cvector_size(cr->rules) - 1].repub   = repub;
	cr->rules[cvector_size(cr->rules) - 1].raw_sql = nng_strdup(rawsql);
	cr->rules[cvector_size(cr->rules) - 1].enabled = true;
	cr->rules[cvector_size(cr->rules) - 1].rule_id =
	    rule_generate_rule_id();
	cr->option |= RULE_ENG_RPB;
	return SUCCEED;
}
#endif

static http_msg
post_rules(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	int      rc  = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}

	cJSON *res_obj = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)
	conf      *config = get_global_conf();
	conf_rule *cr     = &config->rule_eng;

	cJSON *jso_sql = cJSON_GetObjectItem(req, "rawsql");
	char  *rawsql  = cJSON_GetStringValue(jso_sql);
	log_debug("rawsql: %s\n", rawsql);

	cJSON *jso_actions = cJSON_GetObjectItem(req, "actions");
	cJSON *jso_action  = NULL;
	cJSON_ArrayForEach(jso_action, jso_actions)
	{
		cJSON *jso_name = cJSON_GetObjectItem(jso_action, "name");
		char  *name     = cJSON_GetStringValue(jso_name);
		log_debug("name: %s\n", name);
		cJSON *jso_params = cJSON_GetObjectItem(jso_action, "params");
		cJSON *jso_param  = NULL;
		if (!nng_strcasecmp(name, "repub")) {
			if ((rc = post_rules_repub(cr, jso_params, rawsql)) !=
			    SUCCEED) {
				goto error;
			}

#if defined(NNG_SUPP_SQLITE)
		} else if (!nng_strcasecmp(name, "sqlite")) {
			if ((rc = post_rules_sqlite(cr, jso_params, rawsql)) !=
			    SUCCEED) {
				goto error;
			}
#endif

#if defined(SUPP_MYSQL)
		} else if (!nng_strcasecmp(name, "mysql")) {
			if ((rc = post_rules_mysql(cr, jso_params, rawsql)) !=
			    SUCCEED) {
					goto error;
			}
#endif
#if defined(SUPP_POSTGRESQL)
		} else if (!nng_strcasecmp(name, "postgresql")) {
			if ((rc = post_rules_postgresql(cr, jso_params, rawsql)) !=
			    SUCCEED) {
					goto error;
			}
#endif
#if defined(SUPP_TIMESCALEDB)
		} else if (!nng_strcasecmp(name, "timescaledb")) {
			if ((rc = post_rules_timescaledb(cr, jso_params, rawsql)) !=
			    SUCCEED) {
					goto error;
			}
#endif
		} else {
			log_error("Unsupport forword type !");
			rc = PLUGIN_IS_CLOSED;
		error:
			cJSON_Delete(req);
			cJSON_Delete(res_obj);
			return error_response(
			    msg, NNG_HTTP_STATUS_BAD_REQUEST, rc);
		}
	}

	cJSON *jso_desc = cJSON_GetObjectItem(req, "description");
	if (jso_desc) {
		char *desc = cJSON_GetStringValue(jso_desc);
		log_debug("%s\n", desc);
	}

	cJSON *data_info = cJSON_CreateObject();
	cJSON *actions   = cJSON_CreateArray();

	cJSON_AddStringToObject(data_info, "rawsql",
	    cr->rules[cvector_size(cr->rules) - 1].raw_sql);
	cJSON_AddNumberToObject(
	    data_info, "id", cr->rules[cvector_size(cr->rules) - 1].rule_id);
	cJSON_AddBoolToObject(data_info, "enabled",
	    cr->rules[cvector_size(cr->rules) - 1].enabled);
	cJSON_AddItemToObject(res_obj, "data", data_info);
	cJSON_AddItemToObject(res_obj, "actions", actions);
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
#else
	cJSON_AddNumberToObject(res_obj, "code", PLUGIN_IS_CLOSED);

#endif
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static int
put_rules_repub_parse(cJSON *jso_params, repub_t *repub)
{
	cJSON *jso_param = NULL;

	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (!nng_strcasecmp(jso_param->string, "topic")) {
			if (repub->topic) {
				nng_strfree(repub->topic);
			}
			repub->topic = nng_strdup(jso_param->valuestring);
			log_debug("topic: %s\n", jso_param->valuestring);
		} else if (!nng_strcasecmp(jso_param->string, "address")) {
			if (repub->address) {
				nng_strfree(repub->address);
			}
			repub->address = nng_strdup(jso_param->valuestring);
			log_debug("address: %s\n", jso_param->valuestring);
		} else if (!nng_strcasecmp(jso_param->string, "proto_ver")) {
			repub->proto_ver = jso_param->valueint;
			log_debug("proto_ver: %d\n", jso_param->valueint);
		} else if (!nng_strcasecmp(jso_param->string, "keepalive")) {
			repub->keepalive = jso_param->valueint;
			log_debug("keepalive: %d\n", jso_param->valueint);
		} else if (!nng_strcasecmp(jso_param->string, "clientid")) {
			if (repub->clientid) {
				nng_strfree(repub->clientid);
			}
			repub->clientid = nng_strdup(jso_param->valuestring);
			log_debug("clientid: %s\n", jso_param->valuestring);
		} else if (!nng_strcasecmp(jso_param->string, "username")) {
			if (repub->username) {
				nng_strfree(repub->username);
			}
			repub->username = nng_strdup(jso_param->valuestring);
			log_debug("username: %s\n", jso_param->valuestring);
		} else if (!nng_strcasecmp(jso_param->string, "password")) {
			if (repub->password) {
				nng_strfree(repub->password);
			}
			repub->password = nng_strdup(jso_param->valuestring);
			log_debug("password: %s\n", jso_param->valuestring);
		} else if (!nng_strcasecmp(jso_param->string, "clean_start")) {
			repub->clean_start =
			    !nng_strcasecmp(jso_param->string, "true");
			log_debug("clean_start: %s\n", jso_param->valuestring);
		} else {
			log_error("Unsupport key word!");
			return REQ_PARAM_ERROR;
		}
	}
	return SUCCEED;
}

static int
put_rules_sqlite_parse(cJSON *jso_params, rule *new_rule)
{
	cJSON *jso_param = NULL;
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				log_debug(
				    "table: %s\n", jso_param->valuestring);
				new_rule->sqlite_table =
				    nng_strdup(jso_param->valuestring);
			} else {
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	return SUCCEED;
}

static int
put_rules_mysql_parse(cJSON *jso_params, rule_mysql *mysql)
{
	cJSON *jso_param = NULL;
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				if (mysql->table) {
					nng_strfree(mysql->table);
				}
				mysql->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				if (mysql->username) {
					nng_strfree(mysql->username);
				}
				mysql->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				if (mysql->password) {
					nng_strfree(mysql->password);
				}
				mysql->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				if (mysql->host) {
					nng_strfree(mysql->host);
				}
				mysql->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	return SUCCEED;
}


static int
put_rules_postgresql_parse(cJSON *jso_params, rule_postgresql *postgresql)
{
	cJSON *jso_param = NULL;
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				if (postgresql->table) {
					nng_strfree(postgresql->table);
				}
				postgresql->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				if (postgresql->username) {
					nng_strfree(postgresql->username);
				}
				postgresql->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				if (postgresql->password) {
					nng_strfree(postgresql->password);
				}
				postgresql->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				if (postgresql->host) {
					nng_strfree(postgresql->host);
				}
				postgresql->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	return SUCCEED;
}

static int
put_rules_timescaledb_parse(cJSON *jso_params, rule_timescaledb *timescaledb)
{
	cJSON *jso_param = NULL;
	cJSON_ArrayForEach(jso_param, jso_params)
	{
		if (jso_param) {
			if (!nng_strcasecmp(jso_param->string, "table")) {
				if (timescaledb->table) {
					nng_strfree(timescaledb->table);
				}
				timescaledb->table =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "table: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "username")) {
				if (timescaledb->username) {
					nng_strfree(timescaledb->username);
				}
				timescaledb->username =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "username: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "password")) {
				if (timescaledb->password) {
					nng_strfree(timescaledb->password);
				}
				timescaledb->password =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "password: %s\n", jso_param->valuestring);
			} else if (!nng_strcasecmp(
			               jso_param->string, "host")) {
				if (timescaledb->host) {
					nng_strfree(timescaledb->host);
				}
				timescaledb->host =
				    nng_strdup(jso_param->valuestring);
				log_debug(
				    "host: %s\n", jso_param->valuestring);
			} else {
				log_error("Unsupport key word!");
				return REQ_PARAM_ERROR;
			}
		}
	}

	return SUCCEED;
}

static int
put_rules_update_action(cJSON *jso_actions, rule *new_rule, conf_rule *cr)
{
	cJSON *jso_action = NULL;
	int    rc         = SUCCEED;
	cJSON_ArrayForEach(jso_action, jso_actions)
	{
		cJSON *jso_name = cJSON_GetObjectItem(jso_action, "name");
		char  *name     = cJSON_GetStringValue(jso_name);
		log_debug("name: %s\n", name);
		cJSON *jso_params = cJSON_GetObjectItem(jso_action, "params");
		cJSON *jso_param  = NULL;
		if (!nng_strcasecmp(name, "repub")) {
			if (new_rule->forword_type != RULE_FORWORD_REPUB) {
				log_error("Unsupport change from other type to repub");
				return REQ_PARAM_ERROR;
			}
			repub_t *repub = new_rule->repub;
			rc = put_rules_repub_parse(jso_params, repub);
			if (rc != SUCCEED) {
				rule_repub_free(repub);
				return rc;
			}
		} else if (!nng_strcasecmp(name, "sqlite")) {
			if (new_rule->forword_type != RULE_FORWORD_SQLITE) {
				log_error("Unsupport change from other type to sqlite");
				return REQ_PARAM_ERROR;
			}
			rc = put_rules_sqlite_parse(jso_params, new_rule);
			cr->rules[cvector_size(cr->rules) - 1] =
			    *new_rule;
			if (rc != SUCCEED) {
				return rc;
			}
		} else if (!nng_strcasecmp(name, "mysql")) {
			if (new_rule->forword_type != RULE_FORWORD_MYSQL) {
				log_error("Unsupport change from other type to mysql");
				return REQ_PARAM_ERROR;
			}
			rule_mysql *mysql = new_rule->mysql;
			rc = put_rules_mysql_parse(jso_params, mysql);
			if (rc != SUCCEED) {
				rule_mysql_free(mysql);
				return rc;
			}
		} else if (!nng_strcasecmp(name, "postgresql")) {
			if (new_rule->forword_type != RULE_FORWORD_POSTGRESQL) {
				log_error("Unsupport change from other type to postgresql");
				return REQ_PARAM_ERROR;
			}
			rule_postgresql *postgresql = new_rule->postgresql;
			rc = put_rules_postgresql_parse(jso_params, postgresql);
			if (rc != SUCCEED) {
				rule_postgresql_free(postgresql);
				return rc;
			}
		} else if (!nng_strcasecmp(name, "timescaledb")) {
			if (new_rule->forword_type != RULE_FORWORD_TIMESCALEDB) {
				log_error("Unsupport change from other type to timescaledb");
				return REQ_PARAM_ERROR;
			}
			rule_timescaledb *timescaledb = new_rule->timescaledb;
			rc = put_rules_timescaledb_parse(jso_params, timescaledb);
			if (rc != SUCCEED) {
				rule_timescaledb_free(timescaledb);
				return rc;
			}
		} else {
			log_debug("Unsupport forword type !");
			return REQ_PARAM_ERROR;
		}
	}
	return rc;
}

static http_msg
put_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	int      rc  = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		cJSON_Delete(req);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}

	cJSON *res_obj = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)

	conf      *config = get_global_conf();
	conf_rule *cr     = &config->rule_eng;
	uint32_t  id     = 0;
	rule *old_rule = NULL;
	rule *new_rule = NULL;

	// Updated three parts， enabled status，sql and action
	// 1. update sql: parse sql, set raw_sql, set rule_id, do not need deal connection. free origin sql data,
	// 2. update enabled status: need to deal connection,  status changed will lead to connect/disconnect.
	// 3, update actions: need to deal connection，update repub/table.

	sscanf(rule_id, "rule:%u", &id);
	int i = 0;

	// Get old rule;
	for (; i < cvector_size(cr->rules); i++) {
		if (rule_id && cr->rules[i].rule_id == id) {
			old_rule = &cr->rules[i];
			break;
		}
	}

	if (NULL == old_rule) {
		rc = REQ_PARAM_ERROR;
		goto error;
	}

	cJSON *jso_sql = cJSON_GetObjectItem(req, "rawsql");
	if (NULL != jso_sql) {
		char *rawsql = cJSON_GetStringValue(jso_sql);
		rule_sql_parse(cr, rawsql);
		new_rule = &cr->rules[cvector_size(cr->rules) - 1];
		new_rule->forword_type = cr->rules[i].forword_type;
		new_rule->raw_sql = nng_strdup(rawsql);
		new_rule->enabled = true;
		new_rule->rule_id = id;

		switch (cr->rules[i].forword_type)
		{
		case RULE_FORWORD_REPUB:
			new_rule->repub = cr->rules[i].repub;
			break;
		case RULE_FORWORD_MYSQL:
			new_rule->mysql = cr->rules[i].mysql;
			break;
		case RULE_FORWORD_POSTGRESQL:
			new_rule->postgresql = cr->rules[i].postgresql;
			break;
		case RULE_FORWORD_TIMESCALEDB:
			new_rule->timescaledb = cr->rules[i].timescaledb;
			break;
		case RULE_FORWORD_SQLITE:
			new_rule->sqlite_table = cr->rules[i].sqlite_table;
			break;
		default:
			break;
		}

		// Maybe cvector_push_back() will realloc,
		// so for safety reassign it.
		old_rule = &cr->rules[i];
		rule_free(old_rule);
		cvector_erase(cr->rules, i);
	} else {
		if (old_rule->repub) {
			nng_close(*(nng_socket *) old_rule->repub->sock);
		}
		new_rule = old_rule;
	}

	cJSON *jso_enabled = cJSON_GetObjectItem(req, "enabled");
	if (NULL != jso_enabled) {
		new_rule->enabled = cJSON_IsTrue(jso_enabled);
	}

	// TODO support multi actions
	cJSON *jso_actions = cJSON_GetObjectItem(req, "actions");
	if (NULL != jso_actions) {
		rc = put_rules_update_action(jso_actions, new_rule, cr);
		if (rc != SUCCEED) {
		error:
			cJSON_Delete(res_obj);
			cJSON_Delete(req);
			return error_response(
			    msg, NNG_HTTP_STATUS_BAD_REQUEST, rc);
		}

		if ((jso_enabled || jso_actions) && new_rule->enabled) {
			// TODO nng_mqtt_disconnct()
			// if (old_rule->repub) {
			// 	nng_close(*(nng_socket*) old_rule->repub->sock);
			// }
			if (RULE_FORWORD_REPUB == new_rule->forword_type) {
				nano_client(new_rule->repub->sock, new_rule->repub);
			} else if (RULE_FORWORD_SQLITE == new_rule->forword_type)
			{
#if defined(NNG_SUPP_SQLITE)
				nanomq_client_sqlite(cr, true);
#endif
			}

		} else if (jso_enabled && false == new_rule->enabled) {
			// TODO nng_mqtt_disconnct()
		}
	}

	// cJSON *jso_desc = cJSON_GetObjectItem(req, "description");
	// char *desc= cJSON_GetStringValue(jso_desc);

 	cJSON *data_info = cJSON_CreateObject();
	cJSON *actions = cJSON_CreateArray();

	cJSON_AddStringToObject(data_info, "rawsql", new_rule->raw_sql);
	cJSON_AddNumberToObject(data_info, "id", new_rule->rule_id);
	cJSON_AddBoolToObject(data_info, "enabled", new_rule->enabled);
	cJSON_AddItemToObject(res_obj, "data", data_info);
	cJSON_AddItemToObject(res_obj, "actions", actions);

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
#else
	cJSON_AddNumberToObject(res_obj, "code", PLUGIN_IS_CLOSED);
#endif
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static http_msg
delete_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res     = { 0 };
	res.status       = NNG_HTTP_STATUS_OK;
	cJSON   *res_obj = NULL;
	uint32_t id      = 0;
	res_obj          = cJSON_CreateObject();

#if defined(SUPP_RULE_ENGINE)
	if (rule_id) {
		sscanf(rule_id, "rule:%d", &id);
		conf      *config = get_global_conf();
		conf_rule *cr     = &config->rule_eng;
		int        i      = 0;
		size_t     size   = cvector_size(cr->rules);
		for (; i < size; i++) {
			if (cr->rules[i].rule_id == id) {
				rule *re = &cr->rules[i];
				switch (re->forword_type)
				{
				case RULE_FORWORD_MYSQL:
					rule_mysql_free(re->mysql);
					break;
				case RULE_FORWORD_POSTGRESQL:
					rule_postgresql_free(re->postgresql);
					break;
				case RULE_FORWORD_TIMESCALEDB:
					rule_timescaledb_free(re->timescaledb);
					break;
				case RULE_FORWORD_REPUB:
					rule_repub_free(re->repub);
					break;
				default:
					break;
				}
				rule_free(re);
				cvector_erase(cr->rules, i);
				break;
			}
		}

		if (size == i) {
			goto error;
		}

		// cJSON *meta = cJSON_CreateObject();
		// cJSON_AddItemToObject(res_obj, "meta", meta);
		// TODO add meta content: page, limit, count
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);

	} else {
		goto error;
	}

#else
	cJSON_AddNumberToObject(res_obj, "code", PLUGIN_IS_CLOSED);
#endif

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
error:
	cJSON_Delete(res_obj);
	return error_response(
	    msg, NNG_HTTP_STATUS_BAD_REQUEST, MISSING_KEY_REQUEST_PARAMES);
}

static void
get_rules_helper(cJSON *data, rule *r)
{

	char *forword_type = NULL;
	switch (r->forword_type) {
	case RULE_FORWORD_SQLITE:
		forword_type = "sqlite";
		break;
	case RULE_FORWORD_REPUB:
		forword_type = "repub";
		break;
	case RULE_FORWORD_MYSQL:
		forword_type = "mysql";
		break;
	case RULE_FORWORD_POSTGRESQL:
		forword_type = "postgresql";
		break;
	case RULE_FORWORD_TIMESCALEDB:
		forword_type = "timescaledb";
		break;
	default:
		break;
	}
	cJSON_AddStringToObject(data, "name", forword_type);
	cJSON_AddStringToObject(data, "rawsql", r->raw_sql);
	cJSON_AddNumberToObject(data, "id", r->rule_id);
	cJSON_AddBoolToObject(data, "enabled", r->enabled);
}

static http_msg
get_rules(http_msg *msg, kv **params, size_t param_num, const char *rule_id)
{
	http_msg res = { 0 };
	res.status   = NNG_HTTP_STATUS_OK;

	cJSON   *res_obj = NULL;
	cJSON   *data    = NULL;
	uint32_t id      = 0;
	res_obj          = cJSON_CreateObject();
#if defined(SUPP_RULE_ENGINE)

	if (rule_id) {
		sscanf(rule_id, "rule:%d", &id);
		data = cJSON_CreateObject();
	} else {
		data = cJSON_CreateArray();
	}

	conf      *config = get_global_conf();
	conf_rule *cr     = &config->rule_eng;
	int        i      = 0;
	for (; i < cvector_size(cr->rules); i++) {
		if (rule_id) {
			if (cr->rules[i].rule_id == id) {
				get_rules_helper(data, &cr->rules[i]);
				break;
			}

		} else {
			cJSON *data_info = cJSON_CreateObject();
			get_rules_helper(data_info, &cr->rules[i]);
			cJSON_AddItemToArray(data, data_info);
		}
	}

	if (rule_id && cvector_size(cr->rules) == i) {
		cJSON_Delete(res_obj);
		cJSON_Delete(data);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    MISSING_KEY_REQUEST_PARAMES);
	}

	// cJSON *meta = cJSON_CreateObject();
	// cJSON_AddItemToObject(res_obj, "meta", meta);
	// TODO add meta content: page, limit, count
	cJSON_AddItemToObject(res_obj, "data", data);
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
#else
	cJSON_AddNumberToObject(res_obj, "code", PLUGIN_IS_CLOSED);
#endif

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static void *
get_client_info_cb(uint32_t pid)
{

	nng_pipe       pipe     = { .id = pid };
	conn_param    *cp       = nng_pipe_cparam(pipe);
	const uint8_t *clientid = conn_param_get_clientid(cp);
	conn_param_free(cp);
	return (void *) clientid;
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

	dbtree        *db = get_broker_db();
	dbtree_info ***vn =
	    (dbtree_info ***) dbtree_get_tree(db, get_client_info_cb);

	for (int i = 0; i < cvector_size(vn); i++) {
		cJSON *data_info_elem = cJSON_CreateArray();
		cJSON_AddItemToArray(data_info, data_info_elem);
		for (int j = 0; j < cvector_size(vn[i]); j++) {
			cJSON *elem = cJSON_CreateObject();
			cJSON_AddItemToArray(data_info_elem, elem);
			cJSON_AddStringToObject(
			    elem, "topic", vn[i][j]->topic);
			nng_free(vn[i][j]->topic, strlen(vn[i][j]->topic));
			cJSON_AddNumberToObject(
			    elem, "cld_cnt", vn[i][j]->cld_cnt);
			cJSON *clients = cJSON_CreateStringArray(
			    (const char *const *) vn[i][j]->clients,
			    cvector_size(vn[i][j]->clients));
			cvector_free(vn[i][j]->clients);
			nng_free(vn[i][j], sizeof(dbtree_info));
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
	char  *str = NULL;
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

	if (nng_strcasecmp(action, "stop") == 0) {
		argv[1] = "stop";
		cmd     = mk_str(2, argv, " ");
	} else if (nng_strcasecmp(action, "restart") == 0) {
		argv[1] = "restart";
		cmd     = mk_str(argc, argv, " ");
	}
	nng_strfree(action);
	if (cmd) {
		log_info("run system cmd: '%s'", cmd);
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

	if (nng_strcasecmp(type, "stop") == 0 ||
	    nng_strcasecmp(type, "restart") == 0) {
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
show_reload_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	enum result_code code = SUCCEED;

	conf *config = get_global_conf();

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	cJSON *data = get_reload_config(config);
	cJSON_AddItemToObject(res_obj, "data", data);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
post_reload_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *conf_data = cJSON_GetObjectItem(req, "data");
	conf * config    = get_global_conf();

	set_reload_config(conf_data, config);
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
// Update sub config file, create one if it is not exist. Partially Duplicated with update config
static http_msg
write_file(http_msg *msg)
{
	int  		 rv;
	char *path = NULL, *data;
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	conf * config    = get_global_conf();
	cJSON *conf_data = cJSON_GetObjectItem(req, "data");
	cJSON *item;
	getStringValue(conf_data, item, "path", path, rv);

	if (path == NULL) {
		if (config->conf_file == NULL) {
			cJSON_Delete(req);
			return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    	REQ_PARAM_ERROR);
		} else {
			path = config->conf_file;
			log_warn("Update default config file %s", path);
		}
	}
	if (!nano_file_exists(path)) {
		log_warn("Create new file %s! ", path);
	}

	getStringValue(conf_data, item, "content", data, rv);
	log_info("config content len %d", strlen(data));

	cJSON *hocon = (cJSON *)nng_hocon_parse_str(data, strlen(data));
	if (!cJSON_IsObject(hocon)) {
		cJSON_Delete(req);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    PARAMS_HOCON_FORMAT_ILLEGAL);
	}

	log_info("Writting to file %s", path);

	cJSON *res_obj = cJSON_CreateObject();
	int rc = nng_file_put(path, data, strlen(data));

	// nng_hocon_parse_str cause memleak in nng_hocon_parse_file
	// cJSON *jso2 = nng_hocon_parse_file(path);
	// if (!cJSON_IsObject(jso2)) {
	// 	cJSON_Delete(res_obj);
	// 	cJSON_Delete(req);
	// 	return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
	// 	    PARAMS_HOCON_FORMAT_ILLEGAL);
	// }
	// cJSON_Delete(jso2);

	if (0 != rc) {
		cJSON_AddNumberToObject(res_obj, "code", WRITE_CONFIG_FAILED);
		log_error("Error writing config to %s, error code: %s", config->conf_file, rc);
	} else {
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	}

	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	cJSON_Delete(hocon);
	return res;
}
//Update core config file.
static http_msg
update_config(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	conf * config    = get_global_conf();
	cJSON *req = (cJSON *)nng_hocon_parse_str(msg->data, msg->data_len);
	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    PARAMS_HOCON_FORMAT_ILLEGAL);
	}

	log_info("Writting new config to %s", config->conf_file);
	log_debug("%.*s", msg->data_len, msg->data);

	cJSON *res_obj = cJSON_CreateObject();
	int rc = nng_file_put(config->conf_file, msg->data, msg->data_len);
	if (0 != rc) {
		cJSON_AddNumberToObject(res_obj, "code", WRITE_CONFIG_FAILED);
		log_error("Error writing config to %s, error code: %s", config->conf_file, rc);
	} else {
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	}

	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;
}

static http_msg
get_config(http_msg *msg, const char *type)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	enum result_code code = SUCCEED;

	conf * config   = get_global_conf();
	cJSON *conf_obj = cJSON_CreateObject();

	if (type != NULL) {
		if (strcmp(type, "basic") == 0) {

			cJSON *basic = get_basic_config(config);
			cJSON_AddItemToObject(conf_obj, "basic", basic);

		} else if (strcmp(type, "tls") == 0) {

			cJSON *tls = get_tls_config(&config->tls, true);
			cJSON_AddItemToObject(conf_obj, "tls", tls);

		} else if (strcmp(type, "auth") == 0) {

			cJSON *auth = get_auth_config(&config->auths);
			cJSON_AddItemToObject(conf_obj, "auth", auth);

		} else if (strcmp(type, "auth_http") == 0) {

			cJSON *auth_http =
			    get_auth_http_config(&config->auth_http);
			cJSON_AddItemToObject(
			    conf_obj, "auth_http", auth_http);

		} else if (strcmp(type, "websocket") == 0) {

			cJSON *ws = get_websocket_config(&config->websocket);
			cJSON_AddItemToObject(conf_obj, "websocket", ws);

		} else if (strcmp(type, "http_server") == 0) {

			cJSON *http = get_http_config(&config->http_server);
			cJSON_AddItemToObject(conf_obj, "http_server", http);

		} else if (strcmp(type, "sqlite") == 0) {

			cJSON *sqlite = get_sqlite_config(&config->sqlite);
			cJSON_AddItemToObject(conf_obj, "sqlite", sqlite);

		} else if (strcmp(type, "bridge") == 0) {

			cJSON *bridge = get_bridge_config(&config->bridge, NULL);
			cJSON_AddItemToObject(conf_obj, "bridge", bridge);

		}
#ifdef SUPP_AWS_BRIDGE
		else if (strcmp(type, "aws_bridge") == 0) {
			cJSON *aws_bridge =
			    get_bridge_config(&config->aws_bridge, NULL);
			cJSON_AddItemToObject(
			    conf_obj, "aws_bridge", aws_bridge);
		}
#endif
		// TODO webhook ?
		// TODO log ?
		else {
			res.status = NNG_HTTP_STATUS_NOT_FOUND;
			code       = RPC_ERROR;
		}
	} else {
		cJSON *basic = get_basic_config(config);
		cJSON_AddItemToObject(conf_obj, "basic", basic);

		cJSON *tls = get_tls_config(&config->tls, true);
		cJSON_AddItemToObject(conf_obj, "tls", tls);

		cJSON *auth = get_auth_config(&config->auths);
		cJSON_AddItemToObject(conf_obj, "auth", auth);

		cJSON *auth_http = get_auth_http_config(&config->auth_http);
		cJSON_AddItemToObject(conf_obj, "auth_http", auth_http);

		cJSON *ws = get_websocket_config(&config->websocket);
		cJSON_AddItemToObject(conf_obj, "websocket", ws);

		cJSON *http = get_http_config(&config->http_server);
		cJSON_AddItemToObject(conf_obj, "http_server", http);

		cJSON *sqlite = get_sqlite_config(&config->sqlite);
		cJSON_AddItemToObject(conf_obj, "sqlite", sqlite);

		cJSON *bridge = get_bridge_config(&config->bridge, NULL);
		cJSON_AddItemToObject(conf_obj, "bridge", bridge);

#ifdef SUPP_AWS_BRIDGE
		cJSON *aws_bridge = get_bridge_config(&config->aws_bridge, NULL);
		cJSON_AddItemToObject(conf_obj, "aws_bridge", aws_bridge);
#endif
		// TODO webhook ?
		// TODO log ?
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);
	cJSON_AddItemToObject(res_obj, "data", conf_obj);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
post_config(http_msg *msg, const char *type)
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
		if (type != NULL) {
			cJSON *item;
			// shared by all sub feature section
			int  rv     = -1;
			bool enable = true;
			getBoolValue(conf_data, item, "enable", enable, rv);
			if (strcmp(type, "basic") == 0) {
				cJSON *basic =
				    cJSON_GetObjectItem(conf_data, "basic");
				if (cJSON_IsObject(basic)) {
					set_basic_config(basic, config);
				}

			} else if (strcmp(type, "tls") == 0) {
				cJSON *tls =
				    cJSON_GetObjectItem(conf_data, "tls");
				if (cJSON_IsObject(tls)) {
					set_tls_config(tls, config->conf_file,
					    &config->tls, "");
				}
			} else if (strcmp(type, "auth") == 0) {
				cJSON *auth =
				    cJSON_GetObjectItem(conf_data, "auth");
				if (cJSON_IsArray(auth)) {
					if (rv == 0)
						config->auths.enable = enable;
					set_auth_config(auth,
					    config->conf_file, &config->auths);
				}
			} else if (strcmp(type, "auth_http") == 0) {
				cJSON *auth_http = cJSON_GetObjectItem(
				    conf_data, "auth_http");
				if (cJSON_IsObject(auth_http)) {
					set_auth_http_config(auth_http,
					    config->conf_file, &config->auth_http);
				}
			} else if (strcmp(type, "websocket") == 0) {
				cJSON *ws = cJSON_GetObjectItem(
				    conf_data, "websocket");
				if (cJSON_IsObject(ws)) {
					set_websocket_config(ws,
					    config->conf_file,
					    &config->websocket);
				}
			} else if (strcmp(type, "http_server") == 0) {
				cJSON *http = cJSON_GetObjectItem(
				    conf_data, "http_server");
				if (cJSON_IsObject(http)) {
					set_http_config(http,
					    config->conf_file,
					    &config->http_server);
				}
			} else if (strcmp(type, "sqlite") == 0) {
				cJSON *sqlite =
				    cJSON_GetObjectItem(conf_data, "sqlite");
				if (cJSON_IsObject(sqlite)) {
					set_sqlite_config(sqlite,
					    config->conf_file, &config->sqlite,
					    "");
				}
			} else if (strcmp(type, "bridge") == 0) {
			}
#ifdef SUPP_AWS_BRIDGE
			else if (strcmp(type, "aws_bridge") == 0) {
			}
#endif

		} else {
			cJSON *basic = cJSON_GetObjectItem(conf_data, "basic");
			if (cJSON_IsObject(basic)) {
				set_basic_config(basic, config);
			}

			cJSON *tls = cJSON_GetObjectItem(conf_data, "tls");
			if (cJSON_IsObject(tls)) {
				set_tls_config(
				    tls, config->conf_file, &config->tls, "");
			}

			cJSON *auth = cJSON_GetObjectItem(conf_data, "auth");
			if (cJSON_IsArray(auth)) {
				set_auth_config(
				    auth, config->conf_file, &config->auths);
			}

			cJSON *auth_http =
			    cJSON_GetObjectItem(conf_data, "auth_http");
			if (cJSON_IsArray(auth_http)) {
				set_auth_http_config(auth_http,
				    config->conf_file, &config->auth_http);
			}

			cJSON *ws =
			    cJSON_GetObjectItem(conf_data, "websocket");
			if (cJSON_IsObject(ws)) {
				set_websocket_config(
				    ws, config->conf_file, &config->websocket);
			}

			cJSON *http =
			    cJSON_GetObjectItem(conf_data, "http_server");
			if (cJSON_IsObject(http)) {
				set_http_config(http, config->conf_file,
				    &config->http_server);
			}

			cJSON *sqlite =
			    cJSON_GetObjectItem(conf_data, "sqlite");
			if (cJSON_IsObject(sqlite)) {
				set_sqlite_config(sqlite, config->conf_file,
				    &config->sqlite, "");
			}

			// TODO bridge
			// TODO aws_bridge
			// TODO webhook
			// TODO log
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

static int
send_publish(nng_socket *sock, const char *clientid, char *payload,
    char **topics, size_t topic_count, uint8_t qos, uint8_t retain,
    bool encode_base64, bool decode_base64, property *props)
{
	int rv = 0;
	for (size_t i = 0; i < topic_count; i++) {
		nng_msg *pub_msg;
		nng_mqtt_msg_alloc(&pub_msg, 0);
		nng_mqtt_msg_set_packet_type(pub_msg, NNG_MQTT_PUBLISH);

		size_t payload_len = strlen(payload);
		if (encode_base64) {
			size_t out_size = BASE64_ENCODE_OUT_SIZE(payload_len);
			char * encode_data = nng_zalloc(out_size + 1);
			size_t len         = base64_encode(
                            (uint8_t *) payload, payload_len, encode_data);
			if (len > 0) {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, (uint8_t *) encode_data, len);
			} else {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, NULL, 0);
			}
			nng_strfree(encode_data);
		} else if(decode_base64){
			char * decode_data = nng_zalloc(payload_len);
			size_t len         = base64_decode(
							(uint8_t *) payload, payload_len, decode_data);
			if (len > 0) {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, (uint8_t *) decode_data, len);
			} else {
				nng_mqtt_msg_set_publish_payload(
				    pub_msg, NULL, 0);
			}
			nng_strfree(decode_data);
		} else {
			nng_mqtt_msg_set_publish_payload(
			    pub_msg, (uint8_t *) payload, payload_len);
		}
		nng_mqtt_msg_set_publish_qos(pub_msg, qos);
		nng_mqtt_msg_set_publish_retain(pub_msg, retain);
		nng_mqtt_msg_set_publish_topic(pub_msg, topics[i]);

		uint8_t protover = MQTT_PROTOCOL_VERSION_v311;
		if (props != NULL) {
			protover = MQTT_PROTOCOL_VERSION_v5;
			property *dup_prop;
			property_dup(&dup_prop, props);
			nng_mqtt_msg_set_publish_property(pub_msg, dup_prop);
		}

		nng_msg *msg = NULL;
		if ((rv = encode_common_mqtt_msg(
		              &msg, pub_msg, clientid, protover) != 0) ||
		    (rv = nng_sendmsg(*sock, msg, 0)) != 0) {
     			nng_msg_free(msg);
			break;
		}
	}
	property_free(props);
	return rv;
}

static int
properties_parse(property **properties, cJSON *json)
{
	cJSON *   item;
	int       rv        = 0;
	uint8_t   byte      = 0;
	uint16_t  word      = 0;
	uint32_t  dword     = 0;
	char *    str       = NULL;
	uint8_t * bytes     = NULL;
	property *prop_list = property_alloc();
	property *sub_prop;

	getNumberValue(json, item, "payload_format_indicator", byte, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_u8(PAYLOAD_FORMAT_INDICATOR, byte);
		property_append(prop_list, sub_prop);
	}

	getNumberValue(json, item, "message_expiry_interval", word, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_u16(MESSAGE_EXPIRY_INTERVAL, word);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "response_topic", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_str(
		    RESPONSE_TOPIC, str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "correlation_data", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_binary(
		    CORRELATION_DATA, (uint8_t *) str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	getNumberValue(json, item, "subscription_identifier	", dword, rv);
	if (rv == 0) {
		sub_prop =
		    property_set_value_varint(SUBSCRIPTION_IDENTIFIER, dword);
		property_append(prop_list, sub_prop);
	}

	getStringValue(json, item, "content_type", str, rv);
	if (rv == 0) {
		sub_prop = property_set_value_str(
		    CORRELATION_DATA, str, strlen(str), true);
		property_append(prop_list, sub_prop);
	}

	cJSON *prop_obj = cJSON_GetObjectItem(json, "user_properties");

	char number_str[50] = {0};

	cJSON_ArrayForEach(item, prop_obj)
	{
		if (cJSON_IsNumber(item)) {
			if (item->valuedouble - item->valueint == 0) {
				snprintf(number_str, 50, "%ld",
				    (long) item->valuedouble);
			} else {
				snprintf(
				    number_str, 50, "%lf", item->valuedouble);
			}
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), number_str,
		    strlen(number_str), true);
		}
		else if (cJSON_IsBool(item)) {
			snprintf(number_str, 50, "%s",
			    cJSON_IsTrue(item) ? "true" : "false");
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), number_str,
		    strlen(number_str), true);
		} else if (cJSON_IsString(item)) {
			sub_prop = property_set_value_strpair(USER_PROPERTY,
		    item->string, strlen(item->string), item->valuestring,
		    strlen(item->valuestring), true);
		} else {
			continue;
		}

		property_append(prop_list, sub_prop);
	}

	*properties = prop_list;
	return 0;

err:
	property_free(prop_list);
	return -1;
}

/**
 * send MQTT msg to broker socket
*/
static int
handle_publish_msg(cJSON *pub_obj, nng_socket *sock)
{
	cJSON *item;
	char   tmpid[]= "NanoMQ-HTTP-Client";
	int    rv;
	char * topic          = NULL;
	char **topics         = NULL;
	size_t topic_count    = 0;
	getStringValue(pub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		getStringValue(pub_obj, item, "topics", topic, rv);
		if (rv != 0) {
			goto out;
		}
		// split topic by ","
		char *temp = NULL;
		char *ptr  = nano_strtok(topic, ",", &temp);

		while (ptr != NULL) {
			topic_count++;
			char **new_topics = NULL;
			new_topics = realloc(topics, topic_count * sizeof(char *));
			if (new_topics == NULL) {
				goto out;
			}
			topics = new_topics;
			topics[topic_count - 1] = ptr;
			ptr = nano_strtok(NULL, ",", &temp);
		}
	} else {
		topics      = nng_zalloc(sizeof(char *));
		topics[0]   = topic;
		topic_count = 1;
	}
	// clientid
	char *clientid;
	getStringValue(pub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		// use default clientid
		clientid = tmpid;
	}
	// payload
	char *payload;
	getStringValue(pub_obj, item, "payload", payload, rv);
	if (rv != 0) {
		goto out;
	}
	// encoding
	char *encoding;

	getStringValue(pub_obj, item, "encoding", encoding, rv);
	if (rv != 0) {
		encoding = "plain";
	}

	// decoding
	char *decoding;
	getStringValue(pub_obj, item, "decoding", decoding, rv);
	if (rv != 0) {
		decoding = "plain";
	}

	// qos
	uint8_t qos = 0;
	getNumberValue(pub_obj, item, "qos", qos, rv);

	// retain
	bool retain = false;
	getBoolValue(pub_obj, item, "retain", retain, rv);

	// properties
	cJSON *json_prop = cJSON_GetObjectItem(pub_obj, "properties");
	property *props = NULL;
	if (cJSON_IsObject(json_prop)) {
		rv = properties_parse(&props, json_prop);
		if (rv != 0) {
			property_free(props);
			goto out;
		}
	}

	rv = send_publish(sock, clientid, payload, topics, topic_count, qos,
	    retain, strcmp(encoding, "base64") == 0, strcmp(decoding, "base64") == 0, props);
	if (topics) {
		free(topics);
	}
	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	if (topics) {
		free(topics);
	}
	return REQ_PARAM_ERROR;
}

static int
handle_subscribe_msg(cJSON *sub_obj, nng_socket *sock)
{
	int    rv;
	char  *topic       = NULL;
	char **topics      = NULL;
	size_t topic_count = 0;
	cJSON *item;
	getStringValue(sub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		getStringValue(sub_obj, item, "topics", topic, rv);
		if (rv != 0) {
			goto out;
		}
		// split topic by ","
		char *temp = NULL;
		char *ptr  = nano_strtok(topic, ",", &temp);

		while (ptr != NULL) {
			topic_count++;
			char **new_topics = NULL;
			new_topics = realloc(topics, topic_count * sizeof(char *));
			if (new_topics == NULL) {
				goto out;
			}
			topics = new_topics;
			topics[topic_count - 1] = ptr;
			ptr = nano_strtok(NULL, ",", &temp);
		}
	} else {
		topics      = nng_zalloc(sizeof(char *));
		topics[0]   = topic;
		topic_count = 1;
	}

	char *clientid = NULL;
	getStringValue(sub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		goto out;
	}

	uint8_t qos = 0;
	getNumberValue(sub_obj, item, "qos", qos, rv);

	uint32_t          pid   = 0;
	struct hashmap_s *table = get_hashmap();
	dbtree           *db    = get_broker_db();
	if (0 != (pid = nano_hashmap_get(table, clientid, strlen(clientid)))) {
#ifdef STATISTICS
		// TODO
#endif

		int   topic_index = 0;
		int   topic_len   = 0;
		char *topic_str   = NULL;
		bool  topic_exist = false;
		while (topic_index < topic_count) {
			topic_str = topics[topic_index];
			puts(topic_str);
			topic_len = strlen(topic_str);

			/* Add items which not included in dbhash */
			topic_exist = dbhash_check_topic(pid, topic_str);
			if (!topic_exist) {
				dbtree_insert_client(db, topic_str, pid);

				dbhash_insert_topic(pid, topic_str, qos);
			}

			topic_index++;
		}
	}
	dbtree_print(db);

	if (topics) {
		free(topics);
	}
	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	if (topics) {
		free(topics);
	}
	return REQ_PARAM_ERROR;
}

static int
handle_unsubscribe_msg(cJSON *sub_obj, nng_socket *sock)
{
	int    rv;
	char  *topic       = NULL;
	char **topics      = NULL;
	size_t topic_count = 0;
	cJSON *item;
	getStringValue(sub_obj, item, "topic", topic, rv);
	if (rv != 0) {
		goto out;
	}

	char *clientid = NULL;
	getStringValue(sub_obj, item, "clientid", clientid, rv);
	if (rv != 0) {
		goto out;
	}

	uint32_t          pid   = 0;
	struct hashmap_s *table = get_hashmap();
	dbtree           *db    = get_broker_db();
	if (0 != (pid = nano_hashmap_get(table, clientid, strlen(clientid)))) {
		sub_ctx_del(db, topic, pid);
	}

	dbtree_print(db);

	return rv != SUCCEED ? UNKNOWN_MISTAKE : rv;

out:
	return REQ_PARAM_ERROR;
}

/**
 * Post MQTT msg to broker via HTTP REST API
*/
static http_msg
post_mqtt_msg(http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	// send msg to broker via cb
	int rv = cb(req, sock);
	// return result code
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", rv);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);

	return res;
}

static http_msg
post_mqtt_msg_batch(http_msg *msg, nng_socket *sock, handle_mqtt_msg_cb cb)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsArray(req)) {
		goto out;
	}

	cJSON *temp;
	int rv = 0;
	int i;
	cJSON *res_arr = cJSON_CreateArray();
	for (i = 0; i < cJSON_GetArraySize(req); i++) {
		cJSON *item  = cJSON_GetArrayItem(req, i);
		char * topic = NULL;
		getStringValue(item, temp, "topics", topic, rv);
		if (rv != 0) {
			getStringValue(item, temp, "topic", topic, rv);
		}
		cJSON *res_item = cJSON_CreateObject();
		cJSON_AddStringToObject(res_item, "topic", topic);
		int code = cb(item, sock);
		cJSON_AddNumberToObject(res_item, "code", code);
		cJSON_AddItemToArray(res_arr, res_item);
	}
	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddItemToObject(res_obj, "data", res_arr);
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);
	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cJSON_Delete(req);
	return res;

out:
	if (!cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}
	return error_response(
	    msg, NNG_HTTP_STATUS_BAD_REQUEST, REQ_PARAMS_JSON_FORMAT_ILLEGAL);
}

#if NANO_PLATFORM_WINDOWS
// windows version memmem
static void *
memmem(const void *haystack, size_t haystack_len, const void *needle,
    size_t needle_len)
{
	if (needle_len == 0)
		return (void *) haystack;
	if (haystack_len < needle_len)
		return NULL;

	const unsigned char *h = (const unsigned char *) haystack;
	const unsigned char *n = (const unsigned char *) needle;

	for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
		if (memcmp(h + i, n, needle_len) == 0) {
			return (void *) (h + i);
		}
	}
	return NULL;
}
#endif

char *
parse_formdata_file(char *data, int len, int *retlen)
{
	char *pattern = "Content-Type: application/octet-stream\r\n\r\n";
	//log_info("pattern sz:%d", strlen(pattern));
	char split[80] = {0}; // boundary  RFC 1341 (MIME) max 70 bytes
	int split_sz = 0;
	for (int i=0; i<len-1; ++i) {
		if (data[i] == '\r' && data[i+1] == '\n') {
			memcpy(split, data, i);
			split_sz = i;
			break;
		}
	}
	if (split_sz <= 0 || split[0] != '-')
		return NULL;
	log_debug("split sz:%d %s", split_sz, split);
	char *pos = memmem(data, len, pattern, strlen(pattern));
	if (pos == NULL) {
		log_error("failed to found file in formdata [%.*s]", len, data);
		return NULL;
	}
	pos += strlen(pattern);
	char *split_pos = memmem(pos, len - (pos-data) - 1, split, split_sz);
	if (split_pos == NULL) {
		log_error("failed to found end of file content [%.*s]", len, data);
		return NULL;
	}
	log_debug("start %d end %d len %d", (pos - data), (split_pos - data), len);
	int file_sz = split_pos - pos - 2;
	char *file = nng_alloc(sizeof(char) * file_sz + 1);
	memcpy(file, pos, file_sz);
	if (file[file_sz-1] == '\n') {
		file[file_sz-1] = '\0';
	} else
		file[file_sz] = '\0';
	log_info("license (%d)[%.*s]\n", file_sz, file_sz, file);
	*retlen = file_sz;
	return file;
}

static http_msg
post_license_update(http_msg *msg)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	int rv;
	char dest[128];
	char *lic_path;
	char *body;
	//log_info("http request(%d)[%.*s]\n", msg->data_len, msg->data_len, msg->data);

#if defined(SUPP_LICENSE_STD)
	if (msg->data_len == 0) {
		log_error("http request's length of body is invalid %d", msg->data_len);
		res.status = NNG_HTTP_STATUS_BAD_REQUEST;
		return res;
	}
	//body = strndup(msg->data, msg->data_len);
	int body_len = 0;
	body = parse_formdata_file(msg->data, msg->data_len, &body_len);
	if (body == NULL || body_len == 0) {
		log_error("http request's is not formdata %d or invalid license file", body_len);
		res.status = NNG_HTTP_STATUS_BAD_REQUEST;
		sprintf(dest, "{\"code\":%d}", NNG_EINVAL);
		put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
		return res;
	}
	if ((rv = lic_std_renew(body)) != 0) {
		log_error("renew failed %d", rv);
		sprintf(dest, "{\"code\":%d}", rv);
		nng_free(body, 0);
		put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
		return res;
	}
	if ((lic_path = lic_std_path()) != NULL) {
		if ((rv = nng_file_put(lic_path, body, body_len)) == 0) {
			log_info("lic is updated %s", body);
			sprintf(dest, "{\"code\":0}");
		} else {
			log_error("failed to write to lic %d", rv);
			sprintf(dest, "{\"code\":%d}", rv);
		}
		nng_free(lic_path, 0);
	} else {
		log_error("failed to get lic path");
		sprintf(dest, "{\"code\":%d}", NNG_EINVAL);
	}
#else
	log_error("license is disabled");
	res.status = NNG_HTTP_STATUS_NOT_FOUND;
	return res;
#endif
	nng_free(body, 0);
	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	return res;
}

static http_msg
get_logs_latest(http_msg *msg, kv **params, size_t param_num)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	int rv = 0;
	int lines = 0, page = 0, totallines = 0;
	for (int i=0; i<param_num; ++i) {
		if (0 == strcmp(params[i]->key, "lines")) {
			lines = atoi(params[i]->value);
		} else if (0 == strcmp(params[i]->key, "page")) {
			page = atoi(params[i]->value);
		}
	}
	if (page < 0 || lines < 1 || lines > 256) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAM_ERROR);
	}

	// read file
	char  logs_path[512];
	conf *config = get_global_conf();
	if (config && config->log.dir) {
		char *dir = config->log.dir;
		char *fname = config->log.file;
		if (!fname)
			fname = (char *)"nanomq.log";
#if NANO_PLATFORM_WINDOWS
		if (dir[strlen(dir)] != '\\') {
			sprintf(logs_path, "%s/%s", dir, config->log.file);
		} else {
			sprintf(logs_path, "%s%s", dir, config->log.file);
		}
#else
		if (dir[strlen(dir)] != '/') {
			sprintf(logs_path, "%s/%s", dir, config->log.file);
		} else {
			sprintf(logs_path, "%s%s", dir, config->log.file);
		}
#endif
	} else {
		log_warn("configuration or log.dir unavailable");
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    CONTENT_NOT_AVAILABLE);
	}
	log_info("lines:%d page:%d log path %s", lines, page, logs_path);

	char *logs_ct = NULL;
	size_t logs_ct_sz;

#ifdef NANO_PLATFORM_WINDOWS
	FILE *fp = _fsopen(logs_path, "r", _SH_DENYNO);
	if (NULL != fp) {
		fseek(fp, 0, SEEK_END);
		int cap = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		if (cap <= 0) {
			int werrno = GetLastError();
			log_warn("failed to read offset of %s lasterror%d", logs_path, werrno);
			rv = NNG_EEXIST;
		} else {
			int   pos = 0;
			char *str = malloc(sizeof(char) * cap + 1);
			if (str == NULL) {
				rv = NNG_ENOMEM;
			} else {
				memset(str, 0, cap + 1);
				pos = fread(str, 1, cap, fp);
				if (pos == 0) {
					rv = NNG_EINVAL;
				}
				logs_ct_sz = pos;
				logs_ct = str;
			}
		}
		fclose(fp);
	} else {
		int werrno = GetLastError();
		log_warn("failed to read log file %s lasterror%d", logs_path, werrno);
		rv = NNG_EEXIST;
	}
#else
	rv = nng_file_get(logs_path, (void **)&logs_ct, &logs_ct_sz);
#endif

	if (rv != 0) {
		log_warn("failed to read log file %s rv%d", logs_path, rv);
		if (logs_ct)
			free(logs_ct);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    UNKNOWN_MISTAKE);
	}
	// construct result
	cJSON *res_obj = cJSON_CreateObject();
	char *start_pos = logs_ct;
	int slice_sz = 0;
	int slice_lines = 0;
	for (int i=0; i<(int)logs_ct_sz; ++i) {
		if (logs_ct[i] == '\n') {
			slice_lines ++;
			if (slice_lines == lines || i == logs_ct_sz-1) {
				slice_sz ++;
				if (slice_sz == page + 1) {
					logs_ct[i] = '\0';
					cJSON *slice = cJSON_CreateStringReference((const char *)start_pos);
					if (!slice) {
						log_error("failed to create slice(%s)", start_pos);
						break;
					}
					cJSON_AddItemToObject(res_obj, "contents", slice);
					// break;
				}
				start_pos = logs_ct + i + 1;
				slice_lines = 0;
			}
			totallines ++;
		}
	}

	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddNumberToObject(res_obj, "totallines", totallines);

	char *dest = cJSON_PrintUnformatted(res_obj);

	cJSON_Delete(res_obj);
	nng_free(logs_ct, 0);
	if (!dest) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    CONTENT_NOT_AVAILABLE);
	}
	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	return res;
}

static http_msg
get_logs_full(http_msg *msg, kv **params, size_t param_num)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	int rv;
	char *type = NULL;
	for (int i=0; i<param_num; ++i) {
		if (0 == strcmp(params[i]->key, "type")) {
			type = params[i]->value;
		}
	}

	if (type == NULL || strcmp(type, "tar") != 0) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAM_ERROR);
	}

	// get direct
	char *logs_dir = NULL;
	char *logs_file = NULL;
	conf *config = get_global_conf();
	if (config && config->log.dir && config->log.file) {
		logs_dir = config->log.dir;
		logs_file = config->log.file;
	} else {
		log_warn("configuration or log.dir or log.file unavailable");
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    CONTENT_NOT_AVAILABLE);
	}

	// exec tar and get content of tarball
	if (strlen(logs_dir) + strlen(logs_file) + 40 > 1024
			|| strlen(logs_dir) > 512 || strlen(logs_file) > 512) {
		log_warn("path and filename of logs files are too long. length of each should less than 512");
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST, UNKNOWN_MISTAKE);
	}

	char logs_tar_cmd[1024];
	sprintf(logs_tar_cmd, "(cd %s && tar -czf edge-logs.tar.gz %s*)", logs_dir, logs_file);
	log_info("type:%s logdir:%s file:%s cmd:%s", type, logs_dir, logs_file, logs_tar_cmd);

#if NANO_PLATFORM_WINDOWS
	log_warn("get_logs_full is unavailable on windows");
	return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
	    CONTENT_NOT_AVAILABLE);
#else
	if ((rv = nano_cmd_run(logs_tar_cmd)) != 0) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
			CONTENT_NOT_AVAILABLE);
	}
#endif

	char  logs_tar_path[512];
	char *logs_tar_ct;
	size_t logs_tar_ct_sz;
#if NANO_PLATFORM_WINDOWS
	if (logs_dir[strlen(logs_dir)] != '\\') {
		sprintf(logs_tar_path, "%s/%s", logs_dir, "edge-logs.tar.gz");
	} else {
		sprintf(logs_tar_path, "%s%s", logs_dir, "edge-logs.tar.gz");
	}
#else
	if (logs_dir[strlen(logs_dir)] != '/') {
		sprintf(logs_tar_path, "%s/%s", logs_dir, "edge-logs.tar.gz");
	} else {
		sprintf(logs_tar_path, "%s%s", logs_dir, "edge-logs.tar.gz");
	}
#endif

	rv = nng_file_get(logs_tar_path, (void **)&logs_tar_ct, &logs_tar_ct_sz);
	if (rv != 0) {
		log_warn("failed to read log tarball %s", logs_tar_path);
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    UNKNOWN_MISTAKE);
	}

	// construct result
	put_http_msg(&res, "application/gzip", NULL, NULL, NULL, logs_tar_ct, logs_tar_ct_sz);

	nng_free(logs_tar_ct, logs_tar_ct_sz);
	return res;
}

static http_msg
post_tools_aes_enc(http_msg *msg)
{
	(void) msg;
	http_msg res = { .status = NNG_HTTP_STATUS_OK };
	char *dest = NULL;
#if defined(SUPP_LICENSE_STD) || defined(SUPP_PARQUET)
	int    rv = 0;
	char  *plain;
	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	cJSON *data;
	getStringValue(req, data, "data", plain, rv);
	if (rv != 0) {
		log_error("Parameter data can not be found in request json");
		cJSON_Delete(req);
		return error_response(
		    msg, NNG_HTTP_STATUS_GONE, REQ_PARAM_ERROR);
	}
	if (plain) {
		int   len = 0;
		char *cipher = aes_gcm_encrypt(plain,
				strlen(plain), NANO_AES_KEY_BRIDGE, &len);
		if (cipher == NULL || len == 0) {
			log_error("aes enc failed");
			cJSON_Delete(req);
			return error_response(
					msg, NNG_HTTP_STATUS_GONE, REQ_PARAM_ERROR);
		} else {
			char *cipher_b64 = nng_alloc(len * 2);
			size_t cipher_b64_sz = base64_encode((uint8_t *)cipher, len, cipher_b64);
			if (cipher_b64_sz <= 0) {
				log_error("base64 encode failed");
				cJSON_Delete(req);
				nng_free(cipher_b64, 0);
				return error_response(
						msg, NNG_HTTP_STATUS_GONE, REQ_PARAM_ERROR);
			} else {
				dest = malloc(cipher_b64_sz + 32);
				sprintf(dest, "{\"data\":\"%s\"}", cipher_b64);
			}
			nng_free(cipher_b64, 0);
			nng_free(cipher, 0);
		}
	}
	cJSON_Delete(req);
#else
	dest = nng_strdup("{}");
	log_error("aes enc tool unavailable. compile with it first");
	res.status = NNG_HTTP_STATUS_NOT_FOUND;
#endif
	put_http_msg(&res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	nng_free(dest, 0);
	return res;
}


// Used for get config file
static http_msg
get_file_content(http_msg *msg, char *path)
{
	int  		 rv;
	char 		*data;

	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	if (path == NULL) {
		conf * config = get_global_conf();
		path = config->conf_file;
	}
	if (!nano_file_exists(path)) {
		return error_response(
		    msg, NNG_HTTP_STATUS_GONE, REQ_PARAM_ERROR);
	}
	cJSON *file_json = cJSON_CreateObject();
	file_load_data(path, (void **)&data);
	cJSON_AddStringOrNullToObject(file_json, "path", path);
	cJSON_AddStringOrNullToObject(file_json, "content", data);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", file_json);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	nng_free(data, strlen(data));
	return res;
}

static http_msg
get_mqtt_bridge(http_msg *msg, const char *name)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	conf * config    = get_global_conf();

	cJSON *bridge_json = cJSON_CreateObject();

	cJSON *bridge = get_bridge_config(&config->bridge, name);
	cJSON_AddItemToObject(bridge_json, "bridge", bridge);

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	cJSON_AddItemToObject(res_obj, "data", bridge_json);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;
}

static http_msg
put_mqtt_bridge(http_msg *msg, const char *name)
{
	int rv = 0;
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	cJSON *node_obj = cJSON_GetObjectItem(req, name);
	conf * config   = get_global_conf();

	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	nng_mtx_lock(config->restapi_lk);
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node     = bridge->nodes[i];
		bool              tenable  = node->enable;
		size_t            parallel = node->parallel;

		if (name != NULL && strcmp(node->name, name) != 0) {
			continue;
		}
		node->enable = false;
		if (node->dialer != NULL)
			nng_dialer_off(*node->dialer);

		nng_mtx_lock(node->mtx);
		conf_bridge_node_destroy(node);	// TODO potential dead lock here!!
		conf_bridge_node_parse(node, &bridge->sqlite, node_obj);
#if defined(SUPP_LICENSE_STD) || defined(SUPP_PARQUET)
		conf_bridge_node_parse_cipher_password(node, NANO_AES_KEY_BRIDGE);
#endif
		node->parallel = parallel;
		log_info("Bridge Reload with %.*s", msg->data_len, msg->data);
		bridge->nodes[i] = node;
		// restart bridge client, parameters: config, node, node->sock
		if ((rv = bridge_reload(node->sock, config, node)) != 0) {
			// Error might happened in reload bridge
			log_warn("bridge reload failed!");
			nng_mtx_unlock(node->mtx);
		} else {
			nng_mtx_unlock(node->mtx);
			found = true;
			if (node->enable == true) {
				log_info("enabled bridge %s by reload!", node->name);
				nng_dialer_set_bool(*node->dialer, NNG_OPT_BRIDGE_SET_EP_CLOSED, false);
				if ((rv = nng_dialer_start(*node->dialer, NNG_FLAG_NONBLOCK)) != 0) {
					log_warn("turn on bridge %s failed! %d", name, rv);
				} else {
					log_warn("successfully turn on bridge %s", name);
				}
			}
		}
		break;
	}
	nng_mtx_unlock(config->restapi_lk);

	if (found && rv == 0) {
		cJSON *res_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
		char *dest = cJSON_PrintUnformatted(res_obj);

		put_http_msg(&res, "application/json", NULL, NULL, NULL, dest,
		    strlen(dest));

		cJSON_free(dest);
		cJSON_Delete(res_obj);
		cJSON_Delete(req);
		return res;
	} else if (rv == -1 || rv == -2) {
		cJSON_Delete(req);
		return error_response(
		    msg, NNG_HTTP_STATUS_FORBIDDEN, REQ_PARAM_ERROR);
	} else if (rv != 0) {
		cJSON_Delete(req);
		return error_response(
		    msg, NNG_HTTP_STATUS_FORBIDDEN, UNKNOWN_MISTAKE);
	} else {
		cJSON_Delete(req);
		return error_response(
		    msg, NNG_HTTP_STATUS_NOT_FOUND, ILLEGAL_SUBJECT);
	}
}

static http_msg
put_mqtt_bridge_switch(http_msg *msg, const char *name)
{
	http_msg res = { .status = NNG_HTTP_STATUS_OK };

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);

	if (!cJSON_IsObject(req)) {
		return error_response(msg, NNG_HTTP_STATUS_BAD_REQUEST,
		    REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	}
	int  		 rv;
	bool         found = false;
	bool         bridge_switch;
	cJSON       *conf_data = cJSON_GetObjectItem(req, "data");
	cJSON       *item;
	conf        *config = get_global_conf();
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node = bridge->nodes[i];
		if (name != NULL && strcmp(node->name, name) != 0) {
			continue;
		}
		getBoolValue(
		    conf_data, item, "bridge_switch", bridge_switch, rv);
		if (rv == 0) {
			found = true;
			log_info("processing bridge switch %d for %s",bridge_switch, name);
			nng_dialer *dialer = node->dialer;
			if (bridge_switch == true) {
				nng_dialer_set_bool(*dialer, NNG_OPT_BRIDGE_SET_EP_CLOSED, false);
				if ((rv = nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK)) != 0) {
					log_warn("turn on bridge %s failed! %d", name, rv);
				} else {
					log_warn("successfully turn on bridge %s", name);
					node->enable = bridge_switch;
				}
			} else if (bridge_switch == false) {
				nng_dialer_set_bool(*dialer, NNG_OPT_BRIDGE_SET_EP_CLOSED, true);
				if ((rv = nng_dialer_off(*dialer)) != 0) {
					log_warn("turn off bridge %s failed! %d", name, rv);
				} else {
					log_warn("successfully turn off bridge %s", name);
					node->enable = bridge_switch;
				}
			}
		}
	}
	// NNG_ENOENT dialer not found
	// NNG_ENOMEM no mem
	// NNG_ESTATE
	if (found && rv == 0) {
		cJSON *res_obj = cJSON_CreateObject();
		cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
		char *dest = cJSON_PrintUnformatted(res_obj);

		put_http_msg(&res, "application/json", NULL, NULL, NULL, dest,
		    strlen(dest));

		cJSON_free(dest);
		cJSON_Delete(res_obj);
		cJSON_Delete(req);
		return res;
	} else if (rv == NNG_ESTATE) {
		cJSON_Delete(req);
		log_warn("change %s bridge state failed!", name);
		return error_response(
		    msg, NNG_HTTP_STATUS_ALREADY_REPORTED, REQ_PARAM_ERROR);
	} else if (!found) {
		cJSON_Delete(req);
		log_warn("no such bridge: %s!", name);
		return error_response(
		    msg, NNG_HTTP_STATUS_FORBIDDEN, ILLEGAL_SUBJECT);
	} else if (rv != 0) {
		cJSON_Delete(req);
		log_warn("change %s bridge is failed!", name);
		return error_response(
		    msg, NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR, rv);
	}
}

static void
free_user_property(conf_user_property **prop, size_t sz)
{
	if (sz > 0 && prop) {
		for (size_t i = 0; i < sz; i++) {
			if (prop[i]) {
				if (prop[i]->key) {
					free(prop[i]->key);
				}
				if (prop[i]->value) {
					free(prop[i]->value);
				}
				free(prop[i]);
			}
		}
		cvector_free(prop);
		prop = NULL;
	}
}

static void
free_sub_property(conf_bridge_sub_properties *prop)
{
	if (prop) {
		free_user_property(
		    prop->user_property, prop->user_property_size);
		prop->user_property_size = 0;
		prop->identifier         = 0;
		free(prop);
		prop = NULL;
	}
}

static void
free_topic_list(topics **list, size_t count)
{
	if (list && count > 0) {
		for (size_t i = 0; i < count; i++) {
			if (list[i]->remote_topic) {
				nng_free(list[i]->remote_topic, list[i]->remote_topic_len);
				list[i]->remote_topic = NULL;
			}
			if (list[i]->local_topic) {
				nng_free(list[i]->local_topic, list[i]->local_topic_len);
				list[i]->local_topic = NULL;
			}

			nng_free(list[i], sizeof(topics));
		}
		cvector_free(list);
		list = NULL;
	}
}

static void
free_string_list(char **list, size_t count)
{
	if (list && count > 0) {
		for (size_t i = 0; i < count; i++) {
			if (list[i]) {
				free(list[i]);
				list[i] = NULL;
			}
		}
		cvector_free(list);
		list = NULL;
	}
}

static nng_mqtt_topic_qos *
convert_topic_qos(topics **list, size_t count)
{
	nng_mqtt_topic_qos *topics = nng_mqtt_topic_qos_array_create(count);
	for (size_t i = 0; i < count; i++) {
		nng_mqtt_topic_qos_array_set(topics, i, list[i]->remote_topic,
		    list[i]->qos, 1, list[i]->retain_as_published,
		    list[i]->retain_handling);
	}
	return topics;
}

static nng_mqtt_topic *
convert_topic(char **list, size_t count)
{
	nng_mqtt_topic *topics = nng_mqtt_topic_array_create(count);

	for (size_t i = 0; i < count; i++) {
		nng_mqtt_topic_array_set(topics, i, list[i]);
	}
	return topics;
}

static http_msg
post_mqtt_bridge_sub(http_msg *msg, const char *name)
{
	// node, [topic, qos], property
	http_msg             res    = { .status = NNG_HTTP_STATUS_OK };
	enum nng_http_status status = NNG_HTTP_STATUS_OK;
	int                  code   = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsObject(req)) {
		goto out;
	}

	cJSON *data_obj = cJSON_GetObjectItem(req, "data");
	if (!cJSON_IsObject(data_obj)) {
		goto out;
	}

	cJSON *sub_array = cJSON_GetObjectItem(data_obj, "subscription");

	if (!cJSON_IsArray(sub_array)) {
		goto out;
	}

	size_t   array_size = cJSON_GetArraySize(sub_array);

	topics **sub_topics = NULL;
	size_t   sub_count  = 0;

	cJSON *item;
	int    rv = 0;

	// Get topic list
	for (size_t i = 0; i < array_size; i++) {
		topics *tp = nng_zalloc(sizeof(topics));
		// default value for qos, rap and rh.
		uint8_t qos          = 0;
		uint8_t rap          = 1;
		uint8_t rh           = 0;
		char   *remote_topic = NULL;
		char   *local_topic  = NULL;
		cJSON  *sub_item = cJSON_GetArrayItem(sub_array, i);
		getNumberValue(sub_item, item, "qos", qos, rv);
		getNumberValue(sub_item, item, "retain_as_published", rap, rv);
		getNumberValue(sub_item, item, "retain_handling", rh, rv);
		getStringValue(sub_item, item, "remote_topic", remote_topic, rv);
		if (rv == 0) {
			tp->remote_topic     = nng_strdup(remote_topic);
			tp->remote_topic_len = strlen(tp->remote_topic);
		} else {
			nng_free(tp, sizeof(topics));
			continue;
		}
		getStringValue(sub_item, item, "local_topic", local_topic, rv);
		if (rv == 0) {
			tp->local_topic     = nng_strdup(local_topic);
			tp->local_topic_len = strlen(tp->local_topic);
		} else {
			nng_free(tp, sizeof(topics));
			continue;
		}
		tp->qos                 = qos;
		tp->retain_as_published = rap;
		tp->retain_handling     = rh;
		cvector_push_back(sub_topics, tp);
		sub_count++;
	}

	// Get properties
	cJSON *json_prop = cJSON_GetObjectItem(data_obj, "sub_properties");
	conf_bridge_sub_properties *sub_props = NULL;

	if (cJSON_IsObject(json_prop)) {
		sub_props = nng_zalloc(sizeof(conf_bridge_sub_properties));
		getNumberValue(
		    json_prop, item, "identifier", sub_props->identifier, rv);
		cJSON *up_array =
		    cJSON_GetObjectItem(json_prop, "user_properties");
		size_t up_count = cJSON_GetArraySize(up_array);

		conf_user_property **conf_ups = NULL;

		for (size_t i = 0; i < up_count; i++) {
			char *key   = NULL;
			char *value = NULL;

			getStringValue(json_prop, item, "key", key, rv);
			if (rv == 0) {
				getStringValue(
				    json_prop, item, "value", value, rv);
				if (rv == 0) {
					conf_user_property *up = nng_zalloc(
					    sizeof(conf_user_property));
					up->key   = nng_strdup(key);
					up->value = nng_strdup(value);
					cvector_push_back(conf_ups, up);
				}
			}
		}
		sub_props->user_property      = conf_ups;
		sub_props->user_property_size = cvector_size(conf_ups);
	}

	conf *config = get_global_conf();

	rv = 0;
	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node = bridge->nodes[i];

		nng_mtx_lock(node->mtx);
		if (name != NULL && strcmp(node->name, name) != 0) {
			nng_mtx_unlock(node->mtx);
			continue;
		}
		nng_mtx_unlock(node->mtx);

		// Decode properties to nng_mqtt_property
		property *prop_list = NULL;
		if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
			if (cJSON_IsObject(json_prop)) {
				properties_parse(&prop_list, json_prop);
			}
		}

		found = true;

		// convert sub_topics to nng_mqtt_topic_qos
		nng_mqtt_topic_qos *topic_list = convert_topic_qos(sub_topics, sub_count);

		// handle subscribe
		rv = bridge_subscribe(node->sock, node, topic_list, sub_count, prop_list);

		if (rv == 0) {
			// Add to sub_list in node only when bridge_subscribe successfully
			nng_mtx_lock(node->mtx);
			if (sub_count > 0) {
				// TODO handle repeated topics
				cvector_copy(sub_topics, node->sub_list);
				node->sub_count += sub_count;
			}
			if (sub_props != NULL) {
				free_sub_property(node->sub_properties);
				node->sub_properties = sub_props;
			}
			nng_mtx_unlock(node->mtx);
		}

		nng_mqtt_topic_qos_array_free(topic_list, sub_count);
		break;
	}

	if (!found || rv != 0) {
		if (!found) {
			status = NNG_HTTP_STATUS_NOT_FOUND;
		} else if (rv != 0)
			status = NNG_HTTP_STATUS_BAD_REQUEST;
		code   = REQ_PARAM_ERROR;
		free_sub_property(sub_props);
		free_topic_list(sub_topics, sub_count);
		goto out;
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_Delete(req);
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	cvector_free(sub_topics);
	return res;

out:
	if (cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}

	return error_response(msg,
	    status == NNG_HTTP_STATUS_NOT_FOUND ? status
	                                        : NNG_HTTP_STATUS_BAD_REQUEST,
	    (code == REQ_PARAM_ERROR ? code : REQ_PARAMS_JSON_FORMAT_ILLEGAL));
}

static http_msg
post_mqtt_bridge_unsub(http_msg *msg, const char *name)
{
	http_msg             res    = { .status = NNG_HTTP_STATUS_OK };
	enum nng_http_status status = NNG_HTTP_STATUS_OK;
	int                  code   = SUCCEED;

	cJSON *req = cJSON_ParseWithLength(msg->data, msg->data_len);
	if (!cJSON_IsObject(req)) {
		goto out;
	}

	cJSON *data_obj = cJSON_GetObjectItem(req, "data");
	if (!cJSON_IsObject(data_obj)) {
		goto out;
	}

	// Get unsub topic list
	cJSON *unsub_array = cJSON_GetObjectItem(data_obj, "unsubscription");
	if (!cJSON_IsArray(unsub_array)) {
		goto out;
	}

	char **  unsub_topics = NULL;
	size_t   unsub_count  = 0;

	cJSON *item;
	int    rv = 0;

	size_t   array_size = cJSON_GetArraySize(unsub_array);

	for (size_t i = 0; i < array_size; i++) {
		cJSON * unsub_item = cJSON_GetArrayItem(unsub_array, i);
		char *topic = NULL;
		getStringValue(unsub_item, item, "topic", topic, rv);
		if (rv == 0) {
			topic     = nng_strdup(topic);
		} else {
			continue;
		}
		cvector_push_back(unsub_topics, topic);
		unsub_count++;
	}

	conf *config = get_global_conf();

	rv = 0;
	bool         found  = false;
	conf_bridge *bridge = &config->bridge;
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node = bridge->nodes[i];
		nng_mtx_lock(node->mtx);
		if (name != NULL && strcmp(node->name, name) != 0) {
			nng_mtx_unlock(node->mtx);
			continue;
		}
		if (!node->enable) {
			nng_mtx_unlock(node->mtx);
			continue;
		}
		nng_mtx_unlock(node->mtx);

		// Get properties
		property *prop_list = NULL;
		if (node->proto_ver == MQTT_VERSION_V5) {
			cJSON *json_prop =
			    cJSON_GetObjectItem(data_obj, "unsub_properties");

			if (cJSON_IsObject(json_prop)) {
				properties_parse(&prop_list, json_prop);
			}
		}

		found = true;

		// convert unsub_topics to nng_mqtt_topic
		nng_mqtt_topic *topic_list = convert_topic(unsub_topics, unsub_count);

		// handle unsubscribe
		// TODO params: config, node, node->sock, topic_list, unsub_count, prop_list
		rv = bridge_unsubscribe(node->sock, node, topic_list, unsub_count, prop_list);

		nng_mqtt_topic_array_free(topic_list, unsub_count);

		if (rv != 0) {
			break;
		}

		nng_mtx_lock(node->mtx);
		for (size_t i = 0; i < unsub_count; i++) {
			char *unsub_topic = unsub_topics[i];
			for (size_t j = 0; j < node->sub_count; j++) {
				topics *sub_topic = node->sub_list[j];
				if (strcmp(unsub_topic,
				        sub_topic->remote_topic) == 0) {

					cvector_erase(node->sub_list, j);
					node->sub_count--;
					nng_free(sub_topic->remote_topic,
					    sub_topic->remote_topic_len);
					nng_free(sub_topic->local_topic,
					    sub_topic->local_topic_len);
					nng_free(sub_topic, sizeof(topics));
					break;
				}
			}
		}
		nng_mtx_unlock(node->mtx);
		break;
	}

	free_string_list(unsub_topics, unsub_count);

	if (!found || rv != 0) {
		if (!found)
			status = NNG_HTTP_STATUS_NOT_FOUND;
		else if (rv != 0)
			status = NNG_HTTP_STATUS_BAD_REQUEST;

		code   = REQ_PARAM_ERROR;
		goto out;
	}

	cJSON *res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", SUCCEED);
	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &res, "application/json", NULL, NULL, NULL, dest, strlen(dest));

	cJSON_Delete(req);
	cJSON_free(dest);
	cJSON_Delete(res_obj);
	return res;

out:
	if (cJSON_IsObject(req)) {
		cJSON_Delete(req);
	}

	return error_response(msg,
	    status == NNG_HTTP_STATUS_NOT_FOUND ? status
	                                        : NNG_HTTP_STATUS_BAD_REQUEST,
	    (code == REQ_PARAM_ERROR ? code : REQ_PARAMS_JSON_FORMAT_ILLEGAL));
}
