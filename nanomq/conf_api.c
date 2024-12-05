#include "conf_api.h"
#include "include/mqtt_api.h"
#include "include/nanomq.h"

#include "nng/protocol/pipeline0/push.h"
#include "include/webhook_inproc.h"

static nng_socket *hook_sock = NULL;

static cJSON *get_auth_http_req_config(conf_auth_http_req *req);

#define update_string(var, value) \
	if (var != NULL) {        \
		nng_strfree(var); \
	}                         \
	var = nng_strdup(value);

#define update_var(var, value) var = value

cJSON *
get_reload_config(conf *config)
{
	cJSON *data = cJSON_CreateObject();

	cJSON_AddNumberToObject(data, "property_size", config->property_size);
	cJSON_AddNumberToObject(
	    data, "max_packet_size", config->max_packet_size / 1024);
	cJSON_AddNumberToObject(data, "client_max_packet_size",
	    config->client_max_packet_size / 1024);
	cJSON_AddNumberToObject(data, "msq_len", config->msq_len);
	cJSON_AddNumberToObject(data, "qos_duration", config->qos_duration);
	cJSON_AddNumberToObject(
	    data, "keepalive_backoff", (double) config->backoff);
	cJSON_AddBoolToObject(
	    data, "allow_anonymous", config->allow_anonymous);
	cJSON_AddBoolToObject(
	    data, "enable_mqtt_stream", config->parquet.enable);
	cJSON_AddBoolToObject(
	    data, "bridge_mode", config->bridge_mode);
	return data;
}

cJSON *
get_basic_config(conf *config)
{
	cJSON *basic = cJSON_CreateObject();
	cJSON_AddStringOrNullToObject(basic, "url", config->url);
	cJSON_AddNumberToObject(
	    basic, "num_taskq_thread", config->num_taskq_thread);
	cJSON_AddNumberToObject(
	    basic, "max_taskq_thread", config->max_taskq_thread);
	cJSON_AddNumberToObject(basic, "parallel", config->parallel);
	cJSON_AddNumberToObject(basic, "property_size", config->property_size);
	cJSON_AddBoolToObject(basic, "daemon", config->daemon);
	cJSON_AddNumberToObject(
	    basic, "max_packet_size", config->max_packet_size / 1024);
	cJSON_AddNumberToObject(basic, "client_max_packet_size",
	    config->client_max_packet_size / 1024);
	cJSON_AddNumberToObject(basic, "msq_len", config->msq_len);
	cJSON_AddNumberToObject(basic, "qos_duration", config->qos_duration);
	cJSON_AddNumberToObject(
	    basic, "keepalive_backoff", (double) config->backoff);
	cJSON_AddBoolToObject(
	    basic, "allow_anonymous", config->allow_anonymous);
	cJSON_AddBoolToObject(basic, "ipc_internal", config->ipc_internal);

	return basic;
}

cJSON *
get_tls_config(conf_tls *tls, bool is_server)
{
	cJSON *tls_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(tls_obj, "enable", tls->enable);
	cJSON_AddStringOrNullToObject(tls_obj, "url", tls->url);
	cJSON_AddStringOrNullToObject(
	    tls_obj, "key_password", tls->key_password);
	cJSON_AddStringOrNullToObject(tls_obj, "key", tls->key);
	cJSON_AddStringOrNullToObject(tls_obj, "cert", tls->cert);
	cJSON_AddStringOrNullToObject(tls_obj, "cacert", tls->ca);
	cJSON_AddBoolToObject(tls_obj, "verify_peer", tls->verify_peer);
	cJSON_AddBoolToObject(tls_obj, "fail_if_no_peer_cert", tls->set_fail);
	return tls_obj;
}

cJSON *
get_auth_config(conf_auth *auth)
{
	cJSON *auth_arr = cJSON_CreateArray();
	for (size_t i = 0; i < auth->count; i++) {
		cJSON *item = cJSON_CreateObject();
		// TODO Does the password need to be encrypted ?
		cJSON_AddStringOrNullToObject(
		    item, "login", auth->usernames[i]);
		cJSON_AddStringOrNullToObject(
		    item, "password", auth->passwords[i]);

		cJSON_AddItemToArray(auth_arr, item);
	}

	return auth_arr;
}

static cJSON *
get_auth_http_req_config(conf_auth_http_req *req)
{
	cJSON *req_obj = cJSON_CreateObject();
	cJSON_AddStringOrNullToObject(req_obj, "url", req->url);
	cJSON_AddStringOrNullToObject(req_obj, "method", req->method);
	cJSON *headers = cJSON_CreateObject();
	for (size_t i = 0; i < req->header_count; i++) {
		cJSON_AddStringToObject(
		    headers, req->headers[i]->key, req->headers[i]->value);
	}
	cJSON_AddItemToObject(req_obj, "headers", headers);

	cJSON *params = cJSON_CreateArray();
	for (size_t i = 0; i < req->param_count; i++) {
		cJSON *param = cJSON_CreateString(req->params[i]->name);
		cJSON_AddItemToArray(params, param);
	}

	cJSON_AddItemToObject(req_obj, "params", params);

	cJSON *tls = get_tls_config(&req->tls, false);
	cJSON_AddItemToObject(req_obj, "tls", tls);

	return req_obj;
}

cJSON *
get_auth_http_config(conf_auth_http *auth_http)
{
	cJSON *auth_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(auth_obj, "enable", auth_http->enable);
	cJSON_AddNumberToObject(auth_obj, "timeout", auth_http->timeout);
	cJSON_AddNumberToObject(
	    auth_obj, "connect_timeout", auth_http->connect_timeout);
	cJSON_AddNumberToObject(auth_obj, "pool_size", auth_http->pool_size);

	cJSON *auth_req  = get_auth_http_req_config(&auth_http->auth_req);
	cJSON *acl_req   = get_auth_http_req_config(&auth_http->acl_req);
	cJSON *super_req = get_auth_http_req_config(&auth_http->super_req);

	cJSON_AddItemToObject(auth_obj, "auth_req", auth_req);
	cJSON_AddItemToObject(auth_obj, "acl_req", acl_req);
	cJSON_AddItemToObject(auth_obj, "super_req", super_req);

	return auth_obj;
}

cJSON *
get_websocket_config(conf_websocket *ws)
{
	cJSON *ws_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(ws_obj, "enable", ws->enable);
	cJSON_AddStringOrNullToObject(ws_obj, "url", ws->url);
	cJSON_AddStringOrNullToObject(ws_obj, "tls_url", ws->tls_url);

	return ws_obj;
}

cJSON *
get_http_config(conf_http_server *http)
{
	cJSON *http_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(http_obj, "enable", http->enable);
	cJSON_AddNumberToObject(http_obj, "port", http->port);
	cJSON_AddStringOrNullToObject(http_obj, "username", http->username);
	cJSON_AddStringOrNullToObject(http_obj, "password", http->password);
	cJSON_AddStringToObject(
	    http_obj, "auth_type", http->auth_type == JWT ? "jwt" : "basic");
	return http_obj;
}

cJSON *
get_sqlite_config(conf_sqlite *sqlite)
{
	cJSON *sqlite_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(sqlite_obj, "enable", sqlite->enable);
	cJSON_AddNumberToObject(
	    sqlite_obj, "disk_cache_size", sqlite->disk_cache_size);
	cJSON_AddNumberToObject(
	    sqlite_obj, "flush_mem_threshold", sqlite->flush_mem_threshold);
	cJSON_AddNumberToObject(
	    sqlite_obj, "resend_interval", sqlite->resend_interval);
	cJSON_AddStringOrNullToObject(
	    sqlite_obj, "mounted_file_path", sqlite->mounted_file_path);
	return sqlite_obj;
}

cJSON *
get_user_properties(conf_user_property **up, size_t count)
{
	if (count > 0) {
		cJSON *user_properties = cJSON_CreateArray();
		for (size_t i = 0; i < count; i++) {
			cJSON *item = cJSON_CreateObject();
			cJSON_AddStringToObject(item, "key", up[i]->key);
			cJSON_AddStringToObject(item, "value", up[i]->value);
			cJSON_AddItemToArray(user_properties, item);
		}
		return user_properties;
	} else {
		return NULL;
	}
}

cJSON *
get_bridge_connector(conf_bridge_node *node)
{
	cJSON *connector = cJSON_CreateObject();

	cJSON_AddStringToObject(connector, "server", node->address);
	cJSON_AddNumberToObject(connector, "proto_ver", node->proto_ver);
	cJSON_AddStringOrNullToObject(connector, "clientid", node->clientid);
	cJSON_AddBoolToObject(connector, "clean_start", node->clean_start);
	cJSON_AddStringOrNullToObject(connector, "username", node->username);
	cJSON_AddStringOrNullToObject(connector, "password", node->password);
	cJSON_AddNumberToObject(connector, "keepalive", node->keepalive);

	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		if (node->conn_properties != NULL) {
			conf_bridge_conn_properties *conn_prop =
			    node->conn_properties;
			cJSON *conn_prop_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(conn_prop_obj,
			    "session_expiry_interval",
			    conn_prop->session_expiry_interval);
			cJSON_AddNumberToObject(conn_prop_obj,
			    "receive_maximum", conn_prop->receive_maximum);
			cJSON_AddNumberToObject(conn_prop_obj,
			    "maximum_packet_size",
			    conn_prop->maximum_packet_size);
			cJSON_AddNumberToObject(conn_prop_obj,
			    "topic_alias_maximum",
			    conn_prop->topic_alias_maximum);
			cJSON_AddBoolToObject(conn_prop_obj,
			    "request_response_information",
			    conn_prop->request_response_info);
			cJSON_AddBoolToObject(conn_prop_obj,
			    "request_problem_information",
			    conn_prop->request_problem_info);

			if (conn_prop->user_property_size) {
				cJSON *user_properties = get_user_properties(conn_prop->user_property,
				    conn_prop->user_property_size);
				cJSON_AddItemToObject(conn_prop_obj,
				    "user_properties", user_properties);
			}

			cJSON_AddItemToObject(
			    connector, "conn_properties", conn_prop_obj);
		}

		if (node->will_properties != NULL) {
			conf_bridge_conn_will_properties *will_prop =
			    node->will_properties;
			cJSON *will_prop_obj = cJSON_CreateObject();
			cJSON_AddNumberToObject(will_prop_obj,
			    "payload_format_indicator",
			    will_prop->payload_format_indicator);
			cJSON_AddNumberToObject(will_prop_obj,
			    "message_expiry_interval",
			    will_prop->message_expiry_interval);
			cJSON_AddStringToObject(will_prop_obj,
			    "content_type", will_prop->content_type);
			cJSON_AddNumberToObject(will_prop_obj,
			    "will_delay_interval",
			    will_prop->will_delay_interval);
			cJSON_AddStringToObject(will_prop_obj,
			    "response_topic", will_prop->response_topic);
			cJSON_AddStringToObject(will_prop_obj,
			    "correlation_data", will_prop->correlation_data);

			if (will_prop->user_property_size) {
				cJSON *user_properties = get_user_properties(
				    will_prop->user_property,
				    will_prop->user_property_size);
				cJSON_AddItemToObject(will_prop_obj,
				    "user_properties", user_properties);
			}

			cJSON_AddItemToObject(
			    connector, "will_properties", will_prop_obj);
		}
	}

	return connector;
}

cJSON *
get_bridge_sub_properties(conf_bridge_node *node)
{
	if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5 &&
	    node->sub_properties) {
		conf_bridge_sub_properties *sub_prop = node->sub_properties;
		cJSON *sub_prop_obj                  = cJSON_CreateObject();
		cJSON_AddNumberToObject(
		    sub_prop_obj, "identifier", sub_prop->identifier);

		if (sub_prop->user_property_size) {
			cJSON *user_properties =
			    get_user_properties(sub_prop->user_property,
			        sub_prop->user_property_size);
			cJSON_AddItemToObject(
			    sub_prop_obj, "user_properties", user_properties);
		}

		return sub_prop_obj;
	}
	return NULL;
}

static void
add_time_field(cJSON *obj, const char *key, uint64_t second)
{
	char time[100] = { 0 };
	snprintf(time, 100, "%zus", second);
	//FIXME It's more reasonable to use 'ms' .
	cJSON_AddStringToObject(obj, key, time);
}

static void
add_bridge_quic(cJSON *obj, conf_bridge_node *node)
{
#if defined(SUPP_QUIC)
	add_time_field(obj, "quic_keepalive", node->qkeepalive);
	
	add_time_field(
	    obj, "quic_idle_timeout", (uint64_t)node->qidle_timeout);
	add_time_field(
	    obj, "quic_discon_timeout", (uint64_t)node->qdiscon_timeout);
	// add_time_field(
	//     obj, "quic_handshake_timeout", node->quic_handshake_timeout);
	add_time_field(
	    obj, "quic_send_idle_timeout", (uint64_t)node->qsend_idle_timeout);
	add_time_field(
	    obj, "quic_initial_rtt_ms", (uint64_t)node->qinitial_rtt_ms);
	add_time_field(
	    obj, "quic_max_ack_delay_ms", (uint64_t)node->qmax_ack_delay_ms);
	cJSON_AddBoolToObject(obj, "quic_multi_stream", node->multi_stream);
	cJSON_AddBoolToObject(obj, "hybrid_bridging", node->hybrid);
	cJSON_AddBoolToObject(obj, "quic_qos_priority", node->qos_first);
	cJSON_AddBoolToObject(obj, "quic_0rtt", node->quic_0rtt);
#endif
}

cJSON *
get_bridge_config(conf_bridge *bridge, const char *node_name)
{
	cJSON *bridge_obj        = cJSON_CreateObject();
	
	cJSON *bridge_node_obj = cJSON_CreateArray();
	for (size_t i = 0; i < bridge->count; i++) {
		if (node_name != NULL &&
		    strcmp(node_name, bridge->nodes[i]->name) != 0) {
			continue;
		}

		conf_bridge_node *node     = bridge->nodes[i];
		cJSON *           node_obj = cJSON_CreateObject();
		cJSON_AddStringOrNullToObject(node_obj, "name", node->name);
		cJSON_AddBoolToObject(node_obj, "enable", node->enable);
		cJSON_AddNumberToObject(node_obj, "parallel", node->parallel);

		cJSON *connector = get_bridge_connector(node);

		cJSON_AddItemToObject(node_obj, "connector", connector);

		cJSON *pub_infos = cJSON_CreateArray();
		for (size_t j = 0; j < node->forwards_count; j++) {
			cJSON * pub_obj = cJSON_CreateObject();
			topics *pub     = node->forwards_list[j];
			cJSON_AddStringOrNullToObject(
				pub_obj, "remote_topic", pub->remote_topic);
			cJSON_AddStringOrNullToObject(
				pub_obj, "local_topic", pub->local_topic);
			cJSON_AddItemToArray(pub_infos, pub_obj);
		}
		cJSON_AddItemToObject(node_obj, "forwards", pub_infos);

		cJSON *sub_infos = cJSON_CreateArray();
		for (size_t j = 0; j < node->sub_count; j++) {
			cJSON * sub_obj = cJSON_CreateObject();
			topics *sub     = node->sub_list[j];
			cJSON_AddStringOrNullToObject(
			    sub_obj, "remote_topic", sub->remote_topic);
			cJSON_AddStringOrNullToObject(
			    sub_obj, "local_topic", sub->local_topic);
			cJSON_AddNumberToObject(sub_obj, "qos", sub->qos);
			cJSON_AddItemToArray(sub_infos, sub_obj);
		}

		cJSON_AddItemToObject(node_obj, "subscription", sub_infos);

		if (node->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
			cJSON *sub_properties =
			    get_bridge_sub_properties(node);
			cJSON_AddItemToObject(
			    node_obj, "sub_properties", sub_properties);
		}

		cJSON *tls = get_tls_config(&node->tls, false);
		cJSON_AddItemToObject(node_obj, "tls", tls);
		cJSON_AddItemToArray(bridge_node_obj, node_obj);

		add_bridge_quic(node_obj, node);
	}

	cJSON_AddItemToObject(bridge_obj, "nodes", bridge_node_obj);
#if defined(NNG_SUPP_SQLITE)
	cJSON *bridge_sqlite_obj = get_sqlite_config(&bridge->sqlite);
	cJSON_AddItemToObject(bridge_obj, "sqlite", bridge_sqlite_obj);
#endif

	return bridge_obj;
}

void
set_reload_config(cJSON *json, conf *config)
{
	int      property_size;
	bool     allow_anonymous;
	uint32_t max_packet_size;
	uint32_t client_max_packet_size;
	int      msq_len;
	uint32_t qos_duration;
	float    backoff;
	bool     enable_mqtt_stream;

	cJSON *item;
	int    rv;

	getNumberValue(json, item, "property_size", property_size, rv);
	if (rv == 0) {
		update_var(config->property_size, property_size);
	}
	getNumberValue(json, item, "msq_len", msq_len, rv);
	if (rv == 0) {
		update_var(config->msq_len, msq_len);
	}
	getNumberValue(json, item, "qos_duration", qos_duration, rv);
	if (rv == 0) {
		update_var(config->qos_duration, qos_duration);
	}
	getBoolValue(json, item, "allow_anonymous", allow_anonymous, rv);
	if (rv == 0) {
		update_var(config->allow_anonymous, allow_anonymous);
	}
	getNumberValue(json, item, "max_packet_size", max_packet_size, rv);
	if (rv == 0) {
		update_var(config->max_packet_size, max_packet_size * 1024);
	}
	getNumberValue(
	    json, item, "client_max_packet_size", client_max_packet_size, rv);
	if (rv == 0) {
		update_var(config->client_max_packet_size,
		    client_max_packet_size * 1024);
	}
	getNumberValue(json, item, "msq_len", msq_len, rv);
	if (rv == 0) {
		update_var(config->msq_len, msq_len);
	}
	getNumberValue(json, item, "qos_duration", qos_duration, rv);
	if (rv == 0) {
		update_var(config->qos_duration, qos_duration);
	}
	getNumberValue(json, item, "keepalive_backoff", backoff, rv);
	if (rv == 0) {
		update_var(config->backoff, backoff);
	}
	getBoolValue(json, item, "enable_mqtt_stream", enable_mqtt_stream, rv);
	if (rv == 0) {
		bool enable_mqtt_stream_before = config->parquet.enable;
		// Update first. Is error happened in follow codes. revert.
		update_var(config->parquet.enable, enable_mqtt_stream);

		if (enable_mqtt_stream_before == true &&
		    enable_mqtt_stream == false) {
			if (hook_sock == NULL) {
				hook_sock = nng_alloc(sizeof(nng_socket));
				if (0 != nng_push0_open(hook_sock)) {
					log_error("error in update enable "
					          "mqtt stream, hook open");
					update_var(config->parquet.enable,
					    enable_mqtt_stream_before);
					return;
				}
				char *hook_ipc_url =
				    config->hook_ipc_url == NULL
				    ? HOOK_IPC_URL
				    : config->hook_ipc_url;
				if (0 !=
				    nng_dial(
				        *hook_sock, hook_ipc_url, NULL, 0)) {
					log_error("error in update enable "
					          "mqtt stream, hook dial");
					update_var(config->parquet.enable,
					    enable_mqtt_stream_before);
					return;
				}
			}
			// send a msg to trigger MQ clean
			cJSON *obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "id", EXTERNAL2NANO_IPC);
			cJSON_AddStringToObject(obj, "cmd", "stop");
			char *json = cJSON_PrintUnformatted(obj);
			int   rc   = nng_send(
                            *hook_sock, json, strlen(json), NNG_FLAG_ALLOC);
			if (rc != 0) {
				log_error("error in update enable mqtt "
				          "stream, hook sending");
				update_var(config->parquet.enable,
				    enable_mqtt_stream_before);
				free(json);
				cJSON_Delete(obj);
				return;
			}
			log_info("cmd for update enable mqtt stream was sent");
			cJSON_Delete(obj);
		} else if (enable_mqtt_stream_before == false &&
		    enable_mqtt_stream == true) {
			log_info("Parquet & MQ service restarted");
		}
	}
}

void
set_basic_config(cJSON *json, conf *config)
{
	char *   url = NULL;
	bool     daemon;
	bool     enable;
	int      num_taskq_thread;
	int      max_taskq_thread;
	uint64_t parallel;
	int      property_size;
	bool     allow_anonymous;
	bool     ipc_internal;
	uint32_t max_packet_size;
	uint32_t client_max_packet_size;
	int      msq_len;
	uint32_t qos_duration;
	float    backoff;

	cJSON *item;
	int    rv;
	getStringValue(json, item, "url", url, rv);
	if (rv == 0) {
		// conf_update(config->conf_file, "url", url);
		update_string(config->url, url);
	}
	getBoolValue(json, item, "enable", enable, rv);
	if (rv == 0) {
		// conf_update_bool(config->conf_file, "enable", enable);
		update_var(config->enable, enable);
	}
	getBoolValue(json, item, "daemon", daemon, rv);
	if (rv == 0) {
		// conf_update_bool(config->conf_file, "daemon", daemon);
		update_var(config->daemon, daemon);
	}
	getNumberValue(json, item, "num_taskq_thread", num_taskq_thread, rv);
	if (rv == 0) {
		// conf_update_int(
		//     config->conf_file, "num_taskq_thread",
		//     num_taskq_thread);
		update_var(config->num_taskq_thread, num_taskq_thread);
	}
	getNumberValue(json, item, "max_taskq_thread", max_taskq_thread, rv);
	if (rv == 0) {
		// conf_update_int(
		//     config->conf_file, "max_taskq_thread",
		//     max_taskq_thread);
		update_var(config->max_taskq_thread, max_taskq_thread);
	}
	getNumberValue(json, item, "parallel", parallel, rv);
	if (rv == 0) {
		// conf_update_u64(config->conf_file, "parallel", parallel);
		update_var(config->parallel, parallel);
	}
	getNumberValue(json, item, "property_size", property_size, rv);
	if (rv == 0) {
		// conf_update_int(
		// config->conf_file, "property_size", property_size);
		update_var(config->property_size, property_size);
	}
	getNumberValue(json, item, "msq_len", msq_len, rv);
	if (rv == 0) {
		// conf_update_int(config->conf_file, "msq_len", msq_len);
		update_var(config->msq_len, msq_len);
	}
	getNumberValue(json, item, "qos_duration", qos_duration, rv);
	if (rv == 0) {
		// conf_update_int(
		// config->conf_file, "qos_duration", qos_duration);
		update_var(config->qos_duration, qos_duration);
	}
	getBoolValue(json, item, "allow_anonymous", allow_anonymous, rv);
	if (rv == 0) {
		// conf_update_bool(
		// config->conf_file, "allow_anonymous", allow_anonymous);
		update_var(config->allow_anonymous, allow_anonymous);
	}
	getBoolValue(json, item, "ipc_internal", ipc_internal, rv);
	if (rv == 0) {
		// conf_update_bool(
		// config->conf_file, "ipc_internal", ipc_internal);
		update_var(config->ipc_internal, ipc_internal);
	}
	getNumberValue(json, item, "max_packet_size", max_packet_size, rv);
	if (rv == 0) {
		// conf_update_u32(
		// config->conf_file, "max_packet_size", max_packet_size);
		update_var(config->max_packet_size, max_packet_size * 1024);
	}
	getNumberValue(
	    json, item, "client_max_packet_size", client_max_packet_size, rv);
	if (rv == 0) {
		// conf_update_u32(config->conf_file, "client_max_packet_size",
		// client_max_packet_size);
		update_var(config->client_max_packet_size,
		    client_max_packet_size * 1024);
	}
	getNumberValue(json, item, "msq_len", msq_len, rv);
	if (rv == 0) {
		// conf_update_int(config->conf_file, "msq_len", msq_len);
		update_var(config->msq_len, msq_len);
	}
	getNumberValue(json, item, "qos_duration", qos_duration, rv);
	if (rv == 0) {
		// conf_update_u32(
		// config->conf_file, "qos_duration", qos_duration);
		update_var(config->qos_duration, qos_duration);
	}
	getNumberValue(json, item, "keepalive_backoff", backoff, rv);
	if (rv == 0) {
		// conf_update_double(
		// config->conf_file, "keepalive_backoff", backoff);
		update_var(config->backoff, backoff);
	}
}

void
set_tls_config(
    cJSON *json, const char *conf_path, conf_tls *tls, const char *key_prefix)
{
	int   rv;
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

	cJSON *item;

	getBoolValue(json, item, "enable", tls_enable, rv);
	if (rv == 0) {
		// conf_update2_bool(
		// conf_path, key_prefix, "", "tls.enable", tls_enable);
		update_var(tls->enable, tls_enable);
	}
	getStringValue(json, item, "url", tls_url, rv);
	if (rv == 0) {
		// conf_update(conf_path, "tls.url", tls_url);
		update_string(tls->url, tls_url);
	}
	getStringValue(json, item, "keypass", tls_keypass, rv);
	if (rv == 0) {
		// conf_update(conf_path, "tls.keypass", tls_keypass);
		update_string(tls->key_password, tls_keypass);
	}
	getStringValue(json, item, "key", tls_key, rv);
	if (rv == 0) {
		// if (tls->keyfile == NULL) {
		// 	memset(dir, 0, 1024);
		// 	if (nano_getcwd(dir, sizeof(dir)) != NULL) {
		// 		path_len =
		// 		    strlen(dir) + strlen("/key.pem") + 1;
		// 		tls->keyfile = nng_zalloc(path_len);
		// 		strcat(tls->keyfile, dir);
		// 		strcat(tls->keyfile, "/key.pem");
		// 		conf_update(
		// 		    conf_path, "tls.keyfile", tls->keyfile);
		// 	}
		// }
		// file_write_string(tls->keyfile, tls_key);
		update_string(tls->key, tls_key);
	}
	getStringValue(json, item, "cert", tls_cert, rv);
	if (rv == 0) {
		// if (tls->certfile == NULL) {
		// 	memset(dir, 0, 1024);
		// 	if (nano_getcwd(dir, sizeof(dir)) != NULL) {
		// 		path_len =
		// 		    strlen(dir) + strlen("/cert.pem") + 1;
		// 		tls->certfile = nng_zalloc(path_len);
		// 		strcat(tls->certfile, dir);
		// 		strcat(tls->certfile, "/cert.pem");
		// 		conf_update(
		// 		    conf_path, "tls.certfile", tls->certfile);
		// 	}
		// }
		// file_write_string(tls->certfile, tls_cert);
		update_string(tls->cert, tls_cert);
	}
	getStringValue(json, item, "cacert", tls_cacert, rv);
	if (rv == 0) {
		// if (tls->cafile == NULL) {
		// 	memset(dir, 0, 1024);
		// 	if (nano_getcwd(dir, sizeof(dir)) != NULL) {
		// 		path_len =
		// 		    strlen(dir) + strlen("/cacert.pem") + 1;
		// 		tls->cafile = nng_zalloc(path_len);
		// 		strcat(tls->cafile, dir);
		// 		strcat(tls->cafile, "/cacert.pem");
		// 		conf_update(
		// 		    conf_path, "tls.cacertfile", tls->cafile);
		// 	}
		// }
		// file_write_string(tls->cafile, tls_cacert);
		update_string(tls->ca, tls_cacert);
	}
	getBoolValue(json, item, "verify_peer", tls_verify_peer, rv);
	if (rv == 0) {
		// conf_update_bool(
		//     conf_path, "tls.verify_peer", tls_verify_peer);
		update_var(tls->verify_peer, tls_verify_peer);
	}
	getBoolValue(
	    json, item, "fail_if_no_peer_cert", tls_fail_if_no_peer_cert, rv);
	if (rv == 0) {
		// conf_update_bool(conf_path, "tls.fail_if_no_peer_cert",
		//     tls_fail_if_no_peer_cert);
		update_var(tls->set_fail, tls_fail_if_no_peer_cert);
	}
}

void
set_http_config(cJSON *json, const char *conf_path, conf_http_server *http)
{
	cJSON *item;
	int    rv;

	bool     http_enable;
	uint16_t http_port;
	char *   http_username = NULL;
	char *   http_password = NULL;
	char *   auth_type     = NULL;
	getBoolValue(json, item, "enable", http_enable, rv);
	if (rv == 0) {
		// conf_update_bool(conf_path, "http_server.enable",
		// http_enable);
		update_var(http->enable, http_enable);
	}
	getNumberValue(json, item, "port", http_port, rv);
	if (rv == 0) {
		// conf_update_u16(conf_path, "http_server.port", http_port);
		update_var(http->port, http_port);
	}
	getStringValue(json, item, "username", http_username, rv);
	if (rv == 0) {
		// conf_update(conf_path, "http_server.username",
		// http_username);
		update_string(http->username, http_username);
	}
	getStringValue(json, item, "password", http_password, rv);
	if (rv == 0) {
		// conf_update(conf_path, "http_server.password",
		// http_password);
		update_string(http->password, http_password);
	}
	getStringValue(json, item, "auth_type", auth_type, rv);
	if (rv == 0) {
		if (strcmp("basic", auth_type) == 0) {
			// conf_update(
			//     conf_path, "http_server.auth_type", auth_type);
			update_var(http->auth_type, BASIC);
		} else if (strcmp("jwt", auth_type) == 0) {
			// conf_update(
			//     conf_path, "http_server.auth_type", auth_type);
			update_var(http->auth_type, JWT);
		}
	}
}

void
set_websocket_config(cJSON *json, const char *conf_path, conf_websocket *ws)
{
	int    rv;
	cJSON *item;
	bool   ws_enable;
	char * ws_url;
	char * ws_tls_url;

	getBoolValue(json, item, "enable", ws_enable, rv);
	if (rv == 0) {
		// conf_update_bool(conf_path, "websocket.enable", ws_enable);
		update_var(ws->enable, ws_enable);
	}
	getStringValue(json, item, "url", ws_url, rv);
	if (rv == 0) {
		// conf_update(conf_path, "websocket.url", ws_url);
		update_string(ws->url, ws_url);
	}
	getStringValue(json, item, "tls_url", ws_tls_url, rv);
	if (rv == 0) {
		// conf_update(conf_path, "websocket.tls_url", ws_tls_url);
		update_string(ws->tls_url, ws_tls_url);
	}
}

void
set_sqlite_config(cJSON *json, const char *conf_path, conf_sqlite *sqlite,
    const char *key_prefix)
{
	int    rv;
	cJSON *item;
	bool   sqlite_enable;
	char * mount_path;
	size_t disk_cache_size;
	size_t mem_cache_size;
	size_t resend_interval;

	getBoolValue(json, item, "enable", sqlite_enable, rv);
	if (rv == 0) {
		// conf_update2_bool(
		//     conf_path, key_prefix, "", "sqlite.enable",
		//     sqlite_enable);
		update_var(sqlite->enable, sqlite_enable);
	}
	getStringValue(json, item, "mounted_file_path", mount_path, rv);
	if (rv == 0) {
		// conf_update2(conf_path, key_prefix, "",
		// "sqlite.mounted_file_path", mount_path);
		update_string(sqlite->mounted_file_path, mount_path);
	}
	getNumberValue(json, item, "disk_cache_size", disk_cache_size, rv);
	if (rv == 0) {
		// conf_update2_u64(conf_path, key_prefix, "",
		// "sqlite.disk_cache_size", disk_cache_size);
		update_var(sqlite->disk_cache_size, disk_cache_size);
	}
	getNumberValue(json, item, "flush_mem_threshold", mem_cache_size, rv);
	if (rv == 0) {
		// conf_update2_u64(conf_path, key_prefix, "",
		// "sqlite.flush_mem_threshold", mem_cache_size);
		update_var(sqlite->flush_mem_threshold, mem_cache_size);
	}
	getNumberValue(json, item, "resend_interval", resend_interval, rv);
	if (rv == 0) {
		// conf_update2_u64(conf_path, key_prefix, "",
		// "sqlite.resend_interval", resend_interval);
		update_var(sqlite->resend_interval, resend_interval);
	}
}

void
set_auth_config(cJSON *json, const char *conf_path, conf_auth *auth)
{
	int sz = cJSON_GetArraySize(json);

	size_t user_count = auth->count;
	cJSON *item;
	int    rv;

	for (size_t i = 0; i < sz; i++) {
		cJSON *kv = cJSON_GetArrayItem(json, i);
		char * username = NULL, *password = NULL;
		getStringValue(kv, item, "login", username, rv);
		getStringValue(kv, item, "password", password, rv);

		if (username && password) {
			// char key2[10] = { 0 };
			// snprintf(key2, sizeof(key2), "%zu", i + 1);
			// conf_update2(
			//     conf_path, "auth.", key2, ".login", username);
			// conf_update2(
			//     conf_path, "auth.", key2, ".password",
			//     password);

			if (user_count <= i) {
				auth->count++;
				auth->usernames = realloc(auth->usernames,
				    (auth->count) * sizeof(char *));
				auth->passwords = realloc(auth->passwords,
				    (auth->count) * sizeof(char *));
			}
			update_string(auth->usernames[i], username);
			update_string(auth->passwords[i], password);
		}
	}
}

static size_t
str_append(char **dest, const char *str)
{
	char *old_str = *dest == NULL ? "" : (*dest);
	char *new_str =
	    calloc(strlen(old_str) + strlen(str) + 1, sizeof(char));

	strcat(new_str, old_str);
	strcat(new_str, str == NULL ? "" : str);

	if (*dest) {
		free(*dest);
	}
	*dest = new_str;
	return strlen(new_str);
}

static void
set_auth_http_req(cJSON *json, const char *conf_path, conf_auth_http_req *req,
    const char *key_prefix)
{
	int    rv;
	cJSON *item;
	char * url;
	char * method;

	getStringValue(json, item, "url", url, rv);
	if (rv == 0) {
		// conf_update2(conf_path, key_prefix, "", "url", url);
		update_string(req->url, url);
	}

	getStringValue(json, item, "method", method, rv);
	if (rv == 0) {
		// conf_update2(conf_path, key_prefix, "", "method", method);
		update_string(req->method, method);
	}

	cJSON *headers = cJSON_GetObjectItem(json, "headers");

	size_t header_count = req->header_count;

	int index = 0;
	cJSON_ArrayForEach(item, headers)
	{
		if (cJSON_IsString(item)) {
			char *key   = item->string;
			char *value = item->valuestring;

			// conf_update2(
			//     conf_path, key_prefix, "headers.", key, value);
			if (header_count <= index) {
				req->header_count++;
				req->headers = realloc(req->headers,
				    (req->header_count) * sizeof(char *));
			}
			update_string(req->headers[index]->key, key);
			update_string(req->headers[index]->value, value);
			index++;
		}
	}

	// char *param_str = NULL;
	if (cJSON_HasObjectItem(json, "params")) {
		cJSON *params = cJSON_GetObjectItem(json, "params");

		conf_http_param **req_param   = req->params;
		size_t            param_count = req->param_count;
		for (size_t i = 0; i < param_count; i++) {
			if (req_param[i]->name) {
				free(req->params[i]->name);
			}
			free(req->params[i]);
			req->params[i] = NULL;
		}
		req_param = realloc(req_param,
		    sizeof(conf_http_param *) * cJSON_GetArraySize(params));

		index = 0;
		cJSON_ArrayForEach(item, params)
		{
			char *arg        = cJSON_GetStringValue(item);
			req_param[index] = nng_zalloc(sizeof(conf_http_param));
			if (nng_strcasecmp(arg, "username") == 0) {
				// str_append(&param_str, "username");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%u");
				update_string(
				    req_param[index]->name, "username");
				update_var(req_param[index]->type, USERNAME);
			} else if (nng_strcasecmp(arg, "password") == 0) {
				// str_append(&param_str, "password");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%P");
				update_string(
				    req_param[index]->name, "password");
				update_var(req_param[index]->type, PASSWORD);
			} else if (nng_strcasecmp(arg, "clientid") == 0) {
				// str_append(&param_str, "clientid");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%c");
				update_string(
				    req_param[index]->name, "clientid");
				update_var(req_param[index]->type, CLIENTID);
			} else if (nng_strcasecmp(arg, "access") == 0) {
				// str_append(&param_str, "access");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%A");
				update_string(
				    req_param[index]->name, "access");
				update_var(req_param[index]->type, ACCESS);
			} else if (nng_strcasecmp(arg, "topic") == 0) {
				// str_append(&param_str, "topic");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%t");
				update_string(req_param[index]->name, "topic");
				update_var(req_param[index]->type, TOPIC);
			} else if (nng_strcasecmp(arg, "ipaddress") == 0) {
				// str_append(&param_str, "ipaddress");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%a");
				update_string(
				    req_param[index]->name, "ipaddress");
				update_var(req_param[index]->type, IPADDRESS);
			} else if (nng_strcasecmp(arg, "sockport") == 0) {
				// str_append(&param_str, "sockport");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%p");
				update_string(
				    req_param[index]->name, "sockport");
				update_var(req_param[index]->type, SOCKPORT);
			} else if (nng_strcasecmp(arg, "common") == 0) {
				// str_append(&param_str, "common");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%C");
				update_string(
				    req_param[index]->name, "common");
				update_var(
				    req_param[index]->type, COMMON_NAME);
			} else if (nng_strcasecmp(arg, "protocol") == 0) {
				// str_append(&param_str, "protocol");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%r");
				update_string(
				    req_param[index]->name, "protocol");
				update_var(req_param[index]->type, PROTOCOL);
			} else if (nng_strcasecmp(arg, "subject") == 0) {
				// str_append(&param_str, "subject");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%d");
				update_string(
				    req_param[index]->name, "protocol");
				update_var(req_param[index]->type, PROTOCOL);
			} else if (nng_strcasecmp(arg, "mountpoint") == 0) {
				// str_append(&param_str, "mountpoint");
				// str_append(&param_str, "=");
				// str_append(&param_str, "%m");
				update_string(
				    req_param[index]->name, "mountpoint");
				update_var(req_param[index]->type, MOUNTPOINT);
			} else {
				continue;
			}
			// str_append(&param_str, ",");
			index++;
		}
		// if (param_str != NULL &&
		//     param_str[strlen(param_str) - 1] == ',') {
		// 	param_str[strlen(param_str) - 1] = '\0';
		// }
		update_var(req->params, req_param);
		update_var(req->param_count, index);
		// conf_update2(conf_path, key_prefix, "", "params",
		// param_str);
	}
}

void
set_auth_http_config(cJSON *json, const char *conf_path, conf_auth_http *auth)
{
	char     tm_str[100] = { 0 };
	bool     enable;
	uint64_t timeout;
	uint64_t connect_timeout;
	uint64_t pool_size;

	cJSON *item;
	int    rv;

	getBoolValue(json, item, "enable", enable, rv);
	if (rv == 0) {
		// conf_update_bool(conf_path, "auth.http.enable", enable);
		update_var(auth->enable, enable);
	}

	getNumberValue(json, item, "timeout", timeout, rv);
	if (rv == 0) {
		// snprintf(tm_str, sizeof(tm_str), "%llus", timeout);
		// conf_update(conf_path, "auth.http.timeout", tm_str);
		update_var(auth->timeout, timeout);
	}

	getNumberValue(json, item, "connect_timeout", connect_timeout, rv);
	if (rv == 0) {
		// snprintf(tm_str, sizeof(tm_str), "%llus", connect_timeout);
		// conf_update(
		//     conf_path, "auth.http.connect_timeout", tm_str);
		update_var(auth->connect_timeout, connect_timeout);
	}

	getNumberValue(json, item, "pool_size", pool_size, rv);
	if (rv == 0) {
		// conf_update_u64(conf_path, "auth.http.pool_size",
		// pool_size);
		update_var(auth->pool_size, pool_size);
	}

	if (cJSON_HasObjectItem(json, "auth_req")) {
		cJSON *req = cJSON_GetObjectItem(json, "auth_req");
		set_auth_http_req(
		    req, conf_path, &auth->auth_req, "auth.http.auth_req.");
	}

	if (cJSON_HasObjectItem(json, "acl_req")) {
		cJSON *req = cJSON_GetObjectItem(json, "acl_req");
		set_auth_http_req(
		    req, conf_path, &auth->acl_req, "auth.http.acl_req.");
	}

	if (cJSON_HasObjectItem(json, "super_req")) {
		cJSON *req = cJSON_GetObjectItem(json, "super_req");
		set_auth_http_req(
		    req, conf_path, &auth->super_req, "auth.http.super_req.");
	}
}

void
reload_basic_config(conf *cur_conf, conf *new_conf)
{
	cur_conf->property_size          = new_conf->property_size;
	cur_conf->max_packet_size        = new_conf->max_packet_size;
	cur_conf->client_max_packet_size = new_conf->client_max_packet_size;
	cur_conf->msq_len                = new_conf->msq_len;
	cur_conf->qos_duration           = new_conf->qos_duration;
	cur_conf->backoff                = new_conf->backoff;
	cur_conf->allow_anonymous        = new_conf->allow_anonymous;
}

void
reload_sqlite_config(conf_sqlite *cur_conf, conf_sqlite *new_conf)
{
	cur_conf->flush_mem_threshold = new_conf->flush_mem_threshold;
}

void
reload_auth_config(conf_auth *cur_conf, conf_auth *new_conf)
{
	for (size_t i = 0; i < cur_conf->count; i++) {
		free(cur_conf->usernames[i]);
		free(cur_conf->passwords[i]);
		cur_conf->usernames[i] = NULL;
		cur_conf->passwords[i] = NULL;
	}
	cvector_free(cur_conf->usernames);
	cvector_free(cur_conf->passwords);
	cur_conf->usernames = NULL;
	cur_conf->passwords = NULL;

	cur_conf->count = new_conf->count;
	if (new_conf->count == 0) {
		return;
	}
	cur_conf->usernames = nng_zalloc(sizeof(char *) * cur_conf->count);
	cur_conf->passwords = nng_zalloc(sizeof(char *) * cur_conf->count);
	for (size_t i = 0; i < new_conf->count; i++) {
		cur_conf->usernames[i] = nng_strdup(new_conf->usernames[i]);
		cur_conf->passwords[i] = nng_strdup(new_conf->passwords[i]);
	}
}

void
reload_log_config(conf *old, conf *new)
{
#if defined(ENABLE_LOG)
	int rc = 0;
	conf_log log = old->log;
	old->log     = new->log;
	new->log     = log;
	log_fini(&new->log);
	if ((rc = log_init(&old->log)) != 0) {
		NANO_NNG_FATAL("log_reload", rc);
	}
#endif
}
