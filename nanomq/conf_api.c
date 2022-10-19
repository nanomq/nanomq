#include "conf_api.h"

cJSON *
basic_config(conf *config)
{
	cJSON *basic = cJSON_CreateObject();
	cJSON_AddStringOrNullToObject(basic, "url", config->url);
	cJSON_AddNumberToObject(
	    basic, "num_taskq_thread", config->num_taskq_thread);
	cJSON_AddNumberToObject(
	    basic, "max_taskq_thread", config->max_taskq_thread);
	cJSON_AddNumberToObject(basic, "parallel", config->parallel);
	cJSON_AddNumberToObject(basic, "property_size", config->property_size);
	cJSON_AddNumberToObject(basic, "msq_len", config->msq_len);
	cJSON_AddBoolToObject(
	    basic, "allow_anonymous", config->allow_anonymous);
	cJSON_AddBoolToObject(basic, "daemon", config->daemon);
	cJSON_AddNumberToObject(
	    basic, "max_packet_size", config->max_packet_size);
	cJSON_AddNumberToObject(
	    basic, "client_max_packet_size", config->client_max_packet_size);
	cJSON_AddNumberToObject(basic, "msq_len", config->msq_len);
	cJSON_AddNumberToObject(basic, "qos_duration", config->qos_duration);
	cJSON_AddNumberToObject(basic, "keepalive_backoff", config->backoff);
	cJSON_AddBoolToObject(
	    basic, "allow_anonymous", config->allow_anonymous);

	return basic;
}

cJSON *
tls_config(conf_tls *tls, bool is_server)
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
auth_config(conf_auth *auth)
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

cJSON *
auth_http_config(conf_auth_http *auth_http)
{
}

cJSON *
websocker_config(conf_websocket *ws)
{
	cJSON *ws_obj = cJSON_CreateObject();
	cJSON_AddBoolToObject(ws_obj, "enable", ws->enable);
	cJSON_AddStringOrNullToObject(ws_obj, "url", ws->url);
	cJSON_AddStringOrNullToObject(ws_obj, "tls_url", ws->tls_url);

	return ws_obj;
}

cJSON *
http_config(conf_http_server *http)
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
sqlite_config(conf_sqlite *sqlite)
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
bridge_config(conf_bridge *bridge)
{
	cJSON *bridge_obj        = cJSON_CreateObject();
	cJSON *bridge_sqlite_obj = sqlite_config(&bridge->sqlite);

	cJSON *bridge_node_obj = cJSON_CreateArray();
	for (size_t i = 0; i < bridge->count; i++) {
		conf_bridge_node *node     = bridge->nodes[i];
		cJSON *           node_obj = cJSON_CreateObject();
		cJSON_AddStringOrNullToObject(node_obj, "name", node->name);
		cJSON_AddBoolToObject(node_obj, "bridge_mode", node->enable);
		if (node->address) {
			cJSON_AddStringToObject(
			    node_obj, "address", node->address);
		} else {
			cJSON_AddStringOrNullToObject(
			    node_obj, "host", node->host);
			cJSON_AddNumberToObject(node_obj, "port", node->port);
		}

		cJSON_AddNumberToObject(
		    node_obj, "proto_ver", node->proto_ver);
		cJSON_AddStringOrNullToObject(
		    node_obj, "clientid", node->clientid);
		cJSON_AddBoolToObject(
		    node_obj, "clean_start", node->clean_start);
		cJSON_AddStringOrNullToObject(
		    node_obj, "username", node->username);
		cJSON_AddStringOrNullToObject(
		    node_obj, "password", node->password);
		cJSON_AddNumberToObject(
		    node_obj, "keepalive", node->keepalive);
		cJSON_AddNumberToObject(node_obj, "parallel", node->parallel);

		cJSON *pub_topics = cJSON_CreateArray();
		for (size_t i = 0; i < node->forwards_count; i++) {
			cJSON *topic = cJSON_CreateString(node->forwards[i]);
			cJSON_AddItemToArray(pub_topics, topic);
		}
		cJSON_AddItemToObject(node_obj, "forwards", pub_topics);

		cJSON *sub_infos = cJSON_CreateArray();
		for (size_t j = 0; j < node->sub_count; j++) {
			cJSON *   sub_obj = cJSON_CreateObject();
			subscribe sub     = node->sub_list[j];
			cJSON_AddStringOrNullToObject(
			    sub_obj, "topic", sub.topic);
			cJSON_AddNumberToObject(sub_obj, "qos", sub.qos);
			cJSON_AddItemToArray(sub_infos, sub_obj);
		}

		cJSON_AddItemToObject(node_obj, "subscription", sub_infos);
		cJSON *tls = tls_config(&node->tls, false);
		cJSON_AddItemToObject(node_obj, "tls", tls);
		cJSON_AddItemToArray(bridge_node_obj, node_obj);
	}

	cJSON_AddItemToObject(bridge_obj, "nodes", bridge_node_obj);
	cJSON_AddItemToObject(bridge_obj, "sqlite", bridge_sqlite_obj);

	return bridge_obj;
}
