//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>

#include "include/cJSON.h"
#include "include/conf.h"
#include "include/dbg.h"
#include "include/file.h"
#include "nanomq.h"

static char *
strtrim(char *str, size_t len)
{
	// size_t len   = strlen(str);
	char * dest  = calloc(1, len);
	size_t index = 0;

	for (size_t i = 0; i < len; i++) {
		if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n') {
			dest[index] = str[i];
			index++;
		}
	}
	return dest;
}

void
conf_update_var(const char *fpath, const char *key, uint8_t type, void *var)
{
	char varstr[50] = { 0 };
	switch (type) {
	case 0:
		// int
		sprintf(varstr, "%d", *(int *) var);
		break;
	case 1:
		// uint8
		sprintf(varstr, "%hhu", *(uint8_t *) var);
		break;
	case 2:
		// uint16
		sprintf(varstr, "%hu", *(uint16_t *) var);
		break;
	case 3:
		// uint32
		sprintf(varstr, "%u", *(uint32_t *) var);
		break;
	case 4:
		// uint64
		sprintf(varstr, "%llu", *(uint64_t *) var);
		break;
	case 5:
		// long
		sprintf(varstr, "%ld", *(long *) var);
		break;
	case 6:
		// double
		snprintf(varstr, 20, "%lf", *(double *) var);
		break;
	case 7:
		// bool
		sprintf(varstr, "%s", (*(bool *) var) ? "true" : "false");
	default:
		return;
	}
	conf_update(fpath, key, varstr);
}

void
conf_update(const char *fpath, const char *key, char *value)
{
	char **linearray = NULL;
	int    count     = 0;
	if (fpath == NULL || value == NULL) {
		return;
	}
	size_t descstrlen = strlen(key) + strlen(value) + 3;
	char * deststr    = calloc(1, descstrlen);
	char * ptr        = NULL;
	FILE * fp         = fopen(fpath, "r+");
	char * line       = NULL;
	size_t len        = 0;
	bool   is_found   = false;
	if (fp) {
		sprintf(deststr, "%s=", key);
		while (nano_getline(&line, &len, fp) != -1) {
			linearray =
			    realloc(linearray, (count + 1) * (sizeof(char *)));
			if (linearray == NULL) {
				debug_msg("realloc fail");
			}
			ptr = strstr(line, deststr);
			if (ptr == line) {
				is_found = true;
				strcat(deststr, value);
				strcat(deststr, "\n");
				linearray[count] = strdup(deststr);
			} else {
				linearray[count] = strdup(line);
			}
			count++;
		}
		if (!is_found) {
			linearray =
			    realloc(linearray, (count + 1) * (sizeof(char *)));
			strcat(deststr, value);
			strcat(deststr, "\n");
			linearray[count] = strdup(deststr);
			count++;
		}
		if (line) {
			free(line);
		}
	} else {
		debug_msg("Open file %s error", fpath);
	}

	if (deststr) {
		free(deststr);
	}

	rewind(fp);
	feof(fp);
	fflush(fp);
	fclose(fp);

	fp = fopen(fpath, "w");

	for (int i = 0; i < count; i++) {
		fwrite(linearray[i], 1, strlen(linearray[i]), fp);
		free((linearray[i]));
	}
	free(linearray);
	fclose(fp);
}

static char *
get_conf_value(char *line, size_t len, const char *key)
{
	if (strlen(key) > len || len <= 0) {
		return NULL;
	}
	char  prefix[len];
	char *trim  = strtrim(line, len);
	char *value = calloc(1, len);
	int   match = sscanf(trim, "%[^=]=%s", prefix, value);
	free(trim);

	if (match == 2 && strcmp(prefix, key) == 0) {
		return value;
	} else {
		free(value);
		return NULL;
	}
}

bool
conf_parser(conf *nanomq_conf)
{
	const char *dest_path = nanomq_conf->conf_file;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_PATH_NAME)) {
			debug_msg("Configure file [%s] or [%s] not found or "
			          "unreadable",
			    dest_path, CONF_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_PATH_NAME;
		}
	}

	char * line = NULL;
	size_t sz   = 0;
	FILE * fp;
	conf * config = nanomq_conf;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		debug_msg("File %s open failed", dest_path);
		return true;
	}

	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value(line, sz, "url")) != NULL) {
			FREE_NONULL(config->url);
			config->url = value;
		} else if ((value = get_conf_value(line, sz, "daemon")) !=
		    NULL) {
			config->daemon = strcasecmp(value, "yes") == 0 ||
			    strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "num_taskq_thread")) != NULL) {
			config->num_taskq_thread = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "max_taskq_thread")) != NULL) {
			config->max_taskq_thread = atoi(value);
			free(value);
		} else if ((value = get_conf_value(line, sz, "parallel")) !=
		    NULL) {
			config->parallel = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "property_size")) != NULL) {
			config->property_size = atoi(value);
			free(value);
		} else if ((value = get_conf_value(line, sz, "msq_len")) !=
		    NULL) {
			config->msq_len = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "qos_duration")) != NULL) {
			config->qos_duration = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "allow_anonymous")) != NULL) {
			config->allow_anonymous =
			    strcasecmp(value, "yes") == 0 ||
			    strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "websocket.enable")) != NULL) {
			config->websocket.enable =
			    strcasecmp(value, "yes") == 0 ||
			    strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "websocket.url")) != NULL) {
			FREE_NONULL(config->websocket.url);
			config->websocket.url = value;
		} else if ((value = get_conf_value(
		                line, sz, "websocket.tls_url")) != NULL) {
			FREE_NONULL(config->websocket.tls_url);
			config->websocket.tls_url = value;
		} else if ((value = get_conf_value(
		                line, sz, "http_server.enable")) != NULL) {
			config->http_server.enable =
			    strcasecmp(value, "yes") == 0 ||
			    strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "http_server.port")) != NULL) {
			config->http_server.port = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "http_server.username")) != NULL) {
			FREE_NONULL(config->http_server.username);
			config->http_server.username = value;
		} else if ((value = get_conf_value(
		                line, sz, "http_server.password")) != NULL) {
			FREE_NONULL(config->http_server.password);
			config->http_server.password = value;
		} else if ((value = get_conf_value(line, sz, "tls.enable")) !=
		    NULL) {
			config->tls.enable = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(line, sz, "tls.url")) !=
		    NULL) {
			FREE_NONULL(config->tls.url);
			config->tls.url = value;
		} else if ((value = get_conf_value(
		                line, sz, "tls.key_password")) != NULL) {
			FREE_NONULL(config->tls.key_password);
			config->tls.key_password = value;
		} else if ((value = get_conf_value(line, sz, "tls.keyfile")) !=
		    NULL) {
			FREE_NONULL(config->tls.key);
			FREE_NONULL(config->tls.keyfile);
			config->tls.keyfile = value;
			file_load_data(
			    config->tls.keyfile, (void **) &config->tls.key);
		} else if ((value = get_conf_value(
		                line, sz, "tls.certfile")) != NULL) {
			FREE_NONULL(config->tls.cert);
			FREE_NONULL(config->tls.certfile);
			config->tls.certfile = value;
			file_load_data(
			    config->tls.certfile, (void **) &config->tls.cert);
		} else if ((value = get_conf_value(
		                line, sz, "tls.cacertfile")) != NULL) {
			FREE_NONULL(config->tls.ca);
			FREE_NONULL(config->tls.cafile);
			config->tls.cafile = value;
			file_load_data(
			    config->tls.cafile, (void **) &config->tls.ca);
		} else if ((value = get_conf_value(
		                line, sz, "tls.verify_peer")) != NULL) {
			config->tls.verify_peer =
			    strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "tls.fail_if_no_peer_cert")) != NULL) {
			config->tls.set_fail = strcasecmp(value, "true") == 0;
			free(value);
		}

		free(line);
		line = NULL;
	}

	if (line) {
		free(line);
	}

	fclose(fp);
	return true;
}

void
conf_init(conf *nanomq_conf)
{
	nanomq_conf->url              = NULL;
	nanomq_conf->conf_file        = NULL;
	nanomq_conf->bridge_file      = NULL;
	nanomq_conf->web_hook_file    = NULL;
	nanomq_conf->auth_file        = NULL;
	nanomq_conf->num_taskq_thread = 10;
	nanomq_conf->max_taskq_thread = 10;
	nanomq_conf->parallel         = 30; // not work
	nanomq_conf->property_size    = sizeof(uint8_t) * 32;
	nanomq_conf->msq_len          = 64;
	nanomq_conf->qos_duration     = 30;
	nanomq_conf->allow_anonymous  = true;
	nanomq_conf->daemon           = false;

	nanomq_conf->tls.enable       = false;
	nanomq_conf->tls.cafile       = NULL;
	nanomq_conf->tls.certfile     = NULL;
	nanomq_conf->tls.keyfile      = NULL;
	nanomq_conf->tls.ca           = NULL;
	nanomq_conf->tls.cert         = NULL;
	nanomq_conf->tls.key          = NULL;
	nanomq_conf->tls.key_password = NULL;
	nanomq_conf->tls.set_fail     = false;
	nanomq_conf->tls.verify_peer  = false;

	nanomq_conf->http_server.enable   = false;
	nanomq_conf->http_server.port     = 8081;
	nanomq_conf->http_server.username = NULL;
	nanomq_conf->http_server.password = NULL;

	nanomq_conf->websocket.enable  = true;
	nanomq_conf->websocket.url     = NULL;
	nanomq_conf->websocket.tls_url = NULL;

	nanomq_conf->bridge.bridge_mode = false;
	nanomq_conf->bridge.sub_count   = 0;
	nanomq_conf->bridge.parallel    = 1;

	nanomq_conf->web_hook.enable           = false;
	nanomq_conf->web_hook.url              = NULL;
	nanomq_conf->web_hook.encode_payload   = plain;
	nanomq_conf->web_hook.pool_size        = 8;
	nanomq_conf->web_hook.headers          = NULL;
	nanomq_conf->web_hook.header_count     = 0;
	nanomq_conf->web_hook.rules            = NULL;
	nanomq_conf->web_hook.rule_count       = 0;
	nanomq_conf->web_hook.tls.enable       = false;
	nanomq_conf->web_hook.tls.enable       = false;
	nanomq_conf->web_hook.tls.cafile       = NULL;
	nanomq_conf->web_hook.tls.certfile     = NULL;
	nanomq_conf->web_hook.tls.keyfile      = NULL;
	nanomq_conf->web_hook.tls.ca           = NULL;
	nanomq_conf->web_hook.tls.cert         = NULL;
	nanomq_conf->web_hook.tls.key          = NULL;
	nanomq_conf->web_hook.tls.key_password = NULL;
	nanomq_conf->web_hook.tls.set_fail     = false;
	nanomq_conf->web_hook.tls.verify_peer  = false;
}

void
print_conf(conf *nanomq_conf)
{
	debug_msg("This NanoMQ instance configured as:");

	debug_msg("tcp url:                  %s ", nanomq_conf->url);
	debug_msg("enable websocket:         %s",
	    nanomq_conf->websocket.enable ? "true" : "false");
	debug_msg("websocket url:            %s", nanomq_conf->websocket.url);
	debug_msg(
	    "websocket tls url:        %s", nanomq_conf->websocket.tls_url);
	debug_msg("daemon:                   %s",
	    nanomq_conf->daemon ? "true" : "false");
	debug_msg(
	    "num_taskq_thread:         %d", nanomq_conf->num_taskq_thread);
	debug_msg(
	    "max_taskq_thread:         %d", nanomq_conf->max_taskq_thread);
	debug_msg("parallel:                 %lu", nanomq_conf->parallel);
	debug_msg("property_size:            %d", nanomq_conf->property_size);
	debug_msg("msq_len:                  %d", nanomq_conf->msq_len);
	debug_msg("qos_duration:             %d", nanomq_conf->qos_duration);
	debug_msg("enable http server:       %s",
	    nanomq_conf->http_server.enable ? "true" : "false");
	debug_msg(
	    "http server port:         %d", nanomq_conf->http_server.port);
	debug_msg("enable tls:               %s",
	    nanomq_conf->tls.enable ? "true" : "false");
	if (nanomq_conf->tls.enable) {
		debug_msg(
		    "tls url:                  %s", nanomq_conf->tls.url);
		debug_msg("tls verify peer:          %s",
		    nanomq_conf->tls.verify_peer ? "true" : "false");
		debug_msg("tls fail_if_no_peer_cert: %s",
		    nanomq_conf->tls.set_fail ? "true" : "false");
	}
}

void
conf_auth_parser(conf *nanomq_conf)
{
	char *dest_path = nanomq_conf->auth_file;
	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_AUTH_PATH_NAME)) {
			debug_msg("Configure file [%s] or [%s] not found or "
			          "unreadable",
			    dest_path, CONF_AUTH_PATH_NAME);
			return;
		} else {
			dest_path = CONF_AUTH_PATH_NAME;
		}
	}

	char   name_key[64] = "";
	char   pass_key[64] = "";
	char * name;
	char * pass;
	size_t index    = 1;
	bool   get_name = false;
	bool   get_pass = false;
	char * line;
	size_t sz = 0;
	char * value;

	conf_auth *auth = &nanomq_conf->auths;

	auth->count = 0;

	FILE *fp;
	if ((fp = fopen(dest_path, "r")) == NULL) {
		debug_msg("File %s open failed", dest_path);
		return;
	}

	while (nano_getline(&line, &sz, fp) != -1) {
		sprintf(name_key, "auth.%ld.login", index);
		if (!get_name &&
		    (value = get_conf_value(line, sz, name_key)) != NULL) {
			name     = value;
			get_name = true;
			goto check;
		}

		sprintf(pass_key, "auth.%ld.password", index);
		if (!get_pass &&
		    (value = get_conf_value(line, sz, pass_key)) != NULL) {
			pass     = value;
			get_pass = true;
			goto check;
		}

		free(line);
		line = NULL;

	check:
		if (get_name && get_pass) {
			index++;
			auth->count++;
			auth->usernames = realloc(
			    auth->usernames, sizeof(char *) * auth->count);
			auth->passwords = realloc(
			    auth->passwords, sizeof(char *) * auth->count);

			auth->usernames[auth->count - 1] = name;
			auth->passwords[auth->count - 1] = pass;

			get_name = false;
			get_pass = false;
		}
	}

	if (line) {
		free(line);
	}

	fclose(fp);
}

bool
conf_bridge_parse_subs(conf_bridge *bridge, const char *path)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		debug_msg("File %s open failed", path);
		return false;
	}

	char    topic_key[64] = "";
	char    qos_key[64]   = "";
	char *  topic;
	uint8_t qos;
	size_t  sub_index = 1;
	bool    get_topic = false;
	bool    get_qos   = false;
	char *  line      = NULL;
	size_t  sz        = 0;
	char *  value     = NULL;

	bridge->sub_count = 0;
	while (nano_getline(&line, &sz, fp) != -1) {
		sprintf(topic_key, "bridge.mqtt.subscription.%ld.topic",
		    sub_index);
		if (!get_topic &&
		    (value = get_conf_value(line, sz, topic_key)) != NULL) {
			topic     = value;
			get_topic = true;
			goto check;
		}

		sprintf(
		    qos_key, "bridge.mqtt.subscription.%ld.qos", sub_index);
		if (!get_qos &&
		    (value = get_conf_value(line, sz, qos_key)) != NULL) {
			qos = (uint8_t) atoi(value);
			free(value);
			get_qos = true;
			goto check;
		}

		free(line);
		line = NULL;

	check:
		if (get_topic && get_qos) {
			sub_index++;
			bridge->sub_count++;
			bridge->sub_list = realloc(bridge->sub_list,
			    sizeof(subscribe) * bridge->sub_count);
			bridge->sub_list[bridge->sub_count - 1].topic = topic;
			bridge->sub_list[bridge->sub_count - 1].topic_len =
			    strlen(topic);
			bridge->sub_list[bridge->sub_count - 1].qos = qos;

			get_topic = false;
			get_qos   = false;
		}
	}

	if (line) {
		free(line);
	}

	fclose(fp);
	return true;
}

bool
conf_bridge_parse(conf *nanomq_conf)
{
	const char *dest_path = nanomq_conf->bridge_file;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_BRIDGE_PATH_NAME)) {
			debug_msg("Configure file [%s] or [%s] not found or "
			          "unreadable",
			    dest_path, CONF_BRIDGE_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_BRIDGE_PATH_NAME;
		}
	}

	char * line = NULL;
	size_t sz   = 0;
	FILE * fp;

	conf_bridge *bridge = &nanomq_conf->bridge;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		debug_msg("File %s open failed", dest_path);
		bridge->bridge_mode = false;
		return true;
	}

	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value(
		         line, sz, "bridge.mqtt.bridge_mode")) != NULL) {
			bridge->bridge_mode = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.proto_ver")) != NULL) {
			bridge->proto_ver = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.keepalive")) != NULL) {
			bridge->keepalive = atoi(value);
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "bridge.mqtt.clean_start")) != NULL) {
			bridge->clean_start = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.parallel")) != NULL) {
			bridge->parallel = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.address")) != NULL) {
			bridge->address = value;
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.clientid")) != NULL) {
			bridge->clientid = value;
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.username")) != NULL) {
			bridge->username = value;
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.password")) != NULL) {
			bridge->password = value;
		} else if ((value = get_conf_value(
		                line, sz, "bridge.mqtt.forwards")) != NULL) {
			char *tk = strtok(value, ",");
			while (tk != NULL) {
				bridge->forwards_count++;
				bridge->forwards = realloc(bridge->forwards,
				    sizeof(char *) * bridge->forwards_count);
				bridge->forwards[bridge->forwards_count - 1] =
				    strdup(tk);
				tk = strtok(NULL, ",");
			}
			free(value);
		}

		free(line);
		line = NULL;
	}
	if (line) {
		free(line);
	}

	fclose(fp);
	conf_bridge_parse_subs(bridge, dest_path);
	return true;

out:
	fclose(fp);
	return true;
}

void
conf_bridge_destroy(conf_bridge *bridge)
{
	if (bridge->clientid) {
		free(bridge->clientid);
	}
	if (bridge->address) {
		free(bridge->address);
	}
	if (bridge->username) {
		free(bridge->username);
	}
	if (bridge->password) {
		free(bridge->password);
	}
	if (bridge->forwards) {
		free(bridge->forwards);
	}
	if (bridge->forwards_count > 0 && bridge->forwards) {
		for (size_t i = 0; i < bridge->forwards_count; i++) {
			if (bridge->forwards[i]) {
				free(bridge->forwards[i]);
			}
		}
		free(bridge->forwards);
	}
	if (bridge->sub_count > 0 && bridge->sub_list) {
		for (size_t i = 0; i < bridge->sub_count; i++) {
			if (bridge->sub_list[i].topic) {
				free(bridge->sub_list[i].topic);
			}
		}
		free(bridge->sub_list);
	}
}

void
print_bridge_conf(conf_bridge *bridge)
{
	debug_msg("bridge.mqtt.bridge_mode:  %s",
	    bridge->bridge_mode ? "true" : "false");
	if (!bridge->bridge_mode) {
		return;
	}
	debug_msg("bridge.mqtt.address:      %s", bridge->address);
	debug_msg("bridge.mqtt.proto_ver:    %d", bridge->proto_ver);
	debug_msg("bridge.mqtt.clientid:     %s", bridge->clientid);
	debug_msg("bridge.mqtt.clean_start:  %d", bridge->clean_start);
	debug_msg("bridge.mqtt.username:     %s", bridge->username);
	debug_msg("bridge.mqtt.password:     %s", bridge->password);
	debug_msg("bridge.mqtt.keepalive:    %d", bridge->keepalive);
	debug_msg("bridge.mqtt.parallel:     %ld", bridge->parallel);
	debug_msg("bridge.mqtt.forwards: ");
	for (size_t i = 0; i < bridge->forwards_count; i++) {
		debug_msg("\t[%ld] topic:        %s", i, bridge->forwards[i]);
	}
	debug_msg("bridge.mqtt.subscription: ");
	for (size_t i = 0; i < bridge->sub_count; i++) {
		debug_msg("\t[%ld] topic:        %.*s", i + 1,
		    bridge->sub_list[i].topic_len, bridge->sub_list[i].topic);
		debug_msg("\t[%ld] qos:          %d", i + 1,
		    bridge->sub_list[i].qos);
	}
	debug_msg("");
}

bool
conf_web_hook_parse_headers(conf_web_hook *webhook, const char *path)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		debug_msg("File %s open failed", path);
		return false;
	}

	char * line = NULL;
	size_t sz   = 0;

	webhook->header_count = 0;
	while (nano_getline(&line, &sz, fp) != -1) {
		if (sz <= 16) {
			goto next;
		}
		char *key   = calloc(1, sz - 16);
		char *value = calloc(1, sz - 16);
		int   res =
		    sscanf(line, "web.hook.headers.%[^=]=%[^\n]", key, value);
		if (res == 2) {
			webhook->header_count++;
			webhook->headers = realloc(webhook->headers,
			    webhook->header_count *
			        sizeof(conf_web_hook_header *));
			webhook->headers[webhook->header_count - 1] =
			    calloc(1, sizeof(conf_web_hook_header));
			webhook->headers[webhook->header_count - 1]->key = key;
			webhook->headers[webhook->header_count - 1]->value =
			    value;
		} else {
			if (key) {
				free(key);
			}
			if (value) {
				free(value);
			}
		}
	next:
		free(line);
		line = NULL;
	}

	if (line) {
		free(line);
	}
	fclose(fp);
	return true;
}

static webhook_event
get_webhook_event(const char *hook_type, const char *hook_name)
{
	if (strcasecmp("client", hook_type) == 0) {
		if (strcasecmp("connect", hook_name) == 0) {
			return CLIENT_CONNECT;
		} else if (strcasecmp("connack", hook_name) == 0) {
			return CLIENT_CONNACK;
		} else if (strcasecmp("connected", hook_name) == 0) {
			return CLIENT_CONNECTED;
		} else if (strcasecmp("disconnected", hook_name) == 0) {
			return CLIENT_DISCONNECTED;
		} else if (strcasecmp("subscribe", hook_name) == 0) {
			return CLIENT_SUBSCRIBE;
		} else if (strcasecmp("unsubscribe", hook_name) == 0) {
			return CLIENT_UNSUBSCRIBE;
		}
	} else if (strcasecmp("session", hook_type) == 0) {
		if (strcasecmp("subscribed", hook_name) == 0) {
			return SESSION_SUBSCRIBED;
		} else if (strcasecmp("unsubscribed", hook_name) == 0) {
			return SESSION_UNSUBSCRIBED;
		} else if (strcasecmp("terminated", hook_name) == 0) {
			return SESSION_TERMINATED;
		}
	} else if (strcasecmp("message", hook_type) == 0) {
		if (strcasecmp("publish", hook_name) == 0) {
			return MESSAGE_PUBLISH;
		} else if (strcasecmp("delivered", hook_name) == 0) {
			return MESSAGE_DELIVERED;
		} else if (strcasecmp("acked", hook_name) == 0) {
			return MESSAGE_ACKED;
		}
	}
	return UNKNOWN_EVENT;
}

static void
webhook_action_parse(const char *json, conf_web_hook_rule *hook_rule)
{
	cJSON *object = cJSON_Parse(json);

	cJSON *action = cJSON_GetObjectItem(object, "action");
	if (cJSON_IsString(action)) {
		const char *act_val = cJSON_GetStringValue(action);
		hook_rule->action   = strdup(act_val);
	} else {
		hook_rule->action = NULL;
	}
	cJSON *topic = cJSON_GetObjectItem(object, "topic");
	if (cJSON_IsString(topic)) {
		const char *topic_str = cJSON_GetStringValue(topic);
		hook_rule->topic      = strdup(topic_str);
	} else {
		hook_rule->topic = NULL;
	}

	cJSON_Delete(object);
}

bool
conf_web_hook_parse_rules(conf_web_hook *webhook, const char *path)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		debug_msg("File %s open failed", path);
		return false;
	}

	char * line = NULL;
	size_t sz   = 0;

	webhook->rule_count = 0;
	while (nano_getline(&line, &sz, fp) != -1) {
		if (sz <= 20) {
			goto next;
		}
		char *   spec     = calloc(1, sz - 20);
		char *   hooktype = calloc(1, sz - 20);
		char *   hookname = calloc(1, sz - 20);
		uint16_t num      = 0;
		int res = sscanf(line, "web.hook.rule.%[^.].%[^.].%hu=%[^\n]",
		    hooktype, hookname, &num, spec);
		if (res == 4) {
			webhook->rule_count++;
			webhook->rules = realloc(webhook->rules,
			    webhook->rule_count *
			        (sizeof(conf_web_hook_rule *)));
			webhook->rules[webhook->rule_count - 1] =
			    calloc(1, sizeof(conf_web_hook_rule));
			webhook->rules[webhook->rule_count - 1]->event =
			    get_webhook_event(hooktype, hookname);
			webhook->rules[webhook->rule_count - 1]->rule_num =
			    num;
			webhook_action_parse(
			    spec, webhook->rules[webhook->rule_count - 1]);
		}
		if (spec) {
			free(spec);
		}
		if (hooktype) {
			free(hooktype);
		}
		if (hookname) {
			free(hookname);
		}
	next:
		free(line);
		line = NULL;
	}
	if (line) {
		free(line);
	}

	fclose(fp);
	return true;
}

bool
conf_web_hook_parse(conf *nanomq_conf)
{
	const char *dest_path = nanomq_conf->web_hook_file;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_WEB_HOOK_PATH_NAME)) {
			debug_msg("Configure file [%s] or [%s] not found or "
			          "unreadable",
			    dest_path, CONF_WEB_HOOK_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_WEB_HOOK_PATH_NAME;
		}
	}

	char * line = NULL;
	size_t sz   = 0;
	FILE * fp;

	conf_web_hook *webhook = &nanomq_conf->web_hook;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		debug_msg("File %s open failed", dest_path);
		webhook->enable = false;
		return true;
	}

	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value(line, sz, "web.hook.enable")) !=
		    NULL) {
			webhook->enable = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "web.hook.url")) != NULL) {
			webhook->url = value;
		} else if ((value = get_conf_value(
		                line, sz, "web.hook.pool_size")) != NULL) {
			webhook->pool_size = (size_t) atol(value);
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "web.hook.body.encoding_of_payload_field")) !=
		    NULL) {
			if (strcasecmp(value, "base64") == 0) {
				webhook->encode_payload = base64;
			} else if (strcasecmp(value, "base62") == 0) {
				webhook->encode_payload = base62;
			} else if (strcasecmp(value, "plain") == 0) {
				webhook->encode_payload = plain;
			}
			free(value);
		}
		free(line);
		line = NULL;
	}
	if (line) {
		free(line);
	}
	fclose(fp);

	conf_web_hook_parse_headers(webhook, dest_path);
	conf_web_hook_parse_rules(webhook, dest_path);
	return true;
}

void
conf_web_hook_destroy(conf_web_hook *web_hook)
{
	zfree(web_hook->url);

	if (web_hook->header_count > 0 && web_hook->headers != NULL) {
		for (size_t i = 0; i < web_hook->header_count; i++) {
			zfree(web_hook->headers[i]);
		}
		zfree(web_hook->headers);
	}

	if (web_hook->rule_count > 0 && web_hook->rules != NULL) {
		for (size_t i = 0; i < web_hook->rule_count; i++) {
			zfree(web_hook->rules[i]->action);
			zfree(web_hook->rules[i]->topic);
			zfree(web_hook->rules[i]);
		}
		zfree(web_hook->rules);
	}

	zfree(web_hook->tls.cafile);
	zfree(web_hook->tls.certfile);
	zfree(web_hook->tls.keyfile);
	zfree(web_hook->tls.key);
	zfree(web_hook->tls.key_password);
	zfree(web_hook->tls.cert);
	zfree(web_hook->tls.ca);
}

void
conf_fini(conf *nanomq_conf)
{
	int    i, n = nanomq_conf->auths.count;
	char **usernames = nanomq_conf->auths.usernames;
	char **passwords = nanomq_conf->auths.passwords;

	for (i = 0; i < n; i++) {
		zfree(usernames[i]);
		zfree(passwords[i]);
	}

	zfree(usernames);
	zfree(passwords);
	zfree(nanomq_conf->url);
	zfree(nanomq_conf->conf_file);
	zfree(nanomq_conf->bridge_file);
	zfree(nanomq_conf->web_hook_file);
	zfree(nanomq_conf->auth_file);

	zfree(nanomq_conf->tls.cafile);
	zfree(nanomq_conf->tls.certfile);
	zfree(nanomq_conf->tls.keyfile);
	zfree(nanomq_conf->tls.key);
	zfree(nanomq_conf->tls.key_password);
	zfree(nanomq_conf->tls.cert);
	zfree(nanomq_conf->tls.ca);

	zfree(nanomq_conf->http_server.username);
	zfree(nanomq_conf->http_server.password);

	zfree(nanomq_conf->websocket.url);

	conf_bridge_destroy(&nanomq_conf->bridge);
	conf_web_hook_destroy(&nanomq_conf->web_hook);

	free(nanomq_conf);
}

int
string_trim(char **dst, char *str)
{
	int ns = 0, nd = 0;
	while (str[ns] == ' ') {
		ns++;
	}
	nd = ns;
	while (str[nd] != ' ' || str[nd] != '\n' || str[nd] != '\0') {
		nd++;
		if (nd == strlen(str)) {
			break;
		}
	}

	*dst = str + ns;
	return (nd - ns - 1);
}
