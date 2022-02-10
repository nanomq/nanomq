//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>

#include "include/conf.h"
#include "include/dbg.h"
#include "include/file.h"
#include "nanomq.h"

static char *
strtrim(char *str)
{
	size_t len   = strlen(str);
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

static char *
get_conf_value(char *line, size_t len, const char *key)
{
	if (strlen(key) > len || len <= 0) {
		return NULL;
	}
	char  prefix[len];
	char *trim  = strtrim(line);
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
	while (getline(&line, &sz, fp) != -1) {
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
			file_load_data(value, (void **)&config->tls.key);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "tls.certfile")) != NULL) {
			FREE_NONULL(config->tls.cert);
			file_load_data(value, (void **)&config->tls.cert);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "tls.cacertfile")) != NULL) {
			FREE_NONULL(config->tls.ca);
			file_load_data(value, (void **)&config->tls.ca);
			free(value);
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
	nanomq_conf->websocket.enable     = true;
	nanomq_conf->websocket.url        = NULL;
	nanomq_conf->websocket.tls_url    = NULL;
	nanomq_conf->bridge.bridge_mode   = false;
	nanomq_conf->bridge.sub_count     = 0;
	nanomq_conf->bridge.parallel      = 1;
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
		debug_msg("tls url:                  %s",
		    nanomq_conf->tls.url);
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

	while (getline(&line, &sz, fp) != -1) {
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
	char *  line;
	size_t  sz = 0;
	char *  value;

	bridge->sub_count = 0;
	while (getline(&line, &sz, fp) != -1) {
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
	while (getline(&line, &sz, fp) != -1) {
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
	zfree(nanomq_conf->auth_file);

	zfree(nanomq_conf->tls.key);
	zfree(nanomq_conf->tls.key_password);
	zfree(nanomq_conf->tls.cert);
	zfree(nanomq_conf->tls.ca);

	zfree(nanomq_conf->http_server.username);
	zfree(nanomq_conf->http_server.password);

	zfree(nanomq_conf->websocket.url);

	conf_bridge_destroy(&nanomq_conf->bridge);

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
