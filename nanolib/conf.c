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
conf_parser(conf *nanomq_conf, const char *path)
{
	const char *dest_path = path;

	if (!nano_file_exists(dest_path)) {
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
			if (config->url != NULL) {
				free(value);
			} else {
				config->url = value;
			}
		} else if ((value = get_conf_value(line, sz, "daemon")) !=
		    NULL) {
			config->daemon = strcasecmp(value, "yes") == 0;
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
			    strcasecmp(value, "yes") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "websocket.enable")) != NULL) {
			config->websocket.enable =
			    strcasecmp(value, "yes") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "websocket.url")) != NULL) {
			if (config->websocket.url != NULL) {
				free(value);
			} else {
				config->websocket.url = value;
			}
		} else if ((value = get_conf_value(
		                line, sz, "http_server.enable")) != NULL) {
			config->http_server.enable =
			    strcasecmp(value, "yes") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "http_server.port")) != NULL) {
			config->http_server.port = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "http_server.username")) != NULL) {
			config->http_server.username = value;
		} else if ((value = get_conf_value(
		                line, sz, "http_server.password")) != NULL) {
			config->http_server.password = value;
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
	nanomq_conf->num_taskq_thread     = 10;
	nanomq_conf->max_taskq_thread     = 10;
	nanomq_conf->parallel             = 30; // not work
	nanomq_conf->property_size        = sizeof(uint8_t) * 32;
	nanomq_conf->msq_len              = 64;
	nanomq_conf->qos_duration         = 30;
	nanomq_conf->allow_anonymous      = true;
	nanomq_conf->http_server.enable   = false;
	nanomq_conf->http_server.port     = 8081;
	nanomq_conf->http_server.username = NULL;
	nanomq_conf->http_server.password = NULL;
	nanomq_conf->websocket.enable     = true;
	nanomq_conf->websocket.url        = NULL;
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
}

void
conf_auth_parser(conf *nanomq_conf)
{
	char *line = NULL, buf[64], *username, *password, *tmp;
	int   n = 0, x = 0, nu = 0, lenu = 0, lenp = 0;
	if (!nano_file_exists(CONF_AUTH_PATH_NAME)) {
		debug_msg("file not exists");
		return;
	}

	while (1) {
		n++;
		sprintf(buf, "auth.%d.login", n);
		if ((line = file_find_line(
		         CONF_AUTH_PATH_NAME, (const char *) buf)) == NULL) {
			break;
		}
		if (line[0] == '#' || line[1] == '#') {
			free(line);
			line = NULL;
			continue;
		}
		nu++;
		free(line);
		line = NULL;
	}
	nanomq_conf->auths.count     = nu;
	nanomq_conf->auths.usernames = zmalloc(sizeof(char *) * nu);
	nanomq_conf->auths.passwords = zmalloc(sizeof(char *) * nu);

	n = 0;
	do {
		n++;
		/* username */
		sprintf(buf, "auth.%d.login", n);
		if ((line = file_find_line(
		         CONF_AUTH_PATH_NAME, (const char *) buf)) == NULL) {
			debug_msg("line not found");
			break;
		}
		if (line[0] == '#' || line[1] == '#') {
			free(line);
			line = NULL;
			continue;
		}

		x = 0;
		while (line[x] != '=')
			x++;

		lenu = string_trim(&tmp, line + x + 1);

		username = zmalloc((lenu + 1) * sizeof(uint8_t));
		strncpy(username, tmp, lenu);
		username[lenu] = '\0';
		free(line);
		line = NULL;

		/* password */
		sprintf(buf, "auth.%d.password", n);
		if ((line = file_find_line(
		         CONF_AUTH_PATH_NAME, (const char *) buf)) == NULL) {
			debug_msg("line not found");
			break;
		}
		if (line[0] == '#' || line[1] == '#') {
			continue;
		}

		x = 0;
		while (line[x] != '=')
			x++;

		lenp = string_trim(&tmp, line + x + 1);

		password = zmalloc((lenp + 1) * sizeof(uint8_t));
		strncpy(password, tmp, lenp);
		password[lenp] = '\0';
		free(line);
		line = NULL;

		debug_msg("username: %s, len: %d", username, lenu);
		debug_msg("password: %s, len: %d", password, lenp);

		if (nanomq_conf != NULL) {
			nanomq_conf->auths.usernames[n - 1] = username;
			nanomq_conf->auths.passwords[n - 1] = password;
		}
	} while (1);
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
conf_bridge_parse(conf *nanomq_conf, const char *path)
{
	const char *dest_path = path;

	if (!nano_file_exists(dest_path)) {
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

	zfree(nanomq_conf->http_server.username);
	zfree(nanomq_conf->http_server.password);

	zfree(nanomq_conf->websocket.url);

	conf_bridge_destroy(&nanomq_conf->bridge);

	zfree(nanomq_conf);
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
