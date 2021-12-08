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

bool
conf_parser(conf **nanomq_conf, const char *path)
{
	char * buffer = NULL;
	char * head;
	size_t length       = 0;
	int    temp         = 0;
	bool   read_success = false;
	FILE * fp;

	if (path != NULL) {
		if (!(fp = fopen(path, "r"))) {
			log_warn("Configure file [%s] not found or unreadable",
			    path);
			log_warn("Using default configuration instead.\n");
			return false;
		}
	} else {
		if (!(fp = fopen(CONF_PATH_NAME, "r"))) {
			log_info("Using default configuration.\n");
			return false;
		}
	}

	while (getline(&buffer, &length, fp) != -1) {
		head = buffer;
		while (head[0] == ' ') {
			head++;
		}

		if (head[0] == '#' || head[0] == '\n' || head[0] == '\0') {
			continue;
		}

		char *value = strchr(head, '=') + 1;
		char *key   = strtok(head, "=");

		if (value[0] == '\0' || value[0] == '\n') {
			log_err("No value is specified, conf file parsing "
			        "aborts\n");
			return false;
		}

		char *val_end = value + strlen(value) - 1;
		while (isspace((unsigned char) *val_end))
			val_end--;
		val_end[1] = '\0';

		if (!strcmp(key, "daemon")) {
			if (!strncmp(value, "yes", 3)) {
				(*nanomq_conf)->daemon = true;
				read_success           = true;
				debug_msg(CONF_READ_RECORD, key, value);
			} else if (!strncmp(value, "no", 2)) {
				(*nanomq_conf)->daemon = false;
				read_success           = true;
				debug_msg(CONF_READ_RECORD, key, value);
			}
		} else if (!strcmp(key, "allow_anonymous")) {
			if (!strncmp(value, "yes", 3)) {
				(*nanomq_conf)->allow_anonymous = true;
				read_success                    = true;
				debug_msg(CONF_READ_RECORD, key, value);
			} else if (!strncmp(value, "no", 2)) {
				(*nanomq_conf)->allow_anonymous = false;
				read_success                    = true;
				debug_msg(CONF_READ_RECORD, key, value);
			}
		} else if (!strcmp(key, "url")) {
			if ((*nanomq_conf)->url != NULL) {
				break;
			}
			char *url =
			    zmalloc(sizeof(char) * (strlen(value) + 1));
			if (url == NULL) {
				log_err(
				    "Error: Cannot allocate storge for url, "
				    "parsing aborts\n");
				free(buffer);
				fclose(fp);
				return false;
			}
			strcpy(url, value);
			(*nanomq_conf)->url = url;
			read_success        = true;
			debug_msg(CONF_READ_RECORD, key, value);
		} else if (!strcmp(key, "num_taskq_thread") &&
		    isdigit(value[0]) && ((temp = atoi(value)) > 0) &&
		    (temp < 256)) {
			(*nanomq_conf)->num_taskq_thread = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "max_taskq_thread") &&
		    isdigit(value[0]) && ((temp = atoi(value)) > 0) &&
		    (temp < 256)) {
			(*nanomq_conf)->max_taskq_thread = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "parallel") && isdigit(value[0]) &&
		    ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->parallel = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "property_size") &&
		    isdigit(value[0]) && ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->property_size = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "msq_len") && isdigit(value[0]) &&
		    ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->msq_len = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "qos_duration") && isdigit(value[0]) &&
		    ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->qos_duration = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "http_server.enable")) {
			if (!strncmp(value, "yes", 3)) {
				(*nanomq_conf)->http_server.enable = true;
				read_success                       = true;
				debug_msg(CONF_READ_RECORD, key, value);
			} else if (!strncmp(value, "no", 2)) {
				(*nanomq_conf)->http_server.enable = false;
				read_success                       = true;
				debug_msg(CONF_READ_RECORD, key, value);
			}
		} else if (!strcmp(key, "http_server.port") &&
		    isdigit(value[0]) && ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->http_server.port = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		} else if (!strcmp(key, "http_server.username")) {
			if ((*nanomq_conf)->http_server.username != NULL) {
				break;
			}
			char *username =
			    zmalloc(sizeof(char) * (strlen(value) + 1));
			if (username == NULL) {
				log_err("Cannot allocate storge for "
				        "username, parsing aborts\n");
				free(buffer);
				fclose(fp);
				return false;
			}
			strcpy(username, value);
			(*nanomq_conf)->http_server.username = username;
			read_success                         = true;
			debug_msg(CONF_READ_RECORD, key, value);
		} else if (!strcmp(key, "http_server.password")) {
			if ((*nanomq_conf)->http_server.password != NULL) {
				break;
			}
			char *password =
			    zmalloc(sizeof(char) * (strlen(value) + 1));
			if (password == NULL) {
				log_err("Cannot allocate storge for "
				        "password, parsing aborts\n");
				free(buffer);
				fclose(fp);
				return false;
			}
			strcpy(password, value);
			(*nanomq_conf)->http_server.password = password;
			read_success                         = true;
			debug_msg(CONF_READ_RECORD, key, value);
		} else if (!strcmp(key, "websocket.enable")) {
			if (!strncmp(value, "yes", 3)) {
				(*nanomq_conf)->websocket.enable = true;
				read_success                     = true;
				debug_msg(CONF_READ_RECORD, key, value);
			} else if (!strncmp(value, "no", 2)) {
				(*nanomq_conf)->websocket.enable = false;
				read_success                     = true;
				debug_msg(CONF_READ_RECORD, key, value);
			}
		} else if (!strcmp(key, "websocket.url")) {
			if ((*nanomq_conf)->websocket.url != NULL) {
				break;
			}
			char *url =
			    zmalloc(sizeof(char) * (strlen(value) + 1));
			if (url == NULL) {
				log_err("Cannot allocate storge for "
				        "url, parsing aborts\n");
				free(buffer);
				fclose(fp);
				return false;
			}
			strcpy(url, value);
			(*nanomq_conf)->websocket.url = url;
			read_success                  = true;
			debug_msg(CONF_READ_RECORD, key, value);
		}
		if (!read_success) {
			log_err(
			    "Cannot find the configuration you attemp to set, "
			    "conf file reading halted, stopped at %s",
			    key);
			free(buffer);
			fclose(fp);
			return false;
		}
		read_success = false;
		key          = NULL;
		value        = NULL;
	}

	free(buffer);
	fclose(fp);
	return true;
}

void
conf_init(conf **nanomq_conf)
{
	(*nanomq_conf)->num_taskq_thread     = 10;
	(*nanomq_conf)->max_taskq_thread     = 10;
	(*nanomq_conf)->parallel             = 30; // not work
	(*nanomq_conf)->property_size        = sizeof(uint8_t) * 32;
	(*nanomq_conf)->msq_len              = 64;
	(*nanomq_conf)->qos_duration         = 30;
	(*nanomq_conf)->allow_anonymous      = true;
	(*nanomq_conf)->http_server.enable   = false;
	(*nanomq_conf)->http_server.port     = 8081;
	(*nanomq_conf)->http_server.username = NULL;
	(*nanomq_conf)->http_server.password = NULL;
	(*nanomq_conf)->websocket.enable     = true;
	(*nanomq_conf)->websocket.url        = NULL;
	(*nanomq_conf)->bridge.bridge_mode   = false;
	(*nanomq_conf)->bridge.sub_count     = 0;
}

void
print_conf(conf *nanomq_conf)
{
	fprintf(stdout, "This NanoMQ instance configured as:\n");
	fprintf(stdout, "url is %s\n", nanomq_conf->url);
	fprintf(stdout, "daemon is %d\n", nanomq_conf->daemon);
	fprintf(
	    stdout, "num_taskq_thread is %d\n", nanomq_conf->num_taskq_thread);
	fprintf(
	    stdout, "max_taskq_thread is %d\n", nanomq_conf->max_taskq_thread);
	fprintf(stdout, "parallel is %lu\n", nanomq_conf->parallel);
	fprintf(stdout, "property_size is %d\n", nanomq_conf->property_size);
	fprintf(stdout, "msq_len is %d\n", nanomq_conf->msq_len);
	fprintf(stdout, "qos_duration is %d\n", nanomq_conf->qos_duration);
	fprintf(stdout, "enable http server is %s\n",
	    nanomq_conf->http_server.enable ? "true" : "false");
	fprintf(
	    stdout, "http server port is %d\n", nanomq_conf->http_server.port);

	fprintf(stdout, "enable websocket is %s\n",
	    nanomq_conf->websocket.enable ? "true" : "false");
	fprintf(stdout, "websocket url is %s\n", nanomq_conf->websocket.url);
}

void
conf_auth_parser(conf *nanomq_conf)
{
	char *line = NULL, buf[64], *username, *password, *tmp;
	int   n = 0, x = 0, nu = 0, lenu = 0, lenp = 0;
	if (!nano_file_exists(CONF_AUTH_PATH_NAME)) {
		debug_syslog("file not exists");
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
			debug_syslog("line not found");
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
			debug_syslog("line not found");
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
conf_bridge_parse_subs(conf_bridge *bridge, const char *path)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		log_warn("File %s open failed", path);
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
			log_warn("Configure file [%s] or [%s] not found or "
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
		log_warn("File %s open failed", dest_path);
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
	fprintf(stdout, "bridge_mode: %d\n", bridge->bridge_mode);
	fprintf(stdout, "address: %s\n", bridge->address);
	fprintf(stdout, "proto_ver: %d\n", bridge->proto_ver);
	fprintf(stdout, "clientid: %s\n", bridge->clientid);
	fprintf(stdout, "clean_start: %d\n", bridge->clean_start);
	fprintf(stdout, "username: %s\n", bridge->username);
	fprintf(stdout, "password: %s\n", bridge->password);
	fprintf(stdout, "keepalive: %d\n", bridge->keepalive);

	fprintf(stdout, "forwards: \n");

	for (size_t i = 0; i < bridge->forwards_count; i++) {
		fprintf(stdout, "\t[%ld] topic: %s\n", i, bridge->forwards[i]);
	}

	fprintf(stdout, "subscription: \n");
	for (size_t i = 0; i < bridge->sub_count; i++) {
		fprintf(stdout, "\t[%ld] topic: %.*s\n", i + 1,
		    bridge->sub_list[i].topic_len, bridge->sub_list[i].topic);
		fprintf(stdout, "\t[%ld] qos: %d\n", i + 1,
		    bridge->sub_list[i].qos);
	}
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
