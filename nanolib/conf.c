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
#include "cvector.h"
#include "include/file.h"
#include "nanomq.h"

static conf_http_header **conf_parse_http_headers(
    const char *path, const char *key_prefix, size_t *count);

static char *
strtrim(char *str, size_t len)
{
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
strtrim_head_tail(char *str, size_t len)
{
	size_t head = 0, tail = 0;

	for (size_t i = 0; i < len; i++) {
		if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n') {
			head++;
		} else {
			break;
		}
	}

	for (size_t i = len - 1; i >= 0; i--) {
		if (str[i] == ' ' || str[i] == '\t' || str[i] == '\n') {
			tail++;
		} else {
			break;
		}
	}

	size_t dest_len = len - head - tail + 1;
	char * dest     = calloc(1, dest_len);
	strncpy(dest, str + head, dest_len - 1);

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

static char *
get_conf_value_with_prefix(
    char *line, size_t len, const char *prefix, const char *key)
{
	char str[strlen(prefix) + strlen(key) + 2];
	sprintf(str, "%s%s", prefix, key);
	return get_conf_value(line, len, str);
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
		} else if ((value = get_conf_value(
		                line, sz, "http_server.auth_type")) != NULL) {
			if (strcasecmp("basic", value) == 0) {
				config->http_server.auth_type = BASIC;
			} else if ((strcasecmp("jwt", value) == 0)) {
				config->http_server.auth_type = JWT;
			} else {
				config->http_server.auth_type = NONE_AUTH;
			}
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "http_server.jwt.public.keyfile")) != NULL) {
			FREE_NONULL(config->http_server.jwt.public_keyfile);
			FREE_NONULL(config->http_server.jwt.public_key);
			config->http_server.jwt.public_keyfile = value;
			if (file_load_data(
			        config->http_server.jwt.public_keyfile,
			        (void **) &config->http_server.jwt
			            .public_key) > 0) {
#ifdef NANO_PLATFORM_WINDOWS
				if (strstr(
				        config->http_server.jwt.public_keyfile,
				        "\\")) {
					config->http_server.jwt.iss =
					    strrchr(config->http_server.jwt
					                .public_keyfile,
					        '\\');
					config->http_server.jwt.iss += 1;
				}
#else
				if (strstr(
				        config->http_server.jwt.public_keyfile,
				        "/")) {
					config->http_server.jwt.iss =
					    strrchr(config->http_server.jwt
					                .public_keyfile,
					        '/');
					config->http_server.jwt.iss += 1;
				}
#endif
				else {
					config->http_server.jwt.iss =
					    config->http_server.jwt
					        .public_keyfile;
				}
				config->http_server.jwt.public_key_len =
				    strlen(config->http_server.jwt.public_key);
			}
		} else if ((value = get_conf_value(line, sz,
		                "http_server.jwt.private.keyfile")) != NULL) {
			FREE_NONULL(config->http_server.jwt.private_keyfile);
			FREE_NONULL(config->http_server.jwt.private_key);
			config->http_server.jwt.private_keyfile = value;
			if (file_load_data(
			        config->http_server.jwt.private_keyfile,
			        (void **) &config->http_server.jwt
			            .private_key) > 0) {
				config->http_server.jwt.private_key_len =
				    strlen(
				        config->http_server.jwt.private_key);
			}
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

static void
conf_tls_init(conf_tls *tls)
{
	tls->enable       = false;
	tls->cafile       = NULL;
	tls->certfile     = NULL;
	tls->keyfile      = NULL;
	tls->ca           = NULL;
	tls->cert         = NULL;
	tls->key          = NULL;
	tls->key_password = NULL;
	tls->set_fail     = false;
	tls->verify_peer  = false;
}

static void
conf_tls_destroy(conf_tls *tls)
{
	zfree(tls->cafile);
	zfree(tls->certfile);
	zfree(tls->keyfile);
	zfree(tls->key);
	zfree(tls->key_password);
	zfree(tls->cert);
	zfree(tls->ca);
}

static void
conf_auth_http_req_init(conf_auth_http_req *req)
{
	req->url          = NULL;
	req->method       = NULL;
	req->header_count = 0;
	req->headers      = NULL;
	req->param_count  = 0;
	req->params       = NULL;
}

void
conf_init(conf *nanomq_conf)
{
	nanomq_conf->url              = NULL;
	nanomq_conf->conf_file        = NULL;
	nanomq_conf->bridge_file      = NULL;
	nanomq_conf->rule_engine_file = NULL;
	nanomq_conf->web_hook_file    = NULL;
	nanomq_conf->auth_file        = NULL;
	nanomq_conf->auth_http_file   = NULL;
	nanomq_conf->num_taskq_thread = 10;
	nanomq_conf->max_taskq_thread = 10;
	nanomq_conf->parallel         = 30; // not work
	nanomq_conf->property_size    = sizeof(uint8_t) * 32;
	nanomq_conf->msq_len          = 64;
	nanomq_conf->qos_duration     = 30;
	nanomq_conf->allow_anonymous  = true;
	nanomq_conf->daemon           = false;

	conf_tls_init(&nanomq_conf->tls);

	nanomq_conf->http_server.enable              = false;
	nanomq_conf->http_server.port                = 8081;
	nanomq_conf->http_server.username            = NULL;
	nanomq_conf->http_server.password            = NULL;
	nanomq_conf->http_server.auth_type           = BASIC;
	nanomq_conf->http_server.jwt.iss             = NULL;
	nanomq_conf->http_server.jwt.private_key     = NULL;
	nanomq_conf->http_server.jwt.public_key      = NULL;
	nanomq_conf->http_server.jwt.private_keyfile = NULL;
	nanomq_conf->http_server.jwt.public_keyfile  = NULL;

	nanomq_conf->websocket.enable  = true;
	nanomq_conf->websocket.url     = NULL;
	nanomq_conf->websocket.tls_url = NULL;

	nanomq_conf->bridge.bridge_mode = false;
	nanomq_conf->bridge.sub_count   = 0;
	nanomq_conf->bridge.parallel    = 1;
	conf_tls_init(&nanomq_conf->bridge.tls);

	nanomq_conf->web_hook.enable         = false;
	nanomq_conf->web_hook.url            = NULL;
	nanomq_conf->web_hook.encode_payload = plain;
	nanomq_conf->web_hook.pool_size      = 32;
	nanomq_conf->web_hook.headers        = NULL;
	nanomq_conf->web_hook.header_count   = 0;
	nanomq_conf->web_hook.rules          = NULL;
	nanomq_conf->web_hook.rule_count     = 0;
	conf_tls_init(&nanomq_conf->web_hook.tls);

	nanomq_conf->auth_http.enable = false;
	conf_auth_http_req_init(&nanomq_conf->auth_http.auth_req);
	conf_auth_http_req_init(&nanomq_conf->auth_http.super_req);
	conf_auth_http_req_init(&nanomq_conf->auth_http.acl_req);
	nanomq_conf->auth_http.timeout   = 5;
	nanomq_conf->auth_http.timeout   = 5;
	nanomq_conf->auth_http.pool_size = 32;
	conf_tls_init(&nanomq_conf->auth_http.tls);
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

static void
printf_gateway_conf(zmq_gateway_conf *gateway)
{
	debug_msg("zmq sub url: %s", gateway->zmq_sub_url);
	debug_msg("zmq pub url: %s", gateway->zmq_pub_url);
	debug_msg("zmq sub pre: %s", gateway->zmq_sub_pre);
	debug_msg("zmq pub pre: %s", gateway->zmq_pub_pre);
	debug_msg("mqtt url: %s", gateway->mqtt_url);
	debug_msg("mqtt sub url: %s", gateway->sub_topic);
	debug_msg("mqtt pub url: %s", gateway->pub_topic);
	debug_msg("mqtt username: %s", gateway->username);
	debug_msg("mqtt password: %s", gateway->password);
	debug_msg("mqtt proto version: %d", gateway->proto_ver);
	debug_msg("mqtt keepalive: %d", gateway->keepalive);
	debug_msg("mqtt clean start: %d", gateway->clean_start);
	debug_msg("mqtt parallel: %d", gateway->parallel);
}

static int find_key(const char *str, size_t len)
{
	int i = 0;
	while (rule_engine_key_arr[i]) {
		if (!strncmp(str, rule_engine_key_arr[i], len)) {
			// printf("FIND: %s\n", rule_engine_key_arr[i]);
			return i;
		}
		i++;

	}

	return -1;
}

static int parse_select(const char *select, rule_engine_info *info)
{
	const char * p = select;
	const char * p_b = select;
	int rc = 0;
	while ((p = strchr(p, ','))) {

		if (-1 != (rc = find_key(p_b, p - p_b))) {
			info->flag[rc] = 1;
		}
		p++;

		while (*p == ' ') p++;
		p_b = p;
	}
	if (-1 != (rc = find_key(p_b, strlen(p_b)))) {
		if (rc == 8) {
			memset(info->flag, 1, rc);
		} else {
			info->flag[rc] = 1;
		}
	}

	// for (int i = 0; i < 8; i++) {
	// 	if (info->flag[i]) {
	// 		printf("%s\t", rule_engine_key_arr[i]);
	// 	}
	// }
	// printf("\n");

	return 0;
}

static int parse_from(char *from, rule_engine_info *info)
{
	if (from[0] == '\"') {
		from++;
		char *p = from;
		// TODO check len
		while (*p != '\"') p++;
		*p = '\0';
	}
	info->topic = zstrdup(from);
	// puts(info->topic);
	// TODO mulit topic

	return 0;
}

int insert_filter(const char *str, size_t len, char **filter) 
{
	char *p = str;
	int rc = 0;
	while(*p != ' ' && *p != '=') {
		p++;
	}

	int key_len = p - str;
	// printf("key: %.*s\n", key_len, str);
	if (-1 == (rc = find_key(str, key_len))) {
		log_err("KEY NOT FIND");
		return 1;
	}


	while(*p == ' ' || *p == '=') {
		p++;
	}

	int val_len;

	if (*p == '\'') {
		p++;
		str = p;
		// TODO check len
		while (*p != '\'') p++;
		*p = '\0';
	} else {
		// TODO 
	}

	filter[rc] = zstrdup(str);
	// printf("value: %s\n", filter[rc]);
	return 0;

}

static int parse_where(const char *where, rule_engine_info *info)
{
	const char * p = where;
	const char * p_b = where;
	int rc = 0;

	info->filter = (char **) zmalloc(sizeof(char*) * 8);
	memset(info->filter, 0, 8 * sizeof(char*));

	while ((p = strstr(p, "and"))) {

		// printf("fileter: %.*s\n", p - p_b, p_b);
		
		int key_end, value_st;
		insert_filter(p_b, p - p_b, info->filter);


		p += 3;

		while (*p == ' ') p++;
		p_b = p;
	}
	insert_filter(p_b, strlen(p_b), info->filter);
	// printf("fileter: %.*s\n", strlen(p_b), p_b);
	return 0;
}

bool
conf_rule_engine_parse(conf *nanomq_conf)
{
	const char *dest_path = nanomq_conf->rule_engine_file;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_RULE_ENGINE_PATH_NAME)) {
			printf("Configure file [%s] or [%s] not found or "
			       "unreadable\n",
			    dest_path, CONF_RULE_ENGINE_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_RULE_ENGINE_PATH_NAME;
		}
	}

	char * line = NULL;
	rule_engine_info *rule_infos = NULL;
	size_t sz   = 0;
	FILE * fp;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		printf("File %s open failed\n", dest_path);
		return true;
	}

	while (nano_getline(&line, &sz, fp) != -1) {

		// function 
		if (line[0] != '#' || line[1] !='#') {
			char *srt = strstr(line, "SELECT");
			if (srt != NULL) {
				int len_srt, len_mid, len_end;
				char *mid = strstr(srt, "FROM");
				char *end = strstr(mid, "WHERE");

				rule_engine_info rule_info;
				memset(&rule_info, 0, sizeof(rule_info));

				// function select parser.
				len_srt = mid - srt;
				srt += strlen("SELECT ");
				len_srt -= strlen("SELECT ");
				char select[len_srt];
				memcpy(select, srt, len_srt);
				select[len_srt - 1] = '\0';
				parse_select(select, &rule_info);

				// function from parser
				if (mid != NULL && end != NULL) {
					len_mid = end - mid;
				} else {
					char *p = mid;
					while (*p != '\n') p++;
					len_mid = p - mid + 1;
				}

				mid += strlen("FROM ");
				len_mid -= strlen("FROM ");

				char from[len_mid];
				memcpy(from, mid, len_mid);
				from[len_mid - 1] = '\0';
				parse_from(from, &rule_info);

				// function where parser
				if (end != NULL) {
					char *p = end;
					while (*p != '\n') p++;
					len_end = p - end + 1;
					end += strlen("WHERE ");
					len_end -= strlen("WHERE ");

					char where[len_end];
					memcpy(where, end, len_end);
					where[len_end - 1] = '\0';
					parse_where(where, &rule_info);
				}

				cvector_push_back(rule_infos, rule_info);

			}

		}

		free(line);
		line = NULL;
	}

	nanomq_conf->rule_engine = rule_infos;

	if (line) {
		free(line);
	}


	// printf_rule_engine_conf(rule_engine);

	fclose(fp);
	return true;

out:
	fclose(fp);
	return true;
}

bool
conf_gateway_parse(zmq_gateway_conf *gateway)
{
	const char *dest_path = gateway->path;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_GATEWAY_PATH_NAME)) {
			printf("Configure file [%s] or [%s] not found or "
			       "unreadable\n",
			    dest_path, CONF_GATEWAY_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_GATEWAY_PATH_NAME;
		}
	}

	char * line = NULL;
	size_t sz   = 0;
	FILE * fp;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		printf("File %s open failed\n", dest_path);
		return true;
	}

	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value(
		         line, sz, "gateway.mqtt.proto_ver")) != NULL) {
			gateway->proto_ver = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.keepalive")) != NULL) {
			gateway->keepalive = atoi(value);
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "gateway.mqtt.clean_start")) != NULL) {
			gateway->clean_start = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.parallel")) != NULL) {
			gateway->parallel = atoi(value);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.address")) != NULL) {
			gateway->mqtt_url = value;
		} else if ((value = get_conf_value(line, sz,
		                "gateway.zmq.sub.address")) != NULL) {
			gateway->zmq_sub_url = value;
		} else if ((value = get_conf_value(line, sz,
		                "gateway.zmq.pub.address")) != NULL) {
			gateway->zmq_pub_url = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.username")) != NULL) {
			gateway->username = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.password")) != NULL) {
			gateway->password = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.forward")) != NULL) {
			gateway->pub_topic = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.mqtt.forward")) != NULL) {
			gateway->pub_topic = value;
		} else if ((value = get_conf_value(line, sz,
		                "gateway.mqtt.subscription")) != NULL) {
			gateway->sub_topic = value;
		} else if ((value = get_conf_value(line, sz,
		                "gateway.mqtt.subscription")) != NULL) {
			gateway->sub_topic = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.zmq.sub_pre")) != NULL) {
			gateway->zmq_sub_pre = value;
		} else if ((value = get_conf_value(
		                line, sz, "gateway.zmq.pub_pre")) != NULL) {
			gateway->zmq_pub_pre = value;
		}
		free(line);
		line = NULL;
	}

	if (line) {
		free(line);
	}

	printf_gateway_conf(gateway);

	fclose(fp);
	return true;

out:
	fclose(fp);
	return true;
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
	conf_tls_destroy(&bridge->tls);
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
		char *   key      = calloc(1, sz - 20);
		char *   value    = calloc(1, sz - 20);
		char *   hooktype = NULL;
		char *   hookname = NULL;
		uint16_t num      = 0;
		char *   str      = strtrim_head_tail(line, sz);
		int      res =
		    sscanf(str, "web.hook.rule.%[^=]=%[^\n]", key, value);
		free(str);
		bool  match         = false;
		char *key_trimmed   = NULL;
		char *value_trimmed = NULL;
		if (res == 2) {
			key_trimmed = strtrim_head_tail(key, strlen(key));
			value_trimmed =
			    strtrim_head_tail(value, strlen(value));
			hooktype = calloc(1, strlen(key_trimmed));
			hookname = calloc(1, strlen(key_trimmed));
			res = sscanf(key_trimmed, "%[^.].%[^.].%hu", hooktype,
			    hookname, &num);
			if (res == 3) {
				match = true;
			}
		}
		if (match) {
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
			webhook_action_parse(value_trimmed,
			    webhook->rules[webhook->rule_count - 1]);
		}
		if (key) {
			free(key);
		}
		if (value) {
			free(value);
		}
		if (key_trimmed) {
			free(key_trimmed);
		}
		if (value_trimmed) {
			free(value_trimmed);
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

	webhook->headers = conf_parse_http_headers(
	    dest_path, "web.hook", &webhook->header_count);
	conf_web_hook_parse_rules(webhook, dest_path);
	return true;
}

void
conf_web_hook_destroy(conf_web_hook *web_hook)
{
	zfree(web_hook->url);

	if (web_hook->header_count > 0 && web_hook->headers != NULL) {
		for (size_t i = 0; i < web_hook->header_count; i++) {
			zfree(web_hook->headers[i]->key);
			zfree(web_hook->headers[i]->value);
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

	conf_tls_destroy(&web_hook->tls);
}

static int
get_time(const char *str, uint64_t *second)
{
	char     unit = 0;
	uint64_t s    = 0;
	if (2 == sscanf(str, "%llu%c", &s, &unit)) {
		switch (unit) {
		case 's':
			*second = s;
			break;
		case 'm':
			*second = s * 60;
			break;
		case 'h':
			*second = s * 3600;
			break;
		default:
			break;
		}
		return 0;
	}
	return -1;
}

static conf_http_header **
conf_parse_http_headers(
    const char *path, const char *key_prefix, size_t *count)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		debug_msg("File %s open failed", path);
		return NULL;
	}

	char *             line    = NULL;
	size_t             sz      = 0;
	conf_http_header **headers = NULL;

	char pattern[strlen(key_prefix) + 23];
	sprintf(pattern, "%s.headers.%%[^=]=%%[^\n]", key_prefix);

	size_t header_count = 0;
	while (nano_getline(&line, &sz, fp) != -1) {
		if (sz <= 16) {
			goto next;
		}
		char *key   = calloc(1, sz - 16);
		char *value = calloc(1, sz - 16);
		char *str   = strtrim_head_tail(line, sz);
		int   res   = sscanf(str, pattern, key, value);
		free(str);
		if (res == 2) {
			header_count++;
			headers = realloc(headers,
			    header_count * sizeof(conf_http_header *));
			headers[header_count - 1] =
			    calloc(1, sizeof(conf_http_header));
			headers[header_count - 1]->key =
			    strtrim_head_tail(key, strlen(key));
			headers[header_count - 1]->value =
			    strtrim_head_tail(value, strlen(value));
		}
		if (key) {
			free(key);
		}
		if (value) {
			free(value);
		}

	next:
		free(line);
		line = NULL;
	}

	if (line) {
		free(line);
	}
	fclose(fp);
	*count = header_count;
	return headers;
}

static conf_http_param **
get_params(const char *value, size_t *count)
{
	conf_http_param **params      = NULL;
	size_t            param_count = 0;

	char *line = strdup(value);
	char *tk   = strtok(line, ",");
	while (tk != NULL) {
		param_count++;
		params =
		    realloc(params, sizeof(conf_http_param *) * param_count);
		char *str = strdup(tk);
		char *key = calloc(1, strlen(str));
		char  c   = 0;
		int   res = sscanf(str, "%[^=]=%%%c", key, &c);
		if (res == 2) {
			params[param_count - 1] =
			    calloc(1, sizeof(conf_http_param));
			params[param_count - 1]->name = key;
			switch (c) {
			case 'A':
				params[param_count - 1]->type = ACCESS;
				break;
			case 'u':
				params[param_count - 1]->type = USERNAME;
				break;
			case 'c':
				params[param_count - 1]->type = CLIENTID;
				break;
			case 'a':
				params[param_count - 1]->type = IPADDRESS;
				break;
			case 'P':
				params[param_count - 1]->type = PASSWORD;
				break;
			case 'p':
				params[param_count - 1]->type = SOCKPORT;
				break;
			case 'C':
				params[param_count - 1]->type = COMMON_NAME;
				break;
			case 'd':
				params[param_count - 1]->type = SUBJECT;
				break;
			case 't':
				params[param_count - 1]->type = TOPIC;
				break;
			default:
				break;
			}
		} else {
			param_count--;
			if (key) {
				free(key);
			}
		}
		free(str);
		tk = strtok(NULL, ",");
	}
	if (line) {
		free(line);
	}
	*count = param_count;
	
	return params;
}

static bool
conf_auth_http_req_parse(
    conf_auth_http_req *req, const char *path, const char *key_prefix)
{
	FILE *fp;
	if ((fp = fopen(path, "r")) == NULL) {
		debug_msg("File %s open failed", path);
		return false;
	}
	char * line = NULL;
	size_t sz   = 0;

	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value_with_prefix(
		         line, sz, key_prefix, ".url")) != NULL) {
			req->url = value;
		} else if ((value = get_conf_value_with_prefix(
		                line, sz, key_prefix, ".method")) != NULL) {
			if (strcasecmp(value, "post") == 0 ||
			    strcasecmp(value, "get") == 0) {
				req->method = value;
			} else {
				free(value);
				req->method = strdup("post");
			}
		} else if ((value = get_conf_value_with_prefix(
		                line, sz, key_prefix, ".params")) != NULL) {
			req->params = get_params(value, &req->param_count);
			free(value);
		}

		free(line);
		line = NULL;
	}

	if (line) {
		free(line);
	}
	fclose(fp);

	req->headers =
	    conf_parse_http_headers(path, key_prefix, &req->header_count);

	return true;
}

bool
conf_auth_http_parse(conf *nanomq_conf)
{
	const char *dest_path = nanomq_conf->auth_http_file;

	if (dest_path == NULL || !nano_file_exists(dest_path)) {
		if (!nano_file_exists(CONF_AUTH_HTTP_PATH_NAME)) {
			debug_msg("Configure file [%s] or [%s] not found or "
			          "unreadable",
			    dest_path, CONF_AUTH_HTTP_PATH_NAME);
			return false;
		} else {
			dest_path = CONF_AUTH_HTTP_PATH_NAME;
		}
	}

	char * line = NULL;
	size_t sz   = 0;
	FILE * fp;

	conf_auth_http *auth_http = &nanomq_conf->auth_http;

	if ((fp = fopen(dest_path, "r")) == NULL) {
		debug_msg("File %s open failed", dest_path);
		auth_http->enable = false;
		return true;
	}
	char *value;
	while (nano_getline(&line, &sz, fp) != -1) {
		if ((value = get_conf_value(line, sz, "auth.http.enable")) !=
		    NULL) {
			auth_http->enable = strcasecmp(value, "true") == 0;
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "auth.http.timeout")) != NULL) {
			get_time(value, &auth_http->timeout);
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "auth.http.connect_timeout")) != NULL) {
			get_time(value, &auth_http->connect_timeout);
			free(value);
		} else if ((value = get_conf_value(line, sz,
		                "auth.http.connect_timeout")) != NULL) {
			get_time(value, &auth_http->connect_timeout);
			free(value);
		} else if ((value = get_conf_value(
		                line, sz, "auth.http.pool_size")) != NULL) {
			auth_http->pool_size = (size_t) atol(value);
			free(value);
		}

		free(line);
		line = NULL;
	}
	if (line) {
		free(line);
	}
	fclose(fp);

	conf_auth_http_req_parse(
	    &auth_http->auth_req, dest_path, "auth.http.auth_req");
	conf_auth_http_req_parse(
	    &auth_http->super_req, dest_path, "auth.http.super_req");
	conf_auth_http_req_parse(
	    &auth_http->acl_req, dest_path, "auth.http.acl_req");

	return true;
}

static void
conf_auth_http_req_destroy(conf_auth_http_req *req)
{
	zfree(req->url);
	if (req->header_count > 0 && req->headers != NULL) {
		for (size_t i = 0; i < req->header_count; i++) {
			zfree(req->headers[i]->key);
			zfree(req->headers[i]->value);
			zfree(req->headers[i]);
		}
		zfree(req->headers);
	}

	if (req->param_count > 0 && req->params != NULL) {
		for (size_t i = 0; i < req->param_count; i++) {
			zfree(req->params[i]->name);
			zfree(req->params[i]);
		}
		zfree(req->params);
	}
}

void
conf_auth_http_destroy(conf_auth_http *auth_http)
{
	conf_auth_http_req_destroy(&auth_http->auth_req);
	conf_auth_http_req_destroy(&auth_http->super_req);
	conf_auth_http_req_destroy(&auth_http->acl_req);
	conf_tls_destroy(&auth_http->tls);
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
	zfree(nanomq_conf->rule_engine_file);
	zfree(nanomq_conf->web_hook_file);
	zfree(nanomq_conf->auth_file);
	conf_tls_destroy(&nanomq_conf->tls);

	zfree(nanomq_conf->http_server.username);
	zfree(nanomq_conf->http_server.password);
	zfree(nanomq_conf->http_server.jwt.private_key);
	zfree(nanomq_conf->http_server.jwt.public_key);
	zfree(nanomq_conf->http_server.jwt.private_keyfile);
	zfree(nanomq_conf->http_server.jwt.public_keyfile);

	zfree(nanomq_conf->websocket.url);

	conf_bridge_destroy(&nanomq_conf->bridge);
	conf_web_hook_destroy(&nanomq_conf->web_hook);
	conf_auth_http_destroy(&nanomq_conf->auth_http);

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
