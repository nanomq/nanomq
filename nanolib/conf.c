//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io> //
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <ctype.h>

#include "include/conf.h"
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

	if (!(fp = fopen(path, "r"))) {
		fprintf(stderr,
		    "\"nanomq.conf %s\" file not found or unreadable\n", path);
		return false;
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
			fprintf(stderr,
			    "No value is specified, conf file parsing "
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
				fprintf(stderr,
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
		} else if (!strcmp(key, "qos_timer") && isdigit(value[0]) &&
		    ((temp = atoi(value)) > 0)) {
			(*nanomq_conf)->qos_timer = temp;
			debug_msg(CONF_READ_RECORD, key, value);
			read_success = true;
		}
		if (!read_success) {
			fprintf(stderr,
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
	(*nanomq_conf)->num_taskq_thread = 10;
	(*nanomq_conf)->max_taskq_thread = 10;
	(*nanomq_conf)->parallel         = 30; // not work
	(*nanomq_conf)->property_size    = sizeof(uint8_t) * 32;
	(*nanomq_conf)->msq_len          = 64;
	(*nanomq_conf)->qos_timer        = 30;
	(*nanomq_conf)->allow_anonymous  = true;
}

void
print_conf(conf *nanomq_conf)
{
	debug_syslog("This NanoMQ instance configured as:\n");
	debug_syslog("url is %s\n", nanomq_conf->url);
	debug_syslog("daemon is %d\n", nanomq_conf->daemon);
	debug_syslog(
	    "num_taskq_thread is %d\n", nanomq_conf->num_taskq_thread);
	debug_syslog(
	    "max_taskq_thread is %d\n", nanomq_conf->max_taskq_thread);
	debug_syslog("parallel is %d\n", nanomq_conf->parallel);
	debug_syslog("property_size is %d\n", nanomq_conf->property_size);
	debug_syslog("msq_len is %d\n", nanomq_conf->msq_len);
	debug_syslog("qos_timer is %d\n", nanomq_conf->qos_timer);
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
