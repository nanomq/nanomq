#include "nanomq.h"
#include "include/conf.h"

bool
conf_parser(conf **nanomq_conf, const char* path)
{
	size_t length = 0;
	int    temp   = 0;
	char * buffer;
	char * head;
	bool   read_success = false;
	FILE * fp;

	if (!(fp = fopen(path, "r"))) {
		fprintf(stderr, "\"nanomq.conf %s\" file not found or unreadable\n", path);
		return false;
	}

	while (getline(&buffer, &length, fp) != -1) {
		head = buffer;
		while (head[0] == ' ') {head++;}

		if (head[0] == '#' || head[0] == '\n' || head[0] == '\0') {
			continue;
		}

		char *value                = strchr(head, '=') + 1;
		char *key                  = strtok(head, "=");

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
				(*nanomq_conf)->daemon == 1;
				read_success = true;
				debug_msg(CONF_READ_RECORD, key, value);
			} else if (!strncmp(value, "no", 2)) {
				(*nanomq_conf)->daemon == -1;
				read_success = true;
				debug_msg(CONF_READ_RECORD, key, value);
			}
		} else if (!strcmp(key, "url")) {
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
macro_def_parser(conf **nanomq_conf)
{
#ifdef NANO_PROPERTY_SIZE
	(*nanomq_conf)->property_size = sizeof(uint8_t) * NANO_PROPERTY_SIZE;
#else
	(*nanomq_conf)->property_size = sizeof(uint8_t) * 32;
#endif


#ifdef NANO_MSQ_LEN
	(*nanomq_conf)->msq_len = NANO_PACKET_SIZE;
#else
	(*nanomq_conf)->msq_len       = 64;
#endif

#ifdef NANO_QOS_TIMER
	(*nanomq_conf)->qos_timer = NANO_QOS_TIMER;
#else
	(*nanomq_conf)->qos_timer     = 30;
#endif
}

void 
print_conf(conf *nanomq_conf) {
	debug_syslog("This NanoMQ instance configured as:\n");
	debug_syslog("url is %s\n", nanomq_conf->url);
	debug_syslog("daemon is %d\n", nanomq_conf->daemon);
	debug_syslog("num_taskq_thread is %d\n", nanomq_conf->num_taskq_thread);
	debug_syslog("max_taskq_thread is %d\n", nanomq_conf->max_taskq_thread);
	debug_syslog("parallel is %d\n", nanomq_conf->parallel);
	debug_syslog("property_size is %d\n", nanomq_conf->property_size);
	debug_syslog("msq_len is %d\n", nanomq_conf->msq_len);
	debug_syslog("qos_timer is %d\n", nanomq_conf->qos_timer);
}