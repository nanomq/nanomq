#include "include/env.h"

static void
set_string_var(char **var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		if (*var) {
			free(*var);
			*var = NULL;
		}
		*var = strdup(env);
	}
}

static void
set_int_var(int *var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		*var = atoi(env);
	}
}

static void
set_long_var(long *var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		*var = atol(env);
	}
}

static void
set_bool_var(bool *var, const char *env_str)
{
	char *str = NULL;

	set_string_var(&str, env_str);

	if (str != NULL) {
		*var = strcasecmp(str, "true") == 0
		    ? true
		    : strcasecmp(str, "yes") == 0;
	}
}

void
read_env_conf(conf *config)
{
	set_string_var(&config->url, NANOMQ_BROKER_URL);
	set_bool_var(&config->daemon, NANOMQ_DAEMON);
	set_int_var(&config->num_taskq_thread, NANOMQ_NUM_TASKQ_THREAD);
	set_int_var(&config->max_taskq_thread, NANOMQ_MAX_TASKQ_THREAD);
	set_long_var((long *) &config->parallel, NANOMQ_PARALLEL);
	set_int_var(&config->property_size, NANOMQ_PROPERTY_SIZE);
	set_int_var(&config->msq_len, NANOMQ_MSQ_LEN);
	set_int_var(&config->qos_duration, NANOMQ_QOS_DURATION);
	set_bool_var(&config->allow_anonymous, NANOMQ_ALLOW_ANONYMOUS);
	set_bool_var(&config->websocket.enable, NANOMQ_WEBSOCKET_ENABLE);
	set_string_var(&config->websocket.url, NANOMQ_WEBSOCKET_URL);
	set_bool_var(&config->http_server.enable, NANOMQ_HTTP_SERVER_ENABLE);
	set_int_var(
	    (int *) &config->http_server.port, NANOMQ_HTTP_SERVER_PORT);
	set_string_var(
	    &config->http_server.username, NANOMQ_HTTP_SERVER_USERNAME);
	set_string_var(
	    &config->http_server.password, NANOMQ_HTTP_SERVER_PASSWORD);
	set_string_var(&config->bridge_file, NANOMQ_BRIDGE_CONF_PATH);
	set_string_var(&config->auth_file, NANOMQ_AUTH_CONF_PATH);
}