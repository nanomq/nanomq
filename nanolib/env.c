#include "include/env.h"
#include "include/file.h"

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
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		*var = strcasecmp(env, "true") == 0
		    ? true
		    : strcasecmp(env, "yes") == 0;
	}
}

static void
set_data_from_path_var(void **var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		file_load_data(env, var);
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

	set_bool_var(&config->tls.enable, NANOMQ_TLS_ENABLE);
	set_string_var(&config->tls.url, NANOMQ_TLS_URL);
	set_string_var(&config->tls.cafile, NANOMQ_TLS_CA_CERT_PATH);
	set_string_var(&config->tls.certfile, NANOMQ_TLS_CERT_PATH);
	set_string_var(&config->tls.keyfile, NANOMQ_TLS_KEY_PATH);

	set_data_from_path_var(
	    (void **) &config->tls.ca, NANOMQ_TLS_CA_CERT_PATH);
	set_data_from_path_var(
	    (void **) &config->tls.cert, NANOMQ_TLS_CERT_PATH);
	set_data_from_path_var(
	    (void **) &config->tls.key, NANOMQ_TLS_KEY_PATH);

	set_string_var(&config->tls.key_password, NANOMQ_TLS_KEY_PASSWORD);

	set_bool_var(&config->tls.verify_peer, NANOMQ_TLS_VERIFY_PEER);
	set_bool_var(&config->tls.set_fail, NANOMQ_TLS_FAIL_IF_NO_PEER_CERT);

	set_string_var(&config->conf_file, NANOMQ_CONF_PATH);
	set_string_var(&config->bridge_file, NANOMQ_BRIDGE_CONF_PATH);
	set_string_var(&config->auth_file, NANOMQ_AUTH_CONF_PATH);
}