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

static void
set_msg_persistence(persistence_type *var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		if (strcasecmp(env, "memory") == 0) {
			*var = memory;
		} else if (strcasecmp(env, "sqlite") == 0) {
			*var = sqlite;
		}
	}
}

static void
set_auth_type(auth_type *var, const char *env_str)
{
	char *env = NULL;

	if ((env = getenv(env_str)) != NULL) {
		if (strcasecmp(env, "basic") == 0) {
			*var = BASIC;
		} else if (strcasecmp(env, "jwt") == 0) {
			*var = JWT;
		}
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
	set_long_var(
	    (long *) &config->max_packet_size, NANOMQ_MAX_PACKET_SIZE);
	set_long_var((long *) &config->client_max_packet_size,
	    NANOMQ_CLIENT_MAX_PACKET_SIZE);
	set_msg_persistence(&config->persist, NANOMQ_MSG_PERSISTENCE);
	set_int_var(&config->msq_len, NANOMQ_MSQ_LEN);
	set_int_var(&config->qos_duration, NANOMQ_QOS_DURATION);
	set_bool_var(&config->allow_anonymous, NANOMQ_ALLOW_ANONYMOUS);
	set_bool_var(&config->websocket.enable, NANOMQ_WEBSOCKET_ENABLE);
	set_string_var(&config->websocket.url, NANOMQ_WEBSOCKET_URL);
	set_string_var(&config->websocket.tls_url, NANOMQ_WEBSOCKET_TLS_URL);
	set_bool_var(&config->http_server.enable, NANOMQ_HTTP_SERVER_ENABLE);
	set_int_var(
	    (int *) &config->http_server.port, NANOMQ_HTTP_SERVER_PORT);
	set_long_var((long *) &config->http_server.parallel,
	    NANOMQ_HTTP_SERVER_PARALLEL);
	set_string_var(
	    &config->http_server.username, NANOMQ_HTTP_SERVER_USERNAME);
	set_string_var(
	    &config->http_server.password, NANOMQ_HTTP_SERVER_PASSWORD);
	set_string_var(
	    &config->http_server.password, NANOMQ_HTTP_SERVER_PASSWORD);
	set_auth_type(
	    &config->http_server.auth_type, NANOMQ_HTTP_SERVER_AUTH_TYPE);
	set_data_from_path_var((void **) &config->http_server.jwt.public_key,
	    NANOMQ_HTTP_SERVER_JWT_PUBLIC_KEYFILE);
	set_data_from_path_var((void **) &config->http_server.jwt.private_key,
	    NANOMQ_HTTP_SERVER_JWT_PRIVATE_KEYFILE);

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
	set_string_var(&config->web_hook_file, NANOMQ_WEBHOOK_CONF_PATH);
	set_string_var(&config->auth_http_file, NANOMQ_AUTH_HTTP_CONF_PATH);
	set_string_var(&config->auth_file, NANOMQ_AUTH_CONF_PATH);
#if defined(SUPP_RULE_ENGINE)
	char *rule_engine_file;
	set_string_var(
	    &config->rule_engine_file, NANOMQ_RULE_ENGINE_CONF_PATH);
#endif
}