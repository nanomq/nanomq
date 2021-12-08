#include "include/bridge.h"
#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/nanomq.h"

#if defined(NNG_PLATFORM_POSIX)
#define nano_strtok strtok_r
#elif defined(NNG_PLATFORM_WINDOWS)
#define nano_strtok strtok_s
#else
#define nano_strtok strtok_r
#endif

enum work_state { INIT, RECV, WAIT, SEND };

struct bridge_work {
	enum work_state state;
	nng_aio *       aio;
	nng_msg *       msg;
	nng_ctx         ctx;
	nng_socket      inner_sock;
};

struct inner_work {
	enum work_state state;
	nng_aio *       aio;
	nng_msg *       msg;
	nng_ctx         ctx;
};

static void
fatal(const char *func, int rv)
{
	fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}

int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t len, bool dup, uint8_t qos, bool retain)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, dup);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, retain);
	nng_mqtt_msg_set_publish_payload(pubmsg, payload, len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	printf("publish to '%s' \n", topic);
	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		fatal("nng_sendmsg", rv);
	}

	// nng_msg_free(pubmsg);
	return rv;
}

// Disconnect message callback function
static void
disconnect_cb(void *disconn_arg, nng_msg *msg)
{
	nng_socket sock = *(nng_socket *) disconn_arg;
	printf("%s: %d\n", __FUNCTION__, sock.id);
}

#define SUB_TOPIC1 "/nanomq/msg/1"
#define SUB_TOPIC2 "/nanomq/msg/2"
#define SUB_TOPIC3 "/nanomq/msg/3"

typedef struct {
	nng_socket * sock;
	conf_bridge *config;
} bridge_param;

// Connack message callback function
static void
bridge_connect_cb(void *connect_arg, nng_msg *msg)
{
	uint8_t ret_code = nng_mqtt_msg_get_connack_return_code(msg);
	printf("%s: %s(%d)\n", __FUNCTION__,
	    ret_code == 0 ? "connection established" : "connect failed",
	    ret_code);

	nng_msg_free(msg);
	msg = NULL;

	if (ret_code == 0) {
		// Connected succeed
		bridge_param *param = connect_arg;

		nng_mqtt_msg_alloc(&msg, 0);
		nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_SUBSCRIBE);

		nng_mqtt_topic_qos *topic_qos =
		    nng_mqtt_topic_qos_array_create(param->config->sub_count);
		for (size_t i = 0; i < param->config->sub_count; i++) {
			nng_mqtt_topic_qos_array_set(topic_qos, i,
			    param->config->sub_list[i].topic,
			    param->config->sub_list[i].qos);
		}
		nng_mqtt_msg_set_subscribe_topics(
		    msg, topic_qos, param->config->sub_count);

		nng_mqtt_topic_qos_array_free(
		    topic_qos, param->config->sub_count);

		// Send subscribe message
		nng_sendmsg(*param->sock, msg, NNG_FLAG_NONBLOCK);
	}
}

static void
inner_connect_cb(void *connect_arg, nng_msg *msg)
{
	uint8_t ret_code = nng_mqtt_msg_get_connack_return_code(msg);
	printf("%s: %s(%d)\n", __FUNCTION__,
	    ret_code == 0 ? "connection established" : "connect failed",
	    ret_code);

	nng_msg_free(msg);
}

static nng_mqtt_cb bridge_user_cb = {
	.name            = "bridge_user_cb",
	.on_connected    = bridge_connect_cb,
	.on_disconnected = disconnect_cb,
};

static nng_mqtt_cb inner_user_cb = {
	.name            = "inner_user_cb",
	.on_connected    = inner_connect_cb,
	.on_disconnected = disconnect_cb,
};

void
bridge_cb(void *arg)
{
	struct bridge_work *work = arg;
	nng_msg *           msg;
	int                 rv;

	switch (work->state) {
	case INIT:
		work->state = WAIT;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio2", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}

		work->state = WAIT;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case WAIT:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			fatal("nng_recv_aio2", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		work->msg = nng_aio_get_msg(work->aio);
		msg       = work->msg;
		uint32_t payload_len;
		uint8_t *payload =
		    nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		bool dup    = nng_mqtt_msg_get_publish_dup(msg);
		bool qos    = nng_mqtt_msg_get_publish_qos(msg);
		bool retain = nng_mqtt_msg_get_publish_retain(msg);

		printf("RECV: '%.*s' FROM: '%.*s'\n", payload_len,
		    (char *) payload, topic_len, recv_topic);

		char *send_topic = nng_zalloc(topic_len + 1);
		memcpy(send_topic, recv_topic, topic_len);

		// Send msg to local broker via inner client
		client_publish(work->inner_sock, send_topic, payload,
		    payload_len, dup, qos, retain);

		nng_free(send_topic, topic_len + 1);

		nng_msg_free(msg);
		work->msg   = NULL;
		work->state = RECV;
		nng_aio_finish(work->aio, 0);
		break;

	case SEND:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			fatal("nng_send_aio", rv);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	default:
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

struct bridge_work *
alloc_bridge_work(nng_socket sock, nng_socket inner_sock)
{
	struct bridge_work *w;
	int                 rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, bridge_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}

	w->inner_sock = inner_sock;
	w->state      = INIT;
	return (w);
}

static bridge_param bridge_arg;

int
bridge_client(nng_socket *sock, uint16_t nwork, nng_socket inner_sock,
    conf_bridge *config)
{
	int                 rv;
	nng_dialer          dialer;
	struct bridge_work *work[nwork];

	if ((rv = nng_mqtt_client_open(sock)) != 0) {
		fatal("nng_mqtt_client_open", rv);
		return rv;
	}

	for (uint16_t i = 0; i < nwork; i++) {
		work[i] = alloc_bridge_work(*sock, inner_sock);
	}

	if ((rv = nng_dialer_create(&dialer, *sock, config->address))) {
		fatal("nng_dialer_create", rv);
		return rv;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, config->keepalive);
	nng_mqtt_msg_set_connect_proto_version(connmsg, config->proto_ver);
	nng_mqtt_msg_set_connect_clean_session(connmsg, config->clean_start);
	if (config->clientid) {
		nng_mqtt_msg_set_connect_client_id(connmsg, config->clientid);
	}
	if (config->username) {
		nng_mqtt_msg_set_connect_user_name(connmsg, config->username);
	}
	if (config->password) {
		nng_mqtt_msg_set_connect_password(connmsg, config->password);
	}

	bridge_arg.config = config;
	bridge_arg.sock   = sock;

	bridge_user_cb.connect_arg = &bridge_arg;
	bridge_user_cb.disconn_arg = sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_dialer_set_cb(dialer, &bridge_user_cb);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (uint16_t i = 0; i < nwork; i++) {
		bridge_cb(work[i]);
	}

	return 0;
}

int
inner_client(nng_socket *sock, const char *url)
{
	int        rv;
	nng_dialer dialer;

	if ((rv = nng_mqtt_client_open(sock)) != 0) {
		fatal("nng_mqtt_client_open", rv);
		return rv;
	}

	if ((rv = nng_dialer_create(&dialer, *sock, url))) {
		fatal("nng_dialer_create", rv);
		return rv;
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, 60);
	nng_mqtt_msg_set_connect_proto_version(connmsg, 4);
	nng_mqtt_msg_set_connect_clean_session(connmsg, true);

	inner_user_cb.connect_arg = sock;
	inner_user_cb.disconn_arg = sock;

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_dialer_set_cb(dialer, &inner_user_cb);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	return 0;
}

bool
topic_filter(const char *origin, const char *input)
{
	bool result = true;

	if (strcmp(origin, input) == 0) {
		return true;
	}

	char *p1 = NULL, *p2 = NULL;

	char *origin_str = strdup(origin);
	char *input_str  = strdup(input);

	char *origin_token = nano_strtok(origin_str, "/", &p1);
	char *input_token  = nano_strtok(input_str, "/", &p2);

	while (origin_token != NULL && input_token != NULL) {
		if (strcmp(origin_token, input_token) != 0) {
			if (strcmp(origin_token, "#") == 0) {
				result = true;
				break;
			} else if (strcmp(origin_token, "+") != 0) {
				result = false;
				break;
			}
		}
		origin_token = nano_strtok(NULL, "/", &p1);
		input_token  = nano_strtok(NULL, "/", &p2);
	}

	free(input_str);
	free(origin_str);
	return result;
}