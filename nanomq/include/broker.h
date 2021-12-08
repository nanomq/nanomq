#ifndef NANOMQ_BROKER_H
#define NANOMQ_BROKER_H
#define MQTT_VER 5

#include <nanolib.h>
#include <nng/nng.h>
#include <nng/protocol/mqtt/mqtt.h>
#include <nng/supplemental/util/platform.h>
#include <conf.h>

#define WEBSOCKET_URL "ws://0.0.0.0:8083/mqtt"

struct work {
	enum { INIT, RECV, WAIT, SEND, RESEND, FREE, NOTIFY } state;

	uint8_t   proto;
	nng_aio * aio;
	nng_msg * msg;
	nng_msg **msg_ret;
	nng_ctx   ctx;
	nng_pipe  pid;
	nng_mtx * mutex;
	dbtree *  db;
	dbtree *  db_ret;

	nng_socket   bridge_sock;
	conf_bridge *bridge;

	struct pipe_content *      pipe_ct;
	conn_param *               cparam;
	struct pub_packet_struct * pub_packet;
	struct packet_subscribe *  sub_pkt;
	struct packet_unsubscribe *unsub_pkt;
};

struct client_ctx {
	nng_pipe                 pid;
	conn_param *             cparam;
	struct packet_subscribe *sub_pkt;
	uint8_t                  proto_ver;
};

typedef struct client_ctx client_ctx;

typedef struct work nano_work;

int broker_start(int argc, char **argv);
int broker_stop(int argc, char **argv);
int broker_restart(int argc, char **argv);
int broker_dflt(int argc, char **argv);

dbtree *get_broker_db(void);

#endif
