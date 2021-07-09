#ifndef NANOMQ_BROKER_H
#define NANOMQ_BROKER_H
#define MQTT_VER 5

#include <nanolib.h>
#include <nng/nng.h>
#include <nng/protocol/mqtt/mqtt.h>
#include <nng/supplemental/util/platform.h>

struct work {
	enum { INIT, RECV, WAIT, SEND, RESEND, FREE } state;

	uint8_t   proto;
	nng_aio * aio;
	nng_msg * msg;
	nng_msg **msg_ret;
	nng_ctx   ctx;
	nng_pipe  pid;
	nng_mtx * mutex;
	db_tree * db;
	db_tree * db_ret;

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

#endif
