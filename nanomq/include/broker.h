#ifndef NANOMQ_BROKER_H
#define NANOMQ_BROKER_H
#define MQTT_VER 5

#include <conf.h>
#include <nanolib.h>
#include <nng/nng.h>
#include <nng/protocol/mqtt/mqtt.h>
#include <nng/supplemental/util/platform.h>

#define PROTO_MQTT_BROKER 0x00
#define PROTO_MQTT_BRIDGE 0x01

typedef struct work nano_work;
struct work {
	enum { INIT, RECV, WAIT, SEND, RESEND, FREE, NOTIFY, BRIDGE, END } state;
	// 0x00 mqtt_broker
	// 0x01 mqtt_bridge
	uint8_t   proto;
	nng_aio * aio;
	nng_aio * bridge_aio;
	nng_msg * msg;
	nng_msg **msg_ret;
	nng_ctx   ctx;        // ctx for mqtt broker
	nng_ctx   bridge_ctx; // ctx for bridging
	nng_pipe  pid;
	nng_mtx * mutex;
	dbtree *  db;
	dbtree *  db_ret;
	conf *    config;

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

int broker_start(int argc, char **argv);
int broker_stop(int argc, char **argv);
int broker_restart(int argc, char **argv);
int broker_dflt(int argc, char **argv);

dbtree *get_broker_db(void);

#endif
