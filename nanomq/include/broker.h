#ifndef NANOMQ_BROKER_H
#define NANOMQ_BROKER_H
#define MQTT_VER 5

#include <nanolib.h>
#include <nng/nng.h>
#include <nng/protocol/mqtt/mqtt.h>
#include <nng/supplemental/util/platform.h>

#define USAGE \
		"Usage: nanomq broker {"\
		"{start|restart <url> [-daemon] [-tq_thread <num>] [-max_tq_thread <num>] [-parallel <num>]}|stop}\n"\
		"  -url:                 the form of 'tcp://ip_addr:host'\n"\
		"  -tq_thread <num>:     the number of taskq threads used, `num` greater than 0 and less than 256\n"\
		"  -max_tq_thread <num>: the maximum number of taskq threads used, `num` greater than 0 and less than 256\n"\
		"  -parallel <num>:      the maximum number of outstanding requests we can handle\n"

#define PID_PATH_NAME "/tmp/nanomq/nanomq.pid"
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
};

struct conf {
	bool   daemon;
	int    num_taskq_thread;
	int    max_taskq_thread;
	int    parallel;
};

typedef struct client_ctx client_ctx;

typedef struct work emq_work;

typedef struct conf conf;

int broker_start(int argc, char **argv);
int broker_stop(int argc, char **argv);
int broker_restart(int argc, char **argv);
int broker_dflt(int argc, char **argv);

#endif
