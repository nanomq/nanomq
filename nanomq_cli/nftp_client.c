// Author: yuakng.wei <yukang.wei@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#if defined(SUPP_NFTP)
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/options.h>
#include <nng/supplemental/util/platform.h>

#define MQTTV5 "aaaaaaaaa"

#ifdef MQTTV5

#define FTOPIC_ALLINONE "file/file-123"

#define FTOPIC_HELLO FTOPIC_ALLINONE
#define FTOPIC_ACK FTOPIC_ALLINONE
#define FTOPIC_BLOCKS FTOPIC_ALLINONE
#define FTOPIC_GIVEME FTOPIC_ALLINONE

#else

#define FTOPIC_HELLO "file/hello/file-123"
#define FTOPIC_ACK "file/ack/file-123"
#define FTOPIC_BLOCKS "file/blocks/file-123"
#define FTOPIC_GIVEME "file/giveme/file-123"

#endif

#define FURL "mqtt-tcp://127.0.0.1:1883"
#define FSENDERCLIENTID "file-123-sender"
#define FRECVERCLIENTID "file-123-recver"

#define NFTP_TYPE_HELLO 0x01
#define NFTP_TYPE_ACK 0x02
#define NFTP_TYPE_FILE 0x03
#define NFTP_TYPE_END 0x04
#define NFTP_TYPE_GIVEME 0x05

static char *fname_curr = NULL;
static int   flen_curr  = 0;

#define STN 5
static int stcnt      = 0;
static int stats[STN] = { 0 };

enum client_type { SEND = 1, RECV };

typedef struct nftp_opts {
	char *url;
	char *path_to_file;
	char *dir;
} nftp_opts;

enum options {
	OPT_HELP = 1,
	OPT_MQTT_URL,
	OPT_PATH_TO_FILE,
	OPT_DIR,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "url", .o_val = OPT_MQTT_URL, .o_arg = true },
	{ .o_name = "file", .o_short = 'f', .o_val = OPT_PATH_TO_FILE, .o_arg = true },
	{ .o_name = "dir", .o_short = 'd', .o_val = OPT_DIR, .o_arg = true },

	{ .o_name = NULL, .o_val = 0 },
};

static void
print_help(enum client_type type)
{
	if (type == 0) {
		printf("Usage: nanomq_cli nftp { send | recv } [<opts>]\n");

		printf("<opts>:\n");
		printf(
		    "  --url <url>                  The url for mqtt broker "
		    "('mqtt-tcp://host:port' or 'tls+mqtt-tcp://host:port') "
		    "\n");
		printf("                               [default: "
		       "mqtt-tcp://127.0.0.1:1883]\n");
		printf("--file, -f                     Path to the file.\n");
		printf("--dir, -d                      Directory to save "
		       "file, ended with '\'. [default: current directory]\n");
	} else if (type == SEND) {
		printf("Usage: nanomq_cli nftp send --file <path2file> [--url "
		       "<url4broker>]\n");
	} else if (type == RECV) {
		printf("Usage: nanomq_cli nftp recv [--dir <path4dir> --url "
		       "<url4broker>]\n");
	}
}

static int
stats_push(int v)
{
	for (int i = 0; i < stcnt; i++) {
		if (stats[i] != v) {
			stcnt    = 1;
			stats[0] = v;
		}
	}
	// All value in stack are equal to V
	//
	// If stack is full
	if (stcnt == STN) {
		stcnt = 0;
		return v;
	}
	// If stack is not full
	stats[stcnt] = v;
	stcnt++;
	return -1;
}

int keepRunning = 1;

void
intHandler(int dummy)
{
	keepRunning = 0;
	fprintf(stderr, "\nclient exit(0).\n");
	// nng_closeall();
	exit(0);
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	// nng_socket_get?
	printf("%s: disconnected! %d \n", __FUNCTION__, reason);
}

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	printf("%s: connected!\n", __FUNCTION__);
}

// Connect to the given address.
int
client_connect(nng_socket *sock, nng_dialer *dialer, const char *url,
    bool verbose, int client_type)
{
	int rv;

#ifdef MQTTV5
	if ((rv = nng_mqttv5_client_open(sock)) != 0) {
		fatal("nng_socket", rv);
	}
#else
	if ((rv = nng_mqtt_client_open(sock)) != 0) {
		fatal("nng_socket", rv);
	}
#endif

	if ((rv = nng_dialer_create(dialer, *sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
#ifdef MQTTV5
	nng_mqtt_msg_set_connect_proto_version(connmsg, 5);
#else
	nng_mqtt_msg_set_connect_proto_version(connmsg, 4);
#endif
	nng_mqtt_msg_set_connect_keep_alive(connmsg, 60);
	if (client_type == SEND) {
		nng_mqtt_msg_set_connect_client_id(connmsg, FSENDERCLIENTID);
		nng_mqtt_msg_set_connect_user_name(connmsg, "nng_mqtt_client");
	} else if (client_type == RECV){
		nng_mqtt_msg_set_connect_client_id(connmsg, FRECVERCLIENTID);
		nng_mqtt_msg_set_connect_user_name(connmsg, "aaa");
	}
	nng_mqtt_msg_set_connect_password(connmsg, "secrets");
	nng_mqtt_msg_set_connect_will_msg(
	    connmsg, (uint8_t *) "bye-bye", strlen("bye-bye"));
	nng_mqtt_msg_set_connect_will_topic(connmsg, "will_topic");
	nng_mqtt_msg_set_connect_clean_session(connmsg, true);

	nng_mqtt_set_connect_cb(*sock, connect_cb, sock);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	uint8_t buff[1024] = { 0 };

	if (verbose) {
		nng_mqtt_msg_dump(connmsg, buff, sizeof(buff), true);
		printf("%s\n", buff);
	}

	printf("Connecting to Broker:%s ...\n", url);
	nng_dialer_set_ptr(*dialer, NNG_OPT_MQTT_CONNMSG, connmsg);
	nng_dialer_start(*dialer, NNG_FLAG_NONBLOCK);

	return (0);
}

// Publish a message to the given topic and with the given QoS.
int
client_publish(nng_socket sock, const char *topic, uint8_t *payload,
    uint32_t payload_len, uint8_t qos, bool verbose)
{
	int rv;

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, qos);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) payload, payload_len);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	// printf("Publishing to '%s' ...\n", topic);
	if ((rv = nng_sendmsg(sock, pubmsg, NNG_FLAG_NONBLOCK)) != 0) {
		fatal("nng_sendmsg", rv);
	}

	return rv;
}

static int g_wait = 1;

void
wait_ack_and_giveme(void *args)
{
	int        rv;
	nng_socket sock = *(nng_socket *) args;
	while (true) {
		nng_msg *msg;
		uint8_t *payload;
		uint32_t payload_len;
		if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
			fatal("nng_recvmsg", rv);
			continue;
		}

		// we should only receive publish messages
		if (nng_mqtt_msg_get_packet_type(msg) != NNG_MQTT_PUBLISH) {
			nng_msg_free(msg);
			continue;
		}

		payload = nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		// printf("Received payload length %d \n", payload_len);

		if (payload[0] == NFTP_TYPE_ACK) {
			g_wait = 0;
			nng_msg_free(msg);
			continue;
		}

		if (payload[0] != NFTP_TYPE_GIVEME) {
			printf("NOT GIVEME??? %d \n", payload[0]);
			nng_msg_free(msg);
			continue;
		}

		// handle giveme
		char *nftp_file_msg;
		int   nftp_file_len;
		if ((rv = nftp_proto_handler((char *) payload, payload_len,
		         &nftp_file_msg, &nftp_file_len)) != 0) {
			printf("Error in handle giveme %d\n", rv);
			nng_msg_free(msg);
			continue;
		}
		client_publish(sock, FTOPIC_BLOCKS, (uint8_t *) nftp_file_msg,
		    nftp_file_len, 1, 1);

		nng_msg_free(msg);
		free(nftp_file_msg);
	}
}

void
ask_nextid(void *args)
{
	int        rv;
	nng_socket sock = *(nng_socket *) args;
	while (true) {
		nng_msg *msg;
		uint8_t *payload;
		uint32_t payload_len;
		int      blocks, nextid;

		nng_msleep(100);

		if (fname_curr == NULL) {
			continue;
		}

		if ((rv = nftp_proto_recv_status(
		         fname_curr, &blocks, &nextid)) != 0) {
			printf("Done!!! The ctx of this file has been erase "
			       "%s %d\n",
			    fname_curr, rv);
			free(fname_curr);
			fname_curr = NULL;
			continue;
		}

		if (nextid > blocks - 1) {
			// no more giveme needed
			printf("should not be here %d %d\n", nextid, blocks);
			continue;
		}

		if (stats_push(nextid) < 0) {
			continue;
		}
		// printf("ask nextid %d\n", nextid);

		rv = nftp_proto_maker(fname_curr, NFTP_TYPE_GIVEME, 0, nextid,
		    (char **) &payload, (int *) &payload_len);
		if (rv != 0) {
			printf(
			    "error in make giveme %s %d\n", fname_curr, rv);
			continue;
		}

		client_publish(sock, FTOPIC_GIVEME, (uint8_t *) payload,
		    payload_len, 1, 1);
		free(payload);
	}
}

static void
send_callback(nng_mqtt_client *client, nng_msg *msg, void *arg)
{
	nng_aio *aio = client->send_aio;
	uint32_t count;
	uint8_t *code;
	// code = (uint8_t *) nng_mqtt_msg_get_suback_return_codes(msg, &count);
	// printf("aio mqtt result %d \n", nng_aio_result(aio));
	// for (int i = 0; i < count; ++i)
	// 	printf("suback %x \n", code[i]);
	nng_msg_free(msg);
}

static void
set_default_opts(nftp_opts *n_opts)
{
	n_opts->url = FURL;
	n_opts->path_to_file = NULL;
	n_opts->dir          = NULL;
}

static void
free_opts(nftp_opts *n_opts)
{
	if(strncmp(n_opts->url,FURL,25) != 0) {
		nng_strfree(n_opts->url);
	}
	if (n_opts->path_to_file != NULL) {
		nng_strfree(n_opts->path_to_file);
	}
	if (n_opts->dir != NULL) {
		nng_strfree(n_opts->dir);
	}
	nng_free(n_opts, sizeof(nftp_opts));
}

static int
client_parse_opts(int argc, char **argv, nftp_opts *n_opts, int client_type)
{
	int    idx = 1;
	char  *arg;
	int    val;
	int    rv;
	size_t filelen = 0;

	while ((rv = nng_opts_parse(
	            argc - 2, argv + 2, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			if (client_type == SEND) {
				print_help(SEND);
			} else if (client_type == RECV) {
				print_help(RECV);
			} else {
				print_help(0);
			}
			return 0;
		case OPT_MQTT_URL:
			n_opts->url = nng_strdup(arg);
			break;
		case OPT_PATH_TO_FILE:
			n_opts->path_to_file = nng_strdup(arg);
			break;
		case OPT_DIR:
			n_opts->dir = nng_strdup(arg);
			break;
		}
	}
	return 0;
}

int
nftp_client(const int argc, const char **argv, int client_type)
{
	nng_socket sock;
	nng_dialer dailer;

	int         rv          = 0;
	char       *verbose_env = getenv("VERBOSE");
	bool        verbose     = verbose_env && strlen(verbose_env) > 0;

	nftp_opts *n_opts = NULL;

	n_opts = nng_zalloc(sizeof(nftp_opts));
	set_default_opts(n_opts);
	client_parse_opts(argc, argv, n_opts, client_type);

	if (client_type == SEND && n_opts->path_to_file == NULL) {
		print_help(SEND);
		goto exit;
	}

	nftp_proto_init();

	// TODO: more opts for sub or pub
	client_connect(&sock, &dailer, n_opts->url, verbose, client_type);

	signal(SIGINT, intHandler);

#ifdef MQTTV5
	int count = 1;
#else
	int count = 2;
#endif
	nng_mqtt_topic_qos subscriptions[] = {
#ifdef MQTTV5
		{
		    .qos   = 0,
		    .topic = { 
				.buf    = (uint8_t *) FTOPIC_ALLINONE,
		        .length = strlen(FTOPIC_ALLINONE),
			},
			.nolocal = 1,
		},
#else
		{
		    .qos   = 0,
		    .topic = { 
				.buf    = (uint8_t *) FTOPIC_ACK,
		        .length = strlen(FTOPIC_ACK),
			},
		},
		{
		    .qos   = 0,
		    .topic = { 
				.buf    = (uint8_t *) FTOPIC_GIVEME,
		        .length = strlen(FTOPIC_GIVEME),
			},
		},
#endif
	};
	nng_mqtt_client *client =
	    nng_mqtt_client_alloc(sock, &send_callback, true);
	nng_mqtt_subscribe_async(client, subscriptions, count, NULL);
	if (client_type == SEND) {
		if (0 == nftp_file_exist(n_opts->path_to_file)) {
			printf("%s is not exist\n", n_opts->path_to_file);
			goto exit;
		}
		nng_thread *thr;
		nng_thread_create(&thr, wait_ack_and_giveme, (void *) &sock);
		nng_msleep(1000);

		// Send a Hello
		char *nftp_hello_msg = NULL;
		int   nftp_hello_len = 0;
		rv = nftp_proto_maker(n_opts->path_to_file, NFTP_TYPE_HELLO, 0,
		    0, &nftp_hello_msg, &nftp_hello_len);
		if (rv != 0)
			printf("hello make rv %d\n", rv);
		client_publish(sock, FTOPIC_HELLO, (uint8_t *) nftp_hello_msg,
		    nftp_hello_len, 1, 1);
		free(nftp_hello_msg);

		// Wait an ACK
		// printf("wait ack\n");
		// TODO condition variable
		while (g_wait == 1) {
			nng_msleep(500);
		}
		// printf("get ack and start\n");
		// reset g_wait
		g_wait = 1;

		size_t blocks = 0;
		rv = nftp_file_blocks(n_opts->path_to_file, &blocks);
		if (rv != 0)
			printf("blocks rv %d\n", rv);
		nng_msleep(1000);

		// Send FILEs and END
		for (int i = 0; i < blocks - 1; ++i) {
			char *nftp_file_msg;
			int   nftp_file_len;
			if (i % 10 == 0) {
				printf("Cancel sending block %d to "
				       "simulate poor network.\n",
				    i);
				continue;
			}
			nftp_proto_maker(n_opts->path_to_file, NFTP_TYPE_FILE,
			    0, i, &nftp_file_msg, &nftp_file_len);
			client_publish(sock, FTOPIC_BLOCKS,
			    (uint8_t *) nftp_file_msg, nftp_file_len, 1, 1);
			free(nftp_file_msg);
			// Assume 1 Mbps bandwidth
			// 1Mbps / 8bit * 32KB ~= 4 Packets/sec
			nng_msleep(50);
		}
		char *nftp_end_msg;
		int   nftp_end_len;
		nftp_proto_maker(n_opts->path_to_file, NFTP_TYPE_END, 0,
		    blocks - 1, &nftp_end_msg, &nftp_end_len);
		client_publish(sock, FTOPIC_BLOCKS, (uint8_t *) nftp_end_msg,
		    nftp_end_len, 1, 1);
		free(nftp_end_msg);
		printf("file send done\n");
	} else if (client_type == RECV) {
		nng_thread *thr;
		nng_thread_create(&thr, ask_nextid, (void *) &sock);
		nng_msleep(1000);
		if (n_opts->dir != NULL) {
			nftp_set_recvdir(n_opts->dir);
		}
		while (true) {
			nng_msg *msg;
			char    *nftp_reply_msg = NULL;
			int      nftp_reply_len = 0;
			uint8_t *payload;
			uint32_t payload_len;

			if ((rv = nng_recvmsg(sock, &msg, 0)) != 0) {
				nng_fatal("nng_recvmsg", rv);
				continue;
			}

			// we should only receive publish messages
			if (nng_mqtt_msg_get_packet_type(msg) !=
			    NNG_MQTT_PUBLISH) {
				nng_msg_free(msg);
				continue;
			}

			payload = nng_mqtt_msg_get_publish_payload(
			    msg, &payload_len);
			// printf("Received payload %d \n", payload_len);

			rv = nftp_proto_handler((char *) payload, payload_len,
			    &nftp_reply_msg, &nftp_reply_len);
			// if (rv != 0) {
			// 	printf("Error in handling payload [%x] \n",
			// 	    payload[0]);
			// }

			if (payload[0] == NFTP_TYPE_HELLO) {
				char *fname_;
				int   flen_;
				printf("Received HELLO\n");
				nftp_proto_hello_get_fname((char *) payload,
				    (int) payload_len, &fname_, &flen_);

				fname_curr = strndup(fname_, flen_);
				free(fname_);
				// Ask_nextid start work until now. Ugly but
				// works.

				printf("file name %s ..\n", fname_curr);
				// printf("reply ack\n");
				client_publish(sock, FTOPIC_ACK,
				    (uint8_t *) nftp_reply_msg, nftp_reply_len,
				    1, 1);
				free(nftp_reply_msg);

				nng_msg_free(msg);
				msg = NULL;
				continue;
			}

			if (payload[0] == NFTP_TYPE_FILE ||
			    payload[0] == NFTP_TYPE_END) {
				printf("Received FILE");
				free(nftp_reply_msg);

				nng_msg_free(msg);
				msg = NULL;
				continue;
			}

			printf("INVALID NFTP TYPE [%d]\n", payload[0]);
			nng_msg_free(msg);
			msg = NULL;
		}
	}
	// nng_mqtt_disconnect(&sock, 5, NULL);
	nftp_proto_fini();
exit:
	free_opts(n_opts);

	return 0;
}

int
nftp_start(const int argc, const char **argv)
{
	if (argc < 3) {
		print_help(0);
		return 0;
	}
	if (strncmp(argv[2], "send", 4) == 0) {
		nftp_client(argc, argv, SEND);
	} else if (strncmp(argv[2], "recv", 4) == 0) {
		nftp_client(argc, argv, RECV);
	} else {
		print_help(0);
	}
	return 0;
}
#endif