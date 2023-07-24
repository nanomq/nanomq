/*
 * This is an example of how to use the MQTT client library to send a file to
 * the broker using EMQX's the file transfer extension.
 *
 * The EMQX file transfer extension documentation is available here:
 * https://www.emqx.io/docs/en/v5/file-transfer/introduction.html
 *
 * This example reads a file from the file system and publishes it to the
 * broker (the file transfer feature has to be enabled in the EMQX
 * configuration). The user can specify the file path, file id, file name etc
 * as command line parameters. Run the program with the --help flag to see the
 * list of options.
 *
 * Change the DEBUG macro to 1 to see debug messages.
 */

/*
 * TODO: In order to know that the broker accepted the file and the individual
 * messages one has to check the PUBACK reason code. This is not implemented
 * in this example so even if everything seems to work we don't know that the
 * file has been stored by the broker (without checking with e.g., the HTTP
 * API). The PUBACK reason code is a MQTT v5 feature so in order to fix this we
 * would first have to make sure that the client connects with the MQTT v5
 * protocol and then check the PUBACK reason code fore each message. It seems
 * like this could be done by setting a handler with MQTTClient_setPublished()
 * https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/_m_q_t_t_client_8h.html#a9f13911351a3de6b1ebdabd4cb4116ba
 * . Unfortunately I had some problem with connecting with MQTT v5 so I have
 * not been able to test this yet. See also:
 * https://github.com/emqx/MQTT-Client-Examples/pull/112#discussion_r1253421492
 */


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <MQTTClient.h>

#include "nng/supplemental/nanolib/cJSON.h"

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>


#define CLIENTID	"c-client"
#define TIMEOUT	 100000L
#define DEBUG	   1

struct work {
	enum { INIT, RECV, WAIT, SEND_INIT, SEND_FILE, SEND_FINI, SEND_FINI_DONE, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
	nng_socket   sock;
	char fileid[128];
	char filename[128];
	char filepath[128];
	long filesize;
	int file_off;
	FILE *fp;
};

void print_file_transfer_usage() {
	printf("usage: mqtt_c_file_transfer [-h|--help] [--port PORT] [--host HOST] [--username USERNAME] [--password PASSWORD] --file FILE [--file-name FILE_NAME] [--segments-ttl-seconds SEGMENTS_TTL_SECONDS] [--expire-after-seconds EXPIRE_AFTER_SECONDS] --file-id FILE_ID [--client-id CLIENT_ID]");
}

/*
	Read command line arguments into write back variables and fill in default
	values.
*/
void initial_param(
		int argc,
		char *argv[],
		char **file_path,
		char **file_id,
		char **username,
		char **password,
		char **file_name,
		char **client_id,
		char **host,
		int *port,
		long *segments_ttl_seconds,
		long *expire_after_seconds) {
	// Fill in default values
	*file_name = "myfile.txt";
	*host = "localhost";
	*port = 1883;
	*segments_ttl_seconds = -1;
	*expire_after_seconds = -1;
	*client_id = CLIENTID;
	*username = NULL;
	*password = NULL;
	char *fpa = malloc(sizeof(char) * 30);
	char *fida = malloc(sizeof(char) * 30);

	memset(fpa, '\0', 30);
	memset(fida, '\0', 30);

	*file_path = fpa;
	*file_id = fida;
}

void
client_cb(void *arg)
{
	struct work *work = arg;
	nng_msg *    msg;
	int          rv;
	char *payload = NULL; 
	int buf_size = 1024 * 10;
	char topic[buf_size];
	memset(topic, 0, buf_size);

	switch (work->state) {

	case INIT:
		printf("rhack: %s: %d\n", __func__, __LINE__);
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case RECV:
		printf("rhack: %s: %d work: %p\n", __func__, __LINE__, work);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			printf("rhack: %s: %d rv: %d\n", __func__, __LINE__, rv);
			fatal("nng_recv_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}

		work->msg   = nng_aio_get_msg(work->aio);
		work->state = WAIT;
		nng_sleep_aio(0, work->aio);
		break;

	case WAIT:
		printf("rhack: %s: %d work: %p\n", __func__, __LINE__, work);
		msg = work->msg;

		// Get PUBLISH payload and topic from msg;
		uint32_t payload_len;
		payload = (char *)nng_mqtt_msg_get_publish_payload(msg, &payload_len);
		uint32_t    topic_len;
		const char *recv_topic =
		    nng_mqtt_msg_get_publish_topic(msg, &topic_len);

		printf("RECV: '%.*s' FROM: '%.*s'\n", payload_len,
		    (char *) payload, topic_len, recv_topic);

		cJSON *cjson_objs = cJSON_Parse((char *)payload);
		if (cjson_objs == NULL) {
			printf("Parse json failed recv continue...\n");
		} else {
			cJSON *cjson_filepath = cJSON_GetObjectItem(cjson_objs, "file_path");
			cJSON *cjson_fileid = cJSON_GetObjectItem(cjson_objs, "file_id");
			cJSON *cjson_filename = cJSON_GetObjectItem(cjson_objs, "file_name");
			if (cjson_filepath == NULL || cjson_fileid == NULL ||
				cjson_filename == NULL) {
					printf("Input Json invalid recv continue...\n");
			} else {
				if (DEBUG) {
					printf("Input Json: filepath: %s fileid: %s filename: %s\n",
											cjson_filepath->valuestring,
											cjson_fileid->valuestring,
											cjson_filename->valuestring);
				}
				printf("rhack: %s: %d work: %p aio: %p is working\n", __func__, __LINE__, work, (void *)work->aio);
				memset(work->fileid, 0, 128);
				memset(work->filename, 0, 128);
				memset(work->filepath, 0, 128);
				strcpy(work->fileid, cjson_fileid->valuestring);
				strcpy(work->filename, cjson_filename->valuestring);
				strcpy(work->filepath, cjson_filepath->valuestring);
				work->state = SEND_INIT;
				nng_sleep_aio(0, work->aio);
				break;
			}
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
		break;

	case SEND_INIT:
		printf("rhack: %s: %d work: %p\n", __func__, __LINE__, work);
		payload = malloc(sizeof(char) * buf_size);
		char *expire_at_str = malloc(sizeof(char) * 128);
		char *segments_ttl_str = malloc(sizeof(char) * 128);
		FILE *fp = fopen(work->filepath, "rb");
		if (fp == NULL) {
			printf("Failed to open file %s\n", work->filepath);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			free(payload);
			free(expire_at_str);
			free(segments_ttl_str);
			break;
		}
		work->fp = fp;
		// Get file size
		fseek(fp, 0L, SEEK_END);
		long file_size = ftell(fp);
		work->filesize = file_size;
		fseek(fp, 0L, SEEK_SET);
		int expire_time_s_since_epoch = -1;
		int segments_ttl_seconds = -1;
		if (expire_time_s_since_epoch == -1) {
			expire_at_str[0] = '\0';
		} else {
			// No need to check return value since we know the buffer is large enough
			snprintf(expire_at_str,
					128,
					"  \"expire_at\": %ld,\n",
					expire_time_s_since_epoch);
		}
		if (segments_ttl_seconds == -1) {
			segments_ttl_str[0] = '\0';
		} else {
		// No need to check return value since we know the buffer is large enough
		snprintf(segments_ttl_str,
				128,
				"  \"segments_ttl\": %ld,\n",
				segments_ttl_seconds);
		}
		rv = snprintf(
				payload,
				buf_size,
				"{\n"
				"  \"name\": \"%s\",\n"
				"  \"size\": %ld,\n"
				"%s"
				"%s"
				"  \"user_data\": {}\n"
				"}",
				work->filename,
				file_size,
				expire_at_str,
				segments_ttl_str);
		if (rv < 0 || rv >= buf_size) {
			printf("Failed to create payload for initial message\n");
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		// Create topic of the form $file/{file_id}/init for initial message
		rv = snprintf(topic, buf_size, "$file/%s/init", work->fileid);
		if (rv < 0 || rv >= buf_size) {
			printf("Failed to create topic for initial message\n");
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		// Publish initial message
		if (DEBUG) {
			printf("Publishing initial message to topic %s\n", topic);
			printf("Payload: %s\n", payload);
		}

		nng_msg_header_clear(work->msg);
		nng_msg_clear(work->msg);

		nng_mqtt_msg_set_packet_type(work->msg, NNG_MQTT_PUBLISH);
		nng_mqtt_msg_set_publish_qos(work->msg, 1);
		nng_mqtt_msg_set_publish_topic(work->msg, topic);
		nng_mqtt_msg_set_publish_payload(
		    work->msg, payload, strlen(payload));

		printf("SEND: '%.*s' TO:   '%s'\n", strlen(payload),
		    (char *) payload, topic);

		nng_aio_set_msg(work->aio, work->msg);
		work->msg   = NULL;
		work->state = SEND_FILE;
		work->file_off = 0;
		free(payload);
		free(expire_at_str);
		free(segments_ttl_str);

		nng_ctx_send(work->ctx, work->aio);
		break;

	case SEND_FILE:
//		printf("rhack: %s: %d work: %p\n", __func__, __LINE__, work);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			printf("rhack: %s: %d work: %p\n", __func__, __LINE__, work);
			fatal("nng_send_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		int read_bytes;
		int chunk_size = 1024;
		nng_msg *newmsg;
		nng_mqtt_msg_alloc(&newmsg, 0);
		payload = malloc(sizeof(char) * buf_size);
		memset(payload, 0, buf_size);
		if ((read_bytes = fread(payload, 1, chunk_size, work->fp)) > 0) {
			rv = snprintf(topic, buf_size, "$file/%s/%lu", work->fileid, work->file_off);
			if (rv < 0 || rv >= buf_size) {
				printf("Failed to create topic for file chunk\n");
	
				free(payload);
				free(expire_at_str);
				free(segments_ttl_str);

				work->state = RECV;
				nng_ctx_recv(work->ctx, work->aio);
				break;
			}
			if (DEBUG) {
				printf("Publishing file chunk to topic %s offset %lu\n", topic, work->file_off);
			}
			nng_mqtt_msg_set_packet_type(newmsg, NNG_MQTT_PUBLISH);
			nng_mqtt_msg_set_publish_qos(newmsg, 1);
			nng_mqtt_msg_set_publish_topic(newmsg, topic);
			nng_mqtt_msg_set_publish_payload(
			    newmsg, payload, strlen(payload));

//			printf("SEND: '%.*s' TO:   '%s'\n", strlen(payload),
//			    (char *) payload, topic);

			nng_aio_set_msg(work->aio, newmsg);
			work->file_off += read_bytes;
			nng_ctx_send(work->ctx, work->aio);
	//		printf("SEND: '%.*s' TO:   '%s'\n", strlen(send_data),
	//		    (char *) send_data, topic);
			nng_msleep(100);
		} else {
			work->state = SEND_FINI;
			nng_sleep_aio(0, work->aio);
		}
		free(payload);
		break;

	case SEND_FINI:
		nng_msleep(30 * 1000);
		nng_msg *finimsg;
		nng_mqtt_msg_alloc(&finimsg, 0);
		printf("rhack: %s: %d\n", __func__, __LINE__);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			printf("rhack: %s: %d rv: %d\n", __func__, __LINE__, rv);
			fatal("nng_send_aio", rv);
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		char *topic3 = malloc(sizeof(char) * buf_size);
		fclose(work->fp);
		work->fp = NULL;
		// Send final message to the topic $file/{file_id}/fin/{file_size} with an empty payload
		rv = snprintf(topic3, buf_size, "$file/%s/fin/%ld", work->fileid, work->filesize);
		if (rv < 0 || rv >= buf_size) {
			printf("Failed to create topic for final message\n");
			work->state = RECV;
			nng_ctx_recv(work->ctx, work->aio);
			break;
		}
		if (DEBUG) {
			printf("Publishing final message to topic %s\n", topic3);
		}

		nng_mqtt_msg_set_packet_type(finimsg, NNG_MQTT_PUBLISH);
		nng_mqtt_msg_set_publish_qos(finimsg, 1);
		nng_mqtt_msg_set_publish_topic(finimsg, topic3);
		nng_mqtt_msg_set_publish_payload(
		    finimsg, "", 0);

		nng_aio_set_msg(work->aio, finimsg);
		work->state = SEND_FINI_DONE;
		free(topic3);
		nng_ctx_send(work->ctx, work->aio);
		break;

	case SEND_FINI_DONE:
		printf("rhack: %s: %d\n", __func__, __LINE__);
		if ((rv = nng_aio_result(work->aio)) != 0) {
			nng_msg_free(work->msg);
			fatal("nng_send_aio", rv);
		printf("rhack: %s: %d\n", __func__, __LINE__);
		}
		work->state = RECV;
		nng_ctx_recv(work->ctx, work->aio);
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
		printf("rhack: %s: %d\n", __func__, __LINE__);
		fatal("bad state!", NNG_ESTATE);
		break;
	}
}

#define SUB_TOPIC1 "file_transfer"

void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	printf("%s: connected[%d]!\n", __FUNCTION__, reason);

	if (reason == 0) {
		nng_socket *sock = arg;
		nng_mqtt_topic_qos topic_qos[] = {
			{ .qos     = 0,
			    .topic = { .buf = (uint8_t *) SUB_TOPIC1,
			        .length     = strlen(SUB_TOPIC1) } },
		};

		size_t topic_qos_count =
		    sizeof(topic_qos) / sizeof(nng_mqtt_topic_qos);

		// Connected succeed
		nng_msg *submsg;
		nng_mqtt_msg_alloc(&submsg, 0);
		nng_mqtt_msg_set_packet_type(submsg, NNG_MQTT_SUBSCRIBE);
		nng_mqtt_msg_set_subscribe_topics(
		    submsg, topic_qos, topic_qos_count);

		// Send subscribe message
		nng_sendmsg(*sock, submsg, NNG_FLAG_NONBLOCK);
	}
}

struct work *
alloc_works(nng_socket sock)
{
	struct work *w;
	int          rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		fatal("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, client_cb, w)) != 0) {
		fatal("nng_aio_alloc", rv);
	}
	if ((rv = nng_ctx_open(&w->ctx, sock)) != 0) {
		fatal("nng_ctx_open", rv);
	}
	w->state = INIT;
	return (w);
}

void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	printf("%s: disconnected!\n", __FUNCTION__);
}

static int nwork = 32;
int file_transfer(int argc, char *argv[]) {
	nng_socket   sock;
	nng_dialer   dialer;
	struct work *works[nwork];
	int          i;
	int          rv;
	
	if ((rv = nng_mqttv5_client_open(&sock)) != 0) {
		fatal("nng_socket", rv);
	}

	for (i = 0; i < nwork; i++) {
		works[i] = alloc_works(sock);
		works[i]->sock = sock;
	}

	// Mqtt connect message
	nng_msg *msg;
	nng_mqtt_msg_alloc(&msg, 0);
	nng_mqtt_msg_set_packet_type(msg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_keep_alive(msg, 60);
	nng_mqtt_msg_set_connect_proto_version(
	    msg, MQTT_PROTOCOL_VERSION_v5);
	nng_mqtt_msg_set_connect_clean_session(msg, true);

	nng_mqtt_set_connect_cb(sock, connect_cb, &sock);
	nng_mqtt_set_disconnect_cb(sock, disconnect_cb, NULL);

	if ((rv = nng_dialer_create(&dialer, sock, "mqtt-tcp://127.0.0.1:1883")) != 0) {
		fatal("nng_dialer_create", rv);
	}

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, msg);
	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (i = 0; i < nwork; i++) {
		client_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}

	return 0;
}
