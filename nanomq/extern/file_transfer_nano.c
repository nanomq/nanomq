/*
 * This is an example of how to use the MQTT client library to send a file to * the broker using EMQX's the file transfer extension.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/file.h>
#include <errno.h>
#include "nng/mqtt/mqtt_client.h"

#include "nng/nng.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/cJSON.h"

#include "file_transfer.h"

#include "aes_gcm.h"
static char *key_tmp = "a0958ba0214d6fa6";

#define DEBUG                   1
#define MAX_DELAY_7_DAYS        (1000 * 60 * 60 * 24 * 7)
#define FT_SUB_TOPIC            "file_transfer"
#define FT_RESULT_TOPIC         "file_transfer/result"
#define BUF_SIZE                10 * 1024
#define TOPIC_LEN               1024
#define INPUT_ERROR             0x1000
#define FILE_NOT_EXIST          0x1001
#define ALLOC_ERROR             0x1002
#define FREAD_ERROR             0x1003

//
// Publish a message to the given topic and with the given QoS.
int
client_publish(nng_socket sock, const char *topic, uint8_t *payload, uint32_t payload_len, uint8_t qos, bool verbose)
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

	property *plist = mqtt_property_alloc();

	nng_mqtt_msg_set_publish_property(pubmsg, plist);

	if ((rv = nng_sendmsg(sock, pubmsg, 0)) != 0) {
		log_error("nng_sendmsg", rv);
	}

	return rv;
}

static inline int parse_input(cJSON *cjson_objs,
							  cJSON **cjson_filepaths,
							  cJSON **cjson_filenames,
							  cJSON **cjson_topics,
							  cJSON **cjson_delete,
							  cJSON **cjson_request_id,
							  cJSON **cjson_echo_id)
{
	*cjson_filepaths = cJSON_GetObjectItem(cjson_objs, "files");
	*cjson_filenames = cJSON_GetObjectItem(cjson_objs, "filenames");
	*cjson_topics = cJSON_GetObjectItem(cjson_objs, "topics");
	*cjson_delete = cJSON_GetObjectItem(cjson_objs, "delete");
	*cjson_request_id = cJSON_GetObjectItem(cjson_objs, "request-id");
	*cjson_echo_id = cJSON_GetObjectItem(cjson_objs, "echo-id");
	if (*cjson_filepaths == NULL ||
		*cjson_filenames == NULL ||
		*cjson_topics == NULL ||
		*cjson_delete == NULL ||
		cJSON_GetArraySize(*cjson_filepaths) == 0 ||
		cJSON_GetArraySize(*cjson_filepaths) != cJSON_GetArraySize(*cjson_filenames) ||
		cJSON_GetArraySize(*cjson_filepaths) != cJSON_GetArraySize(*cjson_delete) ||
		cJSON_GetArraySize(*cjson_filepaths) != cJSON_GetArraySize(*cjson_topics)) {
		return -1;
	} 

	if ((*cjson_echo_id == NULL && *cjson_request_id != NULL) ||
		(*cjson_echo_id != NULL && *cjson_request_id == NULL)) {
		return -1;
	}

	if (*cjson_echo_id != NULL && *cjson_echo_id != NULL) {
		if (cJSON_GetArraySize(*cjson_request_id) != cJSON_GetArraySize(*cjson_filepaths)) {
			return -1;
		}
	}

	return 0;
}

void
delete_delay_cb(void *arg)
{
	char *filename = arg;
	int ret;
	if (filename != NULL) {
		ret = nng_file_delete(filename);
		log_warn("delete_delay_cb: file:%s result: %d\n", filename, ret);
		nng_free(filename, strlen(filename) + 1);
	} else {
		log_warn("filename is NULL and delete failed\n");
	}
	return;
}

static int do_flock(FILE *fp, int op)
{
	int fd;
	int rc;

	fd = fileno(fp);
	if (fd == -1) {
		log_warn("Failed to get file discription\n");
		return -1;
	}

	rc = flock(fd, op);
	if (rc != 0) {
		log_warn("Failed to do lock opration with file: op: %d rc: %d error: %s\n",
													op, rc, strerror(errno));
	}

	return rc;
}

static int publish_file(nng_socket *sock, FILE *fp, char *file_name,
                        char *topic, bool is_encrypt, char *key)
{
	char *payload;
	int   payload_len;
	int   rc = 0;

	fseek(fp, 0L, SEEK_END);
	long file_size = ftell(fp);
	rewind(fp);

	char *file_bin = (char *)nng_alloc(file_size);
	if (file_bin == NULL) {
		log_warn("Failed to allocate memory for file content");
		return ALLOC_ERROR;
	}
	rc = fread(file_bin, 1, file_size, fp);
	if (rc <= 0) {
		log_warn("Failed to read file");
		return FREAD_ERROR;
	}

	if (DEBUG) {
		log_info("Publishing file to topic %s", topic);
	}

	if (is_encrypt) {
		char *tag;
		char *payload = aes_gcm_encrypt(file_bin, file_size, key, &tag, &payload_len);
		if (payload == NULL) {
			log_error("Failed to encrypt the file, send origin payload");
			payload = file_bin;
			payload_len = file_size;
		} else {
			nng_free(tag, 0);
			nng_free(file_bin, file_size);
		}
	} else {
		payload = file_bin;
		payload_len = file_size;
	}

	rc = client_publish(*sock, topic, (uint8_t *)payload, (uint32_t)payload_len, 1, true);
	if (rc != 0) {
		log_warn("Failed to publish message, return code %d", rc);
		return rc;
	}
	nng_free(payload, payload_len);

	return 0;
}

int send_file(nng_socket *sock,
			  char *file_path,
			  char *file_name,
			  char *topic,
			  bool is_encrypt,
			  char *key)
{
	FILE *fp;
	int rc = 0;
	bool isLock = true;

	fp = fopen(file_path, "rb");
	if (fp == NULL) {
		log_warn("Failed to open file %s\n", file_path);
		return FILE_NOT_EXIST;
	}

	rc = do_flock(fp, LOCK_SH);
	if (rc != 0) {
		isLock = false;
		log_warn("Failed to lock file. Still send file without a file lock...\n");
	}

	rc = publish_file(sock, fp, file_name, topic, is_encrypt, key);
	if (rc) {
		fclose(fp);
		return rc;
	}

	if (isLock) {
		rc = do_flock(fp, LOCK_UN);
		if (rc != 0) {
			isLock = false;
			log_warn("Failed to unlock file\n");
		}
	}

	fclose(fp);

	return 0;
}

static void
disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	log_warn("%s: disconnected! RC [%d] \n", __FUNCTION__, reason);
}

static void
connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int rv;
	int reason;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	log_info("%s: connected! RC [%d] \n", __FUNCTION__, reason);
	nng_socket *sock = arg;

	// create a SUBSCRIBE message
	nng_mqtt_topic_qos subscriptions[] = {
		{
		    .qos   = 1,
		    .topic = {
				.buf    = (uint8_t *)FT_SUB_TOPIC,
		        .length = strlen(FT_SUB_TOPIC),
			},
			.nolocal         = 1,
			.rap             = 1,
			.retain_handling = 0,
		},
	};

	rv = nng_mqtt_subscribe(*sock, subscriptions, 1, NULL);
	log_info("resub result: %d\n", rv);

	return;
}

//
// Connect to the given address.
int
client_connect(nng_socket *sock, const char *url)
{
	nng_dialer dialer;
	int        rv;

	if ((rv = nng_mqttv5_client_open(sock)) != 0) {
		log_error("nng_socket %d", rv);
	}

	if ((rv = nng_dialer_create(&dialer, *sock, url)) != 0) {
		log_error("nng_dialer_create %d", rv);
	}

	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(connmsg, 5);
	nng_mqtt_msg_set_connect_keep_alive(connmsg, 600);
	nng_mqtt_msg_set_connect_clean_session(connmsg, true);

	property * p = mqtt_property_alloc();
	nng_mqtt_msg_set_connect_property(connmsg, p);
	property *will_prop = mqtt_property_alloc();
	nng_mqtt_msg_set_connect_will_property(connmsg, will_prop);

	nng_mqtt_set_connect_cb(*sock, connect_cb, sock);
	nng_mqtt_set_disconnect_cb(*sock, disconnect_cb, connmsg);

	nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg);

	log_info("Connecting to server ... url: %s\n", url);
	/* connect as sync mode */
	rv = nng_dialer_start(dialer, 0);
	while (rv != 0) {
		log_warn("Connect to %s failed, retry in 10s....\n", url);
		nng_msleep(10 * 1000);
		rv = nng_dialer_start(dialer, 0);
	}

	log_info("Connecting to server finished rv: %d ...\n", rv);

	return (0);
}

static int publish_send_result(nng_socket *sock,
							   char *requestid,
							   char *messages,
							   char *echoid,
							   int success)
{
	int rc;
	char payload[BUF_SIZE * 3];
	char topic[TOPIC_LEN];

	memset(topic, 0, TOPIC_LEN);
	memset(payload, 0, BUF_SIZE * 3);

	rc = snprintf(
			payload,
			BUF_SIZE * 3,
			"{"
			"\"request-id\": %s,"
			"\"message\": %s,"
			"\"result\": \"%s\","
			"\"echo-id\": \"%s\""
			"}",
			requestid == NULL ? "[\"\"]" : requestid,
			messages == NULL ? "[\"\"]" : messages,
			success ? "success" : "fail",
			echoid);
	if (rc < 0 || rc >= BUF_SIZE) {
		log_warn("Failed to create payload for initial message\n");
		return -1;
	}

	// Create topic of the form file_transfer/result for result message
	strcpy(topic, FT_RESULT_TOPIC);
	// Publish result message
	if (DEBUG) {
		log_info("Publishing result message to topic %s\n", topic);
		log_info("Payload:\n%s\n", payload);
	}

	rc = client_publish(*sock, topic, payload, strlen(payload), 1, true);
	if (rc != 0) {
		log_warn("Failed to publish result message, return code %d\n", rc);
		return -1;
	}

	return 0;
}

static inline void messages_requests_append(char *messages, int result,
										   char *requests, char *requestid,
										   int needComma)
{
	if (messages != NULL) {
		char tmp[32];
		memset(tmp, 0, 32);
		sprintf(tmp, "%d", result);

		/* messages + '\"' + "tmp" + '\"' + ']' */
		if (strlen(messages) + 1 + strlen(tmp) + 1 + 1 >= BUF_SIZE) {
			log_warn("messages is too long\n");
		} else {
			messages[strlen(messages)] = '\"';
			strcat(messages, tmp);
			messages[strlen(messages)] = '\"';
			if (needComma) {
				messages[strlen(messages)] = ',';
			}
		}
	}

	if (requests != NULL) {
		if (strlen(requests) + 1 + strlen(requestid) + 1 + 1 >= BUF_SIZE) {
			log_warn("requests is too long\n");
		} else {
			requests[strlen(requests)] = '\"';
			strcat(requests, requestid);
			requests[strlen(requests)] = '\"';
			if (needComma) {
				requests[strlen(requests)] = ',';
			}
		}
	}

	return;
}

static int process_msg(nng_socket *sock, nng_msg *msg, bool verbose)
{
	uint32_t topic_len = 0;
	uint32_t payload_len = 0;
	const char *topic = nng_mqtt_msg_get_publish_topic(msg, &topic_len);
	char *payload = nng_mqtt_msg_get_publish_payload(msg, &payload_len);

    log_info("Receive \'%.*s\' from \'%.*s\'\n", payload_len, payload, topic_len, topic);

	cJSON *cjson_objs = cJSON_Parse(payload);
	if (cjson_objs == NULL) {
		log_warn("Parse json failed\n");
		nng_msg_free(msg);
		return -1;
	} else {
		int result;
		cJSON *cjson_filepaths;
		cJSON *cjson_filenames;
		cJSON *cjson_topics;
		cJSON *cjson_delete;
		cJSON *cjson_request_id;
		cJSON *cjson_echo_id;
		result = parse_input(cjson_objs, &cjson_filepaths,
							 &cjson_filenames, &cjson_topics,
							 &cjson_delete, &cjson_request_id, &cjson_echo_id);
		if (result) {
			log_warn("INPUT JSON INVALID!\n");
			if (cjson_echo_id != NULL) {
				char messages[BUF_SIZE];
				memset(messages, 0, BUF_SIZE);
				messages[0] = '[';

				messages_requests_append(messages, INPUT_ERROR,
										 NULL, cjson_echo_id->valuestring, 0);
				messages[strlen(messages)] = ']';

				publish_send_result(sock, NULL, messages, cjson_echo_id->valuestring, 0);
			}
			nng_msg_free(msg);
			return -1;
		} else {
			bool is_encrypt = true;
			int  fileCount = cJSON_GetArraySize(cjson_filepaths);
			char messages[BUF_SIZE];
			char requests[BUF_SIZE];
			int  echo_success = 1;

			result = 0;

			memset(messages, 0, BUF_SIZE);
			memset(requests, 0, BUF_SIZE);

			messages[0] = '[';
			requests[0] = '[';

			for (int i = 0; i < fileCount; i++) {
				cJSON *pathEle = cJSON_GetArrayItem(cjson_filepaths, i);
				cJSON *nameEle = cJSON_GetArrayItem(cjson_filenames, i);
				cJSON *topicEle = cJSON_GetArrayItem(cjson_topics, i);
				cJSON *deleteEle = cJSON_GetArrayItem(cjson_delete, i);
				cJSON *requestEle = NULL;
				if(cjson_echo_id != NULL) {
					requestEle = cJSON_GetArrayItem(cjson_request_id, i);
				}
				log_info("Sending file: filepath: %s filename: %s\n",
											pathEle->valuestring,
											nameEle->valuestring);
				// Send file
				result = send_file(sock, pathEle->valuestring, nameEle->valuestring,
						topicEle->valuestring, is_encrypt, key_tmp);
				log_info("Send file file_name: %s %s\n", nameEle->valuestring,
									!result ? "success" : "fail");
				/* fail */
				if (result) {
					if (cjson_echo_id != NULL) {
						messages_requests_append(messages, result,
												 requests, requestEle->valuestring,
												 i != fileCount - 1 ? 1 : 0);
					}
					echo_success = 0;
					continue;
				} else {
					if (deleteEle != NULL && deleteEle->valueint >= 0) {
						if (deleteEle->valueint == 0) {
							int ret;
							ret = nng_file_delete(pathEle->valuestring);
							log_info("Delete imediately: file:%s result: %d\n", pathEle->valuestring, ret);
						} else {
							nng_aio *aio;
							char *filename;
							filename = nng_alloc(strlen(pathEle->valuestring) + 1);
							if (filename == NULL) {
								log_warn("Alloc filename failed continue...\n");

								if (cjson_echo_id != NULL) {
									messages_requests_append(messages, ALLOC_ERROR,
															 requests, requestEle->valuestring,
															 i != fileCount - 1 ? 1 : 0);
								}
								continue;
							}
							strcpy(filename, pathEle->valuestring);

							/* Delete after 7 days at the latest */
							int delay = deleteEle->valueint * 1000;
							if (delay > MAX_DELAY_7_DAYS) {
								delay = MAX_DELAY_7_DAYS;
							}
							/* WARNING: when to free aio? */
							nng_aio_alloc(&aio, delete_delay_cb, filename);
							nng_sleep_aio(delay, aio);
							log_warn("Send file finished: Will delete %s in %d milliseconds\n",
																			pathEle->valuestring,
																			delay);
						}
					} else {
						log_info("Send file finished will not delete: %s\n", pathEle->valuestring);
					}
					if (cjson_echo_id != NULL) {
						messages_requests_append(messages, 0,
												 requests, requestEle->valuestring,
												 i != fileCount - 1 ? 1 : 0);
					}
				}
			}
			if (cjson_echo_id != NULL) {
				messages[strlen(messages)] = ']';
				requests[strlen(requests)] = ']';
				publish_send_result(sock, requests, messages,
									cjson_echo_id->valuestring, echo_success);
			}
		}
		cJSON_Delete(cjson_objs);
	}

	nng_msg_free(msg);
	return 0;
}


void start_listening(nng_socket *sock)
{
	int rv;

	nng_mqtt_topic_qos subscriptions[] = {
		{
		    .qos   = 1,
		    .topic = { 
				.buf    = (uint8_t *)FT_SUB_TOPIC,
		        .length = strlen(FT_SUB_TOPIC), 
			},
			.nolocal         = 1,
			.rap             = 1,
			.retain_handling = 0,
		},
	};

	rv = nng_mqtt_subscribe(*sock, subscriptions, 1, NULL);
	log_info("Start file transfer receiving loop(mqtt only not emqx ft):\n");

	/* dead loop? */
	while (true) {
		nng_msg *msg;
		if ((rv = nng_recvmsg(*sock, &msg, 0)) != 0) {
			log_error("nng_recvmsg: %d", rv);
			nng_msg_free(msg);
			continue;
		}

		log_info("recvmsg return rv: %d type: %d\n", rv, nng_mqtt_msg_get_packet_type(msg));
		if (nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_PUBLISH) {
			rv = process_msg(sock, msg, true);
			if (rv) {
				log_warn("something wrong occured when process msg\n");
			}
		} else {
			nng_msg_free(msg);
		}
	}

	return;
}

int file_transfer(int argc, char *argv[]) {
	int rc;
	nng_socket sock;

	// Construct address string from host and port
	char address[2048];
	rc = snprintf(address, 2048, "mqtt%s", *argv+strlen("nmq"));
	if (rc < 0 || rc >= 2048) {
		log_warn("Failed to construct address string\n");
		log_warn("Something wrong occurred. File transfer thread exiting...\n");
		return -1;
	}

	client_connect(&sock, address);

	if (DEBUG) {
		log_info("Connected to MQTT Broker: %s!\n", address);
	}
	
	(void) start_listening(&sock);

	return -1;
}
