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

	log_info("Publishing to '%s' ...\n", topic);
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

static int publish_file(nng_socket *sock, FILE *fp, char *file_name, char *topic)
{
	char *payload;
	int rc = 0;

	fseek(fp, 0L, SEEK_END);
	long file_size = ftell(fp);
	rewind(fp);

	payload = (char *)nng_alloc(file_size);
	if (payload == NULL) {
		log_warn("Failed to allocate memory for file payload\n");
		return ALLOC_ERROR;
	}
	rc = fread(payload, 1, file_size, fp);
	if (rc <= 0) {
		log_warn("Failed to read file\n");
		return FREAD_ERROR;
	}

	if (DEBUG) {
		log_info("Publishing file to topic %s\n", topic);
	}

	rc = client_publish(*sock, topic, (uint8_t *)payload, (uint32_t)file_size, 1, true);
	if (rc != 0) {
		log_warn("Failed to publish message, return code %d\n", rc);
		return rc;
	}
	nng_free(payload, file_size);

	return 0;
}

#define STR_VALUE(val) #val
#define STR(name) STR_VALUE(name)

#define PATH_LEN 256

int CalcFileMD5(char *file_name, char *md5_sum)
{
	#define MD5SUM_CMD_FMT "md5sum %." STR(PATH_LEN) "s 2>/dev/null"
	char cmd[PATH_LEN + sizeof (MD5SUM_CMD_FMT)];
	sprintf(cmd, MD5SUM_CMD_FMT, file_name);
	#undef MD5SUM_CMD_FMT

	FILE *p = popen(cmd, "r");
	if (p == NULL) return 0;

	int i, ch;
	for (i = 0; i < MD5_LEN && isxdigit(ch = fgetc(p)); i++) {
		*md5_sum++ = ch;
	}

	*md5_sum = '\0';
	pclose(p);
	return i == MD5_LEN;
}

int CalcMD5n(char *binary, size_t len, char *tmpfpath, char **md5res)
{
	*md5res = NULL;

	FILE *fp = fopen(tmpfpath, "w+");
	if (fp == NULL) {
		log_warn("Failed to open file %s", tmpfpath);
		return -1;
	}

	int rc = do_flock(fp, LOCK_SH);
	if (rc != 0) {
		log_warn("Failed to lock file %s", tmpfpath);
		fclose(fp);
		return -1;
	}

	size_t res = fwrite(binary, 1, len, fp);
	if (res != len) {
		log_warn("Failed to write to file %s", tmpfpath);
		fclose(fp);
		return -2;
	}

	rc = do_flock(fp, LOCK_UN);
	if (rc != 0) {
		log_warn("Failed to unlock file %s", tmpfpath);
		fclose(fp);
		return -1;
	}
	fclose(fp);

	char *md5_sum = nng_alloc(sizeof(char) * (MD5_LEN + 1));
	if (1 != CalcFileMD5(tmpfpath, md5_sum)) {
		log_warn("Failed to calculate md5sum of %s", tmpfpath);
		nng_free(md5_sum, 0);
		return -1;
	}

	*md5res = md5_sum;
	return 0;
}

int send_file(nng_socket *sock,
			  char *file_path,
			  char *file_name,
			  char *topic)
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

	rc = publish_file(sock, fp, file_name, topic);
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
	int reason;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	log_info("%s: connected! RC [%d] \n", __FUNCTION__, reason);
}

//
// Connect to the given address.
int
client_connect(nng_socket *sock, const char *url)
{
	nng_dialer dialer;
	int        rv;

	if ((rv = nng_mqttv5_client_open(sock)) != 0) {
		fatal("nng_socket", rv);
	}

	if ((rv = nng_dialer_create(&dialer, *sock, url)) != 0) {
		fatal("nng_dialer_create", rv);
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
			cJSON *cjson_type;
			result = parse_input(cjson_objs, &cjson_filepaths,
								 &cjson_filenames, &cjson_topics, &cjson_delete);
			if (result) {
				log_warn("INPUT JSON INVALID!\n");
				nng_msg_free(msg);
				return -1;
			} else {
				int fileCount = cJSON_GetArraySize(cjson_filepaths);
				result = 0;
				for (int i = 0; i < fileCount; i++) {
					cJSON *pathEle = cJSON_GetArrayItem(cjson_filepaths, i);
					cJSON *nameEle = cJSON_GetArrayItem(cjson_filenames, i);
					cJSON *topicEle = cJSON_GetArrayItem(cjson_topics, i);
					cJSON *deleteEle = cJSON_GetArrayItem(cjson_delete, i);
					log_info("Sending file: filepath: %s filename: %s\n",
												pathEle->valuestring,
												nameEle->valuestring);
					// Send file
					result = send_file(sock, pathEle->valuestring, nameEle->valuestring, topicEle->valuestring);
					log_info("Send file file_name: %s %s\n", nameEle->valuestring,
										!result ? "success" : "fail");
					/* fail */
					if (result) {
						break;
					} else {
						if (deleteEle != NULL && deleteEle->valueint >= 0) {
							if (deleteEle->valueint == 0) {
								int ret;
								ret = nng_file_delete(deleteEle->valuestring);
								log_info("Delete imediately: file:%s result: %d\n", pathEle->valuestring, ret);
							} else {
								nng_aio *aio;
								char *filename;
								filename = nng_alloc(strlen(pathEle->valuestring) + 1);
								if (filename == NULL) {
									log_warn("Alloc filename failed continue...\n");
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
					}
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
			fatal("nng_recvmsg", rv);
			continue;
		}

		log_info("recvmsg return rv: %d type: %d\n", rv, nng_mqtt_msg_get_packet_type(msg));
		if (nng_mqtt_msg_get_packet_type(msg) == NNG_MQTT_PUBLISH) {
			rv = process_msg(sock, msg, true);
			if (rv) {
				log_warn("something wrong occured when process msg\n");
			}
		}
	}

	return;
}

int file_transfer(int argc, char *argv[]) {
	int rc;
	nng_socket sock;
	char *host = "127.0.0.1";
	int port = 1883;

	if (DEBUG) {
		log_info("host: %s\n", host);
		log_info("port: %d\n", port);
	}
	// Construct address string from host and port
	char address[2048];
	rc = snprintf(address, 2048, "mqtt-tcp://%s:%d", host, port);
	if (rc < 0 || rc >= 2048) {
		log_warn("Failed to construct address string\n");
		log_warn("Something wrong occurred. File transfer thread exiting...\n");
		return -1;
	}

	client_connect(&sock, address);

	if (DEBUG) {
		log_info("Connected to MQTT Broker!\n");
	}
	
	(void) start_listening(&sock);

	return -1;
}
