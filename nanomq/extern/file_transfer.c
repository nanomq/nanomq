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
#include <sys/file.h>
#include <errno.h>

#include <MQTTClient.h>

#include "nng/nng.h"
#include "nng/supplemental/nanolib/cJSON.h"

#define CLIENTID	"c-client"
#define TIMEOUT	 100000L
#define DEBUG	   1
#define MAX_DELAY_7_DAYS (1000 * 60 * 60 * 24 * 7)

static int publish_send_result(MQTTClient client,
							   char *requestid,
							   int success)
{
	int rc;
	int buf_size = 128;
	int payloadLen = 128;
	char payload[payloadLen];
	rc = snprintf(
			payload,
			payloadLen,
			"{"
			"  \"request-id\": \"%s\","
			"  \"success\": %s,"
			"  \"message\": \"%s\""
			"}",
			requestid,
			success ? "true" : "false",
			"");
	if (rc < 0 || rc >= payloadLen) {
		printf("Failed to create payload for initial message\n");
		return -1;
	}
	// Create topic of the form file_transfer/result for result message
	char topic[buf_size];
	MQTTClient_deliveryToken token;
	strcpy(topic, "file_transfer/result");
//	if (rc < 0 || rc >= buf_size) {
//		printf("Failed to create topic for result message\n");
//		return -1;
//	}
	// Publish result message
	if (DEBUG) {
		printf("Publishing result message to topic %s\n", topic);
		printf("Payload:\n%s\n", payload);
	}
	MQTTProperties props = MQTTProperties_initializer;
	MQTTResponse mqttrc;
	mqttrc = MQTTClient_publish5(client, topic, strlen(payload), payload, 2, 0, &props, &token);
	if (mqttrc.reasonCode != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish message, return code %d\n", rc);
		return -1;
	}
	rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
	if (rc != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish message, return code %d\n", rc);
		return -1;
	}

	return 0;
}

static inline int parse_input(cJSON *cjson_objs,
							  cJSON **cjson_filepaths,
							  cJSON **cjson_filenames, cJSON **cjson_fileids,
							  cJSON **cjson_requestid, cJSON **cjson_segmentsize,
							  cJSON **cjson_delete)
{
	*cjson_filepaths = cJSON_GetObjectItem(cjson_objs, "files");
	*cjson_filenames = cJSON_GetObjectItem(cjson_objs, "filenames");
	*cjson_fileids = cJSON_GetObjectItem(cjson_objs, "fileids");
	*cjson_requestid = cJSON_GetObjectItem(cjson_objs, "request_id");
	*cjson_segmentsize = cJSON_GetObjectItem(cjson_objs, "segment-size");
	*cjson_delete = cJSON_GetObjectItem(cjson_objs, "delete");
	if (*cjson_filepaths == NULL || *cjson_fileids == NULL ||
		*cjson_filenames == NULL || *cjson_requestid == NULL ||
		cJSON_GetArraySize(*cjson_filepaths) == 0 ||
		cJSON_GetArraySize(*cjson_filepaths) != cJSON_GetArraySize(*cjson_fileids) ||
		cJSON_GetArraySize(*cjson_filepaths) != cJSON_GetArraySize(*cjson_filenames)) {
		return -1;
	} 

	return 0;
}

void
delete_delay_cb(void *arg)
{
	char *filename = arg;
	int ret;
	if (filename != NULL) {
		ret = nni_file_delete(filename);
		printf("delete_delay_cb: file:%s result: %d\n", filename, ret);
	} else {
		printf("filename is NULL and delete failed\n");
	}
	return;
}

static int start_listening(MQTTClient client,
						   unsigned long expire_time_s_since_epoch,
						   unsigned long segments_ttl_seconds)
{
	char *topicName = NULL;
	MQTTClient_message *message = NULL;
	int topicNameLen = 0;
	int ret;
	MQTTSubscribe_options subopts = MQTTSubscribe_options_initializer;
	MQTTProperties props = MQTTProperties_initializer;

	subopts.retainAsPublished = 1;
	subopts.noLocal = 0;
	subopts.retainHandling = 0;

	MQTTResponse mqttrc;
	mqttrc = MQTTClient_subscribe5(client, "file_transfer", 2, &subopts, &props);
	if (mqttrc.reasonCode < MQTTCLIENT_SUCCESS) {
		printf("Client subscribe topic failed\n", mqttrc.reasonCode);
		return -1;
	}

	/* dead loop */
	while (1) {
		ret = MQTTClient_receive(client, &topicName, &topicNameLen, &message, 1000 * 60);
		if (ret == MQTTCLIENT_SUCCESS) {
			if (message != NULL) {
				if (DEBUG) {
					printf("Message arrived topic: %s message: %s\n",
														topicName, message->payload);
				}

				cJSON *cjson_objs = cJSON_Parse(message->payload);
				if (cjson_objs == NULL) {
					printf("Parse json failed\n");
				} else {
					int result;
					cJSON *cjson_filepaths;
					cJSON *cjson_filenames;
					cJSON *cjson_fileids;
					cJSON *cjson_requestid;
					cJSON *cjson_segmentsize;
					cJSON *cjson_delete;
					result = parse_input(cjson_objs, &cjson_filepaths,
										 &cjson_filenames, &cjson_fileids,
										 &cjson_requestid, &cjson_segmentsize,
										 &cjson_delete);
					if (result) {
						printf("INPUT JSON INVALID!\n");
						continue;
					} else {
						int fileCount = cJSON_GetArraySize(cjson_filepaths);
						if (DEBUG) {
							printf("Input Json: request-id: %s segment-size: %u\n",
															cjson_requestid->valuestring,
															cjson_segmentsize == NULL ? 0U : cjson_segmentsize->valueint);
						}
						int result = -1;;
						for (int i = 0; i < fileCount; i++) {
							cJSON *pathEle = cJSON_GetArrayItem(cjson_filepaths, i);
							cJSON *idEle = cJSON_GetArrayItem(cjson_fileids, i);
							cJSON *nameEle = cJSON_GetArrayItem(cjson_filenames, i);
							printf("Sending file: filepath: %s fileid: %s filename: %s\n",
														pathEle->valuestring,
														idEle->valuestring,
														nameEle->valuestring);
							// Send file
							result = send_file(client,
													pathEle->valuestring,
													idEle->valuestring,
													nameEle->valuestring,
													cjson_segmentsize == NULL ? 0U : cjson_segmentsize->valueint,
													expire_time_s_since_epoch,
													segments_ttl_seconds);
							printf("Send file file_id: %s %s\n", idEle->valuestring,
												!result ? "success" : "fail");
							/* fail */
							if (result) {
								break;
							} else {
								if (cjson_delete != NULL && cjson_delete->valueint >= 0) {
									if (cjson_delete->valueint == 0) {
										int ret;
										ret = nng_file_delete(pathEle->valuestring);
										printf("Delete imediately: file:%s result: %d\n", pathEle->valuestring, ret);
									} else {
										nng_aio *a;
										char *filename;
										filename = nng_alloc(strlen(pathEle->valuestring) + 1);
										if (filename == NULL) {
											printf("Alloc filename failed continue...\n");
											continue;
										}
										strcpy(filename, pathEle->valuestring);

										/* Delete after 7 days at the latest */
										int delay = cjson_delete->valueint * 1000;
										if (delay > MAX_DELAY_7_DAYS) {
											delay = MAX_DELAY_7_DAYS;
										}
										nng_aio_alloc(&a, delete_delay_cb, filename);
										nng_sleep_aio(delay, a);
										printf("Send file finished: Will delete %s in %d milliseconds\n",
																						pathEle->valuestring,
																						delay);
									}
								} else {
									printf("Send file finished will not delete: %s\n", pathEle->valuestring);
								}
							}
						}
						result = publish_send_result(client, cjson_requestid->valuestring, !result);
						if (DEBUG) {
							printf("Send file request-id: %s transfer result: %s\n",
												cjson_requestid->valuestring,
												!result ? "success" : "fail");
						}
					}
				}
			} else {
				printf("Arrived message is NULL\n");
			}
		} else {
			printf("Client message receive failed return code: %d\n", ret);
		}
	}
}

static int do_flock(FILE *fp, int op)
{
	int fd;
	int rc;

	fd = fileno(fp);
	if (fd == -1) {
		printf("Failed to get file discription\n");
		return -1;
	}

	rc = flock(fd, op);
	if (rc != 0) {
		printf("Failed to do lock opration with file: op: %d rc: %d error: %s\n",
													op, rc, strerror(errno));
	}

	return rc;
}

int send_file(MQTTClient client,
			  char *file_path,
			  char *file_id,
			  char *file_name,
			  unsigned int chunk_size,
			  unsigned long expire_time_s_since_epoch,
			  unsigned long segments_ttl_seconds) {
	FILE *fp = fopen(file_path, "rb");
	int rc;
	int qos = 1;
	const size_t buf_size = 1024 * 10;
	if (fp == NULL) {
		printf("Failed to open file %s\n", file_path);
		return -1;
	}
	// Get file size
	fseek(fp, 0L, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	// Create payload for initial message 
	char payload[buf_size];
	char expire_at_str[128];
	char segments_ttl_str[128];
	memset(payload, 0, buf_size);
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
	rc = snprintf(
			payload,
			buf_size,
			"{"
			"\"name\": \"%s\","
			"\"size\": %ld,"
			"%s"
			"%s"
			"  \"user_data\": {}\n"
			"}",
			file_name,
			file_size,
			expire_at_str,
			segments_ttl_str);
	if (rc < 0 || rc >= buf_size) {
		printf("Failed to create payload for initial message\n");
		return -1;
	}
	// Create topic of the form $file/{file_id}/init for initial message
	char topic[buf_size];
	MQTTClient_deliveryToken token;
	rc = snprintf(topic, buf_size, "$file/%s/init", file_id);
	if (rc < 0 || rc >= buf_size) {
		printf("Failed to create topic for initial message\n");
		return -1;
	}
	// Publish initial message
	if (DEBUG) {
		printf("Publishing initial message to topic %s\n", topic);
		printf("Payload: %s\n", payload);
	}
	MQTTProperties props = MQTTProperties_initializer;
	MQTTResponse mqttrc;
	mqttrc = MQTTClient_publish5(client, topic, strlen(payload), payload, 1, 0, &props, &token);
	if (mqttrc.reasonCode != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish message, return code %d\n", rc);
		return -1;
	}
	rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
	if (rc != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish message, return code %d\n", rc);
		return -1;
	}

	memset(payload, 0, buf_size);
	size_t offset = 0;
	size_t read_bytes;

	// Read binary chunks of max size 1024 bytes and publish them to the broker
	// The chunks are published to the topic of the form $file/{file_id}/{offset}
	// The chunks are read into the payload
	//
	// Payload's length is depend on buf_size, buf_size is 10240 now.
	if (chunk_size > 10240 || chunk_size == 0) {
		chunk_size = 10240;
	}
	while ((read_bytes = fread(payload, 1, chunk_size, fp)) > 0) {
		rc = snprintf(topic, buf_size, "$file/%s/%lu", file_id, offset);
		if (rc < 0 || rc >= buf_size) {
			printf("Failed to create topic for file chunk\n");
			return -1;
		}
		if (DEBUG) {
			printf("Publishing file chunk to topic %s offset %lu\n", topic, offset);
		}
		mqttrc = MQTTClient_publish5(client, topic, read_bytes, payload, 1, 0, &props, &token);
		if (mqttrc.reasonCode != MQTTCLIENT_SUCCESS) {
			printf("Failed to publish file chunk, return code %d\n", rc);
			return -1;
		}
		rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
		if (rc != MQTTCLIENT_SUCCESS) {
			printf("Failed to publish file chunk, return code %d\n", rc);
			return -1;
		}
		memset(payload, 0, buf_size);
		offset += read_bytes;
	}
	// Check if we reached the end of the file
	if (feof(fp)) {
		if (DEBUG) {
			printf("Reached end of file\n");
		}
	} else {
		printf("Failed to read file\n");
		return -1;
	}
	fclose(fp);
	// Send final message to the topic $file/{file_id}/fin/{file_size} with an empty payload
	rc = snprintf(topic, buf_size, "$file/%s/fin/%ld", file_id, file_size);
	if (rc < 0 || rc >= buf_size) {
		printf("Failed to create topic for final message\n");
		return -1;
	}
	if (DEBUG) {
		printf("Publishing final message to topic %s\n", topic);
	}
	mqttrc = MQTTClient_publish5(client, topic, 0, "", 1, 0, &props, &token);
	if (mqttrc.reasonCode != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish final message, return code %d\n", rc);
		return -1;
	}
	rc = MQTTClient_waitForCompletion(client, token, TIMEOUT);
	if (rc != MQTTCLIENT_SUCCESS) {
		printf("Failed to publish final message, return code %d\n", rc);
		return -1;
	}
	return 0;
}

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

int file_transfer(int argc, char *argv[]) {
	int rc;
	MQTTClient client;
	// Declare variables to store command line arguments
	char *file_path;
	char *file_id;
	char *file_name;
	char *client_id;
	char *host;
	int port;
	char *username;
	char *password;
	long segments_ttl_seconds;
	long expire_after_seconds;
	// Read command line arguments
	initial_param(
			argc,
			argv,
			&file_path,
			&file_id,
			&username,
			&password,
			&file_name,
			&client_id,
			&host,
			&port,
			&segments_ttl_seconds,
			&expire_after_seconds);
	if (DEBUG) {
		printf("file_path: %s\n", file_path);
		printf("file_id: %s\n", file_id);
		printf("file_name: %s\n", file_name);
		printf("client_id: %s\n", client_id);
		printf("host: %s\n", host);
		printf("port: %d\n", port);
		if (username != NULL) {
			printf("username: %s\n", username);
		}
		if (password != NULL) {
			printf("password: %s\n", password);
		}
		printf("segments_ttl_seconds: %ld\n", segments_ttl_seconds);
		printf("expire_after_seconds: %ld\n", expire_after_seconds);
	}
	// Construct address string from host and port
	char address[2048];
	rc = snprintf(address, 2048, "tcp://%s:%d", host, port);
	if (rc < 0 || rc >= 2048) {
		printf("Failed to construct address string\n");
		printf("Something wrong occurred. File transfer thread exiting...\n");
		exit(1);
	}
	// Create client
	MQTTClient_createOptions options;
	options.MQTTVersion = MQTTVERSION_5;
	strncpy(options.struct_id, "MQCO", 4);
	rc = MQTTClient_createWithOptions(&client, address, client_id, 0, NULL, &options);
	if (rc != MQTTCLIENT_SUCCESS) {
		printf("Create mqtt client failed: %d\n", rc);
		printf("Something wrong occurred. File transfer thread exiting...\n");
		exit(1);
	}
	MQTTResponse mqttrc;
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	conn_opts.username = username;
	conn_opts.password = password;
	conn_opts.MQTTVersion = MQTTVERSION_5;
	conn_opts.cleanstart = 0;
	conn_opts.cleansession = 0;
	MQTTProperties props = MQTTProperties_initializer;
	MQTTProperties willProps = MQTTProperties_initializer;
	mqttrc = MQTTClient_connect5(client, &conn_opts, &props, &willProps);
	if (mqttrc.reasonCode != MQTTCLIENT_SUCCESS) {
		printf("Failed to connect, return code %d\n", mqttrc.reasonCode);
		printf("Something wrong occurred. File transfer thread exiting...\n");
		exit(1);
	} else {
		if (DEBUG) {
			printf("Connected to MQTT Broker!\n");
		}
	}
	// Calculate expire time
	unsigned long expire_time_s_since_epoch;
	if (expire_after_seconds == -1) {
		expire_time_s_since_epoch = -1;
	} else {
		expire_time_s_since_epoch = time(NULL) + expire_after_seconds;
	}
	(void)start_listening(client,
						  expire_time_s_since_epoch,
						  segments_ttl_seconds);
	printf("Something wrong occurred. File transfer thread exiting...\n");

	(void)MQTTClient_disconnect5(client, TIMEOUT, MQTTREASONCODE_NORMAL_DISCONNECTION, &props);
	(void)MQTTClient_destroy(&client);
	return -1;
}
