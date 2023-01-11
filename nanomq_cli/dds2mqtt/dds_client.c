// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "dds_client.h"
#include "HelloWorld.h"
#include "dds/dds.h"
#include "vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "HelloWorld_mqtt_conversion.h"
#include "mqtt_client.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/hocon.h"

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 1

static int dds_client_init(dds_cli *cli);
static int dds_client(dds_cli *cli, mqtt_cli *mqttcli);

int
dds_proxy(int argc, char **argv)
{
	mqtt_cli mqttcli;
	dds_cli  ddscli;
	cJSON   *jso                  = NULL;
	cJSON   *jso_item_mqtt        = NULL;
	cJSON   *jso_item_broker_url  = NULL;
	cJSON   *jso_item_topic_rules = NULL;
	cJSON   *jso_item_dds2mqtt    = NULL;
	cJSON   *jso_item_mqtt2dds    = NULL;
	cJSON   *jso_item_topic       = NULL;
	cJSON   *jso_item_in          = NULL;
	cJSON   *jso_item_out         = NULL;
	char    *broker_url           = NULL;
	int      dds2mqtt_rules_size  = 0;
	int      mqtt2dds_rules_size  = 0;

	dds_client_init(&ddscli);

	// TODO set topics for ddscli & mqttcli
	// mqtt_set_topics(argv[1], argv[2]);
	/* Read .conf file to get a JSON and fill topics. */
	jso                 = hocon_parse_file(argv[2]);
	jso_item_mqtt       = cJSON_GetObjectItem(jso, "mqtt");
	jso_item_broker_url = cJSON_GetObjectItem(jso_item_mqtt, "broker_url");
	broker_url          = jso_item_broker_url->valuestring;
	jso_item_topic_rules = cJSON_GetObjectItem(jso, "topic_rules");
	// TODO Need to restruct if there is more topics.
	jso_item_dds2mqtt =
	    cJSON_GetObjectItem(jso_item_topic_rules, "dds2mqtt");
	dds2mqtt_rules_size    = cJSON_GetArraySize(jso_item_dds2mqtt);
	jso_item_topic         = cJSON_GetArrayItem(jso_item_dds2mqtt, 0);
	jso_item_in            = cJSON_GetObjectItem(jso_item_topic, "in");
	ddscli.ddsrecv_topic   = jso_item_in->valuestring;
	jso_item_out           = cJSON_GetObjectItem(jso_item_topic, "out");
	mqttcli.mqttsend_topic = jso_item_out->valuestring;
	jso_item_mqtt2dds =
	    cJSON_GetObjectItem(jso_item_topic_rules, "mqtt2dds");
	mqtt2dds_rules_size    = cJSON_GetArraySize(jso_item_mqtt2dds);
	jso_item_topic         = cJSON_GetArrayItem(jso_item_mqtt2dds, 0);
	jso_item_in            = cJSON_GetObjectItem(jso_item_topic, "in");
	mqttcli.mqttrecv_topic = jso_item_in->valuestring;
	jso_item_out           = cJSON_GetObjectItem(jso_item_topic, "out");
	ddscli.ddssend_topic   = jso_item_out->valuestring;

	mqtt_connect(&mqttcli, broker_url, &ddscli);
	mqtt_subscribe(&mqttcli, mqttcli.mqttrecv_topic, 0);

	dds_client(&ddscli, &mqttcli);

	return 0;
}

static int
dds_client_init(dds_cli *cli)
{
	nftp_vec_alloc(&cli->handleq);
	pthread_mutex_init(&cli->mtx, NULL);

	return 0;
}

static int
dds_client(dds_cli *cli, mqtt_cli *mqttcli)
{
	dds_entity_t      participant;
	dds_entity_t      topicw;
	dds_entity_t      topicr;
	dds_entity_t      reader;
	dds_entity_t      writer;
	example_struct   *msg;
	void             *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];
	dds_return_t      rc;
	dds_qos_t        *qos;
	uint32_t          status = 0;
	handle           *hd;

	/* Get current client's handle queue */
	nftp_vec *handleq = cli->handleq;

	/* Create a Participant. */
	participant = dds_create_participant(DDS_DOMAIN_DEFAULT, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a Topic. */
	topicr = dds_create_topic(
	    participant, &example_struct_desc, cli->ddsrecv_topic, NULL, NULL);
	if (topicr < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicr));

	/* Create a Topic. for writer */
	topicw = dds_create_topic(
	    participant, &example_struct_desc, cli->ddssend_topic, NULL, NULL);
	if (topicw < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicw));

	/* Create a reliable Reader. */
	qos = dds_create_qos();
	dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));
	reader = dds_create_reader(participant, topicr, qos, NULL);
	if (reader < 0)
		DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
	dds_delete_qos(qos);

	// TODO Topics for writer and reader **MUST** be different.
	// Or Circle messages happened
	/* Create a Writer */
	writer = dds_create_writer(participant, topicw, NULL, NULL);
	if (writer < 0)
		DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));

	printf("=== [Publisher]  Waiting for a reader to be discovered ...\n");
	fflush(stdout);

	rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));

	/*
	while (!(status & DDS_PUBLICATION_MATCHED_STATUS)) {
	        rc = dds_get_status_changes(writer, &status);
	        if (rc != DDS_RETCODE_OK)
	                DDS_FATAL("dds_get_status_changes: %s\n",
	                    dds_strretcode(-rc));
	*/

	/* Polling sleep. */
	/*
	        dds_sleepfor(DDS_MSECS(20));
	}
	*/

	// MQTT Client create
	// mqtt_connect(&mqttcli, MQTT_URL);

	printf("\n=== [Subscriber] Waiting for a sample ...\n");
	fflush(stdout);

	/* Initialize sample buffer, by pointing the void pointer within
	 * the buffer array to a valid sample memory location. */
	samples[0] = example_struct__alloc();
	nng_msg       *mqttmsg;
	fixed_mqtt_msg midmsg;
	uint32_t       len;

	/* Poll until data has been read. */
	while (true) {
		// If handle queue is not empty. Handle it first.
		// Or we need to receive msgs from DDS in a NONBLOCK way and
		// put it to the handle queue. Sleep when handle queue is
		// empty.
		hd = NULL;

		pthread_mutex_lock(&cli->mtx);
		if (nftp_vec_len(handleq))
			nftp_vec_pop(handleq, (void **) &hd, NFTP_HEAD);
		pthread_mutex_unlock(&cli->mtx);

		if (hd)
			goto work;

		/* Do the actual read.
		 * The return value contains the number of read samples. */
		rc =
		    dds_take(reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
		if (rc < 0)
			DDS_FATAL("dds_read: %s\n", dds_strretcode(-rc));
		/* Check if we read some data and it is valid. */
		if ((rc > 0) && (infos[0].valid_data)) {
			/* Print Message. */
			msg = samples[0];
			printf("=== [Subscriber] Received : ");
			printf("Message (%" PRId32 ", %s)\n", msg->int8_test,
			    msg->message);
			fflush(stdout);

			/* Make a handle */
			hd = mk_handle(HANDLE_TO_MQTT, msg, 0);

			/* Put msg to handleq */
			pthread_mutex_lock(&cli->mtx);
			nftp_vec_append(handleq, (void *) hd);
			pthread_mutex_unlock(&cli->mtx);

			continue;
		} else {
			/* Polling sleep. */
			dds_sleepfor(DDS_MSECS(20));
			continue;
		}

	work:
		switch (hd->type) {
		case HANDLE_TO_DDS:
			mqttmsg = hd->data;
			midmsg.payload =
			    (char *) nng_mqtt_msg_get_publish_payload(
			        mqttmsg, &len);
			midmsg.len = len;
			msg        = (example_struct *) samples[0];
			mqtt_to_HelloWorld(&midmsg, msg);
			/* Send the msg received */
			rc = dds_write(writer, msg);
			if (rc != DDS_RETCODE_OK)
				DDS_FATAL(
				    "dds_write: %s\n", dds_strretcode(-rc));
			printf("[DDS] Send a msg to dds.\n");
			free(hd);
			break;
		case HANDLE_TO_MQTT:
			// Put to MQTTClient's handle queue
			pthread_mutex_lock(&mqttcli->mtx);
			nftp_vec_append(mqttcli->handleq, hd);
			pthread_mutex_unlock(&mqttcli->mtx);
			printf("[DDS] Send a msg to mqtt.\n");
			break;
		default:
			printf("Unsupported handle type.\n");
			break;
		}
	}

	/* Free the data location. */
	example_struct_free(samples[0], DDS_FREE_ALL);

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	nftp_vec_free(cli->handleq);
	pthread_mutex_destroy(&cli->mtx);

	return EXIT_SUCCESS;
}

const char *usage = " {sub <topic> | pub <topic> | proxy <path/to/conf>}\n";

int
dds_proxy_start(int argc, char **argv)
{
	if (argc < 3)
		goto helper;

	if (strcmp(argv[1], "sub") == 0) {
		dds_subscriber(argc, argv);
	} else if (strcmp(argv[1], "pub") == 0) {
		dds_publisher(argc, argv);
	} else if (strcmp(argv[1], "proxy") == 0) {
		dds_proxy(argc, argv);
	} else {
		goto helper;
	}

	return 0;

helper:

	printf("%s %s\n", argv[0], usage);
	return 1;
}

#endif
