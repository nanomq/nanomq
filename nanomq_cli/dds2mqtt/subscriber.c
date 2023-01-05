#include "HelloWorld.h"
#include "dds/dds.h"
#include "dds_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "HelloWorldMQTTTypes.h"
#include "mqtt_client.h"

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 1

#define MQTT_URL "mqtt-tcp://127.0.0.1:1883"

static mqtt_cli mqttcli;

void print_dds_msg(struct example_struct *msg);

int
subscriber(int argc, char **argv)
{
	dds_entity_t      participant;
	dds_entity_t      topic;
	dds_entity_t      reader;
	example_struct   *msg;
	void             *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];
	dds_return_t      rc;
	dds_qos_t        *qos;
	(void) argc;
	(void) argv;

	/* Create a Participant. */
	participant = dds_create_participant(DDS_DOMAIN_DEFAULT, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a Topic. */
	topic = dds_create_topic(
	    participant, &example_struct_desc, "MQTT/HelloWorld", NULL, NULL);
	if (topic < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

	/* Create a reliable Reader. */
	qos = dds_create_qos();
	dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));
	reader = dds_create_reader(participant, topic, qos, NULL);
	if (reader < 0)
		DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
	dds_delete_qos(qos);

	// MQTT Client create
	// mqtt_connect(&mqttcli, MQTT_URL);

	printf("\n=== [Subscriber] Waiting for a sample ...\n");
	fflush(stdout);

	/* Initialize sample buffer, by pointing the void pointer within
	 * the buffer array to a valid sample memory location. */
	samples[0] = example_struct__alloc();

	/* Poll until data has been read. */
	while (true) {
		/* Do the actual read.
		 * The return value contains the number of read samples. */
		rc =
		    dds_take(reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
		if (rc < 0)
			DDS_FATAL("dds_read: %s\n", dds_strretcode(-rc));

		/* Check if we read some data and it is valid. */
		if ((rc > 0) && (infos[0].valid_data)) {
			/* Print Message. */
			msg = (example_struct *) samples[0];
			printf("=== [Subscriber] Received : ");
			printf("Message (%" PRId32 ", %s)\n", msg->int8_test,
			    msg->message);
			print_dds_msg(msg);
			fflush(stdout);

			/*
			fixed_mqtt_msg mqttmsg;
			HelloWorld_to_MQTT(msg, &mqttmsg);
			int rv = mqtt_publish(&mqttcli, "HelloWorld", 0,
			mqttmsg.payload, mqttmsg.len); if (rv != 0)
			        printf("error in mqtt publish.\n");
		    */
		} else {
			/* Polling sleep. */
			dds_sleepfor(DDS_MSECS(20));
		}
	}

	/* Free the data location. */
	example_struct_free(samples[0], DDS_FREE_ALL);

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	return EXIT_SUCCESS;
}

void
print_dds_msg(struct example_struct *msg)
{
	if (msg == NULL) {
		printf("ITS NULL!\n");
	}
	printf("int8_test:%d\n", msg->int8_test);
	printf("uint8_test:%d\n", msg->uint8_test);
	printf("int16_test:%d\n", msg->int16_test);
	printf("uint16_test:%d\n", msg->uint16_test);
	printf("int32_test:%d\n", msg->int32_test);
	printf("uint32_test:%d\n", msg->uint32_test);
	printf("int64_test:%ld\n", msg->int64_test);
	printf("uint64_test:%ld\n", msg->uint64_test);
	printf("message:%s\n", msg->message);
	printf("example_enum:%d\n", msg->example_enum);
	printf("example_stru.message:%s\n", msg->example_stru.message);
}
