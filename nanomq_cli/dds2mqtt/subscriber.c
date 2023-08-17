// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "dds/dds.h"
#include "dds_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "idl_convert.h"

#include "mqtt_client.h"
#include "dds_utils.h"

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 1

static void print_dds_msg(void *msg, dds_to_mqtt_fn_t func);

int
dds_subscriber(int argc, char **argv)
{
	dds_entity_t      participant;
	dds_entity_t      topic;
	dds_entity_t      reader;
	void             *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];
	dds_return_t      rc;
	dds_qos_t        *qossub;
	dds_qos_t        *qosr;
	const char       *partitionssub[] = { "partition" };
	dds_entity_t      subscriber;

	dds_client_opts opts = { .cli_type = DDS_SUB };

	dds_handle_cmd(argc, argv, &opts);

	dds_handler_set *dds_handles = dds_get_handler(opts.struct_name);

	if (dds_handles == NULL) {
		DDS_FATAL("dds_get_handler: %s\n", "dds_handles is NULL");
		exit(1);
	}

	/* Create a Participant. */
	participant = dds_create_participant(opts.domain_id, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a Topic. */
	topic = dds_create_topic(
	    participant, dds_handles->desc, opts.topic, NULL, NULL);
	if (topic < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

	/* Qos for Subscriber */
	qossub = dds_create_qos();
	if (opts.partition != NULL)
		partitionssub[0] = opts.partition;
	dds_qset_partition(qossub, 1, partitionssub);

	/* Create the Subscriber */
	subscriber = dds_create_subscriber(participant, qossub, NULL);
	if (subscriber < 0)
		DDS_FATAL("dds_create_subscriber: %s\n", dds_strretcode(-subscriber));
	dds_delete_qos(qossub);

	/* Qos for Reader. */
	qosr = dds_create_qos();
	dds_qset_reliability(qosr, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

	/* Create a reliable Reader. */
	reader = dds_create_reader(subscriber, topic, qosr, NULL);
	if (reader < 0)
		DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
	dds_delete_qos(qosr);

	printf("\n=== [Subscriber] Waiting for a sample ...\n");
	fflush(stdout);
	
	/* Poll until data has been read. */
	while (true) {
		/* Initialize sample buffer, by pointing the void pointer
		 * within the buffer array to a valid sample memory location.
		 */
		samples[0] = dds_handles->alloc();
		/* Do the actual read.
		 * The return value contains the number of read samples. */
		rc =
		    dds_take(reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
		if (rc < 0)
			DDS_FATAL("dds_read: %s\n", dds_strretcode(-rc));

		/* Check if we read some data and it is valid. */
		if ((rc > 0) && (infos[0].valid_data)) {
			/* Print Message. */
			printf("=== [Subscriber] Received : ");
			print_dds_msg(samples[0], dds_handles->dds2mqtt);
			fflush(stdout);
		} else {
			/* Polling sleep. */
			dds_sleepfor(DDS_MSECS(20));
		}
		/* Free the data location. */
		dds_handles->free(samples[0], DDS_FREE_ALL);
	}

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	dds_client_opts_fini(&opts);

	return EXIT_SUCCESS;
}

void
print_dds_msg(void *msg, dds_to_mqtt_fn_t func)
{
	if (msg == NULL) {
		printf("ITS NULL!\n");
	}

	cJSON *json = func(msg);
	char * str  = cJSON_Print(json);
	printf("%s\n", str);
	cJSON_free(str);
	cJSON_Delete(json);
}

#endif
