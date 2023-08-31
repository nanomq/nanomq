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

// MQTT
#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "mqtt_client.h"
#include "dds_utils.h"

int
dds_publisher(int argc, char **argv)
{
	dds_entity_t  participant;
	dds_entity_t  topic;
	dds_entity_t  writer;
	dds_return_t  rc;
	uint32_t      status  = 0;
	dds_qos_t    *qospub;
	dds_qos_t    *qosw;
	const char   *partitionspub[] = { "partition" };
	dds_entity_t  publisher;

	dds_client_opts opts = { .cli_type = DDS_PUB };

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

	/* Qos for Publisher */
	qospub = dds_create_qos();
	if (opts.partition != NULL)
		partitionspub[0] = opts.partition;
	dds_qset_partition(qospub, 1, partitionspub);

	/* Create the Publisher. */
	publisher = dds_create_publisher(participant, qospub, NULL);
	if (publisher < 0)
		DDS_FATAL("dds_create_publisher: %s\n", dds_strretcode(-publisher));
	dds_delete_qos(qospub);

	/* Qos for Writer */
	qosw = dds_create_qos();
	dds_qset_reliability(qosw, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

	/* Create a Writer. */
	writer = dds_create_writer(publisher, topic, qosw, NULL);
	if (writer < 0)
		DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));
	dds_delete_qos(qosw);

	printf("=== [Publisher]  Waiting for a reader to be discovered ...\n");
	fflush(stdout);

	rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));

	while (!(status & DDS_PUBLICATION_MATCHED_STATUS)) {
		rc = dds_get_status_changes(writer, &status);
		if (rc != DDS_RETCODE_OK)
			DDS_FATAL("dds_get_status_changes: %s\n",
			    dds_strretcode(-rc));

		/* Polling sleep. */
		dds_sleepfor(DDS_MSECS(20));
	}

	void *dds_data = dds_handles->alloc();

	while (1) {
		char *json_str = cJSON_Print(opts.msg);
		printf("=== [Publisher]  Writing : %s\n", json_str);
		fflush(stdout);
		cJSON_free(json_str);

		if (dds_handles->mqtt2dds(opts.msg, dds_data) != 0) {
			fprintf(stderr,
			    "Failed to convert json to struct '%s' \n",
			    opts.struct_name);
			break;
		}

		rc = dds_write(writer, dds_data);
		if (rc != DDS_RETCODE_OK)
			DDS_FATAL("dds_write: %s\n", dds_strretcode(-rc));
		break;
	}

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	dds_client_opts_fini(&opts);

	return EXIT_SUCCESS;
}

#endif
