// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "dds_type.h"
#include "dds/dds.h"
#include "dds_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MQTT
#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>

#include "dds_mqtt_type_conversion.h"
#include "mqtt_client.h"
#include "dds_utils.h"

int
dds_publisher(int argc, char **argv)
{
	dds_entity_t   participant;
	dds_entity_t   topic;
	dds_entity_t   writer;
	dds_return_t   rc;
	DDS_TYPE_NAME  msg;
	test_struct    sub_msg;
	uint32_t       status = 0;

	dds_client_opts opts = { .cli_type = DDS_PUB };

	dds_handle_cmd(argc, argv, &opts);

	/* Create a Participant. */
	participant = dds_create_participant(opts.domain_id, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a Topic. */
	topic = dds_create_topic(
	    participant, &DDS_TYPE_NAME_DESC(), opts.topic, NULL, NULL);
	if (topic < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

	/* Create a Writer. */
	writer = dds_create_writer(participant, topic, NULL, NULL);
	if (writer < 0)
		DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));

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

	while (1) {
		/* Create a message to write. */
		msg.int8_test   = 1;
		msg.uint8_test  = 2;
		msg.int16_test  = 4;
		msg.uint16_test = 8;
		msg.int32_test  = 16;
		msg.uint32_test = 32;
		msg.int64_test  = 64;
		msg.uint64_test = 128;
		strncpy((char *) msg.message, "data->message",
		    strlen("data->message"));
		strncpy((char *) sub_msg.message, "stru.message",
		    strlen("data->message"));
		msg.example_enum = 0;
		msg.example_stru = sub_msg;

		printf("=== [Publisher]  Writing : ");
		printf(
		    "Message (%" PRId32 ", %s)\n", msg.int8_test, msg.message);
		fflush(stdout);

		rc = dds_write(writer, &msg);
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
