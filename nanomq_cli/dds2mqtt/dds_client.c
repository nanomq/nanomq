// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "dds_client.h"
#include "dds_type.h"
#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/heap.h"
#include "nng/supplemental/nanolib/file.h"
#include "vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dds_mqtt_type_conversion.h"
#include "dds_utils.h"
#include "mqtt_client.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/hocon.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"
#include "web_server.h"
#include "proxy.h"

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 1

static int  dds_client_init(dds_cli *cli, dds_gateway_conf *config);
static int  dds_client(dds_cli *cli, mqtt_cli *mqttcli);
static void dds_inner_config(dds_gateway_dds *config);
static int  cmd_parse_opts(int argc, char **argv, char **file_path);

enum options {
	OPT_HELP = 1,
	OPT_CONFIG_PATH,
	OPT_INVALID,
};

static nng_optspec cmd_opts[] = {
	{
	    .o_name  = "help",
	    .o_short = 'h',
	    .o_val   = OPT_HELP,
	},
	{
	    .o_name = "conf",
	    .o_val  = OPT_CONFIG_PATH,
	    .o_arg  = true,
	},
	{
	    .o_name = NULL,
	    .o_val  = 0,
	},
};

static void
help(void)
{
	printf("Usage: \n");
	printf("nanomq_cli ddsproxy proxy --conf <config path> "
	       "[-h, --help] \n\n");

	printf("<config path> must be set: \n");
	printf("\t--conf <path>     Specify dds proxy configuration file.\n");
}

static int
cmd_parse_opts(int argc, char **argv, char **file_path)
{
	int   idx = 2;
	char *arg;
	int   val;
	int   rv;
	char *path = NULL;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_HELP:
			help();
			exit(0);
			break;

		case OPT_CONFIG_PATH:
			if (path != NULL) {
				nng_strfree(path);
				path = NULL;
			}
			path       = nng_strdup(arg);
			*file_path = path;
			break;

		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq_cli ddsproxy proxy "
		    "--help' for more information.\n",
		    argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry "
		    "'nanomq_cli ddsproxy proxy --help' for more "
		    "information.\n",
		    argv[idx]);
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\n"
		    "Try 'nanomq_cli ddsproxy proxy --help' for more "
		    "information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

static void
dds_inner_config(dds_gateway_dds *config)
{
	if (config->shm_mode == false) {
		return;
	}
	if (config->domain_id == DDS_DOMAIN_DEFAULT) {
		DDS_FATAL("please set another domain id when using shm mode");
	}
	char *configstr = dds_shm_xml(config->shm_mode, config->shm_log_level);
	char *xconfigstr = ddsrt_expand_envvars(configstr, config->domain_id);

	const dds_entity_t dom =
	    dds_create_domain(config->domain_id, xconfigstr);

	ddsrt_free(xconfigstr);
	ddsrt_free(configstr);	
	
	if (dom < 0) {
		DDS_FATAL(
		    "dds_create_domain: %s\n", dds_strretcode(-dom));
	}
}

int
dds_proxy(int argc, char **argv)
{
	mqtt_cli mqttcli;
	dds_cli  ddscli;

	dds_gateway_conf *config = nng_zalloc(sizeof(dds_gateway_conf));

	proxy_info *info = NULL;

	conf_dds_gateway_init(config);

	if (cmd_parse_opts(argc, argv, &config->path) == 0) {
		fprintf(stderr, "invalid options.\n");
		exit(1);
	}
	conf_dds_gateway_parse_ver2(config);
	if (config->path == NULL) {
		fprintf(stderr, "Configuration file is required.\n");
		fprintf(stderr,
		    "Please specify a configuration file with '--conf "
		    "<path>' \n");
		exit(1);
	}
	if (config->http_server.enable) {
		info = proxy_info_alloc(PROXY_NAME_DDS, config, config->path,
		    &config->http_server, argc, argv);

		start_rest_server(info);
	}

	/* Configuration from file */
	printf("[mqtt]\n");
	printf("broker.url. %s\n", config->mqtt.address);

	printf("[dds]\n");
	printf("domain.id. %ld\n", config->dds.domain_id);

	printf("[topic forward rules]\n");
	printf("dds2mqtt. %s => %s\n", config->forward.dds2mqtt.from, config->forward.dds2mqtt.to);
	printf("mqtt2dds. %s => %s\n", config->forward.mqtt2dds.from, config->forward.mqtt2dds.to);

	dds_client_init(&ddscli, config);

	mqttcli.mqttrecv_topic = config->forward.mqtt2dds.from;
	mqttcli.mqttsend_topic = config->forward.dds2mqtt.to;

	ddscli.ddsrecv_topic = config->forward.dds2mqtt.from;
	ddscli.ddssend_topic = config->forward.mqtt2dds.to;

	mqtt_connect(&mqttcli, &ddscli, config);
	mqtt_subscribe(&mqttcli, mqttcli.mqttrecv_topic, 0);

	dds_client(&ddscli, &mqttcli);

	conf_dds_gateway_destory(config);

	free(config);
	if (info)
		free(info);

	return 0;
}

static int
dds_client_init(dds_cli *cli, dds_gateway_conf *config)
{
	nftp_vec_alloc(&cli->handleq);
	pthread_mutex_init(&cli->mtx, NULL);
	cli->config = config;

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
	DDS_TYPE_NAME    *msg;
	void             *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];
	dds_return_t      rc;
	dds_qos_t        *qos;
	uint32_t          status = 0;
	handle           *hd;

	/* Get current client's handle queue */
	nftp_vec *handleq = cli->handleq;

	dds_gateway_dds *dds_conf = &cli->config->dds;

	dds_inner_config(dds_conf);

	/* Create a Participant. */
	participant = dds_create_participant(dds_conf->domain_id, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a Topic. */
	topicr = dds_create_topic(
	    participant, &DDS_TYPE_NAME_DESC(), cli->ddsrecv_topic, NULL, NULL);
	if (topicr < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicr));

	/* Create a Topic. for writer */
	topicw = dds_create_topic(
	    participant, &DDS_TYPE_NAME_DESC(), cli->ddssend_topic, NULL, NULL);
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

	printf("=== [Publisher] Started\n");
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

	printf("\n=== [Subscriber] Started\n");
	fflush(stdout);

	/* Initialize sample buffer, by pointing the void pointer within
	 * the buffer array to a valid sample memory location. */
	samples[0] = DDS_TYPE_NAME_ALLOC();
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
			msg        = (DDS_TYPE_NAME *) samples[0];
			mqtt_to_dds_type_convert(&midmsg, msg);
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
	DDS_TYPE_NAME_FREE(samples[0], DDS_FREE_ALL);

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	nftp_vec_free(cli->handleq);
	pthread_mutex_destroy(&cli->mtx);

	return EXIT_SUCCESS;
}

const char *usage = " nanomq_cli ddsproxy { sub | pub | proxy } [--help] \n\n"
					" available apps: \n"
                    " \t* sub   \n"
                    " \t* pub   \n"
                    " \t* proxy ";

int
dds_proxy_start(int argc, char **argv)
{
	if (argc < 3)
		goto help;

#if !defined(DDS_TYPE_NAME)
	printf("Set DDS_TYPE_NAME in cmake and continue.\n");
	return 2;
#endif

	if (strcmp(argv[2], "sub") == 0) {
		dds_subscriber(argc, argv);
	} else if (strcmp(argv[2], "pub") == 0) {
		dds_publisher(argc, argv);
	} else if (strcmp(argv[2], "proxy") == 0) {
		dds_proxy(argc, argv);
	} else if (strcmp(argv[2], "--help") == 0 ||
	    (strcmp(argv[2], "-h") == 0)) {
		printf("%s\n", usage);
	} else {
		goto help;
	}

	return 0;

help:
	printf("%s\n", usage);
	return 1;
}

#endif
