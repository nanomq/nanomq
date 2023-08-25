// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)

#include "dds_client.h"
#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/heap.h"
#include "nng/supplemental/nanolib/file.h"
#include "vector.h"
#include "idl_convert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "dds_mqtt_type_conversion.h"
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

static int recv_cnt = 0;
static int sent_cnt = 0;
static int forward2mqtt_cnt = 0;

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
		log_dds("invalid options.");
		exit(1);
	}
	conf_dds_gateway_parse_ver2(config);
	if (config->path == NULL) {
		log_dds("Configuration file is required.");
		log_dds("Please specify a configuration file with '--conf "
		    "<path>'");
		exit(1);
	}
	if (config->http_server.enable) {
		info = proxy_info_alloc(PROXY_NAME_DDS, config, config->path,
		    &config->http_server, argc, argv);

		start_rest_server(info);
	}
	// Partition must be set
	if (!config->dds.subscriber_partition)
		config->dds.subscriber_partition = strdup("partition");
	if (!config->dds.publisher_partition)
		config->dds.publisher_partition = strdup("partition");

	/* Configuration from file */
	log_dds("[mqtt]");
	log_dds("broker.url. %s", config->mqtt.address);

	log_dds("[dds]");
	log_dds("domain.id. %ld", config->dds.domain_id);
	log_dds("subscriber.partition. %s", config->dds.subscriber_partition);
	log_dds("publisher.partition. %s", config->dds.publisher_partition);

	log_dds("[topic forward rules]");
	log_dds("[dds to mqtt]");
	for (size_t i=0; i<config->forward.dds2mqtt_sz; ++i)
		log_dds("%s => %s {%s}",
			config->forward.dds2mqtt[i]->from,
			config->forward.dds2mqtt[i]->to,
			config->forward.dds2mqtt[i]->struct_name);
	log_dds("[mqtt to dds]");
	for (size_t i=0; i<config->forward.mqtt2dds_sz; ++i)
		log_dds("%s => %s {%s}",
			config->forward.mqtt2dds[i]->from,
			config->forward.mqtt2dds[i]->to,
			config->forward.mqtt2dds[i]->struct_name);

	dds_client_init(&ddscli, config);

	mqttcli.mqttrecv_topic = config->forward.mqtt2dds.from;
	mqttcli.mqttsend_topic = config->forward.dds2mqtt.to;

	ddscli.ddsrecv_topic = config->forward.dds2mqtt.from;
	ddscli.ddssend_topic = config->forward.mqtt2dds.to;

	mqtt_connect(&mqttcli, &ddscli, config);

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
	dds_entity_t      publisher;
	dds_entity_t      subscriber;
	void             *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];
	dds_return_t      rc;
	dds_qos_t        *qos;
	dds_qos_t        *qospub;
	dds_qos_t        *qossub;
	dds_qos_t        *qosw;
	dds_qos_t        *qosr;
	uint32_t          status = 0;
	handle           *hd;

	/* Get current client's handle queue */
	nftp_vec *handleq = cli->handleq;

	dds_handler_set *dds_reader_handles =
	    dds_get_handler(cli->config->forward.dds2mqtt.struct_name);

	if (dds_reader_handles == NULL) {
		DDS_FATAL("Failed to get reader handler from struct '%s'",
		    cli->config->forward.dds2mqtt.struct_name);
		exit(1);
	}

	dds_handler_set *dds_writer_handles =
	    dds_get_handler(cli->config->forward.mqtt2dds.struct_name);
	if (dds_reader_handles == NULL) {
		DDS_FATAL("Failed to get writer handler from struct '%s'",
		    cli->config->forward.mqtt2dds.struct_name);
		exit(1);
	}

	dds_gateway_dds *dds_conf = &cli->config->dds;

	const char *partitionssub[] = { dds_conf->subscriber_partition };
	const char *partitionspub[] = { dds_conf->publisher_partition };

	dds_inner_config(dds_conf);

	/* Create a Participant. */
	participant = dds_create_participant(dds_conf->domain_id, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Qos for Subscriber */
	qossub = dds_create_qos();
	dds_qset_partition(qossub, 1, partitionssub);

	/* Create the Subscriber */
	subscriber = dds_create_subscriber(participant, qossub, NULL);
	if (subscriber < 0)
		DDS_FATAL("dds_create_subscriber: %s\n", dds_strretcode(-subscriber));
	dds_delete_qos(qossub);

	/* Topic for Reader */
	topicr = dds_create_topic(
	    participant, dds_reader_handles->desc, cli->ddsrecv_topic, NULL, NULL);
	if (topicr < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicr));

	/* Qos for Reader. */
	qosr = dds_create_qos();
	dds_qset_reliability(qosr, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

	/* Create the Reader */
	reader = dds_create_reader(subscriber, topicr, qosr, NULL);
	if (reader < 0)
		DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
	dds_delete_qos(qosr);

	log_dds("=== [Subscriber] Started");
	fflush(stdout);

	/* Qos for Publisher */
	qospub = dds_create_qos();
	dds_qset_partition(qospub, 1, partitionspub);

	/* Create the Publisher. */
	publisher = dds_create_publisher(participant, qospub, NULL);
	if (publisher < 0)
		DDS_FATAL("dds_create_publisher: %s\n", dds_strretcode(-publisher));
	dds_delete_qos(qospub);

	/* Topic for writer */
	topicw = dds_create_topic(
	    participant, dds_writer_handles->desc, cli->ddssend_topic, NULL, NULL);
	if (topicw < 0)
		DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicw));

	// TODO Topics for writer and reader **MUST** be different.
	// Or Circle messages happened

	/* Qos for Writer */
	qosw = dds_create_qos();
	dds_qset_reliability(qosw, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

	/* Create a Writer */
	writer = dds_create_writer(publisher, topicw, qosw, NULL);
	if (writer < 0)
		DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));

	log_dds("=== [Publisher] Started");
	fflush(stdout);

	rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));
	
	nng_msg *      mqttmsg;
	fixed_mqtt_msg midmsg;
	uint32_t       len;

	/* Poll until data has been read. */
	while (true) {
		// If handle queue is not empty. Handle it first.
		// Or we need to receive msgs from DDS in a NONBLOCK way and
		// put it to the handle queue. Sleep when handle queue is
		// empty.
		hd = NULL;

		/* Initialize sample buffer, by pointing the void pointer
		 * within the buffer array to a valid sample memory location.
		 */
		samples[0] = dds_reader_handles->alloc();

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
			log_dds("[DDS] Subscriber received struct '%s', counter %d",
			    dds_reader_handles->desc->m_typename, ++recv_cnt);

			/* Make a handle */
			hd = mk_handle(HANDLE_TO_MQTT, samples[0], 0);

			/* Put msg to handleq */
			pthread_mutex_lock(&cli->mtx);
			nftp_vec_append(handleq, (void *) hd);
			pthread_mutex_unlock(&cli->mtx);
			continue;
		} else {
			/* Polling sleep. */
			dds_reader_handles->free(samples[0], DDS_FREE_ALL);
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

			dds_writer_handles->mqtt2dds(
			    cJSON_Parse(midmsg.payload), samples[0]);
			/* Send the msg received */
			rc = dds_write(writer, samples[0]);
			if (rc != DDS_RETCODE_OK)
				DDS_FATAL(
				    "dds_write: %s\n", dds_strretcode(-rc));
			log_dds("[DDS] Publisher sent struct '%s', counter %d",
				dds_writer_handles->desc->m_typename, ++sent_cnt);
			free(hd);
			break;
		case HANDLE_TO_MQTT:
			// Put to MQTTClient's handle queue
			pthread_mutex_lock(&mqttcli->mtx);
			nftp_vec_append(mqttcli->handleq, hd);
			pthread_mutex_unlock(&mqttcli->mtx);
			log_dds("[DDS] Forward msg to mqtt, counter %d", ++forward2mqtt_cnt);
			break;
		default:
			log_dds("Unsupported handle type.\n");
			break;
		}
	}

	/* Free the data location. */
	dds_reader_handles->free(samples[0], DDS_FREE_ALL);

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	nftp_vec_free(cli->handleq);
	pthread_mutex_destroy(&cli->mtx);

	return EXIT_SUCCESS;
}

const char *usage = " nanomq_cli dds { sub | pub | proxy } [--help] \n\n"
					" available apps: \n"
                    " \t* sub   \n"
                    " \t* pub   \n"
                    " \t* proxy ";

int
dds_proxy_start(int argc, char **argv)
{
	if (argc < 3)
		goto help;

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
