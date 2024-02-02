// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <dds/ddsc/dds_basic_types.h>
#if defined(SUPP_DDS_PROXY)

#include "dds_client.h"
#include "dds/dds.h"
#include "dds/version.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/heap.h"
#include "nng/supplemental/nanolib/file.h"
#include "vector.h"
#include "idl_convert.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

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

#define DDS_PROXY_DDSVERSION_USING "0.10.4"

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

	printf("\nBased on CycloneDDS V%s\n", DDS_PROXY_DDSVERSION_USING);
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

static void
dds_subcli_send(dds_subcli *scli, char *payload)
{
	uint32_t rc = 0;
	void    *samples[MAX_SAMPLES];

	samples[0] = scli->handles->alloc();
	cJSON *json = cJSON_Parse(payload);
	scli->handles->mqtt2dds(json, samples[0]);
	cJSON_Delete(json);
	/* Send the msg received */
	rc = dds_write(scli->scli, samples[0]);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_write: %s\n", dds_strretcode(-rc));
	log_dds("[DDS] Pub struct %s, topic %s, cnt %d",
		scli->handles->desc->m_typename,
		scli->ddssend_topic, ++sent_cnt);
	/* Free the data location. */
	scli->handles->free(samples[0], DDS_FREE_ALL);
}

static int
dds_subcli_init(dds_subcli *scli, bool isrd, const char *topic, dds_entity_t participant, dds_entity_t parent, dds_listener_t* listener, dds_gateway_conf *config)
{
	uint32_t rc = 0;
	dds_entity_t topicw, topicr;
	dds_qos_t *qosw, *qosr;
	dds_handler_set *dds_handles;
	dds_entity_t reader, writer;

	if (isrd) {
		scli->ddsrecv_topic = (char *)topic;
		scli->ddssend_topic = NULL;

		dds_handles = NULL;
		dds_gateway_topic **tl = config->forward.dds2mqtt;
		for (size_t i=0; i<config->forward.dds2mqtt_sz; ++i) {
			if (0 == strcmp(topic, tl[i]->from)) {
				dds_handles = dds_get_handler(tl[i]->struct_name);
				if (dds_handles == NULL) {
					log_dds("ERROR Invaild structure:%s", tl[i]->struct_name);
					return -1;
				}
				break;
			}
		}

		if (dds_handles == NULL) {
			log_dds("ERROR Incorrect topic:%s", topic);
			return -1;
		}

		scli->handles = dds_handles;

		/* Topic for reader */
		topicr = dds_create_topic(
		    participant, dds_handles->desc, scli->ddsrecv_topic, NULL, NULL);
		if (topicr < 0) {
			DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicr));
			return topicr;
		}

		/* Qos for Reader. */
		qosr = dds_create_qos();
		dds_qset_reliability(qosr, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

		/* Create the Reader */
		reader = dds_create_reader(parent, topicr, qosr, listener);
		if (reader < 0) {
			DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
			return reader;
		}
		dds_delete_qos(qosr);

		scli->scli = reader;
	} else {
		scli->ddsrecv_topic = NULL;
		scli->ddssend_topic = (char *)topic;

		dds_handles = NULL;
		dds_gateway_topic **tl = config->forward.mqtt2dds;
		for (size_t i=0; i<config->forward.mqtt2dds_sz; ++i) {
			if (0 == strcmp(topic, tl[i]->to)) {
				dds_handles = dds_get_handler(tl[i]->struct_name);
				if (dds_handles == NULL) {
					log_dds("ERROR Invaild structure:%s", tl[i]->struct_name);
					return -1;
				}
				break;
			}
		}

		if (dds_handles == NULL) {
			log_dds("ERROR Incorrect topic:%s", topic);
			return -1;
		}

		scli->handles = dds_handles;

		/* Topic for writer */
		topicw = dds_create_topic(
		    participant, dds_handles->desc, scli->ddssend_topic, NULL, NULL);
		if (topicw < 0) {
			DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topicw));
			return topicw;
		}

		/* Qos for Writer */
		qosw = dds_create_qos();
		dds_qset_reliability(qosw, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));

		/* Create a Writer */
		writer = dds_create_writer(parent, topicw, qosw, NULL);
		if (writer < 0) {
			DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));
			return writer;
		}
		dds_delete_qos(qosw);

		rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
		if (rc != DDS_RETCODE_OK) {
			DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));
			return rc;
		}

		scli->scli = writer;
	}

	scli->config = config;
	return 0;
}

static void
dds_data_available(dds_entity_t rd, void *arg)
{
	dds_cli *cli = arg;
	handle  *hd;
	uint32_t rc = 0;
	void *samples[MAX_SAMPLES];
	dds_sample_info_t infos[MAX_SAMPLES];

	nftp_vec *handleq = cli->handleq;

	char *topic = NULL;
	int   clidx = 0;
	for (size_t i=0; i<cli->nsubrdclis; ++i) {
		if (rd == cli->subrdclis[i]->scli) {
			topic = strdup(cli->subrdclis[i]->ddsrecv_topic);
			clidx = i;
			break;
		}
	}

	if (topic == NULL) {
		log_dds("no topic found for dds reader: %d", rd);
		return;
	}

	// dds_handler_set *dds_reader_handles = dds_get_handler(cli->config->forward.dds2mqtt[0]->struct_name);
	// samples[0] = dds_reader_handles->alloc();
	samples[0] = cli->subrdclis[clidx]->handles->alloc();

	rc = dds_take(rd, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
	if (rc < 0)
		DDS_FATAL("dds_take: %s\n", dds_strretcode(-rc));

	if ((rc > 0) && (infos[0].valid_data)) {
		log_dds("[DDS] Sub recv struct %s, topic %s, cnt%d",
		    cli->subrdclis[clidx]->handles->desc->m_typename,
			cli->subrdclis[clidx]->ddsrecv_topic, ++recv_cnt);

		/* Make a handle */
		hd = mk_handle(HANDLE_TO_MQTT, samples[0], 0, topic);

		/* Put msg to handleq */
		pthread_mutex_lock(&cli->mtx);
		nftp_vec_append(handleq, (void *) hd);
		pthread_cond_signal(&cli->cv);
		pthread_mutex_unlock(&cli->mtx);
	} else {
		cli->subrdclis[clidx]->handles->free(samples[0], DDS_FREE_ALL);
		free(topic);
	}
}

int
dds_proxy(int argc, char **argv)
{
	mqtt_cli mqttcli;
	dds_cli  ddscli;

#ifdef DEBUG
	signal(SIGINT, exit);
#endif

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
	for (size_t i=0; i<config->forward.dds2mqtt_sz; ++i) {
		log_dds("%s => %s {%s}",
			config->forward.dds2mqtt[i]->from,
			config->forward.dds2mqtt[i]->to,
			config->forward.dds2mqtt[i]->struct_name);
		if (NULL == dds_get_handler(config->forward.dds2mqtt[i]->struct_name))
			exit(0);
	}
	log_dds("[mqtt to dds]");
	for (size_t i=0; i<config->forward.mqtt2dds_sz; ++i) {
		log_dds("%s => %s {%s}",
			config->forward.mqtt2dds[i]->from,
			config->forward.mqtt2dds[i]->to,
			config->forward.mqtt2dds[i]->struct_name);
		if (NULL == dds_get_handler(config->forward.mqtt2dds[i]->struct_name))
			exit(0);
	}

	dds_client_init(&ddscli, config);

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
	cli->nsubrdclis = 0;
	cli->subrdclis = NULL;
	cli->nsubwrclis = 0;
	cli->subwrclis = NULL;

	nftp_vec_alloc(&cli->handleq);
	pthread_mutex_init(&cli->mtx, NULL);
	pthread_cond_init(&cli->cv, NULL);
	cli->config = config;

	return 0;
}

static int
dds_client(dds_cli *cli, mqtt_cli *mqttcli)
{
	dds_entity_t      participant;
	dds_entity_t      reader;
	dds_entity_t      writer;
	dds_entity_t      publisher;
	dds_entity_t      subscriber;
	dds_entity_t      waitSet;
	dds_entity_t      readCond;
	dds_return_t      rc;
	dds_qos_t        *qospub;
	dds_qos_t        *qossub;
	uint32_t          status = 0;
	handle           *hd;
	dds_listener_t   *listener;
	dds_subcli       *scli;

	/* Get current client's handle queue */
	nftp_vec *handleq = cli->handleq;

	dds_gateway_dds *dds_conf = &cli->config->dds;

	dds_inner_config(dds_conf);

	// Setting partitions
	const char *partitionssub[] = { dds_conf->subscriber_partition };
	const char *partitionspub[] = { dds_conf->publisher_partition };

	/* Create a Participant. */
	participant = dds_create_participant(dds_conf->domain_id, NULL, NULL);
	if (participant < 0)
		DDS_FATAL("dds_create_participant: %s\n",
		    dds_strretcode(-participant));

	/* Create a listener */
	listener = dds_create_listener(NULL);
	dds_lset_data_available_arg(listener, dds_data_available, cli, true);

	// Create waitSet
	waitSet = dds_create_waitset(participant);
	readCond = 0;

	/* Qos for Subscriber */
	qossub = dds_create_qos();
	dds_qset_partition(qossub, 1, partitionssub);

	/* Create the Subscriber */
	subscriber = dds_create_subscriber(participant, qossub, NULL);
	if (subscriber < 0)
		DDS_FATAL("dds_create_subscriber: %s\n", dds_strretcode(-subscriber));
	dds_delete_qos(qossub);

	// Set wait set
	status = dds_waitset_attach(waitSet, waitSet, waitSet);
	if (status < 0)
		DDS_FATAL("dds_waitset_attach: %s\n", dds_strretcode(-status));

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

	log_dds("=== [Publisher] Started");
	fflush(stdout);

	// Create readers for subscriber
	cli->subrdclis = nng_alloc(sizeof(dds_subcli) * cli->config->forward.dds2mqtt_sz);
	for (size_t i=0; i<cli->config->forward.dds2mqtt_sz; ++i) {
		scli = nng_alloc(sizeof(*scli));
		status = dds_subcli_init(scli, true,
		        cli->config->forward.dds2mqtt[i]->from, participant,
		        subscriber, listener, cli->config);
		if (status != 0)
			continue;
		cli->subrdclis[cli->nsubrdclis++] = scli;
		log_dds("=== [DDS READER] Started {%s}", cli->config->forward.dds2mqtt[i]->from);
	}

	// Create writers for publisher
	cli->subwrclis = nng_alloc(sizeof(dds_subcli) * cli->config->forward.mqtt2dds_sz);
	for (size_t i=0; i<cli->config->forward.mqtt2dds_sz; ++i) {
		scli = nng_alloc(sizeof(*scli));
		status = dds_subcli_init(scli, false,
		        cli->config->forward.mqtt2dds[i]->to, participant,
		        publisher, NULL, cli->config);
		if (status != 0)
			continue;
		cli->subwrclis[cli->nsubwrclis++] = scli;
		log_dds("=== [DDS WRITER] Started {%s}", cli->config->forward.mqtt2dds[i]->to);
	}

	nng_msg *      mqttmsg;
	char *         payload;
	uint32_t       len;

	/* Poll until data has been read. */
	while (true) {
		// If handle queue is not empty. Handle it first.
		// Or we need to receive msgs from DDS in a NONBLOCK way and
		// put it to the handle queue. Wait cv when handle queue is
		// empty.
		hd = NULL;

		/* Initialize sample buffer, by pointing the void pointer
		 * within the buffer array to a valid sample memory location.
		 */

		pthread_mutex_lock(&cli->mtx);
		while (nftp_vec_len(handleq) == 0)
			pthread_cond_wait(&cli->cv, &cli->mtx);
		if (nftp_vec_len(handleq))
			nftp_vec_pop(handleq, (void **) &hd, NFTP_HEAD);
		pthread_mutex_unlock(&cli->mtx);

		if (hd)
			goto work;

		continue;

	work:
		switch (hd->type) {
		case HANDLE_TO_DDS:
			mqttmsg = hd->data;
			payload = (char *) nng_mqtt_msg_get_publish_payload(mqttmsg, &len);

			// Find the right sub client
			dds_gateway_topic *dt = find_dds_topic(cli->config, hd->topic);
			for (size_t i=0; i<cli->nsubwrclis; ++i) {
				if (0 == strcmp(dt->to, cli->subwrclis[i]->ddssend_topic)) {
					scli = cli->subwrclis[i];
				}
			}
			if (!scli) {
				log_dds("ERROR no writer found for topic %s", dt->to);
				break;
			}
			dds_subcli_send(scli, payload);

			nng_msg_free(mqttmsg);
			free(hd->topic);
			free(hd);

			break;
		case HANDLE_TO_MQTT:
			// Put to MQTTClient's handle queue
			pthread_mutex_lock(&mqttcli->mtx);
			nftp_vec_append(mqttcli->handleq, hd);
			pthread_cond_signal(&mqttcli->cv);
			pthread_mutex_unlock(&mqttcli->mtx);

			log_dds("[DDS] Forward msg to mqtt, cnt %d", ++forward2mqtt_cnt);
			break;
		default:
			log_dds("Unsupported handle type.\n");
			break;
		}
	}

	/* Deleting the participant will delete all its children recursively as
	 * well. */
	rc = dds_delete(participant);
	if (rc != DDS_RETCODE_OK)
		DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

	nftp_vec_free(cli->handleq);
	pthread_mutex_destroy(&cli->mtx);
	pthread_cond_destroy(&cli->cv);

	return EXIT_SUCCESS;
}

const char *usage = " nanomq_cli dds { sub | pub | proxy } [--help] \n\n"
					" available apps: \n"
                    " \t* sub   \n"
                    " \t* pub   \n"
                    " \t* proxy ";

static inline void
check_dds_version()
{
	if (0 != strcmp(DDS_VERSION, DDS_PROXY_DDSVERSION_USING)) {
		log_dds("WARN DDS Version unmatched. DDSProxy is based on CycloneDDS V%s.",
			DDS_PROXY_DDSVERSION_USING);
	}
}

int
dds_proxy_start(int argc, char **argv)
{
	check_dds_version();

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
