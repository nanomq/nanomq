// Author: wangha <wanghamax at gmail dot com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#if defined(SUPP_DDS_PROXY)
#include "dds_utils.h"
#include "dds/dds.h"
#include "dds/ddsrt/environ.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/heap.h"
#include "vector.h"
#include <stdio.h>
#include <stdlib.h>

enum options {
	OPT_DDS_HELP = 1,
	OPT_DDS_DOMAIN_ID,
	OPT_DDS_TOPIC,
	OPT_DDS_STRUCT_NAME,
	OPT_DDS_MSG,
	OPT_DDS_SHM_MODE,
	OPT_DDS_SHM_LOG_LEVEL,
	OPT_DDS_PARTITION,
	OPT_DDS_INVALID,
};

static nng_optspec cmd_opts[] = {
	{
	    .o_name  = "help",
	    .o_short = 'h',
	    .o_val   = OPT_DDS_HELP,
	},
	{
	    .o_name  = "domain_id",
	    .o_short = 'd',
	    .o_val   = OPT_DDS_DOMAIN_ID,
	    .o_arg   = true,
	},
	{
	    .o_name  = "struct",
	    .o_short = 'n',
	    .o_val   = OPT_DDS_STRUCT_NAME,
	    .o_arg   = true,
	},
	{
	    .o_name  = "msg",
	    .o_short = 'm',
	    .o_val   = OPT_DDS_MSG,
	    .o_arg   = true,
	},
	{
	    .o_name  = "topic",
	    .o_short = 't',
	    .o_val   = OPT_DDS_TOPIC,
	    .o_arg   = true,
	},
	{
	    .o_name  = "shm_mode",
	    .o_short = 's',
	    .o_val   = OPT_DDS_SHM_MODE,
	},
	{
	    .o_name  = "shm_log_level",
	    .o_short = 'l',
	    .o_val   = OPT_DDS_SHM_LOG_LEVEL,
	    .o_arg   = true,
	},
	{
	    .o_name  = "partition",
	    .o_short = 'p',
	    .o_val   = OPT_DDS_PARTITION,
	    .o_arg   = true,
	},
	{
	    .o_name = NULL,
	    .o_val  = 0,
	},
};

static void help(dds_client_type cli_type);

int
dds_cmd_parse_opts(int argc, char **argv, dds_client_opts *opts)
{
	int   idx = 2;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(
	            argc - 1, argv + 1, cmd_opts, &val, &arg, &idx)) == 0) {
		switch (val) {
		case OPT_DDS_HELP:
			help(opts->cli_type);
			exit(0);
			break;

		case OPT_DDS_DOMAIN_ID:
			opts->domain_id = (uint32_t) atol(arg);
			break;

		case OPT_DDS_TOPIC:
			if (opts->topic != NULL) {
				nng_strfree(opts->topic);
			}
			opts->topic = nng_strdup(arg);
			break;

		case OPT_DDS_STRUCT_NAME:
			if (opts->struct_name != NULL) {
				nng_strfree(opts->struct_name);
			}
			opts->struct_name = nng_strdup(arg);
			break;

		case OPT_DDS_MSG:
			if (cJSON_IsObject(opts->msg)) {
				cJSON_Delete(opts->msg);
				opts->msg = NULL;
			}
			cJSON *json = cJSON_Parse(arg);
			if (cJSON_IsObject(json)) {
				opts->msg = json;
			} else {

				fprintf(
				    stderr, "Invalid json string: %s\n", arg);
				exit(1);
			}
			break;

		case OPT_DDS_SHM_MODE:
			opts->shm_mode = true;
			break;

		case OPT_DDS_SHM_LOG_LEVEL:
			if (opts->shm_log_level != NULL) {
				nng_strfree(opts->shm_log_level);
			}
			opts->shm_log_level = nng_strdup(arg);
			break;

		case OPT_DDS_PARTITION:
			if (opts->partition != NULL) {
				nng_strfree(opts->partition);
			}
			opts->partition = nng_strdup(arg);
			break;

		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq_cli ddsproxy %s "
		    "--help' for more information.\n",
		    argv[idx], opts->cli_type == DDS_PUB ? "pub" : "sub");
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry "
		    "'nanomq_cli ddsproxy %s --help' for more "
		    "information.\n",
		    argv[idx], opts->cli_type == DDS_PUB ? "pub" : "sub");
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\n"
		    "Try 'nanomq_cli ddsproxy %s --help' for more "
		    "information.\n",
		    argv[idx], opts->cli_type == DDS_PUB ? "pub" : "sub");
		break;
	default:
		break;
	}

	return rv == -1;
}

static void
help(dds_client_type cli_type)
{
	printf("Usage: \n"
	       "nanomq_cli ddsproxy %s -t <topic> -n <struct> \n"
	       "       [-h, --help] [-d, --domain_id <domain id>] \n"
           "       [-s, --shm_mode] [-l, --shm_log_level <level>]\n",
           "       [-p, --partition <partition name>]\n\n",
	    cli_type == DDS_PUB ? "pub" : "sub");

	printf("Requirements: \n");
	printf("\t-t, --topic <topic>            Topic for publish or "
	       "subscribe\n");
	printf("\t-n, --struct <struct name>     Specify structure name from "
	       "idl file\n");
	if (cli_type == DDS_PUB) {
		printf("\t-m, --msg <message>            Input message as "
		       "JSON format");
	}
	printf("\n");
	printf("Options:\n");
	printf("\t-d, --domain_id <domain id>    Specify a DDS domain id "
	       "(default: 0)\n");
	printf("\t-s, --shm_mode                 Enable shared memory mode "
	       "(default: false)\n");
	printf("\t-l, --shm_log_level <level>    Specify a shared memory "
	       "(iceoryx) log level\n");
	printf("\t                               (verbose, debug, info, warn, "
	       "error, fatal, off)\n");
	printf("\t                               (default: info)\n");
	printf("\t-p, --partition <partition>    Specify a DDS Partition name"
	       "(default: partition)\n");
	printf("\n");
}

void
dds_handle_cmd(
    int argc, char **argv, dds_client_opts *opts)
{
	opts->domain_id     = 0;
	opts->topic         = NULL;
	opts->shm_mode      = false;
	opts->shm_log_level = NULL;
	opts->partition     = NULL;

	if (!dds_cmd_parse_opts(argc, argv, opts)) {
		help(opts->cli_type);
		exit(1);
	}

	if (opts->topic == NULL) {
		fprintf(stderr,
		    "Topic name is required.\n");
		fprintf(stderr,
		    "Please specify a topic name with '-t <topic>'\n");
		exit(1);
	}

	if (opts->struct_name == NULL) {
		fprintf(stderr, "Structure name is required.\n");
		fprintf(stderr,
		    "Please specify a structure name with '-n, --struct "
		    "<struct>'\n");
		exit(1);
	}

	if (opts->cli_type == DDS_PUB) {
		if (!cJSON_IsObject(opts->msg)) {
			fprintf(stderr, "Message is required.\n");
			fprintf(stderr,
			    "Please input message with '-m, "
			    "--msg "
			    "<json>'\n");
			exit(1);
		}
	}

	if (opts->shm_mode) {
		dds_set_shm_mode(opts);
	}
}

void
dds_client_opts_fini(dds_client_opts *opts)
{
	if (opts->topic) {
		nng_strfree(opts->topic);
		opts->topic = NULL;
	}
	if (opts->shm_log_level) {
		nng_strfree(opts->shm_log_level);
		opts->shm_log_level = NULL;
	}
	if (opts->partition) {
		nng_strfree(opts->partition);
		opts->partition = NULL;
	}
	if (opts->struct_name) {
		nng_strfree(opts->struct_name);
		opts->struct_name = NULL;
	}
	if (cJSON_IsObject(opts->msg)){
		cJSON_Delete(opts->msg);
		opts->msg = NULL;
	}
	opts->domain_id = 0;
	opts->shm_mode  = false;
}

char *
dds_shm_xml(bool enable, const char *log_level)
{
	char *configstr = NULL;
	ddsrt_asprintf(&configstr,
	    "${CYCLONEDDS_URI}${CYCLONEDDS_URI:+,}"
	    "<SharedMemory>"
	    "<Enable>%s</Enable>"
	    "<LogLevel>%s</LogLevel>"
	    "</SharedMemory>",
	    enable ? "true" : "false", log_level == NULL ? "info" : log_level);

	return configstr;
}

void
dds_set_shm_mode(dds_client_opts *opts)
{
	char *configstr  = dds_shm_xml(opts->shm_mode, opts->shm_log_level);
	char *xconfigstr = ddsrt_expand_envvars(configstr, opts->domain_id);

	const dds_entity_t dom =
	    dds_create_domain(opts->domain_id, xconfigstr);

	ddsrt_free(xconfigstr);
	ddsrt_free(configstr);

	if (dom < 0) {
		DDS_FATAL("dds_create_domain: %s\n", dds_strretcode(-dom));
	}
}

dds_handler_set *
dds_get_handler(const char *struct_name)
{
	for (size_t i = 0; i < sizeof(dds_struct_handler_map) /
	         sizeof(dds_struct_handler_map[0]);
	     i++) {
		if (strcmp(dds_struct_handler_map[i].struct_name,
		        struct_name) == 0) {
			return &dds_struct_handler_map[i].op_set;
		}
	}
	log_dds(
	    "ERROR Please make sure the struct name (%s) is correct "
	    "and included in the idl file\n", struct_name);
	return NULL;
}

#endif
