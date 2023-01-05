#ifndef DDS_PROXY_H
#define DDS_PROXY_H

#if defined(SUPP_DDS_PROXY)

#include <pthread.h>
#include <stdlib.h>

#include "vector.h"
#include "mqtt_client.h"

typedef struct dds_cli dds_cli;

struct dds_cli {
	int running;

	nftp_vec       *handleq;
	pthread_mutex_t mtx;

	char *ddssend_topic;
	char *ddsrecv_topic;
};

int publisher (int argc, char ** argv);
int subscriber (int argc, char ** argv);
int dds_proxy (int argc, char ** argv);

int dds2mqtt (int argc, char ** argv);

#endif

#endif
