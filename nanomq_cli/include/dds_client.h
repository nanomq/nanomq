#ifndef DDS_PROXY_H
#define DDS_PROXY_H

#if defined(SUPP_DDS_PROXY)

#include <pthread.h>
#include <stdlib.h>

#include "vector.h"
#include "mqtt_client.h"
#include "idl_convert.h"

#include "dds/dds.h"

// #define DDS_TYPE_NAME_CAT1(A, B) A ## B
// #define DDS_TYPE_NAME_CAT(A, B) DDS_TYPE_NAME_CAT1(A, B)

// #define DDS_TYPE_NAME_FREE1(x, y) do {\
// 	DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, _free)(x, y); \
// } while (0)
// #define DDS_TYPE_NAME_FREE(x, y) DDS_TYPE_NAME_FREE1(x, y)
// #define DDS_TYPE_NAME_ALLOC() DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, __alloc())
// #define DDS_TYPE_NAME_DESC() DDS_TYPE_NAME_CAT(DDS_TYPE_NAME, _desc)

// #define DDS_DATA_FREE(name, func) DDS_TYPE_NAME_FREE(name, func)
// #define DDS_DATA_ALLOC(name) DDS_TYPE_NAME_CAT(name, __alloc())
// #define DDS_DATA_DESC(name) DDS_TYPE_NAME_CAT(name, _desc())

// There is only one dds client. But we need to create more than
// one dds readers and writers thus we could forward msgs to different
// dds topic. Here we named those reader and writer dds_subcli.

typedef struct dds_cli dds_cli;
typedef struct dds_subcli dds_subcli;

struct dds_cli {
	dds_subcli    **subrdclis;
	size_t          nsubrdclis;
	dds_subcli    **subwrclis;
	size_t          nsubwrclis;

	nftp_vec *      handleq;
	pthread_mutex_t mtx;
	pthread_cond_t  cv;

	dds_gateway_conf *config;
};

struct dds_subcli {
	dds_entity_t    scli;

	char *ddssend_topic;
	char *ddsrecv_topic;

	dds_handler_set *handles;

	dds_gateway_conf *config;
};

int dds_publisher (int argc, char ** argv);
int dds_subscriber (int argc, char ** argv);
int dds_proxy_start (int argc, char ** argv);

#endif

#endif
