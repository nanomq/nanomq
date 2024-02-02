#ifndef DDS2MQTT_MQTT_CLIENT
#define DDS2MQTT_MQTT_CLIENT

#if defined(SUPP_DDS_PROXY)

#include <pthread.h>

#include "vector.h"

#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"

#define HANDLE_TO_DDS 1
#define HANDLE_TO_MQTT 2

typedef struct handle handle;
struct handle {
	int   type; // 1->To dds network 2->To mqtt network
	void *data;
	int   len;
	char *topic; // DDS topic or MQTT topic, Source topic
};

handle *mk_handle(int type, void *data, int len, char *topic);

typedef struct mqtt_cli mqtt_cli;

struct mqtt_cli {
	nng_socket sock;
	int        verbose;
	char      *url;
	pthread_t  thr;
	int        running;

	nftp_vec       *handleq;
	pthread_mutex_t mtx;
	pthread_cond_t  cv;

	// dds client
	void *ddscli;
	nng_mqtt_client *client;

	dds_gateway_conf *config;
};

int mqtt_connect(mqtt_cli *cli, void *ddscli, dds_gateway_conf *config);

int mqtt_disconnect(mqtt_cli *cli);

int mqtt_subscribe(mqtt_cli *cli);

// Not supported yet
int mqtt_unsubscribe(mqtt_cli *cli, const char *topic);

int mqtt_publish(
    mqtt_cli *cli, const char *topic, uint8_t qos, uint8_t *data, int len);

int mqtt_recvmsg(mqtt_cli *cli, nng_msg **msgp);

// Return not just topic but also the struct_name
dds_gateway_topic *find_dds_topic(dds_gateway_conf *conf, const char *mqtttopic);
dds_gateway_topic *find_mqtt_topic(dds_gateway_conf *conf, const char *ddstopic);

#endif

#endif
