#ifndef DDS2MQTT_MQTT_CLIENT
#define DDS2MQTT_MQTT_CLIENT

#include <pthread.h>

#include "vector.h"

#include <nng/mqtt/mqtt_client.h>
#include <nng/nng.h>

#define HANDLE_TO_DDS 1
#define HANDLE_TO_MQTT 2

typedef struct handle handle;
struct handle {
	int   type; // 1->To dds network 2->To mqtt network
	void *data;
	int   len;
};

handle *mk_handle(int type, void *data, int len);

typedef struct mqtt_cli mqtt_cli;

struct mqtt_cli {
	nng_socket sock;
	int        verbose;
	char      *url;
	pthread_t  thr;
	int        running;

	nftp_vec       *handleq;
	pthread_mutex_t mtx;

	// dds client
	void *ddscli;

	char *mqttrecv_topic;
	char *mqttsend_topic;
};

int mqtt_connect(mqtt_cli *cli, const char *url, void *ddscli);

int mqtt_disconnect(mqtt_cli *cli);

int mqtt_subscribe(mqtt_cli *cli, const char *topic, const uint8_t qos);

// Not supported yet
int mqtt_unsubscribe(mqtt_cli *cli, const char *topic);

int mqtt_publish(
    mqtt_cli *cli, const char *topic, uint8_t qos, uint8_t *data, int len);

int mqtt_recvmsg(mqtt_cli *cli, nng_msg **msgp);

#endif
