#ifndef MQTT_API_H
#define MQTT_API_H

#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/tls/tls.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/util/platform.h"

#define INPROC_SERVER_URL "inproc://inproc_server"

int nano_listen(
    nng_socket sid, const char *addr, nng_listener *lp, int flags, conf *conf);
int init_listener_tls(nng_listener l, conf_tls *tls);

extern int decode_common_mqtt_msg(nng_msg **dest, nng_msg *src);
extern int encode_common_mqtt_msg(
    nng_msg **dest, nng_msg *src, const char *clientid, uint8_t proto_ver);

extern int log_init(conf_log *log);
extern int log_fini(conf_log *log);

#endif // MQTT_API_H