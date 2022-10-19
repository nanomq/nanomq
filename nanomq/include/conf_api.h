#ifndef NANOMQ_CONF_API_H
#define NANOMQ_CONF_API_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "rest_api.h"

extern cJSON *get_basic_config(conf *config);
extern cJSON *get_tls_config(conf_tls *tls, bool is_server);
extern cJSON *get_auth_config(conf_auth *auth);
extern cJSON *get_auth_http_config(conf_auth_http *auth_http);
extern cJSON *get_websocker_config(conf_websocket *ws);
extern cJSON *get_http_config(conf_http_server *http);
extern cJSON *get_sqlite_config(conf_sqlite *sqlite);
extern cJSON *get_bridge_config(conf_bridge *bridge);

#endif
