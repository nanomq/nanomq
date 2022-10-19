#ifndef NANOMQ_CONF_API_H
#define NANOMQ_CONF_API_H

#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "rest_api.h"

extern cJSON *basic_config(conf *config);
extern cJSON *tls_config(conf_tls *tls, bool is_server);
extern cJSON *auth_config(conf_auth *auth);
extern cJSON *auth_http_config(conf_auth_http *auth_http);
extern cJSON *websocker_config(conf_websocket *ws);
extern cJSON *http_config(conf_http_server *http);
extern cJSON *sqlite_config(conf_sqlite *sqlite);
extern cJSON *bridge_config(conf_bridge *bridge);

#endif
