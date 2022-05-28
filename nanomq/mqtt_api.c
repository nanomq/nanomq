//
// Copyright 2022 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <nng.h>
#include "mqtt_api.h"

/**
 * @brief create listener for MQTT and start listen
 * 
 * @param sid 
 * @param addr 
 * @param lp 
 * @param flags 
 * @return int 
 */
int
nano_listen(
    nng_socket sid, const char *addr, nng_listener *lp, int flags, conf *conf)
{
	int           rv;
	nng_listener  l;

        nng_listener_create(&l, sid, addr);
        nng_listener_setopt(l, NANO_CONF, conf, sizeof(conf));
	if ((rv = nng_listener_start(l, 0)) != 0) {
		nng_listener_close(l);
		return (rv);
	}

	if (lp != NULL) {
		nng_listener lid;
		lid.id = nng_listener_id(l);
		*lp    = lid;
	}
	return (rv);
}

int
init_listener_tls(nng_listener l, conf_tls *tls)
{
	nng_tls_config *cfg;
	int             rv;

	enum nng_tls_auth_mode mode = NNG_TLS_AUTH_MODE_NONE;

	if ((rv = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER)) != 0) {
		return (rv);
	}

	if (tls->verify_peer) {
		if (tls->set_fail) {
			mode = NNG_TLS_AUTH_MODE_REQUIRED;
		} else {
			mode = NNG_TLS_AUTH_MODE_OPTIONAL;
		}
	}

	rv = nng_tls_config_auth_mode(cfg, mode);

	if ((rv == 0) && tls->cert != NULL) {
		char *cert;
		char *key;

		if ((rv = nng_tls_config_own_cert(cfg, tls->cert,
		         tls->key ? tls->key : tls->cert,
		         tls->key_password)) != 0) {
			goto out;
		}
	}

	if ((rv == 0) && (tls->ca != NULL)) {
		if ((rv = nng_tls_config_ca_chain(cfg, tls->ca, NULL)) != 0) {
			goto out;
		}
	}

	rv = nng_listener_set_ptr(l, NNG_OPT_TLS_CONFIG, cfg);

out:
	nng_tls_config_free(cfg);
	return (rv);
}