//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifdef NANO_PLATFORM_WINDOWS
#include <winsock.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include "mqtt_api.h"
#include "nanomq.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/file.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/nng.h"

#if defined(SUPP_SYSLOG)
#include <syslog.h>
#endif

/**
 * @brief create listener for MQTT
 * and start listen
 *
 * @param sid
 * @param addr
 * @param lp
 * @param flags
 * @return int
 */
int
nano_listen(nng_socket sid, const char *addr, nng_listener *lp, int flags,
    conf *config)
{
	int          rv;
	nng_listener l;

	nng_listener_create(&l, sid, addr);
	nng_listener_set(l, NANO_CONF, config, sizeof(conf));
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

static conn_param *
create_cparam(const char *clientid, uint8_t proto_ver)
{
	conn_param *cparam;
	conn_param_alloc(&cparam);
	conn_param_set_clientid(cparam, clientid);
	conn_param_set_proto_ver(cparam, proto_ver);
	return cparam;
}

/**
 * Pair with encode_common_mqtt_msg
*/
int
decode_common_mqtt_msg(nng_msg **dest, nng_msg *src)
{
	nng_msg *msg;
	int      rv = nng_mqtt_msg_alloc(&msg, 0);
	if (rv != 0) {
		nng_msg_free(src);
		return rv;
	}
	uint8_t *ptr        = nng_msg_body(src);
	uint32_t header_len = 0;
	NNI_GET32(ptr, header_len);
	ptr += 4;
	nng_msg_header_append(msg, ptr, header_len);
	ptr += header_len;
	uint32_t body_len = 0;
	NNI_GET32(ptr, body_len);
	ptr += 4;
	nng_msg_append(msg, ptr, body_len);
	ptr += body_len;

	uint32_t clientid_sz = 0;
	NNI_GET32(ptr, clientid_sz);
	ptr += 4;
	char *clientid = nng_zalloc(clientid_sz + 1);
	memcpy(clientid, ptr, clientid_sz);
	ptr += clientid_sz;
	uint8_t proto_ver = *(uint8_t *) ptr;

	conn_param *cparam = create_cparam(clientid, proto_ver);
	nng_free(clientid, clientid_sz + 1);

	if (proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		nng_mqttv5_msg_decode(msg);
	} else {
		nng_mqtt_msg_decode(msg);
	}

	nng_msg_set_conn_param(msg, cparam);

	nng_msg_free(src);
	*dest = msg;
	return 0;
}

int
encode_common_mqtt_msg(
    nng_msg **dest, nng_msg *src, const char *clientid, uint8_t proto_ver)
{
	if (proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		nng_mqttv5_msg_encode(src);
	} else {
		nng_mqtt_msg_encode(src);
	}
	nng_msg *msg;

	size_t clientid_sz = strlen(clientid);

	int rv;
	if ((rv = nng_msg_alloc(&msg, 0)) != 0) {
		nng_msg_free(src);
		return rv;
	}

	nng_msg_append_u32(msg, nng_msg_header_len(src));
	nng_msg_append(msg, nng_msg_header(src), nng_msg_header_len(src));
	nng_msg_append_u32(msg, nng_msg_len(src));
	nng_msg_append(msg, nng_msg_body(src), nng_msg_len(src));
	nng_msg_append_u32(msg, clientid_sz);
	nng_msg_append(msg, clientid, clientid_sz);
	nng_msg_append(msg, &proto_ver, 1);
	*dest = msg;

	nng_msg_free(src);
	return 0;
}

static nng_mtx *log_file_mtx = NULL;

static int
log_file_init(conf_log *log)
{
	if (log->dir != NULL && !nng_file_is_dir(log->dir)) {
		if (nng_make_parent_dirs(log->dir) != 0){
			log_fatal("NanoMQ cannot touch path %s ", log->dir);
			return NNG_EINVAL;
		}
	}
#ifndef NANO_PLATFORM_WINDOWS
	if (nng_access(log->dir, W_OK) < 0) {
        log_fatal("Write %s failed, please check path\n", log->dir);
        return NNG_EINVAL;
    }
#endif
	log->dir   = log->dir == NULL ? nng_strdup("./") : log->dir;
	log->file  = log->file == NULL ? nng_strdup("nanomq.log") : log->file;
	char *path = nano_concat_path(log->dir, log->file);
	log->fp    = fopen(path, "a");
	if (log->fp == NULL) {
		log_fatal("open log file '%s' failed", path);
		nng_strfree(path);
		return NNG_EINVAL;
	}
	log->abs_path = path;
	return 0;
}

int
log_init(conf_log *log)
{
	int rv = 0;

	log_set_level(log->level);

	if (0 != (log->type & LOG_TO_CONSOLE)) {
		log_add_console(log->level, NULL);
	}

	if (0 != (log->type & LOG_TO_FILE)) {
		if (0 != (rv = log_file_init(log)) ||
		    0 != (rv = nng_mtx_alloc(&log_file_mtx))) {
			return rv;
		}
		log_add_fp(log->fp, log->level, log_file_mtx, log);
	}

#if defined(SUPP_SYSLOG)
	if (0 != (log->type & LOG_TO_SYSLOG)) {
		log_add_syslog("nng-nanomq", log->level, NULL);
	}
#endif

	return 0;
}

int
log_fini(conf_log *log)
{
	if (0 != (log->type & LOG_TO_FILE)) {
		nng_mtx_free(log_file_mtx);
	}

#if defined(SUPP_SYSLOG)
	if (0 != (log->type & LOG_TO_SYSLOG)) {
		closelog();
	}
#endif
	log_clear_callback();

	return 0;
}

char *
nano_pipe_get_local_address(nng_pipe p)
{
	int           rv;
	nng_sockaddr  addr;
	uint8_t      *arr;
	char         *res;

	rv = nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &addr);
	if (rv != 0)
		return NULL;

	arr = (uint8_t *)&addr.s_in.sa_addr;

	if ((res = malloc(sizeof(char) * 16)) == NULL)
		return NULL;

	sprintf(res, "%d.%d.%d.%d", arr[0], arr[1], arr[2], arr[3]);
	return res;
}

uint8_t *
nano_pipe_get_local_address6(nng_pipe p)
{
	int           rv;
	nng_sockaddr  addr;
	uint8_t      *arr;
	uint8_t      *res;

	rv = nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &addr);
	if (rv != 0)
		return NULL;

	arr = (uint8_t *) &addr.s_in6.sa_addr;

	if ((res = malloc(sizeof(uint8_t) * 16)) == NULL)
		return NULL;

	memcpy(res, arr, 16);

	return res;
}

uint16_t
nano_pipe_get_local_port(nng_pipe p)
{
	int           rv;
	nng_sockaddr  addr;

	rv = nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &addr);
	if (rv != 0)
		return 0;

	return htons(addr.s_in.sa_port);
}

uint16_t
nano_pipe_get_local_port6(nng_pipe p)
{
	int           rv;
	nng_sockaddr  addr;

	rv = nng_pipe_get_addr(p, NNG_OPT_LOCADDR, &addr);
	if (rv != 0)
		return 0;

	return htons(addr.s_in6.sa_port);
}

#if defined(SUPP_ICEORYX)

#include "nng/iceoryx_shm/iceoryx_shm.h"

bool
nano_iceoryx_topic_filter(char *icetopic, char *topic, uint32_t topicsz)
{
	if (topicsz == 0 || topic == NULL) {
		return false;
	}
	int icetopicsz = strlen(icetopic);
	if (icetopicsz != topicsz) {
		return false;
	}
	return (0 == strncmp(icetopic, topic, topicsz));
}

int
nano_iceoryx_send_nng_msg(nng_iceoryx_puber *puber, nng_msg *msg, nng_socket *sock)
{
	int      rv;
	nng_msg *icemsg;
	size_t   icehdrlen = nng_msg_header_len(msg);
	size_t   icelen = nng_msg_len(msg);
	uint8_t  icehdrbuf[1];
	uint8_t  icebuf[4];

	log_debug("iceoryx send a msg sz %d", icehdrlen + icelen + 5);
	rv = nng_msg_iceoryx_alloc(&icemsg, puber, (int)(icehdrlen + icelen + 5));
	if (rv != 0)
		return rv;

	// append header
	icehdrbuf[0] = (uint8_t)icehdrlen;
	nng_msg_iceoryx_append(icemsg, icehdrbuf, 1);
	nng_msg_iceoryx_append(icemsg, nng_msg_header(msg), icehdrlen);

	// append body
	NNI_PUT32(icebuf, icelen);
	nng_msg_iceoryx_append(icemsg, icebuf, 4);
	nng_msg_iceoryx_append(icemsg, nng_msg_body(msg), icelen);

	nng_aio *aio;
	nng_aio_alloc(&aio, NULL, NULL);
	nng_aio_set_prov_data(aio, puber);
	nng_aio_set_msg(aio, icemsg);
	nng_send_aio(*sock, aio);
	log_debug("iceoryx sending and wait");
	nng_aio_wait(aio);
	rv = nng_aio_result(aio);
	nng_aio_free(aio);

	return rv;
}

int
nano_iceoryx_recv_nng_msg(nng_iceoryx_suber *suber, nng_msg *icemsg, nng_msg **msgp)
{
	int      rv;
	nng_msg *msg;
	size_t   icehdrlen;
	size_t   icebodylen;
	uint8_t *icebuf;

	log_debug("iceoryx recving msg");

	rv = nng_mqtt_msg_alloc(&msg, 0);
	if (rv != 0)
		return rv;

	icebuf = nng_msg_payload_ptr(icemsg);
	// decode header
	icehdrlen = *(uint8_t *)icebuf;
	rv = nng_msg_header_append(msg, icebuf + 1, icehdrlen);
	if (rv != 0)
		return rv;

	// decode body
	NNI_GET32(icebuf + 1 + icehdrlen, icebodylen);
	rv = nng_msg_append(msg, icebuf + 1 + icehdrlen + 4, icebodylen);
	if (rv != 0)
		return rv;

	// Create a cparam ...
	conn_param *cparam = create_cparam("atestclientid", MQTT_PROTOCOL_VERSION_v311);
	nng_mqtt_msg_decode(msg);
	nng_msg_set_conn_param(msg, cparam);

	*msgp = msg;
	return 0;
}

#endif

