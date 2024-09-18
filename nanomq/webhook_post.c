//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/webhook_post.h"
#include "include/pub_handler.h"

#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/canstream.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/exchange/exchange.h"

#ifdef SUPP_PARQUET
#include "nng/supplemental/nanolib/parquet.h"
#endif
#ifdef SUPP_BLF
#include "nng/supplemental/nanolib/blf.h"
#endif

#include "nng/exchange/stream/stream.h"

static bool event_filter(conf_web_hook *hook_conf, webhook_event event);
static bool event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic);
static void         set_char(char *out, unsigned int *index, char c);
static unsigned int base62_encode(
    const unsigned char *in, unsigned int inlen, char *out);

#ifdef SUPP_PARQUET
static int flush_smsg_to_disk(nng_msg **smsg, size_t len, nng_aio *aio, char *topic, uint8_t streamType);
#endif

#define BASE62_ENCODE_OUT_SIZE(s) ((unsigned int) ((((s) * 8) / 6) + 2))

static bool
event_filter(conf_web_hook *hook_conf, webhook_event event)
{
	for (uint16_t i = 0; i < hook_conf->rule_count; i++) {
		if (hook_conf->rules[i]->event == event) {
			return true;
		}
	}

	return false;
}

static bool
event_filter_with_topic(
    conf_web_hook *hook_conf, webhook_event event, const char *topic)
{
	for (uint16_t i = 0; i < hook_conf->rule_count; i++) {
		if (hook_conf->rules[i]->event == event) {
			if (hook_conf->rules[i]->topic != NULL) {
				if (!topic_filter(
				        hook_conf->rules[i]->topic, topic)) {
					continue;
				}
			}
			return true;
		}
	}

	return false;
}

static void
set_char(char *out, unsigned int *index, char c)
{
	unsigned int idx = *index;
	switch (c) {
	case 'i':
		out[idx++] = 'i';
		// out[idx++] = 'a';
		break;
	case '+':
		// out[idx++] = 'i';
		// out[idx++] = 'b';
		out[idx++] = 'A';
		break;
	case '/':
		// out[idx++] = 'i';
		// out[idx++] = 'c';
		out[idx++] = 'B';
		break;
	default:
		out[idx++] = c;
		break;
	}

	*index = idx;
}

static unsigned int
base62_encode(const unsigned char *in, unsigned int inlen, char *out)
{
	unsigned int i;
	unsigned int j;
	unsigned int pos = 0, val = 0;
	const char   base62en[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (i = j = 0; i < inlen; i++) {
		val = (val << 8) | (in[i] & 0xFF);
		pos += 8;
		while (pos > 5) {
			char c = base62en[val >> (pos -= 6)];
			set_char(out, &j, c);
			val &= ((1 << pos) - 1);
		}
	}
	if (pos > 0) {
		char c = base62en[val << (6 - pos)];
		set_char(out, &j, c);
	}
	return j;
}

int
webhook_msg_publish(nng_socket *sock, conf_web_hook *hook_conf,
    pub_packet_struct *pub_packet, const char *username, const char *client_id)
{
	if (!hook_conf->enable ||
	    !event_filter_with_topic(hook_conf, MESSAGE_PUBLISH,
	        pub_packet->var_header.publish.topic_name.body)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();

	cJSON_AddNumberToObject(obj, "ts", nng_timestamp());
	cJSON_AddStringToObject(
	    obj, "topic", pub_packet->var_header.publish.topic_name.body);
	cJSON_AddBoolToObject(obj, "retain", pub_packet->fixed_header.retain);
	cJSON_AddNumberToObject(obj, "qos", pub_packet->fixed_header.qos);
	cJSON_AddStringToObject(obj, "action", "message_publish");
	cJSON_AddStringToObject(
	    obj, "from_username", username == NULL ? "undefined" : username);
	if (client_id) {
		cJSON_AddStringToObject(obj, "from_client_id", client_id);
	} else {
		cJSON_AddNullToObject(obj, "from_client_id");
	}
	size_t out_size = 0;
	char  *encode   = NULL;
	size_t len      = 0;
	switch (hook_conf->encode_payload) {
	case plain:
		cJSON_AddStringToObject(
		    obj, "payload", (const char *) pub_packet->payload.data);
		break;
	case base64:
		out_size = BASE64_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base64_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;
	case base62:
		out_size = BASE62_ENCODE_OUT_SIZE(pub_packet->payload.len);
		encode   = nng_zalloc(out_size);
		len      = base62_encode(
		         pub_packet->payload.data, pub_packet->payload.len, encode);
		if (len > 0) {
			cJSON_AddStringToObject(obj, "payload", encode);
		} else {
			cJSON_AddNullToObject(obj, "payload");
		}
		nng_strfree(encode);
		break;

	default:
		break;
	}

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

int
webhook_client_connack(nng_socket *sock, conf_web_hook *hook_conf,
    uint8_t proto_ver, uint16_t keepalive, uint8_t reason,
    const char *username, const char *client_id)
{
	if (!hook_conf->enable || !event_filter(hook_conf, CLIENT_CONNACK)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();

	cJSON_AddNumberToObject(obj, "proto_ver", proto_ver);
	cJSON_AddNumberToObject(obj, "keepalive", keepalive);
	// TODO get reason string
	cJSON_AddStringToObject(
	    obj, "conn_ack", reason == SUCCESS ? "success" : "fail");
	cJSON_AddStringToObject(
	    obj, "username", username == NULL ? "undefined" : username);
	cJSON_AddStringToObject(obj, "clientid", client_id);
	cJSON_AddStringToObject(obj, "action", "client_connack");

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

int
webhook_client_disconnect(nng_socket *sock, conf_web_hook *hook_conf,
    uint8_t proto_ver, uint16_t keepalive, uint8_t reason,
    const char *username, const char *client_id)
{
	if (!hook_conf->enable ||
	    !event_filter(hook_conf, CLIENT_DISCONNECTED)) {
		return -1;
	}

	cJSON *obj = cJSON_CreateObject();
	// TODO get reason string
	cJSON_AddStringToObject(
	    obj, "reason", reason == SUCCESS ? "normal" : "abnormal");
	cJSON_AddStringToObject(
	    obj, "username", username == NULL ? "undefined" : username);
	cJSON_AddStringToObject(obj, "clientid", client_id);
	cJSON_AddStringToObject(obj, "action", "client_disconnected");

	char *json = cJSON_PrintUnformatted(obj);

	int rv = nng_send(*sock, json, strlen(json), NNG_FLAG_NONBLOCK);

	nng_strfree(json);
	cJSON_Delete(obj);

	return rv;
}

static inline uint64_t
gen_hash_nearby_key(char *clientid, char *topic, uint32_t pid)
{
	uint64_t res = 0;
	char buf[11]; // should be enough put a u32
	sprintf(buf, "%d", pid);

	char buf2[100]; // should be enough put the clienid and topic and pid
	sprintf(buf2, "%s%s%s", clientid, topic, buf);

	uint32_t key32 = DJBHash(buf2);
	res = key32; res = res << 32; res += key32;
	// log_info("%s - %s - %s => %lx %llx", clientid, topic, buf, key32, res);
	// nng_time ts = nng_timestamp();
	return res;
}

static uint32_t g_inc_id = 0;

inline int
hook_entry(nano_work *work, uint8_t reason)
{
	int            rv        = 0;
	conf_web_hook *hook_conf = &work->config->web_hook;
	conf_exchange *ex_conf   = &work->config->exchange;
	conn_param    *cparam    = work->cparam;
	nng_socket    *sock      = &work->hook_sock;
	nng_socket    *ex_sock;
	conf_parquet  *parquetconf = &work->config->parquet;
	conf_blf      *blfconf     = &work->config->blf;

	// process MQ msg first, only pub msg is valid
	// discard online/offline event msg?
	if (ex_conf->count > 0 && parquetconf->enable == true
		&& (work->flag == CMD_PUBLISH)
		&& nng_msg_get_type(work->msg) == CMD_PUBLISH) {
		// dup msg for now, TODO or reuse it?
		nng_msg *msg;
		nng_msg_alloc(&msg, 0);
		nng_msg_header_append(msg, nng_msg_header(work->msg), nng_msg_header_len(work->msg));
		nng_msg_append(msg, nng_msg_body(work->msg), nng_msg_len(work->msg));

		uint8_t *body_ptr = nng_msg_body(work->msg);
		ptrdiff_t offset = (ptrdiff_t)(nng_msg_payload_ptr(work->msg) - body_ptr);
		nng_msg_set_payload_ptr(msg, (uint8_t *)nng_msg_body(msg) + offset);

		/*
		// cparam has cloned at outside of hook_entry
		char *clientid = (char *)conn_param_get_clientid(work->cparam);
		if (clientid == NULL)
			goto done;
		char *topic = work->pub_packet->var_header.publish.topic_name.body;
		if (topic == NULL)
			goto done;
		nng_mtx_lock(hook_conf->ex_mtx);
		uint32_t pid = g_inc_id ++;
		nng_mtx_unlock(hook_conf->ex_mtx);

		nng_time ts = (nng_time)gen_hash_nearby_key(clientid, topic, pid);
		*/
		nng_time ts = nng_timestamp();
		nng_msg_set_timestamp(msg, ts);

		for (size_t i = 0; i < ex_conf->count; i++) {
			if (topic_filter(ex_conf->nodes[i]->topic,
			        work->pub_packet->var_header.publish.topic_name.body)) {

				if (work->proto != PROTO_MQTT_BROKER)
					log_error("Ctx %d type %d", work->ctx.id, work->proto);	// shall be a bug if triggered

				nng_aio *aio = hook_conf->saios[work->ctx.id- 1 - work->config->http_server.parallel];		// 6
				nng_aio_wait(aio);

				nng_msg_clone(msg);
				nng_aio_set_msg(aio, msg);

				ex_sock = ex_conf->nodes[i]->sock;
				nng_send_aio(*ex_sock, aio);
				break;
			}
		}
		nng_msg_free(msg); // Cloned for each exchange before
	}


	if (ex_conf->count > 0 && blfconf->enable == true
		&& (work->flag == CMD_PUBLISH)
		&& nng_msg_get_type(work->msg) == CMD_PUBLISH) {
		// dup msg for now, TODO or reuse it?
		nng_msg *msg;
		nng_msg_alloc(&msg, 0);
		nng_msg_header_append(msg, nng_msg_header(work->msg), nng_msg_header_len(work->msg));
		nng_msg_append(msg, nng_msg_body(work->msg), nng_msg_len(work->msg));

		uint8_t *body_ptr = nng_msg_body(work->msg);
		ptrdiff_t offset = (ptrdiff_t)(nng_msg_payload_ptr(work->msg) - body_ptr);
		nng_msg_set_payload_ptr(msg, (uint8_t *)nng_msg_body(msg) + offset);

		// cparam has cloned at outside of hook_entry
		char *clientid = (char *)conn_param_get_clientid(work->cparam);
		if (clientid == NULL)
			goto done;
		char *topic = work->pub_packet->var_header.publish.topic_name.body;
		if (topic == NULL)
			goto done;
		nng_mtx_lock(hook_conf->ex_mtx);
		uint32_t pid = g_inc_id ++;
		nng_mtx_unlock(hook_conf->ex_mtx);

		nng_time ts = (nng_time)gen_hash_nearby_key(clientid, topic, pid);
		nng_msg_set_timestamp(msg, ts);

		for (size_t i = 0; i < ex_conf->count; i++) {
			if (topic_filter(ex_conf->nodes[i]->topic,
			        work->pub_packet->var_header.publish.topic_name.body)) {

				if (work->ctx.id > work->config->parallel)
					log_error("parallel %d idx %d", work->config->parallel);	// shall be a bug if triggered

				nng_aio *aio = hook_conf->saios[work->ctx.id-1];
				nng_aio_wait(aio);

				nng_msg_clone(msg);
				nng_aio_set_msg(aio, msg);

				ex_sock = ex_conf->nodes[i]->sock;
				nng_send_aio(*ex_sock, aio);
				break;
			}
		}
		nng_msg_free(msg); // Cloned for each exchange before
	}


	if (!hook_conf->enable)
		return 0;
	switch (work->flag) {
	case CMD_CONNACK:
		rv = webhook_client_connack(sock, hook_conf,
		    conn_param_get_protover(cparam),
		    conn_param_get_keepalive(cparam), reason,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
		break;
	case CMD_PUBLISH:
		rv = webhook_msg_publish(sock, hook_conf, work->pub_packet,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
		break;
	case CMD_DISCONNECT_EV:
		rv = webhook_client_disconnect(sock, hook_conf,
		    conn_param_get_protover(cparam),
		    conn_param_get_keepalive(cparam), reason,
		    (const char*)conn_param_get_username(cparam),
		    (const char*)conn_param_get_clientid(cparam));
	case CMD_SUBSCRIBE:
		break;
	case CMD_UNSUBSCRIBE:
		break;
	default:
		break;
	}

done:
	// Do not let online event msg trigger webhook
	work->flag = 0;
	return rv;
}

struct cb_data {
	nng_msg **smsg;
	size_t len;
	struct stream_data_in *sdata;
};

static struct stream_data_in *stream_data_in_init(size_t len, nng_msg **smsg)
{
	struct stream_data_in *sdata = nng_alloc(sizeof(struct stream_data_in));
	if (sdata == NULL) {
		return NULL;
	}

	sdata->datas = nng_alloc(sizeof(void *) * len);
	if (sdata->datas == NULL) {
		nng_free(sdata, sizeof(struct stream_data_in));
		return NULL;
	}

	sdata->keys = nng_alloc(sizeof(uint64_t) * len);
	if (sdata->keys == NULL) {
		nng_free(sdata->datas, sizeof(void *) * len);
		nng_free(sdata, sizeof(struct stream_data_in));
		return NULL;
	}

	sdata->lens = nng_alloc(sizeof(uint32_t) * len);
	if (sdata->lens == NULL) {
		nng_free(sdata->datas, sizeof(void *) * len);
		nng_free(sdata->keys, sizeof(uint64_t) * len);
		nng_free(sdata, sizeof(struct stream_data_in));
		return NULL;
	}

	size_t len2 = 0;
	for (size_t i = 0; i < len; i++) {
		if (smsg[i] == NULL) {
			continue;
		}
		sdata->datas[len2] = nng_msg_payload_ptr(smsg[i]);
		sdata->lens[len2] = nng_msg_len(smsg[i]) - (nng_msg_payload_ptr(smsg[i]) - (uint8_t *)nng_msg_body(smsg[i]));
		sdata->keys[len2] = nng_msg_get_timestamp(smsg[i]);
		len2++;
	}

	sdata->len = len2;

	return sdata;
}

static struct cb_data *cb_data_init(nng_msg **smsg, size_t len)
{
	struct cb_data *cb_data = nng_alloc(sizeof(struct cb_data));
	if (cb_data == NULL) {
		return NULL;
	}

	cb_data->smsg = smsg;
	cb_data->len = len;
	cb_data->sdata = stream_data_in_init(len, smsg);
	if (cb_data->sdata == NULL) {
		nng_free(cb_data, sizeof(struct cb_data));
		return NULL;
	}

	return cb_data;
}

static void smsg_free(nng_msg **smsg, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (smsg[i] != NULL) {
			nng_msg_free(smsg[i]);
		}
	}

	nng_free(smsg, len);

	return;
}

static void cb_data_free(struct cb_data *cb_data)
{
	if (cb_data == NULL) {
		return;
	}

	if (cb_data->sdata != NULL) {
		stream_data_in_free(cb_data->sdata);
	}

	smsg_free(cb_data->smsg, cb_data->len);

	nng_free(cb_data, sizeof(struct cb_data));

	return;
}

#ifdef SUPP_PARQUET
static int
flush_smsg_to_disk(nng_msg **smsg,
				   size_t len,
				   nng_aio *aio,
				   char *topic,
				   uint8_t streamType)
{
	struct cb_data *cb_data = NULL;
	void *encoded_stream_data = NULL;

	if (nng_aio_busy(aio)) {
		smsg_free(smsg, len);
		log_warn("flush aio is busy");
		return NNG_EBUSY;
	}

	cb_data = cb_data_init(smsg, len);
	if (cb_data == NULL) {
		smsg_free(smsg, len);
		log_error("cb_data_init failed");
		return NNG_ENOMEM;
	}


	encoded_stream_data = stream_encode(streamType, cb_data->sdata);
	if (encoded_stream_data == NULL) {
		log_error("encode encoded_stream_data failed");
		cb_data_free(cb_data);
		return NNG_EINVAL;
	}

	parquet_object *parquet_obj = NULL;
	parquet_obj = parquet_object_alloc(encoded_stream_data, WRITE_RAW, aio, (void *)cb_data, topic);
	if (parquet_obj == NULL) {
		log_error("parquet_object_alloc failed");
		cb_data_free(cb_data);
		return NNG_ENOMEM;
	}

	parquet_write_batch_async(parquet_obj);

	return 0;
}
#endif

static int inline get_flush_params(nng_aio *aio,
								   nng_msg *msg,
								   nng_msg ***pmsgs_del,
								   int **pmsgs_lenp,
								   char **ptopic,
								   uint8_t *pstreamType)
{
	uint8_t streamType = 0;
	char *topic = NULL;
	int *msgs_len = NULL;
	nng_msg **msgs_del = NULL;

	msgs_del = nng_aio_get_prov_data(aio);
	msgs_len = (int *)nng_msg_get_proto_data(msg);
	topic = nng_msg_get_conn_param(msg);
	streamType = nng_msg_get_cmd_type(msg);

	if (msgs_len == NULL || msgs_del == NULL || topic == NULL) {
		if (msgs_del != NULL) {
			if (msgs_len != NULL) {
				for (int i = 0; i < *msgs_len; ++i) {
					if (msgs_del[i] != NULL) {
						nng_msg_free(msgs_del[i]);
					}
				}
			}
			nng_free(msgs_del, sizeof(nng_msg *));
		}
		if (msgs_len != NULL) {
			nng_free(msgs_len, sizeof(int));
		}
		if (topic != NULL) {
			nng_free(topic, strlen(topic) + 1);
		}
		return NNG_EINVAL;
	}

	*ptopic = topic;
	*pmsgs_del = msgs_del;
	*pmsgs_lenp = msgs_len;
	*pstreamType = streamType;

	return 0;
}

static void
send_exchange_cb(void *arg)
{
	char *topic = NULL;
	int *msgs_lenp = NULL;
	uint8_t streamType = 0;
	nng_msg *msg = NULL;
	nng_msg **msgs_del = NULL;

	struct work *w = arg;
	int          rv;

	conf_web_hook *hook_conf = &w->config->web_hook;

	nng_aio *aio = hook_conf->saios[w->ctx.id- 1 - w->config->http_server.parallel];		// 6
	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("error %d in send to exchange", rv);
		return;
	}

	msg = nng_aio_get_msg(aio);
	if (msg == NULL) {
		return;
	}

#ifndef SUPP_PARQUET
	log_error("ENABLE_PARQUET is not defined flush to disk failed");
	return;
#endif

	rv = get_flush_params(aio, msg, &msgs_del, &msgs_lenp, &topic, &streamType);
	if (rv != 0) {
		log_error("get_flush_params error %d", rv);
		return;
	}

	// Flush to disk.
	if (w->config->parquet.enable || w->config->blf.enable) {
		nng_mtx_lock(hook_conf->ex_mtx);
#ifdef SUPP_PARQUET
		rv = flush_smsg_to_disk(msgs_del, *msgs_lenp, hook_conf->ex_aio, topic, streamType);
		if (rv != 0) {
			log_error("flush error %d", rv);
		}
#endif
		nng_mtx_unlock(hook_conf->ex_mtx);
	} else {
		for (int i = 0; i < *msgs_lenp; ++i)
			if (msgs_del[i]) {
				nng_msg_free(msgs_del[i]);
			}
		nng_free(msgs_del, *msgs_lenp);
	}

	nng_msg_free(msg);
	nng_free(msgs_lenp, sizeof(int));
}

// Better to be done in sync
static void
send_parquet_cb(void *arg)
{
	conf_web_hook *hook_conf = arg;
	nng_aio *aio = hook_conf->ex_aio;

	struct cb_data *cb_data = (struct cb_data *)nng_aio_get_prov_data(aio);
	if (cb_data == NULL) {
		log_error("cb_data is NULL");
		return;
	}

	cb_data_free(cb_data);

	if (nng_aio_result(aio) != 0) {
		log_warn("Write data to parquet failed");
		return;
	}

	return;
}

int
hook_exchange_init(conf *nanomq_conf, uint64_t num_ctx)
{
	conf_web_hook *hook_conf = &nanomq_conf->web_hook;

	nng_mtx_alloc(&hook_conf->ex_mtx);
	nng_aio_alloc(&hook_conf->ex_aio, send_parquet_cb, hook_conf);
	hook_conf->saios = nng_alloc(sizeof(nng_aio *) * num_ctx);

	return 0;
}

int
hook_exchange_sender_init(conf *nanomq_conf, struct work **works, uint64_t num_ctx)
{
	conf_web_hook *hook_conf = &nanomq_conf->web_hook;
	conf_parquet *parquet_conf = &nanomq_conf->parquet;
	conf_blf *blf_conf = &nanomq_conf->blf;

	for (int i = 0; i < num_ctx; ++i) {
		nng_aio_alloc(
		    &hook_conf->saios[i], send_exchange_cb, works[i]);
	}

#ifdef SUPP_PARQUET
	if (parquet_conf->enable) {
		log_info("init parquet_write_launcher");
		parquet_write_launcher(parquet_conf);
	}
#endif

#ifdef SUPP_BLF
	if (blf_conf->enable) {
		log_info("init blf_write_launcher");
		blf_write_launcher(blf_conf);
	}
#endif

	return 0;
}

