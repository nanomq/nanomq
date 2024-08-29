//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <string.h>

#if defined(SUPP_MYSQL)
#include <mysql.h>
#endif

#if defined(SUPP_POSTGRESQL) || defined (SUPP_TIMESCALEDB)
#include <libpq-fe.h>
#endif


#include "include/nanomq.h"
#include "nng/nng.h"
#include "nng/mqtt/packet.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/mqtt_db.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "include/nanomq_rule.h"
#include "include/bridge.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "include/acl_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/sqlite/sqlite3.h"
#include "nng/supplemental/nanolib/log.h"

#if defined(SUPP_PLUGIN)
	#include "include/plugin.h"
#endif

#define ENABLE_RETAIN 1
#define SUPPORT_MQTT5_0 1

#ifdef STATISTICS
typedef struct {
	bool            initialed;
	nng_atomic_u64 *msg_in;
	nng_atomic_u64 *msg_out;
	nng_atomic_u64 *msg_drop;
} msg_statistics;

static msg_statistics g_msg = { .initialed = false };

static void
msg_statistics_init(msg_statistics *m)
{
	nng_atomic_alloc64(&m->msg_in);
	nng_atomic_alloc64(&m->msg_out);
	nng_atomic_alloc64(&m->msg_drop);
	m->initialed = true;
}

uint64_t
nanomq_get_message_in()
{
	return g_msg.initialed ? nng_atomic_get64(g_msg.msg_in) : 0;
}

uint64_t
nanomq_get_message_out()
{
	return g_msg.initialed ? nng_atomic_get64(g_msg.msg_out) : 0;
}

uint64_t
nanomq_get_message_drop()
{
	return g_msg.initialed ? nng_atomic_get64(g_msg.msg_drop) : 0;
}

#endif

static char *bytes_to_str(const unsigned char *src, char *dest, int src_len);
static void  print_hex(
     const char *prefix, const unsigned char *src, int src_len);
static uint32_t append_bytes_with_type(
    nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len);
static void inline handle_pub_retain(const nano_work *work, char *topic);

void
init_pipe_content(struct pipe_content *pipe_ct)
{
	log_debug("pub_handler: init pipe_info");
	pipe_ct->msg_infos     = NULL;
}

static void
foreach_client(
    uint32_t *cli_ctx_list, nano_work *pub_work, struct pipe_content *pipe_ct)
{
	uint32_t pids;
	int      ctx_list_len;

	ctx_list_len = cvector_size(cli_ctx_list);

	// Dont using msg info buf, Just for Cheat Compiler
	mqtt_msg_info *msg_info     = NULL;
	mqtt_msg_info  msg_info_buf = { 0 };

	cvector(mqtt_msg_info) msg_infos = pipe_ct->msg_infos;
	cvector_grow(msg_infos, ctx_list_len);

	for (int i = 0; i < ctx_list_len; i++) {
		pids = cli_ctx_list[i];

#ifdef STATISTICS
		// TODO
		// nng_atomic_inc64(ctx->recv_cnt);
		nng_atomic_inc64(g_msg.msg_out);
#endif
		if (pids == 0) {
			continue;
		}

		// TODO using pid instead of msg_info
		cvector_push_back(msg_infos, msg_info_buf);
		size_t csize = cvector_size(msg_infos);
		msg_info     = (mqtt_msg_info *) &msg_infos[csize - 1];

		msg_info->pipe = pids;
	}
	pipe_ct->msg_infos = msg_infos;
}

#if defined(SUPP_RULE_ENGINE)
static bool
cmp_int(int value_checked, int value_seted, rule_cmp_type type)
{
	bool filter = true;
	switch (type)
	{
	case RULE_CMP_EQUAL:
		if (value_checked != value_seted) {
			filter = false;
		}
		break;
	case RULE_CMP_UNEQUAL:
		if (value_checked == value_seted) {
			filter = false;
		}
		break;

	case RULE_CMP_GREATER:
		if (value_checked <= value_seted) {
			filter = false;
		}
		break;
	case RULE_CMP_LESS:
		if (value_checked >= value_seted) {
			filter = false;
		}
		break;
	case RULE_CMP_GREATER_AND_EQUAL:
		if (value_checked < value_seted) {
			filter = false;
		}
		break;
	case RULE_CMP_LESS_AND_EQUAL:
		if (value_checked > value_seted) {
			filter = false;
		}
		break;
	
	default:
		break;
	}
	return filter;
}

static bool
cmp_str(
    const char *value_checked, int len, char *value_seted, rule_cmp_type type)
{
	if (value_checked == NULL) {
		return false;
	}

	bool filter = true;
	switch (type) {
	case RULE_CMP_EQUAL:
		if (strncmp(value_checked, value_seted, len)) {
			filter = false;
		}
		break;
	case RULE_CMP_UNEQUAL:
		if (!strncmp(value_checked, value_seted, len)) {
			filter = false;
		}
		break;
	default:
		log_debug("Unsupport compare symbol, string only support equal "
		        "and unequal!");
		break;
	}
	return filter;
}

static bool
payload_filter(pub_packet_struct *pp, rule *info)
{
	bool   filter = true;
	cJSON *jp = cJSON_ParseWithLength(pp->payload.data, pp->payload.len);
	cJSON *jp_reset = jp;
	// info->payload size equal 0, implicit there is no
	// payload filter need to be check, so filter is true.
	for (int pi = 0; pi < cvector_size(info->payload); pi++) {
		jp                    = jp_reset; // reset jp;
		rule_payload *payload = info->payload[pi];
		for (int k = 0; k < cvector_size(payload->psa); k++) {
			if (jp == NULL) {
				filter = false;
				break;
			}
			jp = cJSON_GetObjectItem(jp, payload->psa[k]);
		}

		if (jp == NULL || filter == false) {
			filter = false;
			break;
		}

		switch (jp->type) {
		case cJSON_Number:;
			long num = cJSON_GetNumberValue(jp);

			if (payload->filter && !cmp_int(num, atoi(payload->filter), payload->cmp_type)) {
				filter = false;
			} else {
				payload->value = (void *) num;
				payload->type  = cJSON_Number;
			}
			break;
		case cJSON_String:;
			char *str = cJSON_GetStringValue(jp);
			if (payload->filter && !cmp_str(str, strlen(str), payload->filter, payload->cmp_type)) {
				filter = false;
			} else {
				if (payload->value)
					free(payload->value);
				payload->value = nng_strdup(str);
				payload->type  = cJSON_String;
			}
			break;
		case cJSON_Object:;
			cJSON *filter_obj = cJSON_Parse(payload->filter);
			if (!payload->is_store && filter_obj && !cJSON_Compare(jp, filter_obj, true)) {
				filter = false;
			} else {
				// if (payload->value)
				// 	cJSON_Delete((cJSON*) payload->value);
				payload->value = cJSON_Duplicate(jp, 1);
				payload->type  = cJSON_Object;
			}
			break;

		default:
			break;
		}
	}
	cJSON_Delete(jp_reset);


	return filter;
}

static bool
rule_engine_filter(nano_work *work, rule *info)
{
	pub_packet_struct *pp     = work->pub_packet;
	char	      *topic  = pp->var_header.publish.topic_name.body;
	conn_param        *cp     = work->cparam;
	bool               filter = true;
	if (RULE_FORWORD_REPUB == info->forword_type) {
		const char *cid = (const char *) conn_param_get_clientid(cp);
		if (info->repub->clientid && cmp_str(cid, strlen(cid), info->repub->clientid,
		        RULE_CMP_EQUAL)) {
			return false;
		}
	}

	if (topic_filter(info->topic, topic)) {
		if (info->filter) {
			for (size_t j = 0; j < 9; j++) {
				char *val = NULL;
				if (j < 8) {
					val = info->filter[j];
				}
				if (val != NULL || j == RULE_PAYLOAD_FIELD) {
					switch (j) {
					case RULE_QOS:
						filter = cmp_int(
						    pp->fixed_header.qos,
						    atoi(val),
						    info->cmp_type[j]);
						break;
					case RULE_ID:
						filter = cmp_int(
						    pp->var_header.publish
						        .packet_id,
						    atoi(val),
						    info->cmp_type[j]);
						break;
					case RULE_TOPIC:
						filter = cmp_str(topic,
						    strlen(topic), val,
						    info->cmp_type[j]);
						break;
					case RULE_CLIENTID:;
						const char *cid = (const char
						        *)
						    conn_param_get_clientid(
						        cp);
						filter = cmp_str(cid,
						    strlen(cid), val,
						    info->cmp_type[j]);

						break;
					case RULE_USERNAME:;
						const char *username =
						    (const char *)
						        conn_param_get_username(
						            cp);
						filter = cmp_str(username,
						    strlen(username), val,
						    info->cmp_type[j]);
						break;
					case RULE_PASSWORD:;
						const char *password =
						    (const char *)
						        conn_param_get_password(
						            cp);
						filter = cmp_str(password,
						    strlen(password), val,
						    info->cmp_type[j]);
						break;
					case RULE_TIMESTAMP:
						filter = cmp_int(
						    (unsigned long) time(NULL),
						    atoi(val),
						    info->cmp_type[j]);
						break;
					case RULE_PAYLOAD_ALL:
						if (!pp->payload.data ||
						    pp->payload.len <= 0) {
							filter = false;
							break;
						}

						if (val != NULL) {
							filter = cmp_str(
							    pp->payload.data,
							    pp->payload.len,
							    val,
							    info->cmp_type[j]);
						}

						break;
					case RULE_PAYLOAD_FIELD:
						if (!pp->payload.data ||
						    pp->payload.len <= 0) {
							filter = false;
							break;
						}

						filter =
						    payload_filter(pp, info);
						break;
					default:
						break;
					}
					if (filter == false) {
						break;
					}
				}
			}
		} else {
			if (!pp->payload.data || pp->payload.len <= 0) {
				filter = false;
			}

			payload_filter(pp, info);
			filter = true;
		}
	} else {
		// printf("MISMATCH filter: %s, topic: %s\n", info->topic,
		// topic);
		filter = false;
	}

	return filter;
}


static char*
generate_key(rule *info, int j, nano_work *work)
{
	pub_packet_struct *pp = work->pub_packet;
	conn_param        *cp = work->cparam;
	static uint32_t    index      = 0;

	if (UINT32_MAX == index) {
		index = 0;
	}

	char str[64] = { 0 };

	if (info->key->flag[j]) {
		switch (j) {
		case RULE_QOS:
			if (info->key->auto_inc) {
				sprintf(str, "%d%d", pp->fixed_header.qos, index++);
			} else {
				sprintf(str, "%d", pp->fixed_header.qos);
			}
			break;
		case RULE_ID:
			if (info->key->auto_inc) {
				sprintf(str, "%d%d", pp->var_header.publish.packet_id, index++);
			} else {
				sprintf(str, "%d", pp->var_header.publish.packet_id);
			}
			break;
		case RULE_TOPIC:;
			char *topic = pp->var_header.publish.topic_name.body;
			if (info->key->auto_inc) {
				sprintf(str, "%s%d", topic, index++);
			} else {
				sprintf(str, "%s", topic);
			}
			break;
		case RULE_CLIENTID:;
			char *cid = (char *) conn_param_get_clientid(cp);
			if (info->key->auto_inc) {
				sprintf(str, "%s%d", cid, index++);
			} else {
				sprintf(str, "%s", cid);
			}
			break;
		case RULE_USERNAME:;
			char *username = (char *) conn_param_get_username(cp);
			if (info->key->auto_inc) {
				sprintf(str, "%s%d", username, index++);
			} else {
				sprintf(str, "%s", username);
			}
			break;
		case RULE_PASSWORD:;
			char *password = (char *) conn_param_get_password(cp);
			if (info->key->auto_inc) {
				sprintf(str, "%s%d", password, index++);
			} else {
				sprintf(str, "%s", password);
			}
			break;
		case RULE_TIMESTAMP:
			if (info->key->auto_inc) {
				sprintf(str, "%ld%d", (unsigned long)time(NULL), index++);
			} else {
				sprintf(str, "%ld", (unsigned long)time(NULL));
			}
			break;
		case RULE_PAYLOAD_ALL:;
			char *payload = pp->payload.data;
			if (info->key->auto_inc) {
				sprintf(str, "%s%d", payload, index++);
			} else {
				sprintf(str, "%s", payload);
			}
			break;
		case RULE_PAYLOAD_FIELD:;
			cJSON *jp = cJSON_ParseWithLength(pp->payload.data, pp->payload.len);
			for (int k = 0; k < cvector_size(info->key->key_arr); k++) {
				if (jp == NULL) {
					break;
				}
				jp = cJSON_GetObjectItem(jp, info->key->key_arr[k]);
			}

			switch (jp->type)
			{
			case cJSON_String:
				if (info->key->auto_inc) {
					sprintf(str, "%s%d", cJSON_GetStringValue(jp), index++);
				} else {
					sprintf(str, "%s", cJSON_GetStringValue(jp));
				}
				break;
			case cJSON_Number:
				if (info->key->auto_inc) {
					sprintf(str, "%ld%d", (long) cJSON_GetNumberValue(jp), index++);
				} else {
					sprintf(str, "%ld", (long) cJSON_GetNumberValue(jp));
				}
				break;
			default:
				break;
			}
			break;

		default:
			break;
		}
	}

	if (!strlen(str)) {
		return NULL;
	}

	char *ret = nng_strdup(str);
	return ret;

}


static int
add_info_to_json(rule *info, cJSON *jso, int j, nano_work *work)
{
	pub_packet_struct *pp = work->pub_packet;
	conn_param        *cp = work->cparam;
	if (info->flag[j]) {
		switch (j) {
		case RULE_QOS:
			if (info->as[j]) {
				cJSON_AddNumberToObject(
				    jso, info->as[j], pp->fixed_header.qos);
			} else {
				cJSON_AddNumberToObject(
				    jso, "qos", pp->fixed_header.qos);
			}
			break;
		case RULE_ID:
			if (info->as[j]) {
				cJSON_AddNumberToObject(jso, info->as[j],
				    pp->var_header.publish.packet_id);
			} else {
				cJSON_AddNumberToObject(jso, "id",
				    pp->var_header.publish.packet_id);
			}
			break;
		case RULE_TOPIC:;
			char *topic = pp->var_header.publish.topic_name.body;
			if (info->as[j]) {
				cJSON_AddStringToObject(
				    jso, info->as[j], topic);
			} else {
				cJSON_AddStringToObject(jso, "topic", topic);
			}
			break;
		case RULE_CLIENTID:;
			char *cid = (char *) conn_param_get_clientid(cp);
			if (info->as[j]) {
				cJSON_AddStringToObject(jso, info->as[j], cid);
			} else {
				cJSON_AddStringToObject(jso, "clientid", cid);
			}
			break;
		case RULE_USERNAME:;
			char *username = (char *) conn_param_get_username(cp);
			if (info->as[j]) {
				cJSON_AddStringToObject(
				    jso, info->as[j], username);
			} else {
				cJSON_AddStringToObject(
				    jso, "username", username);
			}
			break;
		case RULE_PASSWORD:;
			char *password = (char *) conn_param_get_password(cp);
			if (info->as[j]) {
				cJSON_AddStringToObject(
				    jso, info->as[j], password);
			} else {
				cJSON_AddStringToObject(
				    jso, "password", password);
			}
			break;
		case RULE_TIMESTAMP:
			if (info->as[j]) {
				cJSON_AddNumberToObject(jso, info->as[j],
				    (unsigned long)time(NULL));
			} else {
				cJSON_AddNumberToObject(jso, "timestamp",
				    (unsigned long)time(NULL));
			}
			break;
		case RULE_PAYLOAD_ALL:;
			char *payload = pp->payload.data;
			cJSON *jp = cJSON_ParseWithLength(payload, pp->payload.len);

			if (info->as[j]) {
				if (jp) {
					cJSON_AddItemToObject(jso, info->as[j], jp);
				} else {
					cJSON_AddStringToObject(
					    jso, info->as[j], payload);
				}
			} else {
				if (jp) {
					cJSON_AddItemToObject(jso, "payload", jp);
				} else {
					cJSON_AddStringToObject(
					    jso, "payload", payload);
				}
			}
			break;
		case RULE_PAYLOAD_FIELD:
			for (int pi = 0; pi < cvector_size(info->payload);
			     pi++) {
				if (info->payload[pi]->is_store) {
					switch (info->payload[pi]->type) {
					case cJSON_Number:
						if (info->payload[pi]->pas) {
							cJSON_AddNumberToObject(jso,
							    info->payload[pi]->pas,
							    (long) info->payload[pi]->value);

						}
						break;
					case cJSON_String:
						if (info->payload[pi]->pas) {
							cJSON_AddStringToObject(jso,
							    info->payload[pi]->pas,
							    (char *) info->payload[pi]->value);
						}
						break;
					case cJSON_Object:
						if (info->payload[pi]->pas) {
							cJSON_AddItemToObject(jso,
							    info->payload[pi]->pas,
							    (cJSON*) info->payload[pi]->value);
						}
						break;
					default:
						break;
					}
				}
			}
			break;

		default:
			break;
		}
	}

	return 0;
}

static char *
compose_sql_clause(rule *info, char *key, char *value, bool is_need_set, int j, nano_work *work)
{
	pub_packet_struct *pp = work->pub_packet;
	conn_param        *cp = work->cparam;
	char *ret = NULL;
	char tmp[800];

	if (info->flag[j]) {
		switch (j) {
		case RULE_QOS:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Qos");
			}
			memset(tmp, 0, 800);
			sprintf(tmp, "%s%d", value, pp->fixed_header.qos);
			strcpy(value, tmp);
			break;
		case RULE_ID:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Id");
			}
			memset(tmp, 0, 800);
			sprintf(tmp, "%s%d", value, pp->var_header.publish.packet_id);
			strcpy(value, tmp);
			break;
		case RULE_TOPIC:;
			char *topic = pp->var_header.publish.topic_name.body;
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Topic");
			}
			memset(tmp, 0, 800);
			sprintf(tmp, "%s\'%s\'", value, topic);
			strcpy(value, tmp);
			break;
		case RULE_CLIENTID:;
			char *cid = (char *) conn_param_get_clientid(cp);
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Clientid");
			}
			memset(tmp, 0, 800);
			sprintf(tmp, "%s\'%s\'", value, cid);
			strcpy(value, tmp);
			break;
		case RULE_USERNAME:;
			char *username = (char *) conn_param_get_username(cp);
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Username");
			}
			if (username == NULL) {
				strcat(value, "NULL");
			} else {
				memset(tmp, 0, 800);
				sprintf(tmp, "%s\'%s\'", value, username);
				strcpy(value, tmp);
			}
			break;
		case RULE_PASSWORD:;
			char *password = (char *) conn_param_get_password(cp);

			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Password");
			}

			if (password == NULL) {
				strcat(value, "NULL");
			} else {
				memset(tmp, 0, 800);
				sprintf(tmp, "%s\'%s\'", value, password);
				strcpy(value, tmp);
			}

			break;
		case RULE_TIMESTAMP:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Timestamp");
			}

			memset(tmp, 0, 800);
			if (RULE_FORWORD_TIMESCALEDB == info->forword_type) {
				sprintf(tmp, "%sto_timestamp(%lu)", value, (unsigned long) time(NULL));
			} else {
				sprintf(tmp, "%s%lu", value, (unsigned long) time(NULL));
			}
			strcpy(value, tmp);
			break;
		case RULE_PAYLOAD_ALL:;
			char *payload = pp->payload.data;

			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Payload");
			}

			memset(tmp, 0, 800);
			sprintf(tmp, "%s\'%s\'", value, payload);
			strcpy(value, tmp);
			break;

		case RULE_PAYLOAD_FIELD:;

			char ret_key[512] = { 0 };
			char tmp_key[128] = { 0 };

			for (int pi = 0; pi < cvector_size(info->payload);
			     pi++) {
				if (info->payload[pi]->is_store) {
					if (info->payload[pi]->pas) {

						switch (info->payload[pi]->type) {
						case cJSON_Number:
								if (is_need_set) {
									  if (RULE_FORWORD_SQLITE == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s INT;\n", info->sqlite_table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_MYSQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s INT;\n", info->mysql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_POSTGRESQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s INT;\n", info->postgresql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_TIMESCALEDB == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s INT;\n", info->timescaledb->table, info->payload[pi]->pas);
									  }
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								if (strlen(value) > strlen("VALUES (")) {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s, %ld", value, (long) info->payload[pi]->value);
									strcpy(value, tmp);
								} else {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s %ld", value, (long) info->payload[pi]->value);
									strcpy(value, tmp);
								}
							break;
						case cJSON_String:
							if (info->payload[pi]->pas) {
								if (is_need_set) {
									  if (RULE_FORWORD_SQLITE == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->sqlite_table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_MYSQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->mysql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_POSTGRESQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->postgresql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_TIMESCALEDB == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->timescaledb->table, info->payload[pi]->pas);
									  }
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								if (strlen(value) > strlen("VALUES (")) {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s, \'%s\'", value, (char*) info->payload[pi]->value);
									strcpy(value, tmp);
								} else {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s \'%s\'", value, (char*) info->payload[pi]->value);
									strcpy(value, tmp);
								}
							}
							break;
						case cJSON_Object:
							if (info->payload[pi]->pas) {
								if (is_need_set) {
									  if (RULE_FORWORD_SQLITE == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->sqlite_table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_MYSQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->mysql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_POSTGRESQL == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->postgresql->table, info->payload[pi]->pas);
									  } else if (RULE_FORWORD_TIMESCALEDB == info->forword_type) {
										snprintf(tmp_key, 128, "ALTER TABLE %s ADD %s TEXT;\n", info->timescaledb->table, info->payload[pi]->pas);
									  }
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								char *cjson_obj = cJSON_PrintUnformatted((cJSON*) info->payload[pi]->value);
								if (strlen(value) > strlen("VALUES (")) {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s, \'%s\'", value, cjson_obj);
									strcpy(value, tmp);
								} else {
									memset(tmp, 0, 800);
									sprintf(tmp, "%s \'%s\'", value, cjson_obj);
									strcpy(value, tmp);
								}
								cJSON_free(cjson_obj);
							}
							break;
						default:
							break;
						}

						strcat(ret_key, tmp_key);
						memset(tmp_key, 0, 128);

					}
				}
			}

			if (strlen(ret_key)) {
				ret = nng_strdup(ret_key);

			}
			break;

		default:
			break;
		}
		if (j != RULE_PAYLOAD_FIELD) {
			strcat(key, ", ");
		}
		strcat(value, ", ");
	}

	return ret;
}

int
rule_engine_insert_sql(nano_work *work)
{
	rule  *rules = work->config->rule_eng.rules;
	size_t             rule_size  = cvector_size(rules);
	pub_packet_struct *pp         = work->pub_packet;
	conn_param        *cp         = work->cparam;
	static uint32_t    index      = 0;
	static bool is_first_time = true;
	bool is_need_set = false;
	static bool is_first_time_mysql = true;
	bool is_need_set_mysql = false;
	static bool is_first_time_postgresql = true;
	bool is_need_set_postgresql = false;
	static bool is_first_time_timescaledb = true;
	bool is_need_set_timescaledb = false;

	nng_mtx *rule_mutex = work->config->rule_eng.rule_mutex;

	for (size_t i = 0; i < rule_size; i++) {
		if (true == rules[i].enabled && rule_engine_filter(work, &rules[i])) {
#if defined(FDB_SUPPORT)
			char fdb_key[pp->var_header.publish.topic_name.len+sizeof(uint64_t)];
			if (RULE_ENG_FDB & work->config->rule_eng.option && RULE_FORWORD_FDB == rules[i].forword_type) {
				cJSON *jso = NULL;
				jso        = cJSON_CreateObject();

				for (size_t j = 0; j < 9; j++) {
					add_info_to_json(
					    &rules[i], jso, j, work);
				}

				char *key = NULL;
				for (size_t j = 0; j < 9; j++) {
					key = generate_key(&rules[i], j, work);
					if (key != NULL) {
						break;
					}
				}

				char *dest = cJSON_PrintUnformatted(jso);
				log_debug("%s", key);
				log_debug("%s", dest);

				FDBTransaction *tr = NULL;
				fdb_error_t     e =
				    fdb_database_create_transaction(
				        work->config->rule_eng.rdb[1], &tr);
				if (e) {
					fprintf(stderr, "%s\n", fdb_get_error(e));
				}

				fdb_transaction_set(tr, key,
				    strlen(key), dest, strlen(dest));
				FDBFuture *f = fdb_transaction_commit(tr);

				e = fdb_future_block_until_ready(f);
				if (e) {
					fprintf(stderr, "%s\n", fdb_get_error(e));
				}

				fdb_future_destroy(f);
				fdb_transaction_clear(tr, fdb_key, strlen(fdb_key));
				fdb_transaction_destroy(tr);

				free(key);
				cJSON_free(dest);
				cJSON_Delete(jso);
			}
#endif

			if (RULE_ENG_RPB & work->config->rule_eng.option && RULE_FORWORD_REPUB == rules[i].forword_type) {
				cJSON *jso = NULL;
				jso        = cJSON_CreateObject();

				for (size_t j = 0; j < 9; j++) {
					add_info_to_json(
					    &rules[i], jso, j, work);
				}

				char *dest = cJSON_PrintUnformatted(jso);
				repub_t *repub = rules[i].repub;

				nano_client_publish(repub->sock, repub->topic, dest, strlen(dest), 0, NULL);
				log_debug("%s", repub->topic);
				log_debug("%s", dest);

				cJSON_free(dest);
				cJSON_Delete(jso);
			}

#if defined(NNG_SUPP_SQLITE)
			if (RULE_ENG_SDB & work->config->rule_eng.option && RULE_FORWORD_SQLITE == rules[i].forword_type) {
				char sql_clause[1024] = "INSERT INTO ";
				char key[128]         = { 0 };
				snprintf(key, 128, "%s (", rules[i].sqlite_table);
				char value[800]       = "VALUES (";
				for (size_t j = 0; j < 9; j++) {
					nng_mtx_lock(rule_mutex);
					if (true == is_first_time) {
						is_need_set   = true;
					}
					char *ret =
					    compose_sql_clause(&rules[i],
					        key, value, is_need_set, j, work);
					if (ret) {
						log_debug("%s", ret);
						log_debug("%s", ret);
						sqlite3 *sdb =
						    (sqlite3 *) work->config
						        ->rule_eng.rdb[0];
						char *err_msg = NULL;
						int   rc      = sqlite3_exec(
						           sdb, ret, 0, 0, &err_msg);
						// FIXME: solve in a more
						// elegant way 
						if (rc != SQLITE_OK) {
							// fprintf(stderr, "SQL error: num %d %s\n",
							//     rc, err_msg);
							sqlite3_free(err_msg);
							// sqlite3_close(sdb);
							// return 1;
						}

						free(ret);
						ret = NULL;
					}

					if (true == is_first_time) {
						is_first_time = false;
					}

					nng_mtx_unlock(rule_mutex);
				}

				

				log_debug("%s", key);
				log_debug("%s", value);
				char *p = strrchr(key, ',');
				*p      = ')';
				p       = strrchr(value, ',');
				*p      = ')';
				strcat(sql_clause, key);
				strcat(sql_clause, value);
				strcat(sql_clause, ";");

				log_debug("%s", sql_clause);
				log_debug("%s", sql_clause);
				sqlite3 *sdb = (sqlite3 *) work->config->rule_eng.rdb[0];
				char    *err_msg = NULL;
				int      rc      = sqlite3_exec(
				              sdb, sql_clause, 0, 0, &err_msg);
				if (rc != SQLITE_OK) {
					fprintf(stderr, "SQL error: %s\n",
					    err_msg);
					sqlite3_free(err_msg);
					sqlite3_close(sdb);

					return 1;
				}

			}

#endif


#if defined(SUPP_MYSQL)
			if (RULE_ENG_MDB & work->config->rule_eng.option && RULE_FORWORD_MYSQL == rules[i].forword_type) {
				char sql_clause[1024] = "INSERT INTO ";
				char key[128]         = { 0 };
				snprintf(key, 128, "%s (", rules[i].mysql->table);
				char value[800]       = "VALUES (";
				for (size_t j = 0; j < 9; j++) {
					nng_mtx_lock(rule_mutex);
					if (true == is_first_time_mysql) {
						is_need_set_mysql   = true;
					}
					char *ret =
					    compose_sql_clause(&rules[i],
					        key, value, is_need_set_mysql, j, work);

					if (ret && is_need_set_mysql) {
						is_need_set_mysql = false;
						log_debug("%s", ret);

						char *p   = ret;
						char *p_b = ret;

						while (NULL != p) {
							char *p = strchr(p_b, '\n');
							if (NULL != p) {
								*p = '\0';
  								if (mysql_query(rules[i].mysql->conn, p_b)) {
  									// fprintf(stderr, "%s\n", mysql_error(rules[i].mysql->conn));
  								}
								p_b = ++p;

							} else {
								break;
							}
						}

						free(ret);
						ret = NULL;
					}

					if (true == is_first_time_mysql) {
						is_first_time_mysql = false;
					}

					nng_mtx_unlock(rule_mutex);
				}

				

				log_debug("%s", key);
				log_debug("%s", value);
				char *p = strrchr(key, ',');
				*p      = ')';
				p       = strrchr(value, ',');
				*p      = ')';
				strcat(sql_clause, key);
				strcat(sql_clause, value);
				strcat(sql_clause, ";");

				log_debug("%s", sql_clause);
  				if (mysql_query(rules[i].mysql->conn, sql_clause)) {
  					fprintf(stderr, "%s\n", mysql_error(rules[i].mysql->conn));
  					mysql_close(rules[i].mysql->conn);
  					exit(1);
  				}
			}
#endif


#if defined(SUPP_POSTGRESQL)
			if (RULE_ENG_PDB & work->config->rule_eng.option && RULE_FORWORD_POSTGRESQL == rules[i].forword_type) {

				if (work->pgconn == NULL) {
					rule_postgresql *postgresql = rules[i].postgresql;
					char conninfo[256] = { 0 };
					snprintf(conninfo , 128, "dbname=postgres user=%s password=%s host=%s port=5432", postgresql->username,postgresql->password, postgresql->host);
					PGconn *conn = PQconnectdb(conninfo);

 					if (PQstatus(conn) != CONNECTION_OK) {
						log_error("Postgresql error %s", PQerrorMessage(conn));
						PQfinish(conn);
						exit(1);
					}
					work->pgconn = conn;
				}

				char sql_clause[1024] = "INSERT INTO ";
				char key[128]         = { 0 };
				snprintf(key, 128, "%s (", rules[i].postgresql->table);
				char value[800]       = "VALUES (";
				for (size_t j = 0; j < 9; j++) {

					nng_mtx_lock(rule_mutex);

					if (true == is_first_time_postgresql) {
						is_need_set_postgresql   = true;
					}
					char *ret =
					    compose_sql_clause(&rules[i],
					        key, value, is_need_set_postgresql, j, work);

					if (ret && is_need_set_postgresql) {
						is_need_set_postgresql = false;
						log_debug("ret - %s", ret);

						char *p   = ret;
						char *p_b = ret;

						while (NULL != p) {
							char *p = strchr(p_b, '\n');
							if (NULL != p) {
								*p = '\0';

								log_debug("p_b %s", p_b);
								PGresult *res = PQexec(rules[i].postgresql->conn, p_b);

								if (PQresultStatus(res) != PGRES_COMMAND_OK) {
									log_debug("p_b Postgresql error %s\n", PQerrorMessage(rules[i].postgresql->conn));
									fprintf(stderr, "%s\n", PQerrorMessage(rules[i].postgresql->conn));
  								}

								PQclear(res);
								p_b = ++p;

							} else {
								break;
							}
						}

						free(ret);
						ret = NULL;
					}

					if (true == is_first_time_postgresql) {
						is_first_time_postgresql = false;
					}

					nng_mtx_unlock(rule_mutex);
				}



				/* log_debug("%s", key); */
				/* log_debug("%s", value); */

				char *p = strrchr(key, ',');
				*p      = ')';
				p       = strrchr(value, ',');
				*p      = ')';
				strcat(sql_clause, key);
				strcat(sql_clause, value);
				strcat(sql_clause, ";");

				log_debug("%s", sql_clause);

				PGresult *res = PQexec(work->pgconn, sql_clause);
			    log_debug("Postgresql res: %d\n", PQresultStatus(res));

  				if (PQresultStatus(res) != PGRES_COMMAND_OK) {
				    log_debug("Postgresql error %s\n", PQerrorMessage(work->pgconn));
  					fprintf(stderr, "Postgresql error %s\n", PQerrorMessage(work->pgconn));
                    PQclear(res);
  					PQfinish(work->pgconn);
  					exit(1);
  				}

				PQclear(res);


			}
#endif

#if defined(SUPP_TIMESCALEDB)
			if (RULE_ENG_TDB & work->config->rule_eng.option && RULE_FORWORD_TIMESCALEDB == rules[i].forword_type) {

				if (work->tsconn == NULL) {
					rule_timescaledb *timescaledb = rules[i].timescaledb;
					char conninfo[256] = { 0 };
					snprintf(conninfo , 128, "dbname=postgres user=%s password=%s host=%s port=5432", timescaledb->username, timescaledb->password, timescaledb->host);
					PGconn *conn = PQconnectdb(conninfo);

 					if (PQstatus(conn) != CONNECTION_OK) {
						log_error("timescaledb error %s", PQerrorMessage(conn));
						PQfinish(conn);
						exit(1);
					}
					work->tsconn = conn;
				}

				char sql_clause[1024] = "INSERT INTO ";
				char key[128]         = { 0 };
				snprintf(key, 128, "%s (", rules[i].timescaledb->table);
				char value[800]       = "VALUES (";
				for (size_t j = 0; j < 9; j++) {

					nng_mtx_lock(rule_mutex);

					if (true == is_first_time_timescaledb) {
						is_need_set_timescaledb   = true;
					}
					char *ret =
					    compose_sql_clause(&rules[i],
					        key, value, is_need_set_timescaledb, j, work);

					if (ret && is_need_set_timescaledb) {
						is_need_set_timescaledb = false;
						log_debug("ret - %s", ret);

						char *p   = ret;
						char *p_b = ret;

						while (NULL != p) {
							char *p = strchr(p_b, '\n');
							if (NULL != p) {
								*p = '\0';

								log_debug("p_b %s", p_b);
								PGresult *res = PQexec(work->tsconn, p_b);

								if (PQresultStatus(res) != PGRES_COMMAND_OK) {
									log_debug("timescaledb error %s\n", PQerrorMessage(work->tsconn));
									fprintf(stderr, "%s\n", PQerrorMessage(work->tsconn));
  								}

								PQclear(res);
								p_b = ++p;

							} else {
								break;
							}
						}

						free(ret);
						ret = NULL;
					}

					if (true == is_first_time_timescaledb) {
						is_first_time_timescaledb = false;
					}

					nng_mtx_unlock(rule_mutex);
				}


				/* log_debug("%s", key); */
				/* log_debug("%s", value); */

				char *p = strrchr(key, ',');
				*p      = ')';
				p       = strrchr(value, ',');
				*p      = ')';
				strcat(sql_clause, key);
				strcat(sql_clause, value);
				strcat(sql_clause, ";");

				log_debug("%s", sql_clause);

				PGresult *res = PQexec(work->tsconn, sql_clause);
			    log_debug("timescaledb res: %d\n", PQresultStatus(res));

  				if (PQresultStatus(res) != PGRES_COMMAND_OK) {
				    log_debug("timescaledb error %s\n", PQerrorMessage(work->tsconn));
  					fprintf(stderr, "timescaledb error %s\n", PQerrorMessage(work->tsconn));
                    PQclear(res);
  					PQfinish(work->tsconn);
  					exit(1);
  				}

				PQclear(res);
			}
#endif

		}
	}

	return 0;
}


#endif
/**
 * 
	only deal with locale publishing
	client - broker - client + bridge - broker - client
	broker - bridge is not included
	@is_event indicates this is not a common pub msg
	it is either a SYS or retain msg
 * 
 */

reason_code
handle_pub(nano_work *work, struct pipe_content *pipe_ct, uint8_t proto,
    bool is_event)
{
	reason_code result          = SUCCESS;
	char      **topic_queue     = NULL;
	uint32_t   *cli_ctx_list    = NULL;
	uint32_t   *shared_cli_list = NULL;
	char       *topic           = NULL;
	pipe_ct->msg_infos          = NULL;

#ifdef STATISTICS
	if (!g_msg.initialed) {
		msg_statistics_init(&g_msg);
	}
	nng_atomic_inc64(g_msg.msg_in);
#endif

	work->pub_packet = (struct pub_packet_struct *) nng_zalloc(
	    sizeof(struct pub_packet_struct));

	result = decode_pub_message(work, proto);
	if (SUCCESS != result) {
		log_warn("decode message failed.");
		return result;
	}

	if (PUBLISH != work->pub_packet->fixed_header.packet_type) {
		return MALFORMED_PACKET;
	}

	topic        = work->pub_packet->var_header.publish.topic_name.body;
	uint32_t len = work->pub_packet->var_header.publish.topic_name.len;

	if (work->config != NULL && work->config->auth_http.enable) {
		struct topic_queue *tq = topic_queue_init(topic, len);
		if (tq == NULL) {
			log_error("topic_queue_init failed!");
		} else {
			int rv = nmq_auth_http_sub_pub(work->cparam, false, tq, &work->config->auth_http);
			if (rv != 0) {
				log_error("Auth failed! publish packet!");
				topic_queue_release(tq);
				return NOT_AUTHORIZED;
			}
		}

		topic_queue_release(tq);
	}

	// deal with topic alias
	if (proto == MQTT_PROTOCOL_VERSION_v5) {
		property_data *pdata = property_get_value(
		    work->pub_packet->var_header.publish.properties,
		    TOPIC_ALIAS);
		log_trace("len: %d, topic: %s", len, topic);
		if (len > 0 && topic != NULL) {
			if (pdata) {
				dbhash_insert_atpair(
				    work->pid.id, pdata->p_value.u16, topic);
			}
		} else {
			if (pdata) {
				const char *tp = dbhash_find_atpair(
				    work->pid.id, pdata->p_value.u16);
				if (tp) {
					topic = work->pub_packet->var_header
					            .publish.topic_name.body =
					    nng_strdup(tp);
					len = work->pub_packet->var_header
					          .publish.topic_name.len =
					    strlen(tp);
				} else {
					log_error("could not find "
					          "topic by alias: %d",
					    pdata->p_value.u16);
					return TOPIC_FILTER_INVALID;
				}
			}
		}
	}

	if (topic == NULL) {
		log_error("Topic is NULL");
		return TOPIC_FILTER_INVALID;
	}
	if (work->proto == PROTO_MQTT_BRIDGE) {
		bridge_handle_topic_reflection(work, &work->config->bridge);
	}

#if defined(SUPP_AWS_BRIDGE)
	if (work->proto == PROTO_AWS_BRIDGE) {
		bridge_handle_topic_reflection(
		    work, &work->config->aws_bridge);
	}
#endif

	topic = work->pub_packet->var_header.publish.topic_name.body;

#ifdef ACL_SUPP
	if (!is_event && work->cparam) {
		if (work->config->acl.enable) {
			bool rv = auth_acl(
			    work->config, ACL_PUB, work->cparam, topic);
			if (!rv) {
				log_warn("acl deny");
				if (work->config->acl_deny_action ==
				    ACL_DISCONNECT) {
					log_warn(
					    "acl deny, disconnect client");
					return NORMAL_DISCONNECTION;
				} else {
					return BANNED;
				}
			} else {
				log_info("acl allow");
			}
		}
	}
#endif
	cli_ctx_list = dbtree_find_clients(work->db, topic);

	shared_cli_list = dbtree_find_shared_clients(work->db, topic);

#ifdef STATISTICS
	if (cli_ctx_list == NULL && shared_cli_list == NULL) {
		nng_atomic_inc64(g_msg.msg_drop);
	}
#endif

	if (cli_ctx_list != NULL) {
		foreach_client(cli_ctx_list, work, pipe_ct);
	}
	log_debug("pipe_info size: [%ld]", cvector_size(cli_ctx_list));
	cvector_free(cli_ctx_list);

	if (shared_cli_list != NULL) {
		foreach_client(shared_cli_list, work, pipe_ct);
	}
	cvector_free(shared_cli_list);

#if ENABLE_RETAIN
	// Exclude DISCONNECT_EV msg?
	handle_pub_retain(work, topic);
#endif
	return result;
}

#if ENABLE_RETAIN

#if defined(NNG_SUPP_SQLITE)

static void inline handle_pub_retain_sqlite(const nano_work *work, char *topic)
{
	if (work->pub_packet->fixed_header.retain) {
		if (work->pub_packet->payload.len > 0) {
			nng_mqtt_qos_db_set_retain(
			    work->sqlite_db, topic, work->msg, work->proto_ver);
		} else {
			nng_mqtt_qos_db_remove_retain(work->sqlite_db, topic);
		}
	}
}

#endif

static void inline handle_pub_retain(const nano_work *work, char *topic)
{
#if defined(NNG_SUPP_SQLITE)
	if (work->config != NULL && work->config->sqlite.enable &&
	    work->sqlite_db) {
		handle_pub_retain_sqlite(work, topic);
		return;
	}
#endif
	nng_msg *ret = NULL;
	if (work->pub_packet->fixed_header.retain) {
		if (work->pub_packet->payload.len > 0) {
			nng_msg_clone(work->msg);
			if (nng_msg_get_proto_data(work->msg) == NULL)
				nng_mqtt_msg_proto_data_alloc(work->msg);
			if (work->proto_ver == MQTT_PROTOCOL_VERSION_v5) {
				if (nng_mqttv5_msg_decode(work->msg) != 0) {
					log_warn("decode retain msg failed, drop msg");
					nng_msg_free(work->msg);
					return;
				}
			} else if (work->proto_ver == MQTT_PROTOCOL_VERSION_v311 ||
					   work->proto_ver == MQTT_PROTOCOL_VERSION_v31) {
				if (nng_mqtt_msg_decode(work->msg) != 0) {
					log_warn("decode retain msg failed, "
					         "drop msg");
					nng_msg_free(work->msg);
					return;
				}
			}
			ret = dbtree_insert_retain(work->db_ret, topic, work->msg);
		} else {
			log_debug("delete retain message");
			ret = dbtree_delete_retain(work->db_ret, topic);
		}

		if (ret != NULL) {
			nng_msg_free(ret);
		}
	}
}
#endif


void
free_pub_packet(struct pub_packet_struct *pub_packet)
{
	if (pub_packet != NULL) {
		if (pub_packet->fixed_header.packet_type == PUBLISH) {
			if (pub_packet->var_header.publish.topic_name.body !=
			        NULL &&
			    pub_packet->var_header.publish.topic_name.len >
			        0) {
				nng_free(pub_packet->var_header.publish
				             .topic_name.body,
				    pub_packet->var_header.publish.topic_name
				            .len +
				        1);
				pub_packet->var_header.publish.topic_name
				    .body = NULL;
				pub_packet->var_header.publish.topic_name.len =
				    0;
				log_debug("free topic");
			}

			if (pub_packet->var_header.publish.prop_len > 0) {
				property_free(
				    pub_packet->var_header.publish.properties);
				pub_packet->var_header.publish.prop_len = 0;
				log_debug("free properties");
			}

			if (pub_packet->payload.len > 0 &&
			    pub_packet->payload.data != NULL) {
				nng_free(pub_packet->payload.data,
				    pub_packet->payload.len + 1);
				pub_packet->payload.data = NULL;
				pub_packet->payload.len  = 0;
				log_debug("free payload");
			}
		}

		nng_free(pub_packet, sizeof(struct pub_packet_struct));
		pub_packet = NULL;
		log_debug("free pub_packet");
	}
}

void
free_msg_infos(mqtt_msg_info *msg_infos)
{
	if (msg_infos != NULL) {
		free(msg_infos);
	}
}

static uint32_t
append_bytes_with_type(
    nng_msg *msg, uint8_t type, uint8_t *content, uint32_t len)
{
	if (len > 0) {
		nng_msg_append(msg, &type, 1);
		nng_msg_append_u16(msg, len);
		nng_msg_append(msg, content, len);
		return 0;
	}

	return 1;
}

/**
 * @brief encode dest_msg with work.
 * @param dest_msg nng_msg
 * @param work nano_work
 * @param cmd mqtt_control_packet_types
 * @return bool
 */
bool
encode_pub_message(
    nng_msg *dest_msg, nano_work *work, mqtt_control_packet_types cmd)
{
	uint8_t  tmp[4]     = { 0 };
	uint32_t arr_len    = 0;
	int      append_res = 0;
	uint8_t  proto      = 0;
	uint32_t buf;

	log_debug("start encode message");
	if (dest_msg == NULL)
		return false;
	nng_msg_clear(dest_msg);
	nng_msg_header_clear(dest_msg);
	if (nng_msg_cmd_type(dest_msg) == CMD_PUBLISH_V5) {
		proto = MQTT_PROTOCOL_VERSION_v5;
	} else if (nng_msg_cmd_type(dest_msg) == CMD_PUBLISH) {
		proto = MQTT_PROTOCOL_VERSION_v311;
	}

	switch (cmd) {
	case PUBLISH:
		/*fixed header*/
		work->pub_packet->fixed_header.packet_type = cmd;
		// work->pub_packet->fixed_header.dup = dup;
		append_res = nng_msg_header_append(
		    dest_msg, (uint8_t *) &work->pub_packet->fixed_header, 1);

		/*variable header*/
		// topic name
		if (work->pub_packet->var_header.publish.topic_name.len > 0) {
			append_res = nng_msg_append_u16(dest_msg,
			    work->pub_packet->var_header.publish.topic_name
			        .len);

			append_res = nng_msg_append(dest_msg,
			    work->pub_packet->var_header.publish.topic_name
			        .body,
			    work->pub_packet->var_header.publish.topic_name
			        .len);
		}

		// identifier
		if (work->pub_packet->fixed_header.qos > 0) {
			append_res = nng_msg_append_u16(dest_msg,
			    work->pub_packet->var_header.publish.packet_id);
		}
		log_debug("after topic and id len in msg already [%ld]",
		    nng_msg_len(dest_msg));

#if SUPPORT_MQTT5_0
		if (MQTT_PROTOCOL_VERSION_v5 == proto) {
#if defined(SUPP_PLUGIN)
			char *uproperty[2];
			uproperty[0] = NULL;
			uproperty[1] = NULL;
			plugin_hook_call(HOOK_USER_PROPERTY, uproperty);
			if (uproperty[0] != NULL && uproperty[1] != NULL) {
				work->user_property =
				    mqtt_property_set_value_strpair(USER_PROPERTY,
				        uproperty[0], strlen(uproperty[0]),
				        uproperty[1], strlen(uproperty[1]),
				        false);

				if (work->pub_packet->var_header.publish
				        .properties == NULL) {
					work->pub_packet->var_header.publish
					    .properties = property_alloc();
				}

				property_append(work->pub_packet->var_header
							.publish.properties, work->user_property);
			}

#endif
			int rv;
			rv = encode_properties(dest_msg,
			    work->pub_packet->var_header.publish.properties,
				CMD_PUBLISH);

			if (rv != 0) {
				return false;
			}

			// rv = encode_properties(dest_msg, NULL);
		}
#endif

		// payload
		if (work->pub_packet->payload.len > 0) {
			// nng_msg_set_payload_ptr(msg, nng_msg_body());
			append_res = nng_msg_append(dest_msg,
			    work->pub_packet->payload.data,
			    work->pub_packet->payload.len);
		}

		log_debug("after payload len in msg already [%ld]",
		    nng_msg_len(dest_msg));

		work->pub_packet->fixed_header.remain_len =
		    nng_msg_len(dest_msg);
		arr_len = put_var_integer(
		    tmp, work->pub_packet->fixed_header.remain_len);
		append_res = nng_msg_header_append(dest_msg, tmp, arr_len);
		nng_msg_set_remaining_len(
		    dest_msg, work->pub_packet->fixed_header.remain_len);
		log_debug("header len [%ld] remain len [%d]\n",
		    nng_msg_header_len(dest_msg),
		    work->pub_packet->fixed_header.remain_len);
		break;

	case PUBREL:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBREL);
	case PUBACK:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBACK);
	case PUBREC:
		nng_msg_set_cmd_type(dest_msg, CMD_PUBREC);
	case PUBCOMP:
		log_debug("encode %d message", cmd);
		nng_msg_set_cmd_type(dest_msg, CMD_PUBCOMP);
		struct pub_packet_struct pub_response = {
			.fixed_header.packet_type = cmd,
			// .fixed_header.dup         = dup,
			.fixed_header.qos        = 0,
			.fixed_header.retain     = 0,
			.fixed_header.remain_len = 2, // TODO
			.var_header.pub_arrc.packet_id =
			    work->pub_packet->var_header.publish.packet_id
		};

		/*fixed header*/
		nng_msg_header_append(
		    dest_msg, (uint8_t *) &pub_response.fixed_header, 1);
		arr_len =
		    put_var_integer(tmp, pub_response.fixed_header.remain_len);
		nng_msg_header_append(dest_msg, tmp, arr_len);

		/*variable header*/
		// identifier
		nng_msg_append_u16(
		    dest_msg, pub_response.var_header.pub_arrc.packet_id);

		// reason code
		if (pub_response.fixed_header.remain_len > 2) {
			uint8_t reason_code =
			    pub_response.var_header.pub_arrc.reason_code;
			nng_msg_append(dest_msg, (uint8_t *) &reason_code,
			    sizeof(reason_code));

#if SUPPORT_MQTT5_0
			if (MQTT_PROTOCOL_VERSION_v5 == proto) { }
#endif
		}
		break;
	default:
		break;
	}

	log_debug("end encode message");
	return true;
}

/**
 * @brief decode work->msg to fill work->pub_packet.
 * @param work nano_work
 * @param proto check protocol verison, more need to be done in MQTTv5
 * @return reason_code
 */
reason_code
decode_pub_message(nano_work *work, uint8_t proto)
{
	uint32_t pos      = 0;
	uint32_t used_pos = 0;
	uint32_t len, len_of_varint;
	bool     is_copy = false;

	nng_msg                  *msg        = work->msg;
	struct pub_packet_struct *pub_packet = work->pub_packet;

	uint8_t *msg_body = nng_msg_body(msg);
	size_t   msg_len  = nng_msg_len(msg);

	// print_hex("", msg_body, msg_len);

	pub_packet->fixed_header =
	    *(struct fixed_header *) nng_msg_header(msg);
	pub_packet->fixed_header.remain_len = nng_msg_remaining_len(msg);

	log_debug(
	    "cmd: %d, retain: %d, qos: %d, dup: %d, remaining length: %d",
	    pub_packet->fixed_header.packet_type,
	    pub_packet->fixed_header.retain, pub_packet->fixed_header.qos,
	    pub_packet->fixed_header.dup, pub_packet->fixed_header.remain_len);

	if (pub_packet->fixed_header.remain_len > msg_len) {
		log_error("remainlen > msg_len");
		return PROTOCOL_ERROR;
	}

	switch (pub_packet->fixed_header.packet_type) {
	case PUBLISH:
		// variable header
		// topic length
		pub_packet->var_header.publish.topic_name.body =
		    (char *) copyn_utf8_str(msg_body, &pos, (int *) &len, msg_len);
		if (len >= 0)
			// topic could be NULL here (topic alias)
			pub_packet->var_header.publish.topic_name.len = len;
		else {
			log_warn("Invalid msg: Protocol error!");
			return PROTOCOL_ERROR;
		}

		if (pub_packet->var_header.publish.topic_name.body != NULL) {
			if (strchr(
			        pub_packet->var_header.publish.topic_name.body,
			        '+') != NULL ||
			    strchr(
			        pub_packet->var_header.publish.topic_name.body,
			        '#') != NULL) {

				// protocol error
				log_error(
				    "protocol error in topic:[%s], len: [%d]",
				    pub_packet->var_header.publish.topic_name
				        .body,
				    pub_packet->var_header.publish.topic_name
				        .len);

				return PROTOCOL_ERROR;
			}
		}

		// TODO if topic_len = 0 && mqtt_version = 5.0, search topic
		// alias from nano_db

		log_debug("topic: [%.*s], len: [%d], qos: %d",
		    pub_packet->var_header.publish.topic_name.len,
		    pub_packet->var_header.publish.topic_name.body,
			pub_packet->var_header.publish.topic_name.len,
		    pub_packet->fixed_header.qos);

		if (pub_packet->fixed_header.qos > 0) {
			NNI_GET16(msg_body + pos,
			    pub_packet->var_header.publish.packet_id);
			log_debug("identifier: [%d]",
			    pub_packet->var_header.publish.packet_id);
			pos += 2;
		}
		used_pos = pos;

		if (MQTT_PROTOCOL_VERSION_v5 == proto) {
			// we copy property each time to avoid memcpy_param_overlap
			// although it reduce overall performance
			pub_packet->var_header.publish.properties =
			    decode_properties(msg, &pos,
			        &pub_packet->var_header.publish.prop_len,
			        true);
			log_debug("property len: %d",
			    pub_packet->var_header.publish.prop_len);

			if (pub_packet->var_header.publish.properties) {
				if (check_properties(
				        pub_packet->var_header.publish
				            .properties, msg) != 0) {
					// check if subid exist in publish msg from client
				    // property_get_value(pub_packet->var_header
				    //                        .publish.properties,
				    //     SUBSCRIPTION_IDENTIFIER) != NULL
					return PROTOCOL_ERROR;
				}
			}
		}

		if (pos > msg_len) {
			log_debug("buffer-overflow: pos = %u, msg_len = %lu",
			    pos, msg_len);
			return PROTOCOL_ERROR;
		}

		used_pos = pos;
		log_debug("used pos: [%d]", used_pos);
		// payload
		pub_packet->payload.len =
		    (uint32_t) (msg_len - (size_t) used_pos);
		nng_msg_set_payload_ptr(msg, msg_body + pos);

		if (pub_packet->payload.len > 0) {
			pub_packet->payload.data =
			    nng_zalloc(pub_packet->payload.len + 1);
			memcpy(pub_packet->payload.data,
			    (uint8_t *) (msg_body + pos),
			    pub_packet->payload.len);
			log_debug("payload: [%s], len = %u",
			    pub_packet->payload.data, pub_packet->payload.len);
		}
		break;

	case PUBACK:
	case PUBREC:
	case PUBREL:
	case PUBCOMP:
		// here could not be reached
		NNI_GET16(msg_body, pub_packet->var_header.pub_arrc.packet_id);
		if (MQTT_PROTOCOL_VERSION_v5 == proto) {
			pos += 2;
			pub_packet->var_header.pub_arrc.reason_code =
			    *(msg_body + pos);
			pos++;
			pub_packet->var_header.pub_arrc.properties =
			    decode_properties(msg, &pos,
			        &pub_packet->var_header.pub_arrc.prop_len,
			        false);
			if (check_properties(
			        pub_packet->var_header.pub_arrc.properties, msg) !=
			    SUCCESS) {
				return PROTOCOL_ERROR;
			}
		}
		break;

	default:
		break;
	}
	return SUCCESS;
}

/**
 * byte array to hex string
 *
 * @param src
 * @param dest
 * @param src_len
 * @return
 */
static char *
bytes_to_str(const unsigned char *src, char *dest, int src_len)
{
	int  i;
	char szTmp[4] = { 0 };

	for (i = 0; i < src_len; i++) {
		snprintf(szTmp, 4, "%02X ", src[i]);
		memcpy(dest + (i * 3), szTmp, 3);
	}
	return dest;
}

static void
print_hex(const char *prefix, const unsigned char *src, int src_len)
{
	if (src_len > 0) {
		char *dest = (char *) nng_zalloc(src_len * 3 + 1);

		if (dest == NULL) {
			log_error("alloc fail!");
			return;
		}
		dest = bytes_to_str(src, dest, src_len);

		log_debug("%s%s", prefix, dest);

		nng_free(dest, src_len * 3 + 1);
	}
}

bool
check_msg_exp(nng_msg *msg, property *prop)
{
	if (nng_msg_cmd_type(msg) == CMD_PUBLISH_V5) {
		// change to nng msg get
		nng_time       rtime = nng_msg_get_timestamp(msg);
		nng_time       ntime = nng_clock();
		property_data *data  = property_get_value(prop, MESSAGE_EXPIRY_INTERVAL);
#if defined(NNG_SUPP_SQLITE)
		if (!data) {
			nng_mqttv5_msg_decode(msg);
			property *pub_prop = (void *)nng_mqtt_msg_get_publish_property(msg);
			data = property_get_value(pub_prop, MESSAGE_EXPIRY_INTERVAL);
		}
#endif
		if (data && ntime > rtime + data->p_value.u32 * 1000) {
#if defined(NNG_SUPP_SQLITE)
			nng_msg_free(msg);
#endif
			return false;
		} else if (data) {
			// TODO replace exp interval with new value without
			// touching prop?
			//  data->p_value.u32 =
			//      data->p_value.u32 - (ntime - rtime) / 1000;
		}
	}
	return true;
}
