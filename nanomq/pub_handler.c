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

#include <include/nanomq.h>
#include <mqtt_db.h>
#include <nng.h>
#include <nng/mqtt/packet.h>
#include <zmalloc.h>

#include "cJSON.h"
#include "include/bridge.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/util/platform.h"
#include <nng/supplemental/sqlite/sqlite3.h>

#define ENABLE_RETAIN 1
#define SUPPORT_MQTT5_0 1

pthread_mutex_t rule_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	debug_msg("pub_handler: init pipe_info");
	pipe_ct->total         = 0;
	pipe_ct->current_index = 0;
	pipe_ct->msg_infos     = NULL;
}

void
foreach_client(
    void **cli_ctx_list, nano_work *pub_work, struct pipe_content *pipe_ct)
{
	bool     equal = false;
	uint32_t pids;
	uint8_t  sub_qos;
	int      ctx_list_len;

	struct client_ctx *ctx;
	dbtree_ctxt       *db_ctxt, *ctxt;
	topic_node        *tn;

	// Dont using msg info buf, Just for Cheat Compiler
	mqtt_msg_info *msg_info, msg_info_buf;

	cvector(mqtt_msg_info) msg_infos = pipe_ct->msg_infos;

	ctx_list_len = cvector_size(cli_ctx_list);

	for (int i = 0; i < ctx_list_len; i++) {
		db_ctxt = (dbtree_ctxt *) cli_ctx_list[i];
		ctx     = (struct client_ctx *) db_ctxt->ctx;

#ifdef STATISTICS
		// nng_atomic_inc64(ctx->recv_cnt);
		// nng_atomic_inc64(g_msg.msg_out);
#endif
		pids = ctx->pid.id;
		tn   = ctx->sub_pkt->node;

		if (pids == 0) {
			goto next;
		}

		char *sub_topic;
		while (tn) {
			sub_topic = tn->it->topic_filter.body;
			if (sub_topic[0] == '$') {
				if (!strncmp(sub_topic, "$share/",
				        strlen("$share/"))) {
					sub_topic = strchr(sub_topic, '/');
					sub_topic++;
					sub_topic = strchr(sub_topic, '/');
					sub_topic++;
				}
			}

			// Note.
			// We filter all the topics for the options carried by
			// the topic
			if (true ==
			    topic_filter(sub_topic,
			        pub_work->pub_packet->var_header.publish
			            .topic_name.body)) {
				break; // find the topic
			}
			tn = tn->next;
		}
		if (!tn) {
			debug_msg("Not find the topic node");
			goto next;
		}
		sub_qos = tn->it->qos;
		// no local
		if (1 == tn->it->no_local) {
			if (pids == pub_work->pid.id) {
				goto next;
			}
		}

		cvector_push_back(msg_infos, msg_info_buf);
		size_t csize = cvector_size(msg_infos);
		msg_info     = (mqtt_msg_info *) &msg_infos[csize - 1];

		msg_info->pipe = pids;
		msg_info->qos  = sub_qos;

	next:

		if (0 == dbtree_ctxt_free(db_ctxt)) {
			client_ctx *ctx = dbtree_ctxt_delete(db_ctxt);
			if (ctx) {
				del_sub_ctx(ctx, tn->it->topic_filter.body);
			}
		}
	}
	pipe_ct->msg_infos = msg_infos;
}

#if defined(SUPP_RULE_ENGINE)
static bool
payload_filter(pub_packet_struct *pp, rule_engine_info *info)
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

			if (payload->filter && num != atoi(payload->filter)) {
				filter = false;
			} else {
				payload->value = (void *) num;
				payload->type  = cJSON_Number;
			}
			break;
		case cJSON_String:;
			char *str = cJSON_GetStringValue(jp);
			if (payload->filter && strcmp(str, payload->filter)) {
				filter = false;
			} else {
				if (payload->value)
					zfree(payload->value);
				payload->value = zstrdup(str);
				payload->type  = cJSON_String;
			}
			break;
		case cJSON_Object:;
			cJSON *filter = cJSON_Parse(payload->filter);
			if (!payload->is_store && filter && !cJSON_Compare(jp, filter, true)) {
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
rule_engine_filter(nano_work *work, rule_engine_info *info)
{
	pub_packet_struct *pp     = work->pub_packet;
	char              *topic  = pp->var_header.publish.topic_name.body;
	bool               filter = true;
	if (topic_filter(info->topic, topic)) {
		if (info->filter) {
			conn_param *cp = work->cparam;
			for (size_t j = 0; j < 9; j++) {
				char *val = NULL;
				if (j < 8) {
					val = info->filter[j];
				}
				if (val != NULL || j == RULE_PAYLOAD_FIELD) {
					switch (j) {
					case RULE_QOS:
						if (pp->fixed_header.qos !=
						    atoi(val)) {
							filter = false;
						}
						break;
					case RULE_ID:
						if (pp->var_header.publish
						        .packet_id !=
						    atoi(val)) {
							filter = false;
						}
						break;
					case RULE_TOPIC:
						if (strcmp(topic, val)) {
							filter = false;
						}
						break;
					case RULE_CLIENTID:;
						const char *cid = (const char
						        *)
						    conn_param_get_clientid(
						        cp);
						if (cid == NULL ||
						    strcmp(cid, val)) {
							filter = false;
						}
						break;
					case RULE_USERNAME:;
						const char *username =
						    (const char *)
						        conn_param_get_username(
						            cp);
						if (username == NULL ||
						    strcmp(username, val)) {
							filter = false;
						}
						break;
					case RULE_PASSWORD:;
						const char *password =
						    (const char *)
						        conn_param_get_password(
						            cp);
						if (password == NULL ||
						    strcmp(password, val)) {
							filter = false;
						}
						break;
					case RULE_TIMESTAMP:
						// TODO
						// get_timestamp
						// if ( != atoi(val)) {
						// 	filter = false;
						// }
						break;
					case RULE_PAYLOAD_ALL:
						if (!pp->payload.data ||
						    pp->payload.len <= 0) {
							filter = false;
							break;
						}

						if (val != NULL) {
							if (strncmp((const char *) pp->payload.data, val,
							        pp->payload.len)) {
								filter = false;
							}
						}

						break;
					case RULE_PAYLOAD_FIELD:
						if (!pp->payload.data ||
						    pp->payload.len <= 0) {
							filter = false;
							break;
						}

						filter = payload_filter(pp, info);
						break;
					default:
						break;
					}
					if (filter == false) {
						break;
					}
				}
			}
		}
	} else {
		// printf("MISMATCH filter: %s, topic: %s\n", info->topic,
		// topic);
		filter = false;
	}

	return filter;
}

static int
add_info_to_json(rule_engine_info *info, cJSON *jso, int j, nano_work *work)
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
compose_sql_clause(rule_engine_info *info, char *key, char *value, int j, nano_work *work)
{
	pub_packet_struct *pp = work->pub_packet;
	conn_param        *cp = work->cparam;
	static bool is_first_time = true;
	char *ret = NULL;

	if (info->flag[j]) {
		switch (j) {
		case RULE_QOS:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Qos");
			}
			sprintf(value, "%s%d", value, pp->fixed_header.qos);
			break;
		case RULE_ID:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Id");
			}
			sprintf(value, "%s\'%d\'", value, pp->var_header.publish.packet_id);
			break;
		case RULE_TOPIC:;
			char *topic = pp->var_header.publish.topic_name.body;
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Topic");
			}
			sprintf(value, "%s\'%s\'", value, topic);
			break;
		case RULE_CLIENTID:;
			char *cid = (char *) conn_param_get_clientid(cp);
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Clientid");
			}
			sprintf(value, "%s\'%s\'", value, cid);
			break;
		case RULE_USERNAME:;
			char *username = (char *) conn_param_get_username(cp);
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Username");
			}
			sprintf(value, "%s\'%s\'", value, username);
			break;
		case RULE_PASSWORD:;
			char *password = (char *) conn_param_get_password(cp);
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Password");
			}
			sprintf(value, "%s\'%s\'", value, password);
			break;
		case RULE_TIMESTAMP:
			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Timestamp");
			}

			sprintf(value, "%s%lu", value, (unsigned long) time(NULL));
			break;
		case RULE_PAYLOAD_ALL:;
			char *payload = pp->payload.data;

			if (info->as[j]) {
				strcat(key, info->as[j]);
			} else {
				strcat(key, "Payload");
			}

			sprintf(value, "%s\'%s\'", value, payload);
			break;

		case RULE_PAYLOAD_FIELD:

			bool is_need_set = false;
			pthread_mutex_lock(&rule_mutex);
			if (is_first_time) {
				is_first_time = false;
				is_need_set = true;
			}
			pthread_mutex_unlock(&rule_mutex);

			char ret_key[512] = { 0 };
			char *tmp_key = NULL;

			for (int pi = 0; pi < cvector_size(info->payload);
			     pi++) {
				if (info->payload[pi]->is_store) {
					if (info->payload[pi]->pas) {

						switch (info->payload[pi]->type) {
						case cJSON_Number:
								if (is_need_set) {
									snprintf(ret_key, 512, "%s\nALTER TABLE Broker ADD %s INT;", tmp_key, info->payload[pi]->pas);
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								if (strlen(value) > strlen("VALUES (")) {
									sprintf(value, "%s, %ld", value, (long) info->payload[pi]->value);
								} else {
									sprintf(value, "%s %ld", value, (long) info->payload[pi]->value);
								}
							break;
						case cJSON_String:
							if (info->payload[pi]->pas) {
								if (is_need_set) {
									snprintf(ret_key, 512, "%s\nALTER TABLE Broker ADD %s TEXT;", tmp_key, info->payload[pi]->pas);
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								if (strlen(value) > strlen("VALUES (")) {
									sprintf(value, "%s, \'%s\'", value, (char*) info->payload[pi]->value);
								} else {
									sprintf(value, "%s \'%s\'", value, (char*) info->payload[pi]->value);
								}
							}
							break;
						case cJSON_Object:
							if (info->payload[pi]->pas) {
								if (is_need_set) {
									snprintf(ret_key, 512, "%s\nALTER TABLE Broker ADD %s TEXT;", tmp_key, info->payload[pi]->pas);
								}
								strcat(key, info->payload[pi]->pas);
								strcat(key, ", ");
								char *tmp = cJSON_PrintUnformatted((cJSON*) info->payload[pi]->value);
								if (strlen(value) > strlen("VALUES (")) {
									sprintf(value, "%s, \'%s\'", value, tmp);
								} else {
									sprintf(value, "%s \'%s\'", value, tmp);
								}
								cJSON_free(tmp);
							}
							break;
						default:
							break;
						}

						tmp_key = ret_key;


					}
				}
			}

			if (strlen(ret_key)) {
				ret = zstrdup(ret_key);

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

static int
rule_engine_insert_sql(nano_work *work)
{
	rule_engine_info  *rule_infos = work->config->rule_engine;
	size_t             rule_size  = cvector_size(rule_infos);
	pub_packet_struct *pp         = work->pub_packet;
	conn_param        *cp         = work->cparam;

	for (size_t i = 0; i < rule_size; i++) {
		if (rule_engine_filter(work, &rule_infos[i])) {
			switch (work->config->rule_engine_db_option)
			{
			case RULE_ENGINE_FDB:
				cJSON *jso = NULL;
				jso        = cJSON_CreateObject();

				for (size_t j = 0; j < 9; j++) {
					add_info_to_json(&rule_infos[i], jso, j, work);
				}

				char *dest = cJSON_PrintUnformatted(jso);
				// puts(dest);
				fdb_transaction_set(work->config->tran,
				    pp->var_header.publish.topic_name.body,
				    pp->var_header.publish.topic_name.len, dest,
				    strlen(dest));
				FDBFuture *f =
				    fdb_transaction_commit(work->config->tran);

				fdb_future_destroy(f);
				cJSON_free(dest);
				cJSON_Delete(jso);
				break;
			
			case RULE_ENGINE_SDB:
				char sql_clause[1024] = "INSERT INTO ";
				char key[128] = "Broker (";
				char value[800] = "VALUES (";
				for (size_t j = 0; j < 9; j++) {
					char *ret =
					    compose_sql_clause(&rule_infos[i],
					        key, value, j, work);
					if (ret) {
						puts(ret);
						sqlite3 *sdb =
						    (sqlite3 *)
						        work->config->sdb;
						char *err_msg = NULL;
						int   rc = sqlite3_exec(sdb,
						      ret, 0, 0,
						      &err_msg);
						// FIXME: solve in a more elegant way
						// if (rc != SQLITE_OK) {
						// 	if (strcmp)
						// 	fprintf(stderr,
						// 	    "SQL error: %s\n",
						// 	    err_msg);
						// 	sqlite3_free(err_msg);
						// 	sqlite3_close(sdb);
						// 	return 1;
						// }
						zfree(ret);
						ret = NULL;
					}
				}
				char *p = strrchr(key, ',');
				*p = ')';
				p = strrchr(value, ',');
				*p = ')';
				strcat(sql_clause, key);
				strcat(sql_clause, value);
				strcat(sql_clause, ";");

				// puts(sql_clause);
				sqlite3 *sdb = (sqlite3 *) work->config->sdb;
				char *err_msg = NULL;
				int rc = sqlite3_exec(sdb, sql_clause, 0, 0, &err_msg);
				if (rc != SQLITE_OK ) {
  					fprintf(stderr, "SQL error: %s\n", err_msg);
  					sqlite3_free(err_msg);        
  					sqlite3_close(sdb);
        
        			return 1;
    			} 

				break;
			
			default:
				break;
			}
		}
	}

	return 0;
}
#endif

reason_code
handle_pub(nano_work *work, struct pipe_content *pipe_ct, uint8_t proto)
{
	reason_code result          = SUCCESS;
	char      **topic_queue     = NULL;
	void      **cli_ctx_list    = NULL;
	void      **shared_cli_list = NULL;
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
		debug_msg("decode message failed.");
		return result;
	}

	if (PUBLISH != work->pub_packet->fixed_header.packet_type) {
		return result;
	}

	// deal with topic alias
	if (proto == PROTOCOL_VERSION_v5) {
		property_data *pdata = property_get_value(
		    work->pub_packet->var_header.publish.properties,
		    TOPIC_ALIAS);
		if (work->pub_packet->var_header.publish.topic_name.len > 0) {
			if (pdata) {
				dbhash_insert_atpair(work->pid.id,
				    pdata->p_value.u16,
				    work->pub_packet->var_header.publish
				        .topic_name.body);
			}
		} else {
			if (pdata) {
				const char *tp = dbhash_find_atpair(
				    work->pid.id, pdata->p_value.u16);
				if (tp) {
					work->pub_packet->var_header.publish
					    .topic_name.body = strdup(tp);
					work->pub_packet->var_header.publish
					    .topic_name.len = strlen(tp);
				} else {
					debug_msg("ERROR: could not find "
					          "topic by alias: %d",
					    pdata->p_value.u16);
					return result;
				}
			}
		}
	}

	topic = work->pub_packet->var_header.publish.topic_name.body;
	if (topic == NULL) {
		debug_msg("ERROR: Topic is NULL");
		return result;
	}

#if defined(SUPP_RULE_ENGINE)
	if (work->config->rule_engine_option == RULE_ENGINE_ON) {
		rule_engine_insert_sql(work);
	}
#endif

	cli_ctx_list = dbtree_find_clients(work->db, topic);

	shared_cli_list = dbtree_find_shared_sub_clients(work->db, topic);

#ifdef STATISTICS
	if (cli_ctx_list == NULL && shared_cli_list == NULL) {
		nng_atomic_inc64(g_msg.msg_drop);
	}
#endif

	if (cli_ctx_list != NULL) {
		foreach_client(cli_ctx_list, work, pipe_ct);
	}
	debug_msg("pipe_info size: [%ld]", cvector_size(cli_ctx_list));
	cvector_free(cli_ctx_list);

	if (shared_cli_list != NULL) {
		foreach_client(shared_cli_list, work, pipe_ct);
	}
	cvector_free(shared_cli_list);

#if ENABLE_RETAIN
	handle_pub_retain(work, topic);
#endif
	return result;
}

#if ENABLE_RETAIN
static void inline handle_pub_retain(const nano_work *work, char *topic)
{
	dbtree_retain_msg *retain = NULL;

	if (work->pub_packet->fixed_header.retain) {
		dbtree_retain_msg *r = NULL;

		if (work->pub_packet->payload.len > 0) {
			retain = nng_alloc(sizeof(dbtree_retain_msg));
			if (retain == NULL) {
				return;
			}
			retain->qos = work->pub_packet->fixed_header.qos;
			nng_msg_clone(work->msg);

			property *prop  = NULL;
			retain->message = work->msg;
			retain->exist   = true;
			retain->m       = NULL;
			// reserve property info
			if (work->proto_ver == PROTOCOL_VERSION_v5 &&
			    work->pub_packet->var_header.publish.properties !=
			        NULL) {
				property_dup(&prop,
				    work->pub_packet->var_header.publish
				        .properties);
				nng_msg_proto_set_property(
				    retain->message, (void *) prop);
			}
			debug_msg("found retain [%p], message: [%p][%p]\n",
			    retain, retain->message,
			    nng_msg_payload_ptr(retain->message));
			r = dbtree_insert_retain(work->db_ret, topic, retain);
		} else {
			debug_msg("delete retain message");
			r = dbtree_delete_retain(work->db_ret, topic);
		}
		dbtree_retain_msg *ret = (dbtree_retain_msg *) r;

		if (ret != NULL) {
			if (ret->message) {
				nng_msg_free(ret->message);
			}
			nng_free(ret, sizeof(dbtree_retain_msg));
			ret = NULL;
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
				debug_msg("free topic");
			}

			if (pub_packet->var_header.publish.prop_len > 0) {
				property_free(
				    pub_packet->var_header.publish.properties);
				pub_packet->var_header.publish.prop_len = 0;
				debug_msg("free properties");
			}

			if (pub_packet->payload.len > 0 &&
			    pub_packet->payload.data != NULL) {
				nng_free(pub_packet->payload.data,
				    pub_packet->payload.len + 1);
				pub_packet->payload.data = NULL;
				pub_packet->payload.len  = 0;
				debug_msg("free payload");
			}
		}

		nng_free(pub_packet, sizeof(struct pub_packet_struct));
		pub_packet = NULL;
		debug_msg("free pub_packet");
	}
}

void
free_msg_infos(mqtt_msg_info *msg_infos)
{
	if (msg_infos != NULL) {
		zfree(msg_infos);
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

bool
encode_pub_message(
    nng_msg *dest_msg, const nano_work *work, mqtt_control_packet_types cmd)
{
	uint8_t  tmp[4]     = { 0 };
	uint32_t arr_len    = 0;
	int      append_res = 0;
	uint8_t  proto      = 0;
	uint32_t buf;

	debug_msg("start encode message");

	nng_msg_clear(dest_msg);
	nng_msg_header_clear(dest_msg);
	if (nng_msg_cmd_type(dest_msg) == CMD_PUBLISH_V5) {
		proto = PROTOCOL_VERSION_v5;
	} else if (nng_msg_cmd_type(dest_msg) == CMD_PUBLISH) {
		proto = PROTOCOL_VERSION_v311;
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
		debug_msg("after topic and id len in msg already [%ld]",
		    nng_msg_len(dest_msg));

#if SUPPORT_MQTT5_0
		if (PROTOCOL_VERSION_v5 == proto) {
			if (encode_properties(dest_msg,
			        work->pub_packet->var_header.publish
			            .properties,
			        CMD_PUBLISH) != 0) {
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

		debug_msg("after payload len in msg already [%ld]",
		    nng_msg_len(dest_msg));

		work->pub_packet->fixed_header.remain_len =
		    nng_msg_len(dest_msg);
		arr_len = put_var_integer(
		    tmp, work->pub_packet->fixed_header.remain_len);
		append_res = nng_msg_header_append(dest_msg, tmp, arr_len);
		nng_msg_set_remaining_len(
		    dest_msg, work->pub_packet->fixed_header.remain_len);
		debug_msg("header len [%ld] remain len [%d]\n",
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
		debug_msg("encode %d message", cmd);
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
			if (PROTOCOL_VERSION_v5 == proto) { }
#endif
		}
		break;
	default:
		break;
	}

	debug_msg("end encode message");
	return true;
}

reason_code
decode_pub_message(nano_work *work, uint8_t proto)
{
	uint32_t pos      = 0;
	uint32_t used_pos = 0;
	uint32_t len, len_of_varint;

	nng_msg                  *msg        = work->msg;
	struct pub_packet_struct *pub_packet = work->pub_packet;

	uint8_t *msg_body = nng_msg_body(msg);
	size_t   msg_len  = nng_msg_len(msg);

	// print_hex("", msg_body, msg_len);

	pub_packet->fixed_header =
	    *(struct fixed_header *) nng_msg_header(msg);
	pub_packet->fixed_header.remain_len = nng_msg_remaining_len(msg);

	debug_msg(
	    "cmd: %d, retain: %d, qos: %d, dup: %d, remaining length: %d",
	    pub_packet->fixed_header.packet_type,
	    pub_packet->fixed_header.retain, pub_packet->fixed_header.qos,
	    pub_packet->fixed_header.dup, pub_packet->fixed_header.remain_len);

	if (pub_packet->fixed_header.remain_len > msg_len) {
		debug_msg("ERROR: remainlen > msg_len");
		return PROTOCOL_ERROR;
	}

	switch (pub_packet->fixed_header.packet_type) {
	case PUBLISH:
		// variable header
		// topic length
		NNI_GET16(msg_body + pos,
		    pub_packet->var_header.publish.topic_name.len);
		pub_packet->var_header.publish.topic_name.body =
		    (char *) copy_utf8_str(msg_body, &pos, &len);

		if (pub_packet->var_header.publish.topic_name.len > 0 &&
		    pub_packet->var_header.publish.topic_name.body != NULL) {
			if (strchr(
			        pub_packet->var_header.publish.topic_name.body,
			        '+') != NULL ||
			    strchr(
			        pub_packet->var_header.publish.topic_name.body,
			        '#') != NULL) {

				// protocol error
				debug_msg(
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

		debug_msg("topic: [%.*s], qos: %d",
		    pub_packet->var_header.publish.topic_name.len,
		    pub_packet->var_header.publish.topic_name.body,
		    pub_packet->fixed_header.qos);

		if (pub_packet->fixed_header.qos > 0) {
			NNI_GET16(msg_body + pos,
			    pub_packet->var_header.publish.packet_id);
			debug_msg("identifier: [%d]",
			    pub_packet->var_header.publish.packet_id);
			pos += 2;
		}
		used_pos = pos;

		if (PROTOCOL_VERSION_v5 == proto) {
			pub_packet->var_header.publish.properties =
			    decode_properties(msg, &pos,
			        &pub_packet->var_header.publish.prop_len,
			        false);
			debug_msg("property len: %d",
			    pub_packet->var_header.publish.prop_len);

			if (pub_packet->var_header.publish.properties) {
				if (check_properties(
				        pub_packet->var_header.publish
				            .properties) != 0 ||
				    property_get_value(pub_packet->var_header
				                           .publish.properties,
				        SUBSCRIPTION_IDENTIFIER) != NULL) {
					return PROTOCOL_ERROR;
				}
			}
		}

		if (pos > msg_len) {
			debug_msg("buffer-overflow: pos = %u, msg_len = %lu",
			    pos, msg_len);
			return PROTOCOL_ERROR;
		}

		used_pos = pos;
		debug_msg("used pos: [%d]", used_pos);
		// payload
		pub_packet->payload.len =
		    (uint32_t) (msg_len - (size_t) used_pos);

		if (pub_packet->payload.len > 0) {
			pub_packet->payload.data =
			    nng_zalloc(pub_packet->payload.len + 1);
			memcpy(pub_packet->payload.data,
			    (uint8_t *) (msg_body + pos),
			    pub_packet->payload.len);
			debug_msg("payload: [%s], len = %u",
			    pub_packet->payload.data, pub_packet->payload.len);
		}
		break;

	case PUBACK:
	case PUBREC:
	case PUBREL:
	case PUBCOMP:
		// here could not be reached
		NNI_GET16(msg_body, pub_packet->var_header.pub_arrc.packet_id);
		if (PROTOCOL_VERSION_v5 == proto) {
			pos += 2;
			pub_packet->var_header.pub_arrc.reason_code =
			    *(msg_body + pos);
			pos++;
			pub_packet->var_header.pub_arrc.properties =
			    decode_properties(msg, &pos,
			        &pub_packet->var_header.pub_arrc.prop_len,
			        false);
			if (check_properties(
			        pub_packet->var_header.pub_arrc.properties) !=
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
		sprintf(szTmp, "%02X ", src[i]);
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
			debug_msg("alloc fail!");
			return;
		}
		dest = bytes_to_str(src, dest, src_len);

		debug_msg("%s%s", prefix, dest);

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
		property_data *data =
		    property_get_value(prop, MESSAGE_EXPIRY_INTERVAL);
		if (data && ntime > rtime + data->p_value.u32 * 1000) {
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
