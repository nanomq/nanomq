//
// Copyright 2023 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "include/webhook_inproc.h"
#include "nanomq.h"
#include "nng/nng.h"
#include "nng/protocol/pipeline0/pull.h"
#include "nng/protocol/pipeline0/push.h"
#include "nng/supplemental/http/http.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/utils.h"
#include "nng/supplemental/util/platform.h"

#include "nng/mqtt/mqtt_client.h"
#include "file_transfer.h"

#ifdef SUPP_PARQUET
#include "nng/supplemental/nanolib/parquet.h"
#endif

#define NANO_LMQ_INIT_CAP 16

#define HOOK_TMPFNAME ".nanomq-exchange-msgs-formd5"

// The server keeps a list of work items, sorted by expiration time,
// so that we can use this to set the timeout to the correct value for
// use in poll.
struct hook_work {
	enum { HOOK_INIT, HOOK_RECV, HOOK_WAIT, HOOK_SEND } state;
	nng_aio *      aio;
	nng_msg *      msg;
	nng_thread *   thread;
	nng_mtx *      mtx;
	nng_lmq *      lmq;
	nng_socket     sock;
	conf_web_hook *conf;
	uint32_t       id;
	bool           busy;
	conf_exchange *exchange;
	conf_parquet  *parquet;
	nng_socket    *mqtt_sock;
};

static void hook_work_cb(void *arg);

static nng_thread     *hook_thr;
static nng_atomic_int *hook_search_limit     = NULL;
static nng_aio        *hook_search_reset_aio = NULL;

static int
send_mqtt_msg_cat(nng_socket *sock, char *tmpfpath, nng_msg **msgs, uint32_t len,
		char *ruleid, uint64_t start_key, uint64_t end_key)
{
	int rv;
	nng_msg *pubmsg;
	uint32_t sz = 0;
	for (int i=0; i<len; ++i) {
		uint32_t diff;
		diff = nng_msg_len(msgs[i]) -
			((uintptr_t)nng_msg_payload_ptr(msgs[i]) - (uintptr_t) nng_msg_body(msgs[i]));
		sz += diff;
	}
	char *buf = nng_alloc(sizeof(char) * sz);
	int   pos = 0;
	for (int i=0; i<len; ++i) {
		uint32_t diff;
		diff = nng_msg_len(msgs[i]) -
			((uintptr_t)nng_msg_payload_ptr(msgs[i]) - (uintptr_t) nng_msg_body(msgs[i]));
		if (sz >= pos + diff)
			memcpy(buf + pos, nng_msg_payload_ptr(msgs[i]), diff);
		else
			log_error("buffer overflow!");
		pos += diff;
	}

	char *md5sum;
	if (0 != CalcMD5n(buf, pos, tmpfpath, &md5sum)) {
		nng_msg_free(pubmsg);
		nng_free(buf, pos);
		return -1;
	}
	char *topic = malloc(sizeof(char) *(strlen(md5sum) + 128));
	sprintf(topic, "$file/upload/MQ/%s/%s/%s-%lld-%lld",
		ruleid, md5sum, "VIN", start_key, end_key);
	log_info("The %ld msgs will go to topic %s", len, topic);

	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_qos(pubmsg, 1);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(pubmsg, (uint8_t *) buf, pos);
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		log_error("nng_sendmsg", rv);
	}
	nng_free(buf, pos);
	nng_free(topic, 0);
	nng_free(md5sum, 0);
	return rv;
}

#ifdef SUPP_PARQUET

static char *
get_file_bname(char *fpath)
{
        char * bname;
#ifdef _WIN32
        if ((bname = malloc(strlen(fpath)+16)) == NULL) return NULL;
        char ext[16];
        _splitpath_s(fpath,
                NULL, 0,    // Don't need drive
                NULL, 0,    // Don't need directory
                bname, strlen(fpath) + 15,  // just the filename
                ext  , 15);
        strncpy(bname+strlen(bname), ext, 15);
#else
		#include <libgen.h>
        // strcpy(bname, basename(fpath));
        bname = basename(fpath);
#endif
        return bname;
}

static int
send_mqtt_msg_result(nng_socket *sock, char *ruleid, cJSON *resjo)
{
	int rv;
	char *buf = cJSON_PrintUnformatted(resjo);

	char *topic = nng_alloc(sizeof(char) * (strlen(ruleid) + 40));
	sprintf(topic, "$file/upload/parquetfile/%s/result", ruleid);

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, 0);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) buf, strlen(buf));
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	log_info("Publish result to '%s' '%s'", topic, buf);

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		log_error("nng_sendmsg", rv);
		return rv;
	}

	nng_free(topic, 0);
	free(buf);
	return 0;
}

static int
send_mqtt_msg_file(nng_socket *sock, const char *topic, const char **fpaths, uint32_t len, char * ruleid)
{
	int rv;
	const char ** filenames = malloc(sizeof(char *) * len);
	char tbuf[MD5_LEN + strlen(ruleid) + 65];
	const char **topics = malloc(sizeof(char *) * len);
	int  *delete = malloc(sizeof(int) * len);
	for (int i=0; i<len; ++i) {
		char md5sum[MD5_LEN+1];
		if (1 != CalcFileMD5((char *)fpaths[i], md5sum)) {
			log_error("error in getting md5sum(%s)", fpaths[i]);
			continue;
		}
		filenames[i] = get_file_bname((char *)fpaths[i]);
		sprintf(tbuf, "$file/upload/parquetfile/%s/%s/%s",
			ruleid, md5sum, filenames[i]);
		topics[i] = strdup(tbuf);
		delete[i] = -1;
	}

	// Create a json as payload to trigger file transport
	cJSON *obj = cJSON_CreateObject();
	cJSON *files_obj = cJSON_CreateStringArray(fpaths, len);
	cJSON_AddItemToObject(obj, "files", files_obj);
	if (!files_obj)
		return -1;

	cJSON *filenames_obj = cJSON_CreateStringArray(filenames, len);
	if (!filenames_obj)
		return -1;
	cJSON_AddItemToObject(obj, "filenames", filenames_obj);

	cJSON *topics_obj = cJSON_CreateStringArray(topics, len);
	if (!topics_obj)
		return -1;
	cJSON_AddItemToObject(obj, "topics", topics_obj);

	cJSON * delete_obj = cJSON_CreateIntArray(delete, len);
	if (!delete_obj)
		return -1;
	cJSON_AddItemToObject(obj, "delete", delete_obj);

	char *buf = cJSON_PrintUnformatted(obj);

	cJSON_Delete(obj);
	for (int i=0; i<len; ++i) {
		free((void *)topics[i]);
	}
	free(filenames);
	free(topics);
	free(delete);

	// create a PUBLISH message
	nng_msg *pubmsg;
	nng_mqtt_msg_alloc(&pubmsg, 0);
	nng_mqtt_msg_set_packet_type(pubmsg, NNG_MQTT_PUBLISH);
	nng_mqtt_msg_set_publish_dup(pubmsg, 0);
	nng_mqtt_msg_set_publish_qos(pubmsg, 0);
	nng_mqtt_msg_set_publish_retain(pubmsg, 0);
	nng_mqtt_msg_set_publish_payload(
	    pubmsg, (uint8_t *) buf, strlen(buf));
	nng_mqtt_msg_set_publish_topic(pubmsg, topic);

	log_info("Publishing to '%s' '%s'", topic, buf);

	if ((rv = nng_sendmsg(*sock, pubmsg, NNG_FLAG_ALLOC)) != 0) {
		log_error("nng_sendmsg", rv);
	}
	free(buf);

	return rv;
}

#endif

static void
send_msg(conf_web_hook *conf, nng_msg *msg)
{
	nng_http_client *client = NULL;
	nng_http_conn *  conn   = NULL;
	nng_url *        url    = NULL;
	nng_aio *        aio    = NULL;
	nng_http_req *   req    = NULL;
	nng_http_res *   res    = NULL;
	int              rv;

	if (((rv = nng_url_parse(&url, conf->url)) != 0) ||
	    ((rv = nng_http_client_alloc(&client, url)) != 0) ||
	    ((rv = nng_http_req_alloc(&req, url)) != 0) ||
	    ((rv = nng_http_res_alloc(&res)) != 0) ||
	    ((rv = nng_aio_alloc(&aio, NULL, NULL)) != 0)) {
		log_error("init failed: %s\n", nng_strerror(rv));
		goto out;
	}

	// Start connection process...
	nng_aio_set_timeout(aio, 1000);
	nng_http_client_connect(client, aio);

	// Wait for it to finish.
	nng_aio_wait(aio);

	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("Webhook connect failed: %s", nng_strerror(rv));
		nng_aio_finish_sync(aio, rv);
		goto out;
	}

	// Get the connection, at the 0th output.
	conn = nng_aio_get_output(aio, 0);

	// Request is already set up with URL, and for GET via HTTP/1.1.
	// The Host: header is already set up too.
	// set_data(req, conf_req, params);
	// Send the request, and wait for that to finish.
	for (size_t i = 0; i < conf->header_count; i++) {
		nng_http_req_add_header(
		    req, conf->headers[i]->key, conf->headers[i]->value);
	}

	nng_http_req_set_method(req, "POST");
	nng_http_req_set_data(req, nng_msg_body(msg), nng_msg_len(msg));
	nng_http_conn_write_req(conn, req, aio);
	nng_aio_set_timeout(aio, 1000);
	nng_aio_wait(aio);
	log_debug("webhook post result %d", nng_aio_result(aio));

	if ((rv = nng_aio_result(aio)) != 0) {
		log_error("Write req failed: %s", nng_strerror(rv));
		nng_aio_finish_sync(aio, rv);
		goto out;
	}

out:
	if (url) {
		nng_url_free(url);
	}
	if (conn) {
		nng_http_conn_close(conn);
	}
	if (client) {
		nng_http_client_free(client);
	}
	if (req) {
		nng_http_req_free(req);
	}
	if (res) {
		nng_http_res_free(res);
	}
	if (aio) {
		nng_aio_free(aio);
	}
}

// an independent thread of each work obj for sending HTTP msg
static void
thread_cb(void *arg)
{
	struct hook_work *w   = arg;
	nng_lmq *         lmq = w->lmq;
	nng_msg *         msg = NULL;
	int               rv;

	while (true) {
		if (!nng_lmq_empty(lmq)) {
			nng_mtx_lock(w->mtx);
			rv = nng_lmq_get(lmq, &msg);
			nng_mtx_unlock(w->mtx);
			if (0 != rv)
				continue;
			// send webhook http requests
			send_msg(w->conf, msg);
			nng_msg_free(msg);
		} else {
			// try to reduce lmq cap
			size_t lmq_len = nng_lmq_len(w->lmq);
			if (lmq_len > (NANO_LMQ_INIT_CAP * 2)) {
				size_t lmq_cap = nng_lmq_cap(w->lmq);
				if (lmq_cap > (lmq_len * 2)) {
					nng_mtx_lock(w->mtx);
					nng_lmq_resize(w->lmq, lmq_cap / 2);
					nng_mtx_unlock(w->mtx);
				}
			}
			nng_msleep(10);
		}
	}
}

static void
hook_work_cb(void *arg)
{
	struct hook_work *work = arg;
	int               rv;
	char *            body;
	conf_exchange *   exconf = work->exchange;
	conf_parquet *    parquetconf = work->parquet;
	nng_msg *         msg;
	cJSON *           root;

	switch (work->state) {
	case HOOK_INIT:
		work->state = HOOK_RECV;
		// get MQTT msg from broker via inproc aio
		nng_recv_aio(work->sock, work->aio);
		break;

	case HOOK_RECV:
		if ((rv = nng_aio_result(work->aio)) != 0) {
			NANO_NNG_FATAL("nng_recv_aio", rv);
		}

		// differ msg of webhook and MQ (cmd) by prefix of body
		work->msg = nng_aio_get_msg(work->aio);

		msg = work->msg;
		body = (char *) nng_msg_body(msg);

		root = NULL;
		// TODO Not efficent
		// Only parse msg when exchange is enabled
		root = cJSON_Parse(body);
		if (!root) {
			// not a json
			nng_msg_free(msg);
			work->state = HOOK_RECV;
			nng_recv_aio(work->sock, work->aio);
			break;
		}
		cJSON *idjo = cJSON_GetObjectItem(root, "id");
		if (!idjo) {
			cJSON_Delete(root);
			root = NULL;
		}
		if (root && idjo) {
			char *idstr = NULL;
			idstr = idjo->valuestring;
			if (idstr) {
				if (strcmp(idstr, EXTERNAL2NANO_IPC) == 0) {
					cJSON_Delete(root);
					root = NULL;
					int l = nng_atomic_dec_nv(hook_search_limit);
					if (l < 0) {
						log_warn("Hook searching too frequently");
						// Ignore, start next recv
						nng_msg_free(msg);
						work->state = HOOK_RECV;
						nng_recv_aio(work->sock, work->aio);
						break;
					}
					work->state = HOOK_WAIT;
					nng_aio_finish(work->aio, 0);
					break;
				}
			}
			cJSON_Delete(root);
			root = NULL;
		}

		// TODO If it's a msg to webhook???
		nng_mtx_lock(work->mtx);
		if (nng_lmq_full(work->lmq)) {
			size_t lmq_cap = nng_lmq_cap(work->lmq);
			if ((rv = nng_lmq_resize(
			         work->lmq, lmq_cap + (lmq_cap / 2))) != 0) {
				NANO_NNG_FATAL("nng_lmq_resize mem error", rv);
			}
		}
		nng_lmq_put(work->lmq, work->msg);
		nng_mtx_unlock(work->mtx);
		work->msg   = NULL;
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	case HOOK_WAIT:
		// Search on MQ and Parquet
		work->msg = nng_aio_get_msg(work->aio);
		msg       = work->msg;
		work->msg = NULL;

		if (exconf->count == 0) {
			log_error("Exchange is not enabled");
			nng_msg_free(msg);

			// Start next recv
			work->state = HOOK_RECV;
			nng_recv_aio(work->sock, work->aio);
			break;
		}

		nng_aio *aio;
		nng_aio_alloc(&aio, NULL, NULL);

		// TODO match exchange with IPC msg (by MQ name)
		nng_socket *ex_sock = exconf->nodes[0]->sock;

		body = (char *) nng_msg_body(msg);

		root = cJSON_Parse(body);
		cJSON *cmdjo = cJSON_GetObjectItem(root,"cmd");
		char *cmdstr = NULL;
		if (cmdjo)
			cmdstr = cmdjo->valuestring;
		if (cmdstr) {
			if (0 == strcmp(cmdstr, "write")) {
				log_warn("Write cmd is not supported");
				goto skip;
			} else if (0 == strcmp(cmdstr, "search")) {
				log_debug("Search is triggered");
			} else if (0 == strcmp(cmdstr, "stop")) {
				log_info("Stop is triggered");
				nng_msg *m;
				nng_msg_alloc(&m, 0);
				if (!m) {
					log_error("Error in alloc memory");
					goto skip;
				}

				nng_time *tss = NULL;
				tss = nng_alloc(sizeof(nng_time) * 3);
				tss[0] = 0;
				tss[1] = 9223372036854775807; // big enough
				tss[2] = 1;
				nng_msg_set_proto_data(m, NULL, (void *)tss);
				nng_aio_set_msg(aio, m);
				// Do clean on MQ
				nng_recv_aio(*ex_sock, aio);
				nng_aio_wait(aio);
				if (nng_aio_result(aio) != 0)
					log_warn("error in clean msgs on exchange");
				nng_msg_free(m);
				nng_free(tss, 0);

				nng_msg **msgs_res = (nng_msg **)nng_aio_get_msg(aio);
				uint32_t  msgs_len = (uintptr_t)nng_aio_get_prov_data(aio);
				log_info("Parquet & MQ Service stopped and free %d msgs", msgs_len);
				if (msgs_len > 0 && msgs_res != NULL) {
					for (int i=0; i<msgs_len; ++i)
						nng_msg_free(msgs_res[i]);
				}
				nng_free(msgs_res, sizeof(nng_msg *) * msgs_len);
	
				goto skip;
			} else {
				log_warn("Invalid cmd");
				goto skip;
			}
		} else {
			log_warn("No cmd field found in json msg");
			goto skip;
		}

		cJSON *ruleidjo = cJSON_GetObjectItem(root,"ruleid");
		if (!cJSON_IsString(ruleidjo)) {
			log_warn("No ruleid field found in json msg");
			goto skip;
		}
		char *ruleidstr = ruleidjo->valuestring;
		if (!ruleidstr) {
			log_warn("Error in parsing json ruleid");
			goto skip;
		}
		log_info("cmd %s ruleid %s", cmdstr, ruleidstr);

		cJSON *rgjo;
		cJSON *rgsjo = cJSON_GetObjectItem(root, "ranges");
		if (!rgsjo) {
			log_warn("No ranges field found in json msg");
			goto skip;
		}

		char **sent_files = NULL;

		cJSON *resjo = NULL;
#ifdef SUPP_PARQUET
		// result json only valid when parquet is enabled
		resjo = cJSON_CreateObject();
		if (cJSON_AddStringToObject(resjo, "ruleid", ruleidstr) == NULL) {
			log_warn("Failed to add ruleid to result json");
			goto skip;
		}

		cJSON *resrgsjo = cJSON_AddArrayToObject(resjo, "ranges");
		if (resrgsjo == NULL) {
			log_warn("Failed to add ranges to result json");
			goto skip;
		}
#endif

		cJSON_ArrayForEach(rgjo, rgsjo) {
			char    *skeystr = NULL;
			char    *ekeystr = NULL;
			uint64_t start_key;
			uint64_t end_key;

			cJSON *skeyjo = cJSON_GetObjectItem(rgjo, "start_key");
			cJSON *ekeyjo = cJSON_GetObjectItem(rgjo, "end_key");
			if (!cJSON_IsString(skeyjo) || !cJSON_IsString(ekeyjo)) {
				log_warn("No start/end key field found in json msg");
				goto skip;
			}
			skeystr = skeyjo->valuestring;
			ekeystr = ekeyjo->valuestring;
			if (!skeystr || !ekeystr) {
				log_warn("Invalid start/end key field found in json msg");
				goto skip;
			}

			rv = sscanf(skeystr, "%" SCNu64, &start_key);
			if (rv == 0) {
				log_error("error in read start_key to number %s", skeystr);
				goto skip;
			}
			rv = sscanf(ekeystr, "%" SCNu64, &end_key);
			if (rv == 0) {
				log_error("error in read end_key to number %s", ekeystr);
				goto skip;
			}

			nng_msg *m;
			nng_msg_alloc(&m, 0);
			if (!m) {
				log_error("Error in alloc memory");
				goto skip;
			}

			nng_time *tss = NULL;
			// When end key > start key. Fuzzing search.
			if (end_key > start_key) {
				tss = nng_alloc(sizeof(nng_time) * 3);
				tss[0] = start_key;
				tss[1] = end_key;
				tss[2] = 0;
				nng_msg_set_proto_data(m, NULL, (void *)tss);
			} else if (end_key == start_key) {
				// normal search
				nng_msg_set_timestamp(m, start_key);
			} else {
				// Invalid json
				log_warn("SKip. start key is greater than end key. It's not allowed");
			}

			log_info("start_key %lld end_key %lld", start_key, end_key);

			nng_aio_set_msg(aio, m);
			// search msgs from MQ
			nng_recv_aio(*ex_sock, aio);

			nng_aio_wait(aio);
			if (nng_aio_result(aio) != 0)
				log_warn("error in taking msgs from exchange");
			nng_msg_free(m);
			if (end_key > start_key)
				nng_free(tss, 0);

			nng_msg **msgs_res = (nng_msg **)nng_aio_get_msg(aio);
			uint32_t  msgs_len = (uintptr_t)nng_aio_get_prov_data(aio);

			// Get msgs and send to localhost:port to active handler
			if (msgs_len > 0 && msgs_res != NULL) {
				// TODO NEED Clone before took from exchange instead of here
				for (int i=0; i<msgs_len; ++i)
					nng_msg_clone(msgs_res[i]);

				size_t dirlen = strlen(parquetconf->dir) + strlen(HOOK_TMPFNAME) + 2;
				char * tmpfpath = malloc(sizeof(char) * dirlen);
				if (parquetconf->enable == false || parquetconf->dir == NULL) {
					sprintf(tmpfpath, "/tmp/%s", HOOK_TMPFNAME);
				} else {
					if (parquetconf->dir[strlen(parquetconf->dir)-1] == '/')
						sprintf(tmpfpath, "%s%s", parquetconf->dir, HOOK_TMPFNAME);
					else
						sprintf(tmpfpath, "%s/%s", parquetconf->dir, HOOK_TMPFNAME);
				}

				log_info("Publish %ld msgs from exchange (%s)", msgs_len, tmpfpath);

				send_mqtt_msg_cat(work->mqtt_sock, tmpfpath, msgs_res, msgs_len,
					ruleidstr, start_key, end_key);

				for (int i=0; i<msgs_len; ++i)
					nng_msg_free(msgs_res[i]);
				nng_free(msgs_res, sizeof(nng_msg *) * msgs_len);
				nng_free(tmpfpath, 0);
			}
#ifdef SUPP_PARQUET
			// Get file names and send to localhost to active handler
			const char **fnames = NULL;
			uint32_t sz = 0;
			if (end_key > start_key) {
				// fuzzing search
				fnames = parquet_find_span(start_key, end_key, &sz);
			} else if (end_key == start_key) {
				// normal search
				const char *fname = parquet_find(start_key);
				if (fname) {
					sz = 1;
					fname = malloc(sizeof(char *) * sz);
					fnames[0] = fname;
				}
			} else {
				// Invalid json
				log_warn("SKip. start key is greater than end key. It's not allowed");
			}
			if (fnames) {
				if (sz > 0) {
					log_info("Ask parquet and found.");
					// Preqare range result
					cJSON *resrgjo = cJSON_CreateObject();
					if (resrgjo == NULL) {
						log_error("Error in create range json for result");
						continue;
					}
					cJSON_AddItemToArray(resrgsjo, resrgjo);
					cJSON *resskeyjo = cJSON_CreateString(skeystr);
					cJSON *resekeyjo = cJSON_CreateString(ekeystr);
					if (resskeyjo == NULL || resekeyjo == NULL) {
						log_error("Error in create start/end key json for result");
						continue;
					}
					cJSON_AddItemToObject(resrgjo, "start_key", resskeyjo);
					cJSON_AddItemToObject(resrgjo, "end_key", resekeyjo);

					const char **fnames_new = NULL;
					for (int i=0; i<sz; i++) {
						// Deduplicate
						int exist = 0;
						for (int j=0; j<cvector_size(sent_files); j++) {
							if (0 == strcmp(sent_files[j], fnames[i])) {
								exist = 1;
								log_info("Deduplicate %s.", fnames[i]);
								break;
							}
						}
						if (exist == 0) {
							char *fname = strdup(fnames[i]);
							cvector_push_back(fnames_new, fname);
							cvector_push_back(sent_files, fname);
						}
					}
					if (fnames_new) {
						send_mqtt_msg_file(work->mqtt_sock, "file_transfer",
							fnames_new, cvector_size(fnames_new), ruleidstr);
						cvector_free(fnames_new);
					}
				}
				for (int i=0; i<(int)sz; ++i)
					nng_free((void *)fnames[i], 0);
				nng_free(fnames, sz);
			}
#endif
		}

		send_mqtt_msg_result(work->mqtt_sock, ruleidstr, resjo);

		int sent_files_sz = cvector_size(sent_files);
		for (int i=sent_files_sz-1; i>=0; --i)
			free(sent_files[i]);
		if (sent_files_sz > 0)
			cvector_free(sent_files);

skip:
		if (resjo)
			cJSON_Delete(resjo);
		nng_aio_free(aio);

		cJSON_Delete(root);
		root = NULL;
		nng_msg_free(msg);
		// Start next recv
		work->state = HOOK_RECV;
		nng_recv_aio(work->sock, work->aio);
		break;
	default:
		NANO_NNG_FATAL("bad state!", NNG_ESTATE);
		break;
	}
}

static nng_msg *
create_connect_msg()
{
	// create a CONNECT message
	/* CONNECT */
	nng_msg *connmsg;
	nng_mqtt_msg_alloc(&connmsg, 0);
	nng_mqtt_msg_set_packet_type(connmsg, NNG_MQTT_CONNECT);
	nng_mqtt_msg_set_connect_proto_version(connmsg, 4);
	nng_mqtt_msg_set_connect_client_id(connmsg, "hook-trigger");
	nng_mqtt_msg_encode(connmsg);
	return connmsg;
}

static void
trigger_tcp_disconnect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int reason = 0;
	// get disconnect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_DISCONNECT_REASON, &reason);
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_DISCONNECT_PROPERTY, &prop);
	log_warn("bridge client disconnected! RC [%d] \n", reason);
}

static void
trigger_tcp_connect_cb(nng_pipe p, nng_pipe_ev ev, void *arg)
{
	int           reason = 0;
	// get connect reason
	nng_pipe_get_int(p, NNG_OPT_MQTT_CONNECT_REASON, &reason);
	// get property for MQTT V5
	// property *prop;
	// nng_pipe_get_ptr(p, NNG_OPT_MQTT_CONNECT_PROPERTY, &prop);
	log_info("trigger connected! RC [%d]", reason);
}

#define HOOK_SEARCH_RESET_DURATION 5
static void
hook_search_reset(void *arg)
{
	conf_parquet *parquetconf = arg;
	// reset limit
	nng_atomic_set(hook_search_limit,
	    HOOK_SEARCH_RESET_DURATION * parquetconf->limit_frequency);
	// Avoid wake frequently
	nng_duration dura = HOOK_SEARCH_RESET_DURATION  * 1000;
	nng_sleep_aio(dura, hook_search_reset_aio);
}

static struct hook_work *
alloc_work(nng_socket sock, conf_web_hook *conf, conf_exchange *exconf,
        conf_parquet *parquetconf)
{
	struct hook_work *w;
	int               rv;

	if ((w = nng_alloc(sizeof(*w))) == NULL) {
		NANO_NNG_FATAL("nng_alloc", NNG_ENOMEM);
	}
	if ((rv = nng_aio_alloc(&w->aio, hook_work_cb, w)) != 0) {
		NANO_NNG_FATAL("nng_aio_alloc", rv);
	}
	if ((rv = nng_mtx_alloc(&w->mtx)) != 0) {
		NANO_NNG_FATAL("nng_mtx_alloc", rv);
	}
	if ((rv = nng_lmq_alloc(&w->lmq, NANO_LMQ_INIT_CAP) != 0)) {
		NANO_NNG_FATAL("nng_lmq_alloc", rv);
	}
	if ((rv = nng_thread_create(&w->thread, thread_cb, w)) != 0) {
		NANO_NNG_FATAL("nng_thread_create", rv);
	}

	w->conf     = conf;
	w->sock     = sock;
	w->state    = HOOK_INIT;
	w->busy     = false;
	w->exchange = exconf;
	w->parquet  = parquetconf;
	return (w);
}

// The server runs forever.
static void
hook_cb(void *arg)
{
	conf              *conf = arg;
	nng_socket         sock;
	nng_socket         mqtt_sock;
	size_t             works_num = 0;
	int                rv;
	size_t             i;

	if (conf->exchange.count > 0) {
		works_num += 8 * conf->exchange.count;
	}
	if (conf->web_hook.enable) {
		works_num += conf->web_hook.pool_size;
	}
	struct hook_work **works =
	    nng_zalloc(works_num * sizeof(struct hook_work *));

	/* Create the socket. */
	rv = nng_pull0_open(&sock);
	if (rv != 0) {
		log_error("nng_pull0_open %d", rv);
		return;
	}

	/* Create a mqtt sock */
	rv = nng_mqtt_client_open(&mqtt_sock);
	if (rv != 0) {
		log_error("nng_mqtt_client_open %d", rv);
		return;
	}

	if (conf->enable != true) {
		log_error("listener is not turned on. Can't connect to local mqtt broker.");
		return;
	}
	char *port_str;
	if ((port_str = strrchr(conf->url, ':')) != NULL)
		port_str += 1;
	if (!port_str)
		port_str = "1883";
	char url_str[32];
	sprintf(url_str, "mqtt-tcp://127.0.0.1:%s", port_str);
	log_info("File trans client will connect to %s", url_str);

	nng_dialer dialer;
	// need to expose url
	if ((rv = nng_dialer_create(&dialer, mqtt_sock, url_str))) {
		log_error("nng_dialer_create failed %d", rv);
		return;
	}
	nng_msg *connmsg = create_connect_msg();
	if (0 != nng_dialer_set_ptr(dialer, NNG_OPT_MQTT_CONNMSG, connmsg)) {
		log_warn("Error in updating connmsg");
	}
	nng_mqtt_set_connect_cb(mqtt_sock, trigger_tcp_connect_cb, NULL);
	nng_mqtt_set_disconnect_cb(mqtt_sock, trigger_tcp_disconnect_cb, NULL);

	nng_dialer_start(dialer, NNG_FLAG_NONBLOCK);

	for (i = 0; i < works_num; i++) {
		works[i] = alloc_work(sock, &conf->web_hook, &conf->exchange, &conf->parquet);
		works[i]->id = i;
		works[i]->mqtt_sock = &mqtt_sock;
	}
	// NanoMQ core thread talks to others via INPROC
	if ((rv = nng_listen(sock, HOOK_IPC_URL, NULL, 0)) != 0) {
		log_error("hook nng_listen %d", rv);
		return;
	}

	if (hook_search_limit == NULL)
		nng_atomic_alloc(&hook_search_limit);

	if (0 != (rv = nng_aio_alloc(&hook_search_reset_aio,
			hook_search_reset, &conf->parquet))) {
		log_error("hook hook_search reset aio init failed %d", rv);
		return;
	}
	nng_aio_finish(hook_search_reset_aio, 0); // Start
	log_info("hook hook_search reset aio started");

	for (i = 0; i < works_num; i++) {
		// shares taskq threads with broker
		hook_work_cb(works[i]);
	}

	for (;;) {
		nng_msleep(3600000); // neither pause() nor sleep() portable
	}

	// Free hook search reset aio and limit atomic
	if (hook_search_limit)
		nng_atomic_free(hook_search_limit);
	hook_search_limit = NULL;
	nng_aio_stop(hook_search_reset_aio);
	nng_aio_free(hook_search_reset_aio);

	for (i = 0; i < works_num; i++) {
		nng_free(works[i], sizeof(struct hook_work));
	}
	nng_free(works, works_num * sizeof(struct hook_work *));
}

int
start_hook_service(conf *conf)
{
	int rv = nng_thread_create(&hook_thr, hook_cb, conf);
	if (rv != 0) {
		NANO_NNG_FATAL("nng_thread_create", rv);
	}
	nng_msleep(500);
	return rv;
}

int
stop_hook_service(void)
{
	nng_thread_destroy(hook_thr);
	return 0;
}

