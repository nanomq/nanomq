/*
 * Unit tests for the ACL deny_action handling in handle_pub() and
 * sub_ctx_handle() (issue #655).
 *
 * Rules used (first-match-wins):
 *   deny  user "eqa"   on "deny/#"   (pubsub)
 *   allow everything else
 *
 * deny_action = disconnect : a denied operation must return a non-SUCCESS
 * code (BANNED) so the broker closes the connection; a denied SUBSCRIBE
 * aborts before any later topic filter is installed.
 * deny_action = ignore    : a denied PUBLISH drops the message (SUCCESS,
 * connection kept); a denied SUBSCRIBE filter gets reason code
 * NMQ_AUTH_SUB_ERROR in the SUBACK but allowed filters on the same packet
 * are still processed.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/acl_conf.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "nng/supplemental/nanolib/mqtt_db.h"

#define DENY_USER    "eqa"
#define ALLOW_USER   "okuser"
#define DENY_TOPIC   "deny/#"
#define DENY_PUB_TOP "deny/x"
#define ALLOW_TOPIC  "ok/x"

/* ---- fixtures ---------------------------------------------------------- */

static void
conf_install_acl(conf *c)
{
	conf_acl *acl    = &c->acl;
	acl->enable      = true;
	acl->rule_count  = 2;
	acl->rules       = nng_zalloc(2 * sizeof(acl_rule *));

	// rule 1: deny DENY_USER on DENY_TOPIC (pubsub)
	acl_rule *r1         = nng_zalloc(sizeof(acl_rule));
	r1->permit           = ACL_DENY;
	r1->rule_type        = ACL_USERNAME;
	r1->rule_ct.ct.type  = ACL_RULE_SINGLE_STRING;
	r1->rule_ct.ct.value.str = nng_strdup(DENY_USER);
	r1->action           = ACL_ALL;
	r1->topic_count      = 1;
	r1->topics           = nng_zalloc(sizeof(char *));
	r1->topics[0]        = nng_strdup(DENY_TOPIC);
	acl->rules[0]        = r1;

	// rule 2: allow everything else (bare rule -> ACL_NONE matches all)
	acl_rule *r2 = nng_zalloc(sizeof(acl_rule));
	r2->permit    = ACL_ALLOW;
	r2->rule_type = ACL_NONE;
	r2->action    = ACL_ALL;
	acl->rules[1] = r2;
}

static void
conf_acl_cleanup(conf *c)
{
	conf_acl *acl = &c->acl;
	for (size_t i = 0; i < acl->rule_count; i++) {
		acl_rule *r = acl->rules[i];
		if (r->rule_type == ACL_USERNAME) {
			nng_strfree(r->rule_ct.ct.value.str);
		}
		for (size_t j = 0; j < r->topic_count; j++) {
			nng_strfree(r->topics[j]);
		}
		nng_free(r->topics, r->topic_count * sizeof(char *));
		nng_free(r, sizeof(acl_rule));
	}
	nng_free(acl->rules, acl->rule_count * sizeof(acl_rule *));
}

static conf *
new_conf(int deny_action)
{
	conf *c = nng_zalloc(sizeof(conf));
	conf_install_acl(c);
	c->acl_deny_action = deny_action;
	c->acl_nomatch     = ACL_ALLOW;
	return c;
}

static void
free_conf(conf *c)
{
	conf_acl_cleanup(c);
	nng_free(c, sizeof(conf));
}

static conn_param *
new_cparam(const char *username)
{
	conn_param *cp = NULL;
	conn_param_alloc(&cp);
	conn_param_set_username(cp, username);
	return cp;
}

/* nano_work carrying a decoded v3.1.1 PUBLISH of `topic` (qos0). */
static nano_work *
new_pub_work(conf *c, conn_param *cp, const char *topic)
{
	nano_work *work = nng_zalloc(sizeof(nano_work));
	work->config    = c;
	work->cparam    = cp;
	work->pipe_ct   = nng_alloc(sizeof(struct pipe_content));
	work->proto     = PROTO_MQTT_BROKER;
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;
	dbtree_create(&work->db);
	dbhash_init_pipe_table();

	nng_msg_alloc(&work->msg, 0);
	size_t   n = strlen(topic);
	uint8_t len[2] = { (uint8_t) (n >> 8), (uint8_t) n };
	nng_msg_append(work->msg, len, 2);
	nng_msg_append(work->msg, (const uint8_t *) topic, n);
	nng_msg_append(work->msg, (const uint8_t *) "hi", 2);
	uint8_t hdr[2] = { 0x30, (uint8_t) (2 + n + 2) }; // PUBLISH qos0
	nng_msg_header_append(work->msg, hdr, 2);
	return work;
}

/* nano_work carrying a decoded v3.1.1 SUBSCRIBE of the two filters. */
static nano_work *
new_sub_work(conf *c, conn_param *cp, const char *f1, const char *f2)
{
	nano_work *work = nng_zalloc(sizeof(nano_work));
	work->config    = c;
	work->cparam    = cp;
	work->proto     = PROTO_MQTT_BROKER;
	work->proto_ver = MQTT_PROTOCOL_VERSION_v311;
	work->pid.id    = 2;
	dbtree_create(&work->db);
	dbhash_init_pipe_table();

	nng_msg_alloc(&work->msg, 0);
	nng_msg_append(work->msg, (const uint8_t *) "\x00\x05", 2); // packet id
	const char *filters[2] = { f1, f2 };
	for (int i = 0; i < 2 && filters[i] != NULL; i++) {
		size_t n = strlen(filters[i]);
		uint8_t len[2] = { (uint8_t) (n >> 8), (uint8_t) n };
		nng_msg_append(work->msg, len, 2);
		nng_msg_append(work->msg, (const uint8_t *) filters[i], n);
		nng_msg_append(work->msg, (const uint8_t *) "\x00", 1); // qos 0
	}
	// decode_sub_msg reads the packet id from the body and the topic list
	// from the payload pointer, which the transport normally sets past the
	// packet id (see nmq_mqtt.c CMD_SUBSCRIBE handling).
	nng_msg_set_payload_ptr(work->msg, nng_msg_body(work->msg) + 2);
	work->sub_pkt = nng_alloc(sizeof(packet_subscribe));
	int rv        = decode_sub_msg(work);
	assert(rv == 0);
	return work;
}

static void
free_work(nano_work *work)
{
	if (work->pub_packet != NULL) {
		free_pub_packet(work->pub_packet);
	}
	dbhash_destroy_pipe_table();
	dbtree_destory(work->db);
	nng_msg_free(work->msg);
	if (work->pipe_ct != NULL) {
		nng_free(work->pipe_ct, sizeof(struct pipe_content));
	}
	nng_free(work, sizeof(nano_work));
}

static void
del_topics(nano_work *work, const char *t1, const char *t2)
{
	// drain the dbhash topic queues that sub_ctx_handle installed
	// (normally freed on client disconnect)
	if (t1 != NULL)
		dbhash_del_topic(work->pid.id, (char *) t1);
	if (t2 != NULL)
		dbhash_del_topic(work->pid.id, (char *) t2);
}

/* ---- the tests -------------------------------------------------------- */

static void
test_pub_deny_disconnect(void)
{
	conf       *c    = new_conf(ACL_DISCONNECT);
	conn_param *cp   = new_cparam(DENY_USER);
	nano_work  *work = new_pub_work(c, cp, DENY_PUB_TOP);

	// publish to the denied topic: a non-SUCCESS code is required so the
	// broker closes the connection. NORMAL_DISCONNECTION would alias
	// SUCCESS(0) and keep it open (the original bug).
	reason_code rc = handle_pub(
	    work, work->pipe_ct, MQTT_PROTOCOL_VERSION_v311, false);
	assert(rc == BANNED);

	free_work(work);
	conn_param_free(cp);
	free_conf(c);
}

static void
test_pub_deny_ignore(void)
{
	conf       *c    = new_conf(ACL_IGNORE);
	conn_param *cp   = new_cparam(DENY_USER);
	nano_work  *work = new_pub_work(c, cp, DENY_PUB_TOP);

	// deny & ignore: message dropped but connection kept -> SUCCESS
	reason_code rc = handle_pub(
	    work, work->pipe_ct, MQTT_PROTOCOL_VERSION_v311, false);
	assert(rc == SUCCESS);

	free_work(work);
	conn_param_free(cp);
	free_conf(c);
}

static void
test_pub_allowed(void)
{
	// the allow-all rule must let other users publish under either
	// deny_action, and the deny rule must not hit the wrong user
	for (int action = ACL_IGNORE; action <= ACL_DISCONNECT; action++) {
		conf       *c    = new_conf(action);
		conn_param *cp   = new_cparam(ALLOW_USER);
		nano_work  *work = new_pub_work(c, cp, ALLOW_TOPIC);

		reason_code rc = handle_pub(
		    work, work->pipe_ct, MQTT_PROTOCOL_VERSION_v311, false);
		assert(rc == SUCCESS);

		free_work(work);
		conn_param_free(cp);
		free_conf(c);
	}
}

static void
test_sub_deny_disconnect_aborts(void)
{
	conf       *c    = new_conf(ACL_DISCONNECT);
	conn_param *cp   = new_cparam(DENY_USER);
	// denied filter first, allowed one second: processing must stop at the
	// first denied filter, so nothing gets installed
	nano_work *work = new_sub_work(c, cp, DENY_TOPIC, ALLOW_TOPIC);

	reason_code rc = sub_ctx_handle(work);
	assert(rc == BANNED);

	uint32_t *clients = dbtree_find_clients(work->db, ALLOW_TOPIC);
	assert(clients == NULL);

	sub_pkt_free(work->sub_pkt);
	free_work(work);
	conn_param_free(cp);
	free_conf(c);
}

static void
test_sub_deny_ignore_rejects_one_filter(void)
{
	conf       *c    = new_conf(ACL_IGNORE);
	conn_param *cp   = new_cparam(DENY_USER);
	// allowed first, denied second: the denied filter is refused with
	// NMQ_AUTH_SUB_ERROR but the allowed one is still installed and the
	// handler returns SUCCESS (connection kept)
	nano_work *work = new_sub_work(c, cp, ALLOW_TOPIC, DENY_TOPIC);

	reason_code rc = sub_ctx_handle(work);
	assert(rc == SUCCESS);

	bool saw_allow       = false;
	bool saw_deny_reason = false;
	for (topic_node *tn = work->sub_pkt->node; tn != NULL; tn = tn->next) {
		if (strncmp(tn->topic.body, ALLOW_TOPIC, strlen(ALLOW_TOPIC)) ==
		    0) {
			saw_allow = true;
			// granted nodes carry a grant code (decode defaults them
			// to GRANTED_QOS_2), never the auth-failure stamp
			assert(tn->reason_code != NMQ_AUTH_SUB_ERROR);
		} else if (strncmp(tn->topic.body, DENY_TOPIC,
		               strlen(DENY_TOPIC)) == 0) {
			saw_deny_reason =
			    (tn->reason_code == NMQ_AUTH_SUB_ERROR);
		}
	}
	assert(saw_allow && saw_deny_reason);

	uint32_t *clients = dbtree_find_clients(work->db, ALLOW_TOPIC);
	assert(clients != NULL);
	cvector_free(clients);
	clients = dbtree_find_clients(work->db, DENY_TOPIC);
	assert(clients == NULL);

	del_topics(work, ALLOW_TOPIC, NULL); // only the allowed filter was installed
	sub_pkt_free(work->sub_pkt);
	free_work(work);
	conn_param_free(cp);
	free_conf(c);
}

static void
test_sub_allowed(void)
{
	// other user under either deny_action: both filters installed, SUCCESS
	for (int action = ACL_IGNORE; action <= ACL_DISCONNECT; action++) {
		conf       *c    = new_conf(action);
		conn_param *cp   = new_cparam(ALLOW_USER);
		nano_work  *work = new_sub_work(c, cp, ALLOW_TOPIC, DENY_TOPIC);

		reason_code rc = sub_ctx_handle(work);
		assert(rc == SUCCESS);

		uint32_t *clients = dbtree_find_clients(work->db, ALLOW_TOPIC);
		assert(clients != NULL);
		cvector_free(clients);
		clients = dbtree_find_clients(work->db, DENY_TOPIC);
		assert(clients != NULL);
		cvector_free(clients);

		del_topics(work, ALLOW_TOPIC, DENY_TOPIC);
		sub_pkt_free(work->sub_pkt);
		free_work(work);
		conn_param_free(cp);
		free_conf(c);
	}
}

static void
test_disconnect_kick_reason(void)
{
	// The broker's close kick (broker.c CLOSE state -> the composer)
	// must put the MQTT 5 reason "Not authorized" (0x87) on the wire
	// when the connection ends because of an ACL deny (internal code
	// BANNED). 0x8A (Banned) is not a valid DISCONNECT reason code.
	nng_msg *msg = nano_dismsg_composer(BANNED, NULL, NULL, NULL);

	// fixed header E0 02 (DISCONNECT, remaining length 2)
	uint8_t *header = nng_msg_header(msg);
	assert(header[0] == 0xE0 && header[1] == 0x02);
	// body: reason code + property length 0x00
	uint8_t *body = nng_msg_body(msg);
	assert(body[0] == NOT_AUTHORIZED);
	assert(body[1] == 0x00);

	nng_msg_free(msg);
}

int
main(int argc, char **argv)
{
	test_pub_deny_disconnect();
	test_pub_deny_ignore();
	test_pub_allowed();
	test_sub_deny_disconnect_aborts();
	test_sub_deny_ignore_rejects_one_filter();
	test_sub_allowed();
	test_disconnect_kick_reason();
	printf("acl_deny_action_test: all passed\n");
	return 0;
}
