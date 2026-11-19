// Exercise reload against the real routing tree and subscription table.
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "include/acl_handler.h"
#include "include/acl_hazard.h"
#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/hash_table.h"

static conn_param *clients[4];

conn_param *
__wrap_nng_pipe_cparam(nng_pipe pipe)
{
	conn_param *cp = pipe.id < 4 ? clients[pipe.id] : NULL;
	if (cp != NULL) {
		conn_param_clone(cp);
	}
	return cp;
}

static void
set_acl(conf *cfg, const char *rules)
{
	cJSON *json = cJSON_Parse(rules);
	assert(json != NULL);
	cfg->acl.enable = true;
	cfg->acl_nomatch = ACL_DENY;
	cfg->acl_deny_action = ACL_IGNORE;
	cfg->acl.rule_count = cJSON_GetArraySize(json);
	for (size_t i = 0; i < cfg->acl.rule_count; i++) {
		acl_rule *rule;
		assert(acl_parse_json_rule(cJSON_GetArrayItem(json, i), i,
		    &rule));
		cvector_push_back(cfg->acl.rules, rule);
	}
	cJSON_Delete(json);
}

static void
reload(conf *cfg, const char *rules)
{
	conf next = { 0 };
	set_acl(&next, rules);
	reload_acl_config(cfg, &next);
	assert(next.acl.rules == NULL && next.acl.rule_count == 0);
}

static uint8_t
subscribe(conf *cfg, uint32_t pid, char *filter)
{
	topic_node topic = { 0 };
	topic.topic.body = filter;
	topic.topic.len = strlen(filter);
	topic.retain_handling = 2;
	packet_subscribe packet = { .packet_id = 1, .node = &topic };
	nano_work work = { 0 };
	work.config = cfg;
	work.db = cfg->db_root;
	work.cparam = clients[pid];
	work.pid.id = pid;
	work.proto_ver = MQTT_PROTOCOL_VERSION_v5;
	work.sub_pkt = &packet;
	assert(sub_ctx_handle(&work) == 0);
	return topic.reason_code;
}

static void
expect_route(conf *cfg, char *topic, uint32_t pid)
{
	uint32_t *ids = dbtree_find_clients(cfg->db_root, topic);
	assert(cvector_size(ids) == (pid == 0 ? 0 : 1));
	if (pid != 0) {
		assert(ids[0] == pid);
	}
	cvector_free(ids);
}

int
main(void)
{
	conf cfg = { 0 };
	dbtree *db;
	dbtree_create(&db);
	cfg.db_root = db;
	dbhash_init_pipe_table();
	for (uint32_t i = 1; i < 4; i++) {
		assert(conn_param_alloc(&clients[i]) == 0);
		conn_param_set_clientid(clients[i], i == 2 ? "alice" : "bob");
	}
	set_acl(&cfg, "[{\"permit\":\"allow\"}]");
	nmq_acl_hazard_init(&cfg);
	assert(nmq_acl_hazard_ready());

	// Cover head/middle/tail removal, a shared group with an allowed member,
	// an exact ACL filter, and an already-mounted filter.
	assert(subscribe(&cfg, 1, "secret/matrix/#") == 0);
	assert(subscribe(&cfg, 1, "public/#") == 0);
	assert(subscribe(&cfg, 1, "tenant/bob/private/#") == 0);
	assert(subscribe(&cfg, 1, "$share/workers/jobs/#") == 0);
	assert(subscribe(&cfg, 1, "exact/#") == 0);
	assert(subscribe(&cfg, 2, "$share/workers/jobs/#") == 0);
	assert(subscribe(&cfg, 3, "secret/matrix/#") == 0);
	// A preset subscription without a connection must remain untouched.
	dbtree_insert_client(db, "preset/#", 99);
	dbhash_insert_topic(99, "preset/#", 0);

	reload(&cfg, "[{\"permit\":\"allow\"}]");
	assert(dbhash_check_topic(1, "secret/matrix/#"));
	assert(dbhash_check_topic(3, "secret/matrix/#"));

	const char *restricted =
	    "[{\"permit\":\"allow\",\"clientid\":\"alice\"},"
	    "{\"permit\":\"allow\",\"clientid\":\"bob\","
	    "\"action\":\"subscribe\",\"topics\":[\"public/#\",\"@exact/#\"]}]";
	reload(&cfg, restricted);
	assert(!dbhash_check_topic(1, "secret/matrix/#"));
	assert(!dbhash_check_topic(1, "tenant/bob/private/#"));
	assert(!dbhash_check_topic(1, "$share/workers/jobs/#"));
	assert(!dbhash_check_id(3));
	assert(dbhash_check_topic(1, "public/#"));
	assert(dbhash_check_topic(1, "exact/#"));
	expect_route(&cfg, "secret/matrix/live2", 0);
	expect_route(&cfg, "tenant/bob/private/item", 0);
	expect_route(&cfg, "public/item", 1);
	expect_route(&cfg, "exact/item", 1);
	expect_route(&cfg, "preset/item", 99);
	for (int i = 0; i < 8; i++) {
		uint32_t *ids = dbtree_find_shared_clients(db, "jobs/item");
		assert(cvector_size(ids) == 1 && ids[0] == 2);
		cvector_free(ids);
	}
	assert(subscribe(&cfg, 3, "secret/matrix/#") == NMQ_AUTH_SUB_ERROR);
	assert(!dbhash_check_id(3));

	// Idempotence and re-grant: removal must not leave a stale hash entry
	// that prevents the client from subscribing again.
	reload(&cfg, restricted);
	reload(&cfg, "[{\"permit\":\"allow\"}]");
	assert(subscribe(&cfg, 1, "secret/matrix/#") == 0);
	expect_route(&cfg, "secret/matrix/regranted", 1);

	// Disabling ACL keeps existing subscriptions, even with default deny.
	conf disabled = { 0 };
	disabled.acl_nomatch = ACL_DENY;
	reload_acl_config(&cfg, &disabled);
	expect_route(&cfg, "secret/matrix/disabled", 1);
	// Re-enabling ACL also rechecks subscriptions installed while disabled.
	reload(&cfg, restricted);
	expect_route(&cfg, "secret/matrix/enabled", 0);

	for (uint32_t i = 1; i < 4; i++) {
		destroy_sub_client(i, db);
		conn_param_free(clients[i]);
	}
	destroy_sub_client(99, db);
	assert(dbhash_get_pipe_cnt() == 0);
	dbhash_destroy_pipe_table();
	dbtree_destory(db);
	nng_fini();
	puts("acl_reload_test: passed");
	return 0;
}
