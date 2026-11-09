// Exercise authorization and subscription registration without a listener.
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "include/acl_handler.h"
#include "include/nanomq.h"
#include "include/sub_handler.h"
#include "nng/supplemental/nanolib/hash_table.h"
#include "acl_test_helper.h"

static void
test_effective_filter(conn_param *cp)
{
	const struct {
		const char *rule;
		const char *topic;
		acl_action_type action;
		bool matches;
	} cases[] = {
		{ "$SYS/#", "$SYS/#", ACL_SUB, true },
		{ "$SYS/#", "$share/workers/$SYS/#", ACL_SUB, true },
		{ "$SYS/#", "$share/other/$SYS/status", ACL_SUB, true },
		{ "tenant/private/#", "tenant/private/#", ACL_SUB, true },
		{ "tenant/private/#", "$share/g/tenant/private/#", ACL_SUB, true },
		{ "tenant/private/#", "$share/g/tenant/public/#", ACL_SUB, false },
		{ "@private/+", "$share/g/private/+", ACL_SUB, true },
		{ "@private/+", "$share/g/private/item", ACL_SUB, false },
		{ "tenant/${username}/${clientid}/#",
		  "$share/g/tenant/alice/client-a/#", ACL_SUB, true },
		{ "tenant/${username}/#", "$share/g/tenant/bob/#", ACL_SUB, false },
		{ "$share/inner/private/#",
		  "$share/outer/$share/inner/private/#", ACL_SUB, true },
		{ "private/#", "$share/outer/$share/inner/private/#", ACL_SUB, false },
		{ "@$shareX/g/private/item", "$shareX/g/private/item", ACL_SUB, true },
		{ "private/#", "$shareX/g/private/#", ACL_SUB, false },
		{ "@$share/group", "$share/group", ACL_SUB, true },
		{ "@$share/group/", "$share/group/", ACL_SUB, true },
		{ "private/#", "$share/g/private/item", ACL_PUB, false },
		{ "@$share/g/private/item", "$share/g/private/item", ACL_PUB, true },
		{ "private/#", "private/item", ACL_PUB, true },
	};
	char *topic = NULL;
	acl_rule rule = {
		.rule_type = ACL_USERNAME,
		.rule_ct.ct = { .type = ACL_RULE_SINGLE_STRING,
		    .value.str = "alice" },
		.action = ACL_ALL,
		.topic_count = 1,
		.topics = &topic,
	};
	acl_rule *rules[] = { &rule };
	conf cfg = { 0 };
	cfg.acl.enable = true;
	cfg.acl.rules = rules;
	cfg.acl.rule_count = 1;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		topic = (char *) cases[i].rule;
		// Both deny with default allow and allow with default deny must
		// make the same rule match for ordinary and shared subscriptions.
		for (int permit = ACL_ALLOW; permit <= ACL_DENY; permit++) {
			rule.permit = permit;
			cfg.acl_nomatch = permit == ACL_ALLOW ? ACL_DENY : ACL_ALLOW;
			bool expected = cases[i].matches ? permit == ACL_ALLOW
			                                    : cfg.acl_nomatch == ACL_ALLOW;
			assert(auth_acl(&cfg, cases[i].action, cp, cases[i].topic) == expected);
		}
	}
}

static void
test_order_and_action(conn_param *cp)
{
	char *topic = "private/#";
	acl_rule deny = { .permit = ACL_DENY, .rule_type = ACL_NONE,
		.action = ACL_SUB, .topic_count = 1, .topics = &topic };
	acl_rule allow = { .permit = ACL_ALLOW, .rule_type = ACL_NONE,
		.action = ACL_ALL };
	acl_rule *rules[] = { &deny, &allow };
	conf cfg = { 0 };
	cfg.acl.rules = rules;
	cfg.acl.rule_count = 2;
	cfg.acl_nomatch = ACL_ALLOW;
	assert(!auth_acl(&cfg, ACL_SUB, cp, "$share/g/private/#"));
	assert(auth_acl(&cfg, ACL_PUB, cp, "private/item"));
	deny.action = ACL_PUB;
	assert(auth_acl(&cfg, ACL_SUB, cp, "$share/g/private/#"));
	deny.action = ACL_SUB;
	rules[0] = &allow;
	rules[1] = &deny;
	assert(auth_acl(&cfg, ACL_SUB, cp, "$share/g/private/#"));
}

static void
test_rejected_filter_not_registered(conn_param *cp)
{
	char *topic = "$SYS/#";
	acl_rule deny = { .permit = ACL_DENY, .rule_type = ACL_NONE,
		.action = ACL_SUB, .topic_count = 1, .topics = &topic };
	acl_rule allow = { .permit = ACL_ALLOW, .rule_type = ACL_NONE,
		.action = ACL_ALL };
	acl_rule *rules[] = { &deny, &allow };
	conf cfg = { 0 };
	cfg.acl.enable = true;
	cfg.acl.rules = rules;
	cfg.acl.rule_count = 2;
	cfg.acl_nomatch = ACL_ALLOW;
	for (int action = ACL_IGNORE; action <= ACL_DISCONNECT; action++) {
		cfg.acl_deny_action = action;
		topic_node allowed = { 0 }, denied = { 0 };
		allowed.topic.body = "$share/readers/public/#";
		allowed.topic.len = strlen(allowed.topic.body);
		allowed.qos = 1;
		allowed.reason_code = GRANTED_QOS_1;
		allowed.retain_handling = 2;
		denied.topic.body = "$share/workers/$SYS/#";
		denied.topic.len = strlen(denied.topic.body);
		denied.qos = 1;
		denied.reason_code = GRANTED_QOS_1;
		denied.retain_handling = 2;
		denied.next = &allowed;
		packet_subscribe sub = { .packet_id = 1, .node = &denied };
		nano_work work = { 0 };
		work.config = &cfg;
		work.cparam = cp;
		work.proto_ver = MQTT_PROTOCOL_VERSION_v5;
		work.proto = PROTO_MQTT_BROKER;
		work.pid.id = 17;
		work.sub_pkt = &sub;
		dbtree_create(&work.db);
		dbhash_init_pipe_table();
		assert(sub_ctx_handle(&work) ==
		    (action == ACL_IGNORE ? NNG_MQTT_SUCCESS : BANNED));
		assert(denied.reason_code == NMQ_AUTH_SUB_ERROR);
		assert(!dbhash_check_topic(work.pid.id, denied.topic.body));
		assert(dbtree_find_shared_clients(work.db, "$SYS/status") == NULL);
		assert(dbhash_check_topic(work.pid.id, allowed.topic.body) ==
		    (action == ACL_IGNORE));
		uint32_t *clients = dbtree_find_shared_clients(work.db, "public/item");
		if (action == ACL_IGNORE) {
			assert(cvector_size(clients) == 1);
			assert(clients[0] == work.pid.id);
		} else {
			assert(clients == NULL);
		}
		cvector_free(clients);
		destroy_sub_client(work.pid.id, work.db);
		dbhash_destroy_pipe_table();
		dbtree_destory(work.db);
	}
}

int
main(void)
{
	conn_param *cp = acl_test_conn_param("alice", "client-a");
	test_effective_filter(cp);
	test_order_and_action(cp);
	test_rejected_filter_not_registered(cp);
	conn_param_free(cp);
	nng_fini();
	puts("acl_shared_subscription_test: all passed");
	return 0;
}
