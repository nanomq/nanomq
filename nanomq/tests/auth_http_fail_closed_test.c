// Inject allocation failures only inside the real HTTP topic-queue builders.
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "include/sub_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/hash_table.h"

static __thread bool building_queue;
static __thread unsigned allocations, fail_at;
static unsigned queue_calls, http_calls, releases;
static int http_result, queue_topic_len;
static bool expected_sub;
static const char *expected_topics[2];

void *__real_nni_alloc(size_t);
void *__real_nni_zalloc(size_t);
topic_queue *__real_topic_queue_init(char *, int);
topic_queue *__real_init_topic_queue_with_topic_node(topic_node *);
void __real_topic_queue_release(topic_queue *);

static bool
allocation_fails(void)
{
	return building_queue && ++allocations == fail_at;
}

void *
__wrap_nni_alloc(size_t size)
{
	return allocation_fails() ? NULL : __real_nni_alloc(size);
}

void *
__wrap_nni_zalloc(size_t size)
{
	return allocation_fails() ? NULL : __real_nni_zalloc(size);
}

topic_queue *
__wrap_topic_queue_init(char *topic, int len)
{
	queue_calls++;
	queue_topic_len = len;
	building_queue = true;
	topic_queue *tq = __real_topic_queue_init(topic, len);
	building_queue = false;
	return tq;
}

topic_queue *
__wrap_init_topic_queue_with_topic_node(topic_node *node)
{
	queue_calls++;
	building_queue = true;
	topic_queue *tq = __real_init_topic_queue_with_topic_node(node);
	building_queue = false;
	return tq;
}

void
__wrap_topic_queue_release(topic_queue *tq)
{
	if (tq != NULL) {
		releases++;
	}
	__real_topic_queue_release(tq);
}

int
__wrap_nmq_auth_http_sub_pub(conn_param *cp, bool is_sub,
    topic_queue *topics, conf_auth_http *cfg)
{
	assert(cp != NULL && cfg->enable);
	assert(is_sub == expected_sub);
	http_calls++;
	unsigned count = expected_sub ? 2 : 1;
	for (unsigned i = 0; i < count; i++) {
		assert(topics != NULL);
		assert(strcmp(topics->topic, expected_topics[i]) == 0);
		topics = topics->next;
	}
	assert(topics == NULL);
	return http_result;
}

static void
reset(unsigned failure, int result)
{
	fail_at = failure;
	allocations = queue_calls = http_calls = releases = 0;
	http_result = result;
	expected_sub = false;
}

static void
test_subscribe(conf *cfg, conn_param *cp, unsigned failure, int result)
{
	topic_node second = { 0 }, first = { 0 };
	first.topic.body = "one/#";
	first.topic.len = strlen(first.topic.body);
	first.retain_handling = 2;
	first.next = &second;
	second.topic.body = "two/#";
	second.topic.len = strlen(second.topic.body);
	second.retain_handling = 2;
	packet_subscribe packet = { .packet_id = 1, .node = &first };
	nano_work work = { 0 };
	work.config = cfg;
	work.cparam = cp;
	work.pid.id = 17;
	work.proto_ver = MQTT_PROTOCOL_VERSION_v5;
	work.sub_pkt = &packet;
	dbtree_create(&work.db);
	conn_param_set_mount_point(cp, "tenant");
	reset(failure, result);
	expected_sub = true;
	expected_topics[0] = "tenant/one/#";
	expected_topics[1] = "tenant/two/#";

	assert(sub_ctx_handle(&work) == 0);
	assert(queue_calls == 1);
	assert(http_calls == (failure ? 0 : 1));
	bool denied = failure || result;
	assert(first.reason_code == (denied ? NMQ_AUTH_SUB_ERROR : 0));
	assert(second.reason_code == (denied ? NMQ_AUTH_SUB_ERROR : 0));
	for (unsigned i = 0; i < 2; i++) {
		assert(dbhash_check_topic(work.pid.id,
		    (char *) expected_topics[i]) == !denied);
	}
	uint32_t *ids = dbtree_find_clients(work.db, "tenant/one/item");
	assert(cvector_size(ids) == (denied ? 0 : 1));
	cvector_free(ids);
	ids = dbtree_find_clients(work.db, "tenant/two/item");
	assert(cvector_size(ids) == (denied ? 0 : 1));
	cvector_free(ids);
	if (failure) {
		assert(allocations == failure); // Prove the injected failure fired.
	} else {
		assert(releases == 1);
	}
	destroy_sub_client(work.pid.id, work.db);
	dbtree_destory(work.db);
	conn_param_set_mount_point(cp, NULL);
}

static nano_work
publish_work(conf *cfg, conn_param *cp, const char *topic, int alias)
{
	nano_work work = { 0 };
	work.config = cfg;
	work.cparam = cp;
	work.pid.id = 21;
	work.proto = PROTO_MQTT_BROKER;
	work.proto_ver = MQTT_PROTOCOL_VERSION_v5;
	dbtree_create(&work.db);
	// A real matching recipient makes "no dispatch" assertions meaningful.
	dbtree_insert_client(work.db, "#", 7);
	assert(nng_msg_alloc(&work.msg, 0) == 0);
	nng_msg_set_conn_param(work.msg, cp);
	size_t len = strlen(topic);
	uint8_t length[2] = { (uint8_t) (len >> 8), (uint8_t) len };
	assert(nng_msg_append(work.msg, length, 2) == 0);
	assert(nng_msg_append(work.msg, topic, len) == 0);
	uint8_t properties[] = { 3, TOPIC_ALIAS, 0, (uint8_t) alias };
	uint8_t empty = 0;
	assert(nng_msg_append(work.msg, alias >= 0 ? properties : &empty,
	    alias >= 0 ? sizeof(properties) : 1) == 0);
	assert(nng_msg_append(work.msg, "body", 4) == 0);
	uint8_t header[] = { 0x30, (uint8_t) nng_msg_len(work.msg) };
	assert(nng_msg_header_append(work.msg, header, sizeof(header)) == 0);
	return work;
}

static void
check_publish(nano_work *work, bool event, reason_code expected,
    unsigned expected_calls, const char *topic)
{
	struct pipe_content pipes = { 0 };
	expected_topics[0] = topic;
	reason_code actual = handle_pub(work, &pipes, work->proto_ver, event);
	if (actual != expected) {
		fprintf(stderr, "publish: expected %u, got %u (failure %u, "
		    "HTTP result %d, event %d, version %u)\n",
		    expected, actual, fail_at, http_result, event, work->proto_ver);
	}
	assert(actual == expected);
	assert(http_calls == expected_calls);
	if (fail_at) {
		assert(allocations == fail_at);
	}
	if (expected_calls) {
		assert(releases == 1);
		assert(queue_topic_len == (int) strlen(topic));
	}
	if (expected == NNG_MQTT_SUCCESS) {
		assert(cvector_size(pipes.msg_infos) == 1);
		assert(pipes.msg_infos[0].pipe == 7);
	} else {
		assert(pipes.msg_infos == NULL);
	}
	cvector_free(pipes.msg_infos);
	free_pub_packet(work->pub_packet);
	nng_msg_free(work->msg);
	dbtree_destory(work->db);
}

int
main(void)
{
	conf cfg = { 0 };
	cfg.auth_http.enable = true;
	cfg.max_topic_alias = 4;
	conn_param *cp = NULL;
	assert(conn_param_alloc(&cp) == 0);
	dbhash_init_pipe_table();
	dbhash_init_alias_table();

	reset(0, 0);
	assert(topic_queue_init(NULL, 0) == NULL);
	assert(topic_queue_init(NULL, 1) == NULL);
	assert(topic_queue_init("x", -1) == NULL);
	assert(allocations == 0);
	topic_queue *empty = topic_queue_init("", 0);
	assert(empty != NULL && empty->topic[0] == '\0');
	topic_queue_release(empty);

	// Both nodes and both strings, including partially built queues.
	for (unsigned failure = 1; failure <= 4; failure++) {
		test_subscribe(&cfg, cp, failure, 0);
	}
	test_subscribe(&cfg, cp, 0, NNG_EPERM);
	test_subscribe(&cfg, cp, 0, 0);

	for (unsigned failure = 1; failure <= 2; failure++) {
		nano_work work = publish_work(&cfg, cp, "topic/item", -1);
		reset(failure, 0);
		check_publish(&work, false, NOT_AUTHORIZED, 0, NULL);
	}
	// Establish an alias, then reuse it with a zero-length wire topic.
	conn_param_set_mount_point(cp, "tenant");
	for (int i = 0; i < 3; i++) {
		nano_work work = publish_work(&cfg, cp, i ? "" : "topic/item", 1);
		reset(0, i == 2 ? NNG_EPERM : 0);
		check_publish(&work, false,
		    i == 2 ? NOT_AUTHORIZED : NNG_MQTT_SUCCESS,
		    1, "tenant/topic/item");
	}
	conn_param_set_mount_point(cp, NULL);

	// Invalid aliases and missing topics must fail before constructing a queue.
	for (int alias = -1; alias <= 5; alias++) {
		if (alias == 1) {
			continue;
		}
		nano_work work = publish_work(&cfg, cp, "", alias);
		reset(0, 0);
		check_publish(&work, false,
		    alias <= 0 ? PROTOCOL_ERROR : TOPIC_ALIAS_INVALID, 0, NULL);
		assert(queue_calls == 0);
	}
	nano_work missing = publish_work(&cfg, cp, "", -1);
	missing.proto_ver = MQTT_PROTOCOL_VERSION_v311;
	reset(0, 0);
	check_publish(&missing, false, TOPIC_FILTER_INVALID, 0, NULL);
	assert(queue_calls == 0);

	// Internal events and identity-less messages do not use HTTP ACL.
	for (int event = 0; event <= 1; event++) {
		nano_work work = publish_work(&cfg, event ? cp : NULL, "topic/item", -1);
		reset(0, NNG_EPERM);
		check_publish(&work, event, NNG_MQTT_SUCCESS, 0, NULL);
		assert(queue_calls == 0);
	}

	dbhash_destroy_pipe_table();
	dbhash_del_atpair_queue(21);
	dbhash_destroy_alias_table();
	conn_param_free(cp);
	nng_fini();
	puts("auth_http_fail_closed_test: passed");
	return 0;
}
