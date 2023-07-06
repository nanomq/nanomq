#include "tests_api.h"

#define STATUS_CODE_OK "HTTP/1.1 200"
#define STATUS_CODE_BAD_REQUEST "HTTP/1.1 400"
#define STATUS_CODE_UNAUTHORIZED "HTTP/1.1 401"
#define STATUS_CODE_NOT_FOUND "HTTP/1.1 404"

#define RESULT_CODE_PASS -1

static cJSON *jsn; // TODO: this could be used for further check.

static conf *
get_http_server_test_conf()
{
	// conf *nmq_conf = get_dflt_conf();

	// nmq_conf->http_server.enable    = true;
	// nmq_conf->http_server.port      = 8081;
	// nmq_conf->http_server.parallel  = 32;
	// nmq_conf->http_server.username  = "admin_test";
	// nmq_conf->http_server.password  = "pw_test";
	// nmq_conf->http_server.auth_type = BASIC;

	// get conf from file
	conf *nmq_conf  = nng_zalloc(sizeof(conf));
	char *conf_path = "../../../nanomq/tests/nanomq_test.conf";
	conf_init(nmq_conf);
	nmq_conf->conf_file = conf_path;
	char cwd[1024];
	getcwd(cwd, sizeof(cwd));
	printf("\ncwd:%s\n", cwd);
	conf_parse_ver2(nmq_conf);
	nmq_conf->parallel = 10;

	return nmq_conf;
}

static bool
check_http_status_code(char *buff, char *sc)
{
	bool rv = true;

	if (strncmp(buff, sc, 12) != 0) {
		fprintf(stderr,
		    "status code not match. what we expect:%s,"
			" what we get:%s\n",
		    sc, buff);
		rv = false;
	}

	return rv;
}

static bool
check_http_result_code(char *buff, int rc)
{
	int    rv   = true;
	if (rc == RESULT_CODE_PASS) {
		return rv;
	}
	cJSON *root = NULL;

	root = cJSON_Parse(buff);
	jsn  = root;
	if (root == NULL) {
		rv = false;
		goto exit;
	}
	cJSON *result_code = cJSON_GetObjectItemCaseSensitive(root, "code");
	if (!cJSON_IsNumber(result_code)) {
		rv = false;
		goto exit;
	}
	if (result_code->valueint != rc) {
		fprintf(stderr,
		    "result code not match. what we expect:%d,"
		    " what we get:%d\n",
		    rc, result_code->valueint);
		rv = false;
		goto exit;
	}

exit:
	cJSON_Delete(root);
	return rv;
}

static bool
check_http_return(FILE *fd, char *sc, int rc)
{
	char buff[5000];
	int  index = 0;
	bool rv    = true;

	while (fgets(buff, sizeof(buff), fd) != NULL) {
		index++;
		// printf("buff:%s\n", buff); // debug only.
		if (index == 1 && !check_http_status_code(buff, sc)) {
			rv = false;
			break;
		} else if (index == 5 && !check_http_result_code(buff, rc)) {
			rv = false;
			break;
		} else {
			continue;
		}
	}
	return rv;
}

static bool
test_get_endpoints()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_brokers()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/brokers'";
	// printf("cmd:%s\n", cmd);
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_nodes()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/nodes'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_clients()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/clients'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_clientid()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/clients/clientid-test'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_client_user_name()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X GET "
	    "'http://localhost:8081/api/v4/clients/username/user-test'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_subscriptions()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/subscriptions'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_subscriptions_clientid()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X GET "
	    "'http://localhost:8081/api/v4/subscriptions/client-id-test'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_topic_tree()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/topic-tree'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_metrics()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/metrics'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, RESULT_CODE_PASS);
	pclose(fd);
	return rv;
}

static bool
test_get_uri()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/?name=ferret&color=purple'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_NOT_FOUND, RESULT_CODE_PASS);
	pclose(fd);
	return rv;
}

static bool
test_get_reload()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/reload'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_bridges()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/bridges'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_bridges()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X PUT "
	    "'http://localhost:8081/api/v4/bridges/emqx'"
	    "-d '{\"data\": {\"name\": \"emqx\",\"enable\":true,\"parallel\": 8,\"connector\": {\"server\": \"mqtt-tcp://127.0.0.1:1881\",\"proto_ver\": 4, \"clientid\": null,\"clean_start\": false,\"username\": \"emqx\",\"password\": \"emqx123\",\"keepalive\": 60},\"forwards\": [\"topic1/#\",\"topic2/#\"],\"subscription\": [{\"topic\": \"cmd/topic1\", \"qos\": 1}, {\"topic\": \"cmd/topic2\",\"qos\": 2}]}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_post_rules()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test 'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": \"select * from \\\"t/a\\\"\",  \"actions\": [{  \"name\": \"repub\",  \"params\": {  \"topic\": \"repub1\", \"address\":\"broker.emqx.io:1881\", \"clean_start\": \"true\", \"clientid\": \"id\", \"username\": \"admin\", \"password\": \"public\", \"proto_ver\": 4, \"keepalive\": 60      }  }],  \"description\": \"repub-rule\"}'";
	// printf("cmd:%s\n", cmd);
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_rules()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/rules'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/rules/rule:4'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X PUT "
	            "'http://localhost:8081/api/v4/rules/rule:4'"
				"-d '{\"rawsql\":\"select * from \\\"t/b\\\"\"}'";
	// printf("\ncmd:%s\n", cmd);
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_disable_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X PUT "
	            "'http://localhost:8081/api/v4/rules/rule:4'"
				"-d '{\"enabled\": false}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_del_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X DELETE "
	            "'http://localhost:8081/api/v4/rules/rule:4'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_pub()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X POST "
	    "'http://localhost:8081/api/v4/mqtt/publish' -d "
	    "'{\"topics\":\"topic-test,topic-test2\", \"payload\":\"Hello World\", "
	    "\"qos\":1, "
	    "\"retain\":false, \"clientid\":\"clientid-test\", "
	    "\"properties\": "
	    "{\"user_properties\": { \"id\": 10010, \"name\": \"name\", "
	    "\"foo\": \"bar\"}, \"content_type\": \"text/plain\"}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_pub_batch()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X POST "
	    "'http://localhost:8081/api/v4/mqtt/publish_batch' -d "
	    "'[{\"topic\":\"topic-test\", \"payload\":\"Hello World\", "
	    "\"qos\":1, "
	    "\"retain\":false, \"clientid\":\"clientid-test\", "
	    "\"properties\": "
	    "{\"user_properties\": { \"id\": 10010, \"name\": \"name\", "
	    "\"foo\": \"bar\"}, \"content_type\": "
	    "\"text/plain\"}},{\"topic\":\"topic-test\", \"payload\":\"Hello "
	    "World Again\", "
	    "\"qos\":1, "
	    "\"retain\":false, \"clientid\":\"clientid-test\", "
	    "\"properties\": "
	    "{\"user_properties\": { \"id\": 10010, \"name\": \"name\", "
	    "\"foo\": \"bar\"}, \"content_type\": \"text/plain\"}}]'";
	// printf("cmd:%s\n", cmd);
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_sub()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/mqtt/subscribe' -d "
	            "'{\"topics\":\"a,b,c\",\"qos\":1,\"clientid\":\"clientid-"
	            "test\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_unsub()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -X POST "
	    "'http://localhost:8081/api/v4/mqtt/unsubscribe' -d "
	    "'{\"topics\":\"a\",\"qos\":1,\"clientid\":\"clientid-test\"}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_post_reload()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/reload' -d "
	            "'{\"data\": {\"property_size\": 64, \"max_packet_size\": "
	            "3, \"client_max_packet_size\": 5,\"msq_len\": "
	            "2048, \"qos_duration\": 10, \"keepalive_backoff\": "
	            "1250, \"allow_anonymous\": false}}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_unauthorized()
{
	char *cmd = "curl -i --basic -u admin:pw -X GET "
	            "'http://localhost:8081/api/v4/brokers'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(
            fd, STATUS_CODE_UNAUTHORIZED, WRONG_USERNAME_OR_PASSWORD);
	pclose(fd);
	return rv;
}

static bool
test_bad_request()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/mqtt/publish' -d 'test'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(
            fd, STATUS_CODE_BAD_REQUEST, REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	close(fd);
	return rv;
}

static bool
test_not_found()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/foo'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
	pclose(fd);
	return rv;
}

static bool
test_restart()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/ctrl/restart'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_stop()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/ctrl/stop'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

int
main()
{
	char *cmd = "mosquitto_sub -h 127.0.0.1 -p 1881 -t topic-test -u "
	            "user-test -i clientid-test";
	nng_thread *nmq;
	conf       *conf;
	FILE       *fd;

	conf = get_http_server_test_conf();
	nng_thread_create(&nmq, broker_start_with_conf, conf);
	// nng_msleep(100);  // wait a while for broker to init
	fd = popen(cmd, "r");
	nng_msleep(50); // wait a while after sub

	// TODO: there is a potential connection refuse case & although they
	// work fine separately but if test_pub() is behind test_gets() there
	// will be a memleak, which indicates there are potential bugs. Got to
	// figure out why.
	assert(test_pub());
	assert(test_pub_batch());
	// not supported for now.
	// assert(test_sub());
	// assert(test_unsub());

	assert(test_get_endpoints());

	assert(test_get_brokers());

	assert(test_get_nodes());

	assert(test_get_clients());
	assert(test_get_clientid());
	assert(test_get_client_user_name());

	assert(test_get_subscriptions());
	assert(test_get_subscriptions_clientid());

	assert(test_get_topic_tree());

	assert(test_get_reload());
	assert(test_get_configuration());
	assert(test_post_reload());

	assert(test_get_metrics());
	assert(test_get_uri());

	// // TODO: more test on bridges & rule engine
	// // assert(test_put_bridges());
	// assert(test_get_bridges());

	// // assert(test_post_rules()); // potential bug
	// assert(test_get_rules());
	// assert(test_get_rule());
	// assert(test_put_rule());
	// assert(test_disable_rule());
	// assert(test_del_rule());

	// failing tests
	assert(test_unauthorized());
	assert(test_bad_request());
	assert(test_not_found());

	// broker ctrl test
	assert(test_restart());
	assert(test_stop());

	nng_thread_destroy(nmq);
}