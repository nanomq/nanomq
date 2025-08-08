#include "tests_api.h"

#define STATUS_CODE_OK "HTTP/1.1 200"
#define STATUS_CODE_BAD_REQUEST "HTTP/1.1 400"
#define STATUS_CODE_UNAUTHORIZED "HTTP/1.1 401"
#define STATUS_CODE_NOT_FOUND "HTTP/1.1 404"
#define STATUS_CODE_METHOD_NOT_ALLOW "HTTP/1.1 405"

#define RESULT_CODE_PASS -1

static cJSON *jsn; // TODO: this could be used for further check.

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
		// printf("\nbuff:%s\n", buff); // debug only.
		if (index == 1 && !check_http_status_code(buff, sc)) {
			rv = false;
		} else if (index == 8 && !check_http_result_code(buff, rc)) {
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
	    "'http://localhost:8081/api/v4/subscriptions/clientid-test'";
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
test_get_configuration_basic()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/basic'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_tls()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/tls'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_auth()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/auth'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_auth_http()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/auth_http'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_websocket()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/websocket'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_http_server()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/http_server'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_sqlite()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/sqlite'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_bridge()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/bridge'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_get_configuration_foo()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/configuration/foo'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_NOT_FOUND, SUCCEED);
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
test_get_bridge()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/bridges/emqx'";
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
	    "'http://localhost:8081/api/v4/bridges/emqx' -d '{"
    	"\"emqx\": {"
        "\"name\": \"emqx\","
        "\"enable\": true,"
        "\"parallel\": 8,"
        "\"server\": \"mqtt-tcp://broker.emqx.io:1883\","
        "\"proto_ver\": 5,"
        "\"clientid\": \"hello3\","
        "\"clean_start\": true,"
        "\"username\": \"emqx\","
        "\"password\": \"emqx123\","
        "\"keepalive\": 60,"
        "\"forwards\": [{\"remote_topic\":\"topic1/#\",\"local_topic\":\"topic1_lo/#\"}],"
        "\"subscription\": [{\"remote_topic\":\"topic1/#\",\"local_topic\":\"topic1_lo/#\",\"qos\": 1}]}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_bridges_sub()
{
	char *cmd = "curl -i --location "
	            "'http://localhost:8081/api/v4/bridges/sub/emqx' "
	            "--basic -u admin_test:pw_test -d '{"
	            "\"data\": {"
	            "\"subscription\": [{\"remote_topic\": "
	            "\"cmd/topic4\",\"local_topic\": \"cmd_lo/topic4\"}],"
	            "\"sub_properties\": {\"user_properties\": [{\"key\": "
	            "\"key1\",\"value\": \"value1\"},{\"key\": "
	            "\"key2\",\"value\": \"value2\"}]}}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_bridges_unsub()
{
	char *cmd = "curl -i --location "
	            "'http://localhost:8081/api/v4/bridges/unsub/emqx' "
	            "--basic -u admin_test:pw_test -d '{"
	            "\"data\": {"
	            "\"unsubscription\": [{\"topic\": \"cmd/topic1\"},"
				"{\"topic\": \"cmd/topic2\"}],"
	            "\"unsub_properties\": {\"user_properties\": [{\"key\": "
	            "\"key1\",\"value\": \"value1\"},{\"key\": "
	            "\"key2\",\"value\": \"value2\"}]}}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_post_rules_repub()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test "
	    "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
	    "\"select * from \\\"t/a\\\"\",  \"actions\": [{  \"name\": "
	    "\"repub\",  \"params\": {  \"topic\": \"repub1\", "
	    "\"address\":\"mqtt-tcp://localhost:1881\", \"clean_start\": "
	    "\"true\", "
	    // TODO: there is a memleak in nanoclient connmsg sending.
	    // "\"clientid\": \"id\", \"username\": \"admin\", \"password\":"
	    // "\"public\", "
	    "\"proto_ver\": 4, \"keepalive\": 60      }  }],  "
	    "\"description\": \"repub-rule\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;	
}

static bool
test_post_rules_sqlite()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test "
	    "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
	    "\"select * from \\\"t/b\\\"\",  \"actions\": [{  \"name\": "
	    "\"sqlite\",  \"params\": {  \"table\": \"table_sqlite\"}  }],  "
	    "\"description\": \"sqlite-rule\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;	
}

static bool
test_post_rules_mysql()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test "
	    "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
	    "\"select * from \\\"t/c\\\"\",  \"actions\": [{  \"name\": "
	    "\"mysql\",  \"params\": {  \"table\": \"table_mysql\", "
	    "\"username\":\"username\", \"password\": \"password\", "
	    "\"host\": \"localhost\"} }],  "
	    "\"description\": \"mysql-rule\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;	
}

static bool
test_post_rules_unsupported()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test "
	    "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
	    "\"select * from \\\"t/d\\\"\",  \"actions\": [{  \"name\": "
	    "\"mesql\",  \"params\": {  \"topic\": \"mesql1\"}  }],  "
	    "\"description\": \"unsup-rule\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_BAD_REQUEST, PLUGIN_IS_CLOSED);
	pclose(fd);
	return rv;	
}

static bool
test_post_rules()
{
	nng_msleep(1000);
	assert(test_post_rules_repub());
	nng_msleep(1000);
	assert(test_post_rules_sqlite());
	nng_msleep(1000);
	// mysql connect to local mysql sever will fail in ci
	// assert(test_post_rules_mysql());
	assert(test_post_rules_unsupported());
	nng_msleep(1000);
	return true;
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
	            "'http://localhost:8081/api/v4/rules/rule:3'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_rule_repub()
{
	char *cmd =
	    "curl -i --basic -u admin_test:pw_test -XPUT "
	    "'http://localhost:8081/api/v4/rules/rule:3' "
	    "-d '{\"rawsql\":\"select * from \\\"t/b\\\"\","
	    "\"actions\": [{\"name\":\"repub\", \"params\": { \"topic\": "
	    "\"repub1\", "
	    "\"address\":\"mqtt-tcp://localhost:1881\", \"clean_start\": "
	    "\"true\", "
	    // TODO: there is a memleak in nanoclient connmsg sending.
	    // "\"clientid\": \"id\", \"username\": \"admin\", \"password\":"
	    // "\"public\", "
	    "\"proto_ver\": 4, \"keepalive\": 60}}]}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_rule_sqlite()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -XPUT "
	            "'http://localhost:8081/api/v4/rules/rule:4' "
	            "-d '{\"rawsql\":\"select * from \\\"t/b\\\"\","
	            "\"actions\": [{\"name\": \"sqlite\","
	            "\"params\": {\"table\": \"table_sqlite\"}}],"
	            "\"description\": \"sqlite-rule\"}'";
	// printf("cmd:%s\n", cmd);
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_rule_mysql()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -XPUT "
	            "'http://localhost:8081/api/v4/rules/rule:2' "
	            "-d '{\"rawsql\":\"select * from \\\"t/b\\\"\","
	            "\"actions\": [{\"name\": \"mysql\","
	            "\"params\": {\"table\": \"table_mysql\"}}],"
	            "\"description\": \"mysql-rule\"}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_put_rule()
{
	nng_msleep(2000);
	assert(test_put_rule_repub());
	assert(test_put_rule_sqlite());
	// assert(test_put_rule_mysql());
	return true;
}

static bool
test_disable_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -XPUT "
	            "'http://localhost:8081/api/v4/rules/rule:3' "
				"-d '{\"enabled\": false}'";
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
	return rv;
}

static bool
test_del_rule()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -XDELETE "
	            "'http://localhost:8081/api/v4/rules/rule:3'";
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
	pclose(fd);
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

static bool
test_get_prometheus()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/prometheus'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_OK, RESULT_CODE_PASS);
	pclose(fd);
	return rv;
}

static bool
test_misuse_of_put()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X PUT "
	            "'http://localhost:8081/api/v4/foo'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
	pclose(fd);
	return rv;
}

static bool
test_misuse_of_del()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X DELETE "
	            "'http://localhost:8081/api/v4/foo'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
	pclose(fd);
	return rv;
}

static bool
test_misuse_of_method()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X METHOD "
	            "'http://localhost:8081/api/v4/foo'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_METHOD_NOT_ALLOW, UNKNOWN_MISTAKE);
	pclose(fd);
	return rv;
}

int
main()
{
	char *cmd = "/bin/mosquitto_sub";

	char *cmd1[] = { "mosquitto_sub", "-h", "127.0.0.1", "-p", "1881",
		"-t", "topic-test", "-u", "user-test", "-i", "clientid-test",
		NULL };
	char *cmd2[] = { "mosquitto_sub", "-h", "127.0.0.1", "-p", "1881",
		"-t", "topic-test2", "-u", "user-test2", "-i",
		"clientid-test2", NULL };
	nng_thread *nmq;
	conf       *conf;
	pid_t       pid_sub;
	pid_t       pid_sub2;
	int         outfp;
	int         outfp2;

	conf = get_test_conf(ALL_FEATURE_CONF);
	assert(conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
	nng_msleep(500);  // wait a while for broker to init
	pid_sub = popen_with_cmd(&outfp, cmd1, cmd);
	pid_sub2 = popen_with_cmd(&outfp2, cmd2, cmd);
	nng_msleep(500); // wait a while after sub

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
	assert(test_get_prometheus());

	assert(test_get_clients());
	assert(test_get_clientid());
	assert(test_get_client_user_name());

	assert(test_get_subscriptions());
	assert(test_get_subscriptions_clientid());

	assert(test_get_topic_tree());

	assert(test_get_reload());
	assert(test_get_configuration());
	assert(test_get_configuration_basic());
	assert(test_get_configuration_tls());
	assert(test_get_configuration_auth());
	assert(test_get_configuration_auth_http());
	assert(test_get_configuration_websocket());
	assert(test_get_configuration_http_server());
	assert(test_get_configuration_sqlite());
	assert(test_get_configuration_bridge());
	assert(test_get_configuration_foo());

	assert(test_post_reload());

	assert(test_get_metrics());
	assert(test_get_uri());

	assert(test_get_bridges());
	assert(test_get_bridge());
	assert(test_put_bridges_sub());
	assert(test_put_bridges_unsub()); // the usage of unsub rest api may need further discussion.
	assert(test_put_bridges()); 

	assert(test_post_rules());
	assert(test_get_rules());
	assert(test_get_rule());
	assert(test_put_rule());
	assert(test_disable_rule());
	assert(test_del_rule());

	// failing tests
	assert(test_unauthorized());
	assert(test_bad_request());
	assert(test_not_found());

	assert(test_misuse_of_put());
	assert(test_misuse_of_del());
	assert(test_misuse_of_method());

	// TODO: more post & get config test; post & get rules test in repub,
	// sqlite, mysql

	// // broker ctrl test
	// // --> ctrl cmd will msleep() for 2 seconds, so they are not fully
	// // tested now.
	// assert(test_restart());
	// assert(test_stop());
	nng_msleep(2000);
	kill(pid_sub, SIGKILL);
	kill(pid_sub2, SIGKILL);

	nng_thread_destroy(nmq);
}