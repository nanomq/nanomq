#include "include/bridge.h"
#include "tests_api.h"

#define STATUS_CODE_OK "HTTP/1.1 200"
#define STATUS_CODE_BAD_REQUEST "HTTP/1.1 400"
#define STATUS_CODE_UNAUTHORIZED "HTTP/1.1 401"
#define STATUS_CODE_NOT_FOUND "HTTP/1.1 404"
#define STATUS_CODE_METHOD_NOT_ALLOW "HTTP/1.1 405"

#define RESULT_CODE_PASS -1

#ifdef SUPP_RULE_ENGINE
#define RULE_RESULT_CODE SUCCEED
#else
#define RULE_RESULT_CODE PLUGIN_IS_CLOSED
#endif

static int last_rule_id = -1;
static int repub_rule_id = -1;
static int sqlite_rule_id = -1;

static void
capture_rule_id(const char *json_body)
{
    cJSON *root;
    cJSON *data;
    cJSON *id;

    if (json_body == NULL) {
        return;
    }
    root = cJSON_Parse(json_body);
    if (root == NULL) {
        return;
    }
    data = cJSON_GetObjectItemCaseSensitive(root, "data");
    id   = cJSON_GetObjectItemCaseSensitive(data, "id");
    if (cJSON_IsNumber(id)) {
        last_rule_id = id->valueint;
    }
    cJSON_Delete(root);
}

static bool
check_http_status_code(const char *buff, const char *sc)
{
    if (strncmp(buff, sc, 12) != 0) {
        fprintf(stderr,
            "[FAIL] Status code mismatch.\nExpected: %s\nGot:      %s\n",
            sc, buff);
        return false;
    }
    return true;
}

static bool
check_http_result_code(const char *json_body, int rc)
{
    if (rc == RESULT_CODE_PASS) {
        return true;
    }

    // Skip if body is empty
    if (json_body == NULL || strlen(json_body) == 0) {
        return false;
    }

    bool rv = true;
    cJSON *root = cJSON_Parse(json_body);
    
    if (root == NULL) {
        fprintf(stderr, "[FAIL] JSON Parse Error. Body: %s\n", json_body);
        return false;
    }

    cJSON *result_code = cJSON_GetObjectItemCaseSensitive(root, "code");
    if (!cJSON_IsNumber(result_code)) {
        // Some endpoints return "data" without "code", imply success if we got JSON
        // But if we expected a specific code and didn't find one, that's an issue
        // unless rc was checked earlier.
        // For this test suite, let's assume missing code != expected rc
        rv = false;
        goto exit;
    }

    if (result_code->valueint != rc) {
        fprintf(stderr,
            "[FAIL] Result code mismatch.\nExpected: %d\nGot:      %d\n",
            rc, result_code->valueint);
        rv = false;
    }

exit:
    cJSON_Delete(root);
    return rv;
}

static bool
check_http_return(FILE *fd, char *expect_sc, int expect_rc)
{
	if (fd == NULL) {
		fprintf(stderr, "[FAIL] failed to start curl command\n");
		return false;
	}

	char line_buff[2048];
    char body_buff[8192] = {0};
    bool got_status = false;
    bool status_checked = false;
    bool headers_done = false;
    bool rv = true;

    // 1. Read Line by Line
    while (fgets(line_buff, sizeof(line_buff), fd) != NULL) {
        // Check Status Line (First Line)
        if (!status_checked) {
            if (!check_http_status_code(line_buff, expect_sc)) {
                rv = false;
                // We continue reading to drain pipe, but we know it failed
            }
            got_status = true;
            status_checked = true;
            continue;
        }

        // Check for End of Headers (Empty line with just \r\n or \n)
        if (!headers_done) {
            if (strcmp(line_buff, "\r\n") == 0 || strcmp(line_buff, "\n") == 0) {
                headers_done = true;
            }
            continue;
        }

        // Accumulate Body
        strncat(body_buff, line_buff, sizeof(body_buff) - strlen(body_buff) - 1);
    }

    // 2. Check JSON Result Code (if status passed)
    if (rv && got_status && headers_done) {
        capture_rule_id(body_buff);
        if (!check_http_result_code(body_buff, expect_rc)) {
            rv = false;
        }
    } else if (!got_status || (rv && !headers_done)) {
        // Case where we got status but no body (unexpected EOF)
        // fprintf(stderr, "[WARN] No body received\n");
        rv = false;
    }

    return rv;
}

// Helper to add -s (silent) to curl to avoid progress bars in output
#define CURL_CMD_PREFIX                                                         \
	"curl -sS -i --basic -u admin_test:pw_test --connect-timeout 1 --max-time 5 "

#define CURL_CMD_PREFIX_NO_AUTH                                                 \
	"curl -sS -i --connect-timeout 1 --max-time 5 "

#define SAFE_POPEN_CLOSE(fd)                                                  \
	do {                                                                    \
		if ((fd) != NULL) {                                               \
			pclose((fd));                                              \
		}                                                                 \
	} while (0)

static bool test_get_endpoints();

static bool
wait_for_http_server_ready(int timeout_ms)
{
	int waited_ms = 0;
	char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4'";

	while (waited_ms < timeout_ms) {
		FILE *fd = popen(cmd, "r");
		char  status[32] = { 0 };
		bool  ready = fd != NULL && fgets(status, sizeof(status), fd) != NULL &&
		    strncmp(status, STATUS_CODE_OK, strlen(STATUS_CODE_OK)) == 0;

		SAFE_POPEN_CLOSE(fd);
		if (ready) {
			return true;
		}
		nng_msleep(100);
		waited_ms += 100;
	}

	return false;
}

static bool
test_get_endpoints()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_brokers()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/brokers'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_nodes()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/nodes'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_prometheus()
{
	char *cmd = CURL_CMD_PREFIX
	            "'http://localhost:8081/api/v4/prometheus'";
	FILE *fd  = popen(cmd, "r");
	bool  rv =
	    check_http_return(fd, STATUS_CODE_OK, RESULT_CODE_PASS);
	SAFE_POPEN_CLOSE(fd);
	return rv;
}

static bool
test_get_clients()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/clients'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_clientid()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/clients/clientid-test'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_client_user_name()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/clients/username/user-test'";
    FILE *fd = popen(cmd, "r");
    bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_subscriptions()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/subscriptions'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_subscriptions_clientid()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/subscriptions/clientid-test'";
    FILE *fd = popen(cmd, "r");
    bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_topic_tree()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/topic-tree'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_metrics()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/metrics'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, RESULT_CODE_PASS);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_uri()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/?name=ferret&color=purple'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_NOT_FOUND, RESULT_CODE_PASS);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_reload()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/reload'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_basic()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/basic'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_tls()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/tls'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_auth()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/auth'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_auth_http()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/auth_http'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_websocket()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/websocket'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_http_server()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/http_server'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_sqlite()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/sqlite'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_bridge()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/bridge'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_configuration_foo()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/configuration/foo'";
    FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_NOT_FOUND, RPC_ERROR);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_bridges()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/bridges'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_bridge()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/bridges/emqx'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_put_bridges()
{
	char cmd[2048];
	snprintf(cmd, sizeof(cmd),
	    CURL_CMD_PREFIX "-X PUT "
	    "'http://localhost:8081/api/v4/bridges/emqx' -d '{"
	    "\"emqx\": {"
	    "\"name\": \"emqx\","
	    "\"enable\": true,"
	    "\"parallel\": 8,"
	    "\"server\": \"mqtt-tcp://127.0.0.1:%s\","
	    "\"proto_ver\": 5,"
	    "\"clientid\": \"hello3\","
	    "\"clean_start\": true,"
	    "\"username\": \"emqx\","
	    "\"password\": \"emqx123\","
	    "\"keepalive\": 60,"
	    "\"forwards\": [{\"remote_topic\":\"topic1/#\",\"local_topic\":\"topic1_lo/#\"}],"
	    "\"subscription\": [{\"remote_topic\":\"topic1/#\",\"local_topic\":\"topic1_lo/#\",\"qos\": 1}]}}'",
	    test_env_test_port_text());
	FILE *fd = popen(cmd, "r");
    bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_put_bridges_replaces_client(conf *config)
{
    conf_bridge_node *node = config->bridge.nodes[0];
    bridge_param *param = node->bridge_arg;
    nng_mqtt_client *client = param->client;

    return test_put_bridges() && param->client != client;
}

static bool
test_put_bridges_sub(char *expected_status, int expected_rc)
{
	char *cmd = CURL_CMD_PREFIX "-X PUT "
                "'http://localhost:8081/api/v4/bridges/sub/emqx' "
                "-d '{"
                "\"data\": {"
                "\"subscription\": [{\"remote_topic\": "
                "\"cmd/topic4\",\"local_topic\": \"cmd_lo/topic4\"}],"
                "\"sub_properties\": {\"user_properties\": [{\"key\": "
                "\"key1\",\"value\": \"value1\"},{\"key\": "
                "\"key2\",\"value\": \"value2\"}]}}}'";
    FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, expected_status, expected_rc);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_put_bridges_switch(bool bridge_switch)
{
	char *cmd = bridge_switch ?
	    CURL_CMD_PREFIX "-X POST "
	                    "'http://localhost:8081/api/v4/bridges/switch/emqx' "
	                    "-d '{\"data\": {\"bridge_switch\": true}}'" :
	    CURL_CMD_PREFIX "-X POST "
	                    "'http://localhost:8081/api/v4/bridges/switch/emqx' "
	                    "-d '{\"data\": {\"bridge_switch\": false}}'";
	FILE *fd = popen(cmd, "r");
	bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	SAFE_POPEN_CLOSE(fd);
	return rv;
}

static bool
test_put_bridges_unsub()
{
	char *cmd = CURL_CMD_PREFIX "-X PUT "
                "'http://localhost:8081/api/v4/bridges/unsub/emqx' "
                "-d '{"
                "\"data\": {"
                "\"unsubscription\": [{\"topic\": \"cmd/topic1\"},"
                "{\"topic\": \"cmd/topic2\"}],"
                "\"unsub_properties\": {\"user_properties\": [{\"key\": "
                "\"key1\",\"value\": \"value1\"},{\"key\": "
                "\"key2\",\"value\": \"value2\"}]}}}'";
    FILE *fd = popen(cmd, "r");
    bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_post_rules_repub()
{
	const char *test_port = test_env_test_port_text();
	char        rule_addr[40];
	char        cmd[1024];

	snprintf(rule_addr, sizeof(rule_addr), "mqtt-tcp://localhost:%s", test_port);
	snprintf(cmd, sizeof(cmd),
	    CURL_CMD_PREFIX
	    "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
	    "\"select * from \\\"t/a\\\"\",  \"actions\": [{  \"name\": "
	    "\"repub\",  \"params\": {  \"topic\": \"repub1\", "
	    "\"address\":\"%s\", \"clean_start\": "
	    "\"true\", "
	    "\"proto_ver\": 4, \"keepalive\": 60      }  }],  "
	    "\"description\": \"repub-rule\"}'",
	    rule_addr);
	last_rule_id = -1;
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd,
#ifdef SUPP_RULE_ENGINE
	    STATUS_CODE_OK, SUCCEED);
#else
	    STATUS_CODE_OK, PLUGIN_IS_CLOSED);
#endif
	SAFE_POPEN_CLOSE(fd);
	if (rv && last_rule_id >= 0) {
		repub_rule_id = last_rule_id;
	}
	return rv;
}

static bool
test_post_rules_sqlite()
{
    char *cmd =
        CURL_CMD_PREFIX
        "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
        "\"select * from \\\"t/b\\\"\",  \"actions\": [{  \"name\": "
        "\"sqlite\",  \"params\": {  \"table\": \"table_sqlite\"}  }],  "
        "\"description\": \"sqlite-rule\"}'";
    last_rule_id = -1;
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd,
#ifdef SUPP_RULE_ENGINE
        STATUS_CODE_OK, SUCCEED);
#else
        STATUS_CODE_OK, PLUGIN_IS_CLOSED);
#endif
    SAFE_POPEN_CLOSE(fd);
    if (rv && last_rule_id >= 0) {
        sqlite_rule_id = last_rule_id;
    }
    return rv;
}

static bool
test_post_rules_unsupported()
{
    char *cmd =
        CURL_CMD_PREFIX
        "'http://localhost:8081/api/v4/rules' -X POST -d '{  \"rawsql\": "
        "\"select * from \\\"t/d\\\"\",  \"actions\": [{  \"name\": "
        "\"mesql\",  \"params\": {  \"topic\": \"mesql1\"}  }],  "
        "\"description\": \"unsup-rule\"}'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd,
#ifdef SUPP_RULE_ENGINE
        STATUS_CODE_BAD_REQUEST, PLUGIN_IS_CLOSED);
#else
        STATUS_CODE_OK, PLUGIN_IS_CLOSED);
#endif
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_post_rules()
{
    assert(test_post_rules_repub());
    assert(test_post_rules_sqlite());
    assert(test_post_rules_unsupported());
    return true;
}

static bool
test_get_rules()
{
    char *cmd = CURL_CMD_PREFIX "-X GET 'http://localhost:8081/api/v4/rules'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_get_rule()
{
    char cmd[256];
    if (repub_rule_id < 0) {
        return false;
    }
    snprintf(cmd, sizeof(cmd), CURL_CMD_PREFIX
        "-X GET 'http://localhost:8081/api/v4/rules/rule:%d'",
        repub_rule_id);
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_put_rule_repub()
{
	const char *test_port = test_env_test_port_text();
	char        rule_addr[40];
	char        cmd[1024];

	snprintf(rule_addr, sizeof(rule_addr), "mqtt-tcp://localhost:%s", test_port);
    if (repub_rule_id < 0) {
        return false;
    }
    snprintf(cmd, sizeof(cmd),
	    CURL_CMD_PREFIX "-X PUT "
	    "'http://localhost:8081/api/v4/rules/rule:%d' "
	    "-d '{\"rawsql\":\"select * from \\\"t/b\\\"\","
	    "\"actions\": [{\"name\":\"repub\", \"params\": { \"topic\": "
	    "\"repub1\", "
	    "\"address\":\"%s\", \"clean_start\": "
	    "\"true\", "
	    "\"proto_ver\": 4, \"keepalive\": 60}}]}'",
	    repub_rule_id, rule_addr);
	FILE *fd  = popen(cmd, "r");
	bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
	SAFE_POPEN_CLOSE(fd);
	return rv;
}
static bool
test_put_rule_sqlite()
{
    char cmd[1024];
    if (sqlite_rule_id < 0) {
        return false;
    }
    snprintf(cmd, sizeof(cmd), CURL_CMD_PREFIX "-X PUT "
        "'http://localhost:8081/api/v4/rules/rule:%d' "
        "-d '{\"rawsql\":\"select * from \\\"t/b\\\"\","
        "\"actions\": [{\"name\": \"sqlite\","
        "\"params\": {\"table\": \"table_sqlite\"}}],"
        "\"description\": \"sqlite-rule\"}'",
        sqlite_rule_id);
     FILE *fd  = popen(cmd, "r");
     bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_put_rule()
{
    assert(test_put_rule_repub());
    assert(test_put_rule_sqlite());
    return true;
}

static bool
test_disable_rule()
{
    char cmd[256];
    if (repub_rule_id < 0) {
        return false;
    }
    snprintf(cmd, sizeof(cmd), CURL_CMD_PREFIX "-X PUT "
        "'http://localhost:8081/api/v4/rules/rule:%d' "
        "-d '{\"enabled\": false}'",
        repub_rule_id);
     FILE *fd  = popen(cmd, "r");
     bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_del_rule()
{
    char cmd[256];
    if (repub_rule_id < 0) {
        return false;
    }
    snprintf(cmd, sizeof(cmd), CURL_CMD_PREFIX
        "-X DELETE 'http://localhost:8081/api/v4/rules/rule:%d'",
        repub_rule_id);
     FILE *fd  = popen(cmd, "r");
     bool  rv  = check_http_return(fd, STATUS_CODE_OK, RULE_RESULT_CODE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_pub()
{
    char *cmd =
        CURL_CMD_PREFIX "-X POST "
        "'http://localhost:8081/api/v4/mqtt/publish' -d "
        "'{\"topics\":\"topic-test,topic-test2\", \"payload\":\"Hello World\", "
        "\"qos\":1, "
        "\"retain\":false, \"clientid\":\"clientid-test\", "
        "\"properties\": "
        "{\"user_properties\": { \"id\": 10010, \"name\": \"name\", "
        "\"foo\": \"bar\"}, \"content_type\": \"text/plain\"}}'";
    FILE *fd = popen(cmd, "r");
    bool  rv = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_pub_batch()
{
    char *cmd =
        CURL_CMD_PREFIX "-X POST "
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
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_post_reload()
{
    char *cmd = CURL_CMD_PREFIX "-X POST "
                "'http://localhost:8081/api/v4/reload' -d "
                "'{\"data\": {\"property_size\": 64, \"max_packet_size\": "
                "3, \"client_max_packet_size\": 5,\"msq_len\": "
                "2048, \"qos_duration\": 10, \"keepalive_backoff\": "
                "1250, \"allow_anonymous\": false}}'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(fd, STATUS_CODE_OK, SUCCEED);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_unauthorized()
{
    char *cmd = CURL_CMD_PREFIX_NO_AUTH "-u admin:pw -X GET "
                "'http://localhost:8081/api/v4/brokers'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(
            fd, STATUS_CODE_UNAUTHORIZED, WRONG_USERNAME_OR_PASSWORD);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_bad_request()
{
    char *cmd = CURL_CMD_PREFIX "-X POST "
                "'http://localhost:8081/api/v4/mqtt/publish' -d 'test'";
    FILE *fd  = popen(cmd, "r");
    bool  rv  = check_http_return(
            fd, STATUS_CODE_BAD_REQUEST, REQ_PARAMS_JSON_FORMAT_ILLEGAL);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_not_found()
{
    char *cmd = CURL_CMD_PREFIX "-X POST "
                "'http://localhost:8081/api/v4/foo'";
    FILE *fd  = popen(cmd, "r");
    bool  rv =
        check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_misuse_of_put()
{
    char *cmd = CURL_CMD_PREFIX "-X PUT "
                "'http://localhost:8081/api/v4/foo'";
    FILE *fd  = popen(cmd, "r");
    bool  rv =
        check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_misuse_of_del()
{
    char *cmd = CURL_CMD_PREFIX "-X DELETE "
                "'http://localhost:8081/api/v4/foo'";
    FILE *fd  = popen(cmd, "r");
    bool  rv =
        check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

static bool
test_misuse_of_method()
{
    char *cmd = CURL_CMD_PREFIX "-X METHOD "
                "'http://localhost:8081/api/v4/foo'";
    FILE *fd  = popen(cmd, "r");
    bool  rv =
        check_http_return(fd, STATUS_CODE_METHOD_NOT_ALLOW, UNKNOWN_MISTAKE);
    SAFE_POPEN_CLOSE(fd);
    return rv;
}

int
main()
{
	if (!test_env_allows_network_binds() || !test_env_allows_port_bind(8081)) {
		fprintf(stderr, "skip: test environment disallows listening sockets\n");
		return 0;
	}
	if (!test_env_has_executable("curl")) {
		fprintf(stderr, "skip: curl not found in PATH\n");
		return 0;
	}
	bool has_mosquitto_sub = test_env_has_executable("mosquitto_sub");
	if (!has_mosquitto_sub) {
		fprintf(stderr,
		    "skip: mosquitto_sub not found; omitting client-specific checks\n");
	}

    char *cmd = "mosquitto_sub";

    char *cmd1[] = { "mosquitto_sub", "-h", "127.0.0.1", "-p", (char *) test_env_test_port_text(),
        "-t", "topic-test", "-u", "user-test", "-i", "clientid-test",
        NULL };
    char *cmd2[] = { "mosquitto_sub", "-h", "127.0.0.1", "-p", (char *) test_env_test_port_text(),
        "-t", "topic-test2", "-u", "user-test2", "-i",
        "clientid-test2", NULL };
    nng_thread *nmq;
    conf       *conf;
	pid_t       pid_sub  = -1;
	pid_t       pid_sub2 = -1;
	int         outfp;
	int         outfp2;

    conf = get_test_conf(ALL_FEATURE_CONF);
    assert(conf != NULL);
    nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) conf);
    nng_msleep(500);  // wait a while for broker to init
    assert(wait_for_http_server_ready(2000));
	if (has_mosquitto_sub) {
		pid_sub = popen_with_cmd(&outfp, cmd1, cmd);
		pid_sub2 = popen_with_cmd(&outfp2, cmd2, cmd);
		nng_msleep(500); // wait a while after sub
	}

    assert(test_pub());
    assert(test_pub_batch());

    assert(test_get_endpoints());

    assert(test_get_brokers());

    assert(test_get_nodes());
    assert(test_get_prometheus());

	if (has_mosquitto_sub) {
		assert(test_get_clients());
		assert(test_get_clientid());
		assert(test_get_client_user_name());

		assert(test_get_subscriptions());
		assert(test_get_subscriptions_clientid());
	}

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
    assert(test_put_bridges());
    // Reconfiguration reconnects the bridge before it can process SUB/UNSUB.
    nng_msleep(1000);
    // The reloaded node must survive the connect-status flag swap and
    // re-parsing (rest_api.c) and stay queryable (bridge.c reload paths).
    assert(test_get_bridge());
    assert(test_put_bridges_sub(STATUS_CODE_OK, SUCCEED));
    assert(test_put_bridges_unsub());
    assert(test_put_bridges_replaces_client(conf));
    assert(test_put_bridges_switch(false));
    // Disabled node (enable=false under node->mtx) must stay queryable.
    assert(test_get_bridge());
    assert(test_put_bridges_sub(STATUS_CODE_NOT_FOUND, RESULT_CODE_PASS));

    // Rules Logic Check
    assert(test_post_rules());
    assert(test_get_rules());
#ifdef SUPP_RULE_ENGINE
    assert(test_get_rule());
    assert(test_put_rule());
    assert(test_disable_rule());
    assert(test_del_rule());
#endif

    assert(test_unauthorized());
    assert(test_bad_request());
    assert(test_not_found());

    assert(test_misuse_of_put());
    assert(test_misuse_of_del());
    assert(test_misuse_of_method());

	if (pid_sub > 0) {
		kill(pid_sub, SIGKILL);
	}
	if (pid_sub2 > 0) {
		kill(pid_sub2, SIGKILL);
	}

	broker_stop_for_test();
	nng_thread_destroy(nmq);
    return 0;
}
