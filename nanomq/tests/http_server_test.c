#include "tests_api.h"

#define STATUS_CODE_OK "HTTP/1.1 200"
#define STATUS_CODE_BAD_REQUEST "HTTP/1.1 400"
#define STATUS_CODE_UNAUTHORIZED "HTTP/1.1 401"
#define STATUS_CODE_NOT_FOUND "HTTP/1.1 404"

enum result_code {
	SUCCEED                        = 0,
	RPC_ERROR                      = 101,
	UNKNOWN_MISTAKE                = 102,
	WRONG_USERNAME_OR_PASSWORD     = 103,
	EMPTY_USERNAME_OR_PASSWORD     = 104,
	USER_DOES_NOT_EXIST            = 105,
	ADMIN_CANNOT_BE_DELETED        = 106,
	MISSING_KEY_REQUEST_PARAMES    = 107,
	REQ_PARAM_ERROR                = 108,
	REQ_PARAMS_JSON_FORMAT_ILLEGAL = 109,
	PLUGIN_IS_ENABLED              = 110,
	PLUGIN_IS_CLOSED               = 111,
	CLIENT_IS_OFFLINE              = 112,
	USER_ALREADY_EXISTS            = 113,
	OLD_PASSWORD_IS_WRONG          = 114,
	ILLEGAL_SUBJECT                = 115,
	TOKEN_EXPIRED                  = 116,
};

static conf *
get_http_server_conf()
{
	conf *nmq_conf = get_dflt_conf();

	nmq_conf->http_server.enable    = true;
	nmq_conf->http_server.port      = 8081;
	nmq_conf->http_server.parallel  = 32;
	nmq_conf->http_server.username  = "admin_test";
	nmq_conf->http_server.password  = "pw_test";
	nmq_conf->http_server.auth_type = BASIC;

	return nmq_conf;
}

static void
check_http_status_code(char *buff, char *sc)
{
	// printf("sc=%s\n", sc);
	assert(strncmp(buff, sc, 12) == 0);
}

static void
check_http_result_code(char *buff, int rc)
{
	cJSON *root = NULL;
	root        = cJSON_Parse(buff);
	assert(root != NULL);
	cJSON *result_code = cJSON_GetObjectItemCaseSensitive(root, "code");
	assert(cJSON_IsNumber(result_code));
	// printf("rc=%d\n", rc);
	assert(result_code->valueint == rc);
	cJSON_Delete(root);
}

static void
check_http_return(FILE *fd, char *sc, int rc)
{
	char buff[5000];
	int  index = 0;
	while (fgets(buff, sizeof(buff), fd) != NULL) {
		index++;
		if (index == 1) {
			check_http_status_code(buff, sc);
		} else if (index == 5) {
			check_http_result_code(buff, rc);
			// printf("data:%s\n", buff);
		} else {
			continue;
		}
	}
}

static void
test_get_endpoints()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_get_brokers()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/brokers'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_get_nodes()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/nodes'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_get_clients()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/clients'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_get_subscriptions()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/subscriptions'";

	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_get_subscriptions_clientid()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X GET "
	            "'http://localhost:8081/api/v4/subscriptions/123'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_OK, SUCCEED);
	pclose(fd);
}

static void
test_unauthorized()
{
	char *cmd = "curl -i --basic -u admin:pw -X GET "
	            "'http://localhost:8081/api/v4/brokers'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_UNAUTHORIZED, WRONG_USERNAME_OR_PASSWORD);
	pclose(fd);
}

static void
test_bad_request()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/mqtt/publish' -d 'test'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_BAD_REQUEST, REQ_PARAMS_JSON_FORMAT_ILLEGAL);
	pclose(fd);
}

static void
test_not_found()
{
	char *cmd = "curl -i --basic -u admin_test:pw_test -X POST "
	            "'http://localhost:8081/api/v4/foo'";
	FILE *fd;
	fd = popen(cmd, "r");
	check_http_return(fd, STATUS_CODE_NOT_FOUND, UNKNOWN_MISTAKE);
	pclose(fd);
}

int
main()
{
	nng_thread *nmq;
	conf       *conf;

	conf = get_http_server_conf();
	nng_thread_create(&nmq, broker_start_with_conf, conf);

	test_get_endpoints();
	test_get_brokers();
	test_get_nodes();
	test_get_clients();
	test_get_subscriptions();
	test_get_subscriptions_clientid();

	test_unauthorized();
	test_bad_request();
	test_not_found();

	nng_thread_destroy(nmq);
}