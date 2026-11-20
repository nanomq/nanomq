// Keep allocation failures inside credential preparation, before publication.
#include "include/conf_api.h"
#include "include/web_server.h"

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __thread bool preparing_auth, inside_allocator;
static __thread unsigned allocations, fail_at;
static __thread bool failure_triggered;

int __real_set_auth_config(cJSON *, const char *, conf_auth *);
void *__real_nng_zalloc(size_t);
char *__real_nng_strdup(const char *);
void *__real_malloc(size_t);

static bool
allocation_fails(void)
{
	if (preparing_auth && !inside_allocator && ++allocations == fail_at) {
		failure_triggered = true;
		return true;
	}
	return false;
}

int
__wrap_set_auth_config(cJSON *json, const char *path, conf_auth *auth)
{
	preparing_auth = true;
	int rv = __real_set_auth_config(json, path, auth);
	preparing_auth = false;
	return rv;
}

void *
__wrap_nng_zalloc(size_t size)
{
	if (allocation_fails()) {
		return NULL;
	}
	inside_allocator = true;
	void *ptr = __real_nng_zalloc(size);
	inside_allocator = false;
	return ptr;
}

char *
__wrap_nng_strdup(const char *value)
{
	if (allocation_fails()) {
		return NULL;
	}
	inside_allocator = true;
	char *ptr = __real_nng_strdup(value);
	inside_allocator = false;
	return ptr;
}

void *
__wrap_malloc(size_t size)
{
	return allocation_fails() ? NULL : __real_malloc(size);
}

static void
arm_failure(unsigned failure)
{
	allocations = 0;
	fail_at = failure;
	failure_triggered = false;
}

static const char *initial_auth =
    "[{\"username\":\"old-user\",\"password\":\"old-password\"}]";
static const char *replacement_auth =
    "[{\"username\":\"first\",\"password\":\"one\"},"
    "{\"username\":\"second\",\"password\":\"two\"}]";
static const char *invalid_auth[] = {
	"null", "{}", "true", "1", "\"text\"", "[null]", "[1]",
	"[[]]", "[true]", "[\"text\"]", "[{}]",
	"[{\"username\":\"u\"}]", "[{\"password\":\"p\"}]",
	"[{\"username\":null,\"password\":\"p\"}]",
	"[{\"username\":\"u\",\"password\":42}]",
	"[{\"username\":{},\"password\":\"p\"}]",
	"[{\"username\":\"u\",\"password\":[]}]",
	"[{\"username\":\"valid\",\"password\":\"pair\"},{}]",
	"[{}, {\"username\":\"valid\",\"password\":\"pair\"}]"
};

static int
set_json(conf_auth *auth, const char *text)
{
	cJSON *json = cJSON_Parse(text);
	assert(json != NULL);
	int rv = set_auth_config(json, NULL, auth);
	cJSON_Delete(json);
	return rv;
}

static void
check_unchanged(conf_auth *auth, const conf_auth *before)
{
	assert(auth->mtx == before->mtx && auth->enable == before->enable);
	assert(auth->count == before->count);
	assert(auth->usernames == before->usernames);
	assert(auth->passwords == before->passwords);
	assert(cvector_size(auth->usernames) == auth->count);
	assert(cvector_size(auth->passwords) == auth->count);
	assert(auth->count == 1);
	assert(strcmp(auth->usernames[0], "old-user") == 0);
	assert(strcmp(auth->passwords[0], "old-password") == 0);
}

static void
check_replacement(conf_auth *auth)
{
	assert(auth->count == 2);
	assert(cvector_size(auth->usernames) == auth->count);
	assert(cvector_size(auth->passwords) == auth->count);
	assert(strcmp(auth->usernames[0], "first") == 0);
	assert(strcmp(auth->passwords[0], "one") == 0);
	assert(strcmp(auth->usernames[1], "second") == 0);
	assert(strcmp(auth->passwords[1], "two") == 0);
}

static unsigned
test_set_auth(conf_auth *auth)
{
	assert(set_json(auth, initial_auth) == 0);
	conf_auth before = *auth;
	assert(set_auth_config(NULL, NULL, auth) == -1);
	check_unchanged(auth, &before);
	cJSON *json = cJSON_Parse(replacement_auth);
	assert(json != NULL);
	assert(set_auth_config(json, NULL, NULL) == -1);
	cJSON_Delete(json);
	for (size_t i = 0; i < sizeof(invalid_auth) / sizeof(*invalid_auth); i++) {
		assert(set_json(auth, invalid_auth[i]) == -1);
		check_unchanged(auth, &before);
	}

	// A cJSON string tag alone is insufficient without its string storage.
	json = cJSON_Parse(initial_auth);
	assert(json != NULL);
	cJSON *username =
	    cJSON_GetObjectItem(cJSON_GetArrayItem(json, 0), "username");
	cJSON_free(username->valuestring);
	username->valuestring = NULL;
	assert(set_auth_config(json, NULL, auth) == -1);
	check_unchanged(auth, &before);
	cJSON_Delete(json);

	arm_failure(0);
	assert(set_json(auth, replacement_auth) == 0);
	unsigned total_allocations = allocations;
	assert(total_allocations >= 7);
	check_replacement(auth);
	for (unsigned i = 1; i <= total_allocations; i++) {
		arm_failure(0);
		assert(set_json(auth, initial_auth) == 0);
		before = *auth;
		arm_failure(i);
		assert(set_json(auth, replacement_auth) == -1);
		assert(failure_triggered);
		check_unchanged(auth, &before);
	}
	arm_failure(0);
	assert(set_json(auth, "[]") == 0);
	assert(auth->count == 0 && cvector_size(auth->usernames) == 0);
	assert(cvector_size(auth->passwords) == 0);
	assert(set_json(auth, "[{\"username\":\"\",\"password\":\"\"}]") == 0);
	assert(auth->count == 1 && strcmp(auth->usernames[0], "") == 0);
	assert(strcmp(auth->passwords[0], "") == 0);
	return total_allocations;
}

static void
free_auth_entries(conf_auth *auth)
{
	for (size_t i = 0; i < cvector_size(auth->usernames); i++) {
		nng_strfree(auth->usernames[i]);
	}
	for (size_t i = 0; i < cvector_size(auth->passwords); i++) {
		nng_strfree(auth->passwords[i]);
	}
	cvector_free(auth->usernames);
	cvector_free(auth->passwords);
}

static void
test_reload(conf_auth *auth)
{
	assert(set_json(auth, initial_auth) == 0);
	conf_auth before = *auth;
	reload_auth_config(NULL, auth);
	reload_auth_config(auth, NULL);
	check_unchanged(auth, &before);
	const size_t sizes[][3] = {
		{ 1, 0, 0 }, { 1, 2, 1 }, { 1, 1, 2 }, { 0, 1, 1 }
	};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		conf_auth invalid = { .count = sizes[i][0] };
		for (size_t j = 0; j < sizes[i][1]; j++) {
			cvector_push_back(invalid.usernames, nng_strdup("u"));
		}
		for (size_t j = 0; j < sizes[i][2]; j++) {
			cvector_push_back(invalid.passwords, nng_strdup("p"));
		}
		reload_auth_config(auth, &invalid);
		check_unchanged(auth, &before);
		free_auth_entries(&invalid);
	}

	conf_auth candidate = { .enable = !auth->enable };
	assert(nng_mtx_alloc(&candidate.mtx) == 0);
	assert(set_json(&candidate, replacement_auth) == 0);
	conf_auth incoming = candidate;
	arm_failure(1);
	preparing_auth = true;
	reload_auth_config(auth, &candidate);
	preparing_auth = false;
	assert(allocations == 0);
	arm_failure(0);
	check_replacement(auth);
	assert(auth->usernames == incoming.usernames);
	assert(auth->passwords == incoming.passwords);
	assert(auth->mtx == before.mtx && auth->enable == before.enable);
	assert(candidate.mtx == incoming.mtx && candidate.enable == incoming.enable);
	assert(candidate.count == before.count);
	assert(candidate.usernames == before.usernames);
	assert(candidate.passwords == before.passwords);
	free_auth_entries(&candidate);
	nng_mtx_free(candidate.mtx);
}

static void
request(conf *cfg, const char *path, const char *body, int status, int result)
{
	http_msg req = { 0 };
	put_http_msg(&req, "application/json", "POST", path,
	    "Basic YWRtaW46cHVibGlj", body, strlen(body));
	http_msg res = process_request(&req, &cfg->http_server, NULL);
	assert(res.status == status);
	cJSON *json = cJSON_ParseWithLength(res.data, res.data_len);
	assert(json != NULL);
	cJSON *code = cJSON_GetObjectItemCaseSensitive(json, "code");
	assert(cJSON_IsNumber(code) && code->valueint == result);
	cJSON_Delete(json);
	destory_http_msg(&res);
	destory_http_msg(&req);
}

static void
test_rest(conf *cfg, unsigned total_allocations)
{
	const char *paths[] = {
		"/api/v4/configuration/auth", "/api/v4/configuration"
	};
	for (size_t p = 0; p < sizeof(paths) / sizeof(*paths); p++) {
		arm_failure(0);
		assert(set_json(&cfg->auths, initial_auth) == 0);
		cfg->auths.enable = true;
		conf_auth before = cfg->auths;
		for (size_t i = 0; i < sizeof(invalid_auth) / sizeof(*invalid_auth); i++) {
			char body[512];
			int len = snprintf(body, sizeof(body),
			    "{\"data\":{\"enable\":false,\"auth\":%s}}", invalid_auth[i]);
			assert(len >= 0 && (size_t) len < sizeof(body));
			request(cfg, paths[p], body, 400, REQ_PARAM_ERROR);
			check_unchanged(&cfg->auths, &before);
		}
		request(cfg, paths[p], "{\"data\":{\"enable\":false}}",
		    p == 0 ? 400 : 200, p == 0 ? REQ_PARAM_ERROR : SUCCEED);
		check_unchanged(&cfg->auths, &before);
		if (p == 1) {
			bool old_anonymous = cfg->allow_anonymous;
			cfg->allow_anonymous = false;
			request(cfg, paths[p],
			    "{\"data\":{\"basic\":{\"allow_anonymous\":true},"
			    "\"auth\":[{}]}}", 400, REQ_PARAM_ERROR);
			assert(!cfg->allow_anonymous);
			check_unchanged(&cfg->auths, &before);
			cfg->allow_anonymous = old_anonymous;
		}

		char body[512];
		int len = snprintf(body, sizeof(body),
		    "{\"data\":{\"enable\":false,\"auth\":%s}}", replacement_auth);
		assert(len >= 0 && (size_t) len < sizeof(body));
		for (unsigned i = 1; i <= total_allocations; i++) {
			arm_failure(i);
			request(cfg, paths[p], body, 400, REQ_PARAM_ERROR);
			assert(failure_triggered);
			check_unchanged(&cfg->auths, &before);
		}
		arm_failure(0);
		request(cfg, paths[p], body, 200, SUCCEED);
		check_replacement(&cfg->auths);
		if (p == 0) {
			assert(!cfg->auths.enable);
		}
		request(cfg, paths[p],
		    "{\"data\":{\"enable\":true,\"auth\":[]}}", 200, SUCCEED);
		assert(cfg->auths.count == 0);
		assert(cvector_size(cfg->auths.usernames) == 0);
		assert(cvector_size(cfg->auths.passwords) == 0);
		assert(cfg->auths.enable);
	}
}

int
main(void)
{
	conf *cfg = nng_zalloc(sizeof(*cfg));
	assert(cfg != NULL);
	conf_init(cfg);
	assert(nng_mtx_alloc(&cfg->restapi_lk) == 0);
	cfg->http_server.auth_type = BASIC;
	conf_http_server_update_legacy(&cfg->http_server, "admin", "public");
	set_global_conf(cfg);
	set_http_server_conf(&cfg->http_server);
	unsigned total_allocations = test_set_auth(&cfg->auths);
	test_reload(&cfg->auths);
	test_rest(cfg, total_allocations);
	set_global_conf(NULL);
	nng_mtx_free(cfg->restapi_lk);
	conf_fini(cfg);
	nng_fini();
	return 0;
}
