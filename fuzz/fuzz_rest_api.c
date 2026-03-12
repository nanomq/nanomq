#ifndef ENABLE_LOG
#define ENABLE_LOG 1
#endif
#ifndef SUPP_RULE_ENGINE
#define SUPP_RULE_ENGINE 1
#endif
#ifndef ACL_SUPP
#define ACL_SUPP 1
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/hash_table.h"

#include "include/rest_api.h"
#include "include/web_server.h"

static conf g_conf;
static bool g_inited = false;

static size_t
hex_encode(char *dst, size_t dst_cap, const uint8_t *src, size_t src_len)
{
	static const char *hex = "0123456789abcdef";
	size_t             o   = 0;

	if (dst_cap == 0) {
		return 0;
	}

	for (size_t i = 0; i < src_len; i++) {
		if (o + 2 >= dst_cap) {
			break;
		}
		dst[o++] = hex[(src[i] >> 4) & 0x0F];
		dst[o++] = hex[src[i] & 0x0F];
	}
	dst[o] = '\0';
	return o;
}

static void
ensure_inited(void)
{
	if (g_inited) {
		return;
	}

	if (g_conf.conf_file == NULL) {
		g_conf.conf_file = nng_strdup("/tmp/nanomq_fuzz.conf");
	}

	if (g_conf.http_server.username == NULL) {
		g_conf.http_server.username = nng_strdup("admin");
	}
	if (g_conf.http_server.password == NULL) {
		g_conf.http_server.password = nng_strdup("public");
	}
	g_conf.http_server.enable   = true;
	g_conf.http_server.max_body = 1024 * 1024;
	g_conf.http_server.auth_type = NONE_AUTH;

	nng_mtx_alloc(&g_conf.restapi_lk);
	if (g_conf.lc == NULL) {
		nng_atomic_alloc(&g_conf.lc);
	}

	set_global_conf(&g_conf);
	set_http_server_conf(&g_conf.http_server);
	dbhash_init_pipe_table();

	g_inited = true;
}

static void
fuzz_rest_api_detailed_cleanup(void)
{
	if (!g_inited) {
		return;
	}

	dbhash_destroy_pipe_table();

	if (g_conf.http_server.username != NULL) {
		nng_strfree(g_conf.http_server.username);
		g_conf.http_server.username = NULL;
	}
	if (g_conf.http_server.password != NULL) {
		nng_strfree(g_conf.http_server.password);
		g_conf.http_server.password = NULL;
	}

	if (g_conf.conf_file != NULL) {
		nng_strfree(g_conf.conf_file);
		g_conf.conf_file = NULL;
	}

	if (g_conf.restapi_lk != NULL) {
		nng_mtx_free(g_conf.restapi_lk);
		g_conf.restapi_lk = NULL;
	}

	if (g_conf.lc != NULL) {
		nng_atomic_free(g_conf.lc);
		g_conf.lc = NULL;
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void) argc;
	(void) argv;
	ensure_inited();
	atexit(fuzz_rest_api_detailed_cleanup);
	return 0;
}

static const char *
pick_method(uint8_t v)
{
	switch (v % 4) {
	case 0:
		return "GET";
	case 1:
		return "POST";
	case 2:
		return "PUT";
	default:
		return "DELETE";
	}
}

static const char *
pick_content_type(uint8_t v)
{
	switch (v % 4) {
	case 0:
		return "application/json";
	case 1:
		return "text/plain";
	case 2:
		return "application/octet-stream";
	default:
		return "multipart/form-data; boundary=fuzz";
	}
}

// Comprehensive list of URI templates derived from nanomq/rest_api.c
static const char *uri_templates[] = {
	"/endpoints",
	"/brokers",
	"/brokers/connections",
	"/nodes",
	"/data_span",
	"/prometheus",
	"/metrics",
	"/retains",
	"/license/info",
	"/logs/latest",
	"/logs/full",
	"/platform_infos",
	"/clients",
	"/clients/%s",
	"/clients/username/%s",
	"/subscriptions",
	"/subscriptions/%s",
	"/rules",
	"/rules/%s",
	"/topic-tree",
	"/reload",
	"/configuration",
	"/configuration/basic",
	"/configuration/tls",
	"/configuration/http_server",
	"/configuration/websocket",
	"/configuration/webhook",
	"/configuration/auth",
	"/configuration/auth_http",
	"/configuration/sqlite",
	"/configuration/bridge",
	"/configuration/aws_bridge",
	"/bridges",
	"/bridges/%s",
	"/get_file?path=%s",
	"/ctrl/stop",
	"/ctrl/restart",
	// "/config_update",
	// "/write_file",
	"/mqtt/publish",
	"/mqtt/publish_batch",
	"/bridges/sub/%s",
	"/bridges/unsub/%s",
	"/bridges/switch/%s",
	"/license/update",
	"/tools/aes_enc"
};

static void
build_uri(char *dst, size_t dst_cap, uint8_t sel, const char *name_hint)
{
	const char *base = "/api/v4";
	size_t num_templates = sizeof(uri_templates) / sizeof(uri_templates[0]);
	const char *tmpl = uri_templates[sel % num_templates];

	if (strstr(tmpl, "%s")) {
		// Use a safe name if name_hint is empty or weird
		const char *safe_name = (name_hint && name_hint[0]) ? name_hint : "default";
		char path[256];
		snprintf(path, sizeof(path), tmpl, safe_name);
		snprintf(dst, dst_cap, "%s%s", base, path);
	} else {
		snprintf(dst, dst_cap, "%s%s", base, tmpl);
	}
}

static void
build_body(char *dst, size_t dst_cap, uint8_t uri_sel, const char *hex_payload)
{
	if (dst_cap == 0) {
		return;
	}

	size_t num_templates = sizeof(uri_templates) / sizeof(uri_templates[0]);
	uint8_t idx = uri_sel % num_templates;
	const char *tmpl = uri_templates[idx];

	// Default empty JSON
	snprintf(dst, dst_cap, "{\"data\":\"%s\"}", hex_payload);

	// Context-aware body generation
	if (strstr(tmpl, "/mqtt/publish")) {
		snprintf(dst, dst_cap,
		    "{\"topic\":\"topic/%s\",\"payload\":\"%s\",\"qos\":1,\"clientid\":\"fuzz_client\"}",
		    hex_payload, hex_payload);
	} else if (strstr(tmpl, "/rules")) {
		snprintf(dst, dst_cap,
		    "{\"rawsql\":\"SELECT * FROM t WHERE payload='%s'\","
		    "\"actions\":[{\"name\":\"sqlite\",\"params\":{\"table\":\"t_%s\"}}],"
		    "\"enabled\":true}",
		    hex_payload, hex_payload);
	} else if (strstr(tmpl, "/configuration/sqlite")) {
		snprintf(dst, dst_cap,
		    "{\"data\":{\"sqlite\":{\"enable\":true,"
		    "\"disk_cache_size\":1024,"
		    "\"mounted_file_path\":\"/tmp/rule_engine.db\","
		    "\"flush_mem_threshold\":1024}}}");
	} else if (strstr(tmpl, "/configuration")) {
		// Generic configuration update attempt
		snprintf(dst, dst_cap,
		    "{\"data\":{\"websocket\":{\"enable\":true,\"url\":\"%s\"}}}",
		    hex_payload);
	} else if (strstr(tmpl, "/bridges")) {
		snprintf(dst, dst_cap,
		    "{\"name\":\"bridge_%s\",\"connector\":{\"server\":\"127.0.0.1:1883\"}}",
		    hex_payload);
	} else if (strstr(tmpl, "/write_file")) {
		snprintf(dst, dst_cap,
		    "{\"data\":{\"path\":\"/tmp/nanomq_fuzz.conf\",\"content\":\"# %s\"}}",
		    hex_payload);
	} else if (strstr(tmpl, "/tools/aes_enc")) {
		snprintf(dst, dst_cap,
		    "{\"data\":\"%s\",\"key\":\"1234567812345678\",\"iv\":\"1234567812345678\"}",
		    hex_payload);
	} else if (strstr(tmpl, "/license/update")) {
		snprintf(dst, dst_cap, "{\"license\":\"%s\"}", hex_payload);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ensure_inited();
	if (data == NULL || size < 4) {
		return 0;
	}

	const uint8_t method_sel = data[0];
	const uint8_t uri_sel    = data[1];
	const uint8_t ctype_sel  = data[2];

	data += 3;
	size -= 3;

	// Split remaining data into name (for URL params) and payload (for Body)
	// Let's use up to 16 bytes for name, rest for payload
	uint8_t name_bytes[16];
	size_t  name_len = size < 16 ? size : 16;
	if (name_len > 0) {
		memcpy(name_bytes, data, name_len);
		data += name_len;
		size -= name_len;
	} else {
		// Default name if empty
		strcpy((char*)name_bytes, "default");
		name_len = 7;
	}

	char name_hex[sizeof(name_bytes) * 2 + 1];
	hex_encode(name_hex, sizeof(name_hex), name_bytes, name_len);

	const uint8_t *payload = data;
	size_t         pay_len = size;
	if (pay_len > 256) {
		pay_len = 256;
	}

	char payload_hex[256 * 2 + 1];
	hex_encode(payload_hex, sizeof(payload_hex), payload, pay_len);

	char uri[512];
	build_uri(uri, sizeof(uri), uri_sel, name_hex);

	const char *method = pick_method(method_sel);
	const char *ctype  = pick_content_type(ctype_sel);

	const char *token = NULL;
	if ((method_sel & 0x20) != 0) {
		g_conf.http_server.auth_type = BASIC;
		token                        = "Basic YWRtaW46cHVibGlj";
	} else {
		g_conf.http_server.auth_type = NONE_AUTH;
	}
	set_http_server_conf(&g_conf.http_server);

	char body[4096];
	build_body(body, sizeof(body), uri_sel, payload_hex);

	http_msg req = { 0 };
	put_http_msg(&req, ctype, method, uri, token, body, strlen(body));

	nng_socket sock = { 0 };
	g_conf.http_server.broker_sock = &sock;
	http_msg resp = process_request(&req, &g_conf.http_server, &sock);

	destory_http_msg(&resp);
	destory_http_msg(&req);

	return 0;
}
