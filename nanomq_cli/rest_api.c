#include "include/rest_api.h"
#include "nng/supplemental/nanolib/base64.h"
#include "nng/supplemental/nanolib/cJSON.h"
#include "nng/supplemental/nanolib/file.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/platform.h"
#include "nng/nng.h"

#include "nng/supplemental/http/http.h"
#include "nng/supplemental/util/platform.h"


typedef struct {
	char *key;
	char *value;
} kv;

typedef struct {
	char *node;
	bool  end;
} tree;

struct uri_content {
	size_t sub_count;
	tree **sub_tree;
	size_t params_count;
	kv **  params;
};

typedef struct uri_content uri_content;

static tree **      uri_parse_tree(const char *path, size_t *count);
static void         uri_tree_free(uri_content *ct);
static kv **        uri_param_parse(const char *path, size_t *count);
static void         uri_param_free(uri_content *ct);
static uri_content *uri_parse(const char *uri);
static void         uri_free(uri_content *ct);

static http_msg error_response(
    http_msg *msg, uint16_t status, enum result_code code);


static tree **
uri_parse_tree(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = strstr(path, REST_URI_ROOT);

	size_t num  = 0;
	tree **root = NULL;
	int    len  = 0;

	if (str) {
		str += strlen(REST_URI_ROOT);
		while (NULL != (ret = strchr(str, '/'))) {
			num++;
			root      = realloc(root, sizeof(tree *) * num);
			len       = ret - str + 1;
			tree *sub = nng_zalloc(sizeof(tree));
			sub->node = nng_zalloc(len);
			strncpy(sub->node, str, len - 1);
			sub->end      = false;
			root[num - 1] = sub;
			str           = ret + 1;
		}
		if (num > 0) {
			if (strlen(str) > 0) {
				num++;
				root = realloc(root, sizeof(char *) * num);
				tree *sub     = nng_zalloc(sizeof(tree));
				sub->node     = nng_strdup(str);
				sub->end      = true;
				root[num - 1] = sub;
			} else {
				tree *sub = root[num - 1];
				sub->end  = true;
			}
		}
	}

	*count = num;
	return root;
}

static void
uri_tree_free(uri_content *ct)
{
	if (ct->sub_count > 0) {
		tree **node = ct->sub_tree;
		for (size_t i = 0; i < ct->sub_count; i++) {
			tree *sub = node[i];
			nng_strfree(sub->node);
			nng_free(sub, sizeof(tree));
		}
		nng_free(node, ct->sub_count * sizeof(tree *));
		ct->sub_count = 0;
	}
}

static kv **
uri_param_parse(const char *path, size_t *count)
{
	char *ret = NULL;
	char *str = (char *) path;

	size_t num    = 0;
	char **kv_str = NULL;
	int    len    = 0;

	while (NULL != (ret = strchr(str, '&'))) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		len             = ret - str + 1;
		kv_str[num - 1] = nng_zalloc(len);
		memcpy(kv_str[num - 1], str, len - 1);
		str = ret + 1;
	}
	if (num > 0) {
		num++;
		kv_str          = realloc(kv_str, sizeof(char *) * num);
		kv_str[num - 1] = nng_strdup(str);
	} else {
		return NULL;
	}

	kv **  params      = calloc(num, sizeof(kv *));
	size_t param_count = 0;

	for (size_t i = 0; i < num; i++) {
		char *key   = nng_zalloc(strlen(kv_str[i]));
		char *value = nng_zalloc(strlen(kv_str[i]));
		if (2 == sscanf(kv_str[i], "%[^=]=%s", key, value)) {
			params[i]        = nng_zalloc(sizeof(kv));
			params[i]->key   = key;
			params[i]->value = value;
			param_count++;
		} else {
			if (key) {
				free(key);
			}
			if (value) {
				free(value);
			}
		}
		free(kv_str[i]);
		kv_str[i] = NULL;
	}

	*count = param_count;
	return params;
}

static void
uri_param_free(uri_content *ct)
{
	if (ct->params_count > 0) {
		kv **params = ct->params;
		for (size_t i = 0; i < ct->params_count; i++) {
			nng_strfree(params[i]->key);
			nng_strfree(params[i]->value);
			nng_free(params[i], sizeof(kv));
		}
		nng_free(params, ct->params_count * sizeof(kv *));
		ct->params_count = 0;
	}
}

static uri_content *
uri_parse(const char *uri)
{
	uri_content *uri_ct  = nng_zalloc(sizeof(uri_content));
	uri_ct->params_count = 0;
	uri_ct->params       = NULL;
	char *path           = NULL;
	char *param          = NULL;
	int   len            = 0;

	if (strcmp(uri, REST_URI_ROOT) == 0 ||
	    strcmp(uri, REST_URI_ROOT "/") == 0) {
		return uri_ct;
	}

	char *p = strchr(uri, '?');
	if (p) {
		// Have parameters
		param = p + 1;
		if (strlen(param) >= 3) {
			uri_ct->params =
			    uri_param_parse(param, &uri_ct->params_count);
		}
		len  = p - uri + 1;
		path = nng_zalloc(len);
		memcpy(path, uri, len - 1);
	} else {
		path = nng_strdup(uri);
	}

	uri_ct->sub_tree = uri_parse_tree(path, &uri_ct->sub_count);
	nng_strfree(path);
	return uri_ct;
}

static void
uri_free(uri_content *ct)
{
	if (ct) {
		uri_tree_free(ct);
		uri_param_free(ct);
		nng_free(ct, sizeof(uri_content));
		ct = NULL;
	}
}

void
put_http_msg(http_msg *msg, const char *content_type, const char *method,
    const char *uri, const char *token, const char *data, size_t data_sz)
{
	if (content_type != NULL) {
		msg->content_type_len = strlen(content_type);
		msg->content_type     = nng_strdup(content_type);
	}

	if (method != NULL) {
		msg->method_len = strlen(method);
		msg->method     = nng_strdup(method);
	}

	if (uri != NULL) {
		msg->uri_len = strlen(uri);
		msg->uri     = nng_strdup(uri);
	}

	if (token != NULL) {
		msg->token_len = strlen(token);
		msg->token     = nng_strdup(token);
	}

	if (data != NULL) {
		msg->data_len = data_sz;
		msg->data     = nng_alloc(msg->data_len);
		memcpy(msg->data, data, msg->data_len);
	}
}

void
destory_http_msg(http_msg *msg)
{
	if (msg->content_type_len > 0) {
		nng_strfree(msg->content_type);
		msg->content_type_len = 0;
	}

	if (msg->method_len > 0) {
		nng_strfree(msg->method);
		msg->method_len = 0;
	}

	if (msg->token_len > 0) {
		nng_strfree(msg->token);
		msg->token_len = 0;
	}
	if (msg->data_len > 0) {
		nng_free(msg->data, msg->data_len);
		msg->data_len = 0;
	}
	if (msg->uri_len > 0) {
		nng_strfree(msg->uri);
		msg->uri_len = 0;
	}
}


static enum result_code
basic_authorize(http_msg *msg, conf_http_server *config)
{
	enum result_code result = SUCCEED;

	if (msg->token_len <= 0 ||
	    sscanf(msg->token, "Basic %s", msg->token) != 1) {
		return EMPTY_USERNAME_OR_PASSWORD;
	}

	size_t   token_len = strlen(msg->token);
	uint8_t *token     = nng_alloc(token_len + 1);
	memcpy(token, msg->token, token_len);
	token[token_len] = '\0';

	// Authorize username:password
	size_t auth_len =
	    strlen(config->username) + strlen(config->password) + 2;
	char *auth = nng_alloc(auth_len);
	snprintf(auth, auth_len, "%s:%s", config->username, config->password);

	uint8_t *decode      = nng_alloc(auth_len);
	decode[auth_len - 1] = '\0';

	base64_decode((const char *) token, token_len, decode);

	if (strncmp(auth, (const char *) decode, auth_len) != 0) {
		result = WRONG_USERNAME_OR_PASSWORD;
	}

	nng_free(auth, auth_len);
	nng_free(decode, msg->token_len);
	nng_free(token, token_len);

	return result;
}

static http_msg
get_config(http_msg *msg, const char* proxy_name)
{
	if (nng_strcasecmp(proxy_name, "dds") == 0) {

	} else if (nng_strcasecmp(proxy_name, "zmq") == 0) {

	} else if (nng_strcasecmp(proxy_name, "someip") == 0) {

	}
}

http_msg
process_request(http_msg *msg, conf_http_server *config)
{
	http_msg         ret    = { 0 };
	uint16_t         status = NNG_HTTP_STATUS_OK;
	enum result_code code   = SUCCEED;
	uri_content *    uri_ct = NULL;

	if ((code = basic_authorize(msg, config)) != SUCCEED) {
		status = NNG_HTTP_STATUS_UNAUTHORIZED;
		goto exit;
	}

	uri_ct = uri_parse(msg->uri);
	if (nng_strcasecmp(msg->method, "GET") == 0) {
		if (uri_ct->sub_count == 3 && uri_ct->sub_tree[2]->end &&
		    strcmp(uri_ct->sub_tree[1]->node, "configuration")) {
			ret = get_config(msg, uri_ct->sub_tree[2]->node);
		}
	} else if (nng_strcasecmp(msg->method, "POST") == 0) {

	} else {
		status = NNG_HTTP_STATUS_METHOD_NOT_ALLOWED;
		code   = UNKNOWN_MISTAKE;
		goto exit;
	}

	uri_free(uri_ct);
	return ret;

exit:
	uri_free(uri_ct);
	ret = error_response(msg, status, code);
	return ret;
}

static http_msg
error_response(http_msg *msg, uint16_t status, enum result_code code)
{
	http_msg ret = { 0 };

	ret.status = status;

	cJSON *res_obj;
	res_obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(res_obj, "code", code);

	char *dest = cJSON_PrintUnformatted(res_obj);

	put_http_msg(
	    &ret, msg->content_type, NULL, NULL, NULL, dest, strlen(dest));

	cJSON_free(dest);
	cJSON_Delete(res_obj);

	return ret;
}
