#include "include/acl_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

bool
auth_acl(conf *config, acl_action_type type, const conn_param *param,
    size_t topic_count, const char **topics)
{
	conn_param_clone(param);

	conf_acl *acl = &config->acl;

    bool matched = false;

	for (size_t i = 0; i < acl->rule_count; i++) {
		acl_rule *rule = acl->rules[i];
		if
	}

	conn_param_free(param);

	if (!matched && config->acl_nomatch && acl->rule_count > 0) {
		return true;
	}
}