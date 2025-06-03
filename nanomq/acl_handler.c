#ifdef ACL_SUPP
#include "include/acl_handler.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/log.h"

// only clientid and username are supported now.
#define placeholder_clientid "${clientid}"
#define placeholder_username "${username}"

static bool
match_rule_content_str(acl_rule_ct *ct, const char *cmp_str)
{
	bool match = false;
	if (ct->type == ACL_RULE_ALL) {
		match = true;
	} else if (ct->type == ACL_RULE_SINGLE_STRING && cmp_str != NULL &&
	    strcmp(ct->value.str, cmp_str) == 0) {
		match = true;
	}
	return match;
}

static char * 
replace_placeholder(char *origin, const char *placeholder, const char *replacement)
{
	size_t originLen      = strlen(origin);
	size_t placeholderLen = strlen(placeholder);
	size_t replacementLen = strlen(replacement);
	size_t resultLen      = originLen;

	const char *p = origin;
	while ((p = strstr(p, placeholder)) != NULL) {
		resultLen += replacementLen - placeholderLen;
		p += placeholderLen;
	}

	char *result = (char *) malloc(resultLen + 1);
	if (result == NULL) {
		log_error("ACL topic placeholder Memory allocation failed\n");
	}

	char *currentPos = result;
	p                = origin;
	char *nextPlaceholder;
	while ((nextPlaceholder = strstr(p, placeholder)) != NULL) {
		size_t segmentLen = nextPlaceholder - p;
		strncpy(currentPos, p, segmentLen);
		currentPos += segmentLen;

		strcpy(currentPos, replacement);
		currentPos += replacementLen;

		p = nextPlaceholder + placeholderLen;
	}

	strcpy(currentPos, p);

	origin = result;

	return result;
}

static char *
replace_topic(const char *origin, conn_param *param)
{
	char *topic = origin;
	char *out_topic  = NULL;

	if (conn_param_get_clientid(param) != NULL &&
	    strstr(topic, placeholder_clientid) != NULL) {
		out_topic = replace_placeholder(topic, placeholder_clientid,
		    (const char *) conn_param_get_clientid(param));
		topic = out_topic;
	}
	if (conn_param_get_username(param) != NULL &&
	    strstr(topic, placeholder_username) != NULL) {
		out_topic = replace_placeholder(topic, placeholder_username,
		    (const char *) conn_param_get_username(param));
		if (topic != origin) {
			nng_strfree(topic);
		}
		topic = out_topic;
	}
	if (out_topic == NULL)
		out_topic = topic;
	return out_topic;
}

bool
auth_acl(conf *config, acl_action_type act_type, conn_param *param,
    const char *topic)
{
	conn_param_clone(param);

	conf_acl *acl = &config->acl;

	bool match     = false;
	bool sub_match = true;
	bool result    = false;

	for (size_t i = 0; i < acl->rule_count; i++) {
		acl_rule *      rule   = acl->rules[i];
		acl_action_type action = rule->action;

		if (action != ACL_ALL && action != act_type) {
			continue;
		}

		switch (rule->rule_type) {
		case ACL_USERNAME:
			match = match_rule_content_str(&rule->rule_ct.ct,
			    (const char *) conn_param_get_username(param));
			break;

		case ACL_CLIENTID:
			match = match_rule_content_str(&rule->rule_ct.ct,
			    (const char *) conn_param_get_clientid(param));
			break;
		case ACL_IPADDR:
			match = match_rule_content_str(&rule->rule_ct.ct,
			    (const char *) conn_param_get_ip_addr_v4(param));
			break;
		case ACL_AND:
			for (size_t j = 0; j < rule->rule_ct.array.count;
			     j++) {
				acl_sub_rule *sub_rule =
				    rule->rule_ct.array.rules[j];
				switch (sub_rule->rule_type) {
				case ACL_USERNAME:
					if (!match_rule_content_str(
					        &sub_rule->rule_ct,
					        (const char *)
					            conn_param_get_username(
					                param))) {
						sub_match = false;
						break;
					}
					break;

				case ACL_CLIENTID:
					if (!match_rule_content_str(
					        &sub_rule->rule_ct,
					        (const char *)
					            conn_param_get_clientid(
					                param))) {
						sub_match = false;
						break;
					}
					break;

				case ACL_IPADDR:
					if (!match_rule_content_str(
					        &sub_rule->rule_ct,
					        (const char *)
					            conn_param_get_ip_addr_v4(
					                param))) {
						sub_match = false;
						break;
					}
					break;

				default:
					break;
				}
				if (!sub_match) {
					break;
				}
			}
			if (sub_match) {
				match = true;
			}
			break;

		case ACL_OR:
			for (size_t j = 0; j < rule->rule_ct.array.count;
			     j++) {
				acl_sub_rule *sub_rule =
				    rule->rule_ct.array.rules[j];
				switch (sub_rule->rule_type) {
				case ACL_USERNAME:
					match |= match_rule_content_str(
					    &sub_rule->rule_ct,
					    (const char *)
					        conn_param_get_username(
					            param));
					break;

				case ACL_CLIENTID:
					match |= match_rule_content_str(
					    &sub_rule->rule_ct,
					    (const char *)
					        conn_param_get_clientid(
					            param));
					break;

				case ACL_IPADDR:
					match |= match_rule_content_str(
					    &sub_rule->rule_ct,
					    (const char *)
					        conn_param_get_ip_addr_v4(
					            param));
					break;

				default:
					break;
				}
				if (match) {
					break;
				}
			}
			break;

		case ACL_NONE:
			match = true;
			break;

		default:
			break;
		}

		if (!match) {
			continue;
		}

		if (rule->topic_count > 0) {
			char **topic_array = rule->topics;
			bool   found       = false;
			bool   free        = false;
			char  *rule_topic  = NULL;
			for (size_t j = 0; j < rule->topic_count && found != true; j++) {
				rule_topic = replace_topic(rule->topics[j], param);
				if (rule_topic != rule->topics[j])
					free = true;
				if (strncmp(rule_topic, "@", 1) == 0 && strlen(rule_topic) > 1) {
					log_debug("@ is taking effect: %s %d",
						rule_topic + 1, strlen(rule_topic));
					if (strcmp(rule_topic + 1, topic) == 0) {
						found = true;
					}
				} else if (topic_filter(rule_topic, topic)) {
					found = true;
				}
				if (free) {
					nng_strfree(rule_topic);
					free = false;
				}
				if (found)
					break;
			}
			if (found == false) {
				match = false;
				continue;
			}
		}

		result = rule->permit == ACL_ALLOW ? match : !match;

		break;
	}

	conn_param_free(param);

	if (match) {
		return result;
	} else {
		return config->acl_nomatch == ACL_ALLOW ? true : result;
	}
}
#endif
