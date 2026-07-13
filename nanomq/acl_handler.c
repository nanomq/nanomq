#ifdef ACL_SUPP
#include "include/acl_handler.h"
#include "include/acl_hazard.h"
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
	char *topic = (char *)origin;
	char *out_topic  = NULL;

	if (origin == NULL)
		return NULL;

	const char *clientid = (const char *) conn_param_get_clientid(param);
	if (clientid != NULL && strstr(topic, placeholder_clientid) != NULL) {
		if (strchr(clientid, '+') != NULL ||
		    strchr(clientid, '#') != NULL ||
		    strchr(clientid, '/') != NULL) {
			log_warn("Security: Client ID [%s] contains wildcards (+, #) or separator (/). ACL substitution aborted.", clientid);
			return NULL;
		}

		out_topic = replace_placeholder(topic, placeholder_clientid, clientid);
		topic = out_topic;
	}

	const char *username = (const char *) conn_param_get_username(param);
	if (username != NULL && strstr(topic, placeholder_username) != NULL) {
		if (strchr(username, '+') != NULL ||
		    strchr(username, '#') != NULL ||
		    strchr(username, '/') != NULL) {
			log_warn("Security: Username [%s] contains wildcards (+, #) or separator (/). ACL substitution aborted.", username);
			if (topic != origin) {
				free(topic);
			}
			return NULL;
		}

		out_topic = replace_placeholder(topic, placeholder_username, username);

		if (topic != origin) {
			free(topic);
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

	// Acquire the live ACL snapshot under hazard-pointer protection so the
	// reload writer cannot free the rules we are about to traverse. On
	// acquire failure pick a path that is both memory-safe and fail-safe:
	// before init the rules still live in config->acl, so traversing it
	// enforces the real boot rules; after init config->acl is empty (the
	// rules were moved into the snapshot), so evaluating it would silently
	// fall through to the acl_nomatch policy (allow by default); deny
	// instead.
	conf_acl *acl        = nmq_acl_hazard_acquire();
	bool      is_hp_held = (acl != NULL);
	if (!is_hp_held) {
		if (nmq_acl_hazard_ready()) {
			conn_param_free(param);
			return false;
		}
		acl = &config->acl;
	}

	bool match     = false;
	bool sub_match = true;
	bool result    = false;

	for (size_t i = 0; i < acl->rule_count; i++) {
		acl_rule *      rule   = acl->rules[i];
		acl_action_type action = rule->action;
		// Reset accumulators for each rule iteration
		match     = false;
		sub_match = true;
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
			bool   free_flag        = false;
			char  *rule_topic  = NULL;
			for (size_t j = 0; j < rule->topic_count && found != true; j++) {
				rule_topic = replace_topic(rule->topics[j], param);
				if (rule_topic == NULL) {
					if (is_hp_held)
						nmq_acl_hazard_release();
					conn_param_free(param);
					return false;
				}
				if (rule_topic != rule->topics[j])
					free_flag = true;
				if (strncmp(rule_topic, "@", 1) == 0 && strlen(rule_topic) > 1) {
					log_debug("@ is taking effect: %s %d",
						rule_topic + 1, strlen(rule_topic));
					if (strcmp(rule_topic + 1, topic) == 0) {
						found = true;
					}
				} else if (topic_filter(rule_topic, topic)) {
					found = true;
				}
				if (free_flag) {
					free(rule_topic);
					free_flag = false;
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

	// Done traversing the snapshot; release the hazard pointer so the writer
	// can reclaim this snapshot once it is retired.
	if (is_hp_held)
		nmq_acl_hazard_release();

	conn_param_free(param);

	if (match) {
		return result;
	} else {
		return config->acl_nomatch == ACL_ALLOW ? true : result;
	}
}
#endif
