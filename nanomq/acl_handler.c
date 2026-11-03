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

/*
 * replace_topic performs single-pass substitution of placeholders.
 * Substituted values are written linearly and never re-scanned
 */
static char *
replace_topic(const char *origin, conn_param *param)
{
	if (origin == NULL) {
		return NULL;
	}

	const char *cid_ph = placeholder_clientid;
	const char *usr_ph = placeholder_username;
	const size_t cid_ph_len = sizeof(placeholder_clientid) - 1;
	const size_t usr_ph_len = sizeof(placeholder_username) - 1;

	const char *clientid = (const char *) conn_param_get_clientid(param);
	const char *username = (const char *) conn_param_get_username(param);

	bool has_cid = (clientid != NULL && strstr(origin, cid_ph) != NULL);
	bool has_usr = (username != NULL && strstr(origin, usr_ph) != NULL);

	// Fast path: if no placeholders match, return origin directly (Zero Allocation)
	if (!has_cid && !has_usr) {
		return (char *) origin;
	}

	// [Security] Fail-closed: only validate fields that are actively required by this rule
	if (has_cid) {
		if (strchr(clientid, '+') != NULL ||
		    strchr(clientid, '#') != NULL ||
		    strchr(clientid, '/') != NULL) {
			log_warn("Security: Client ID [%s] contains wildcards (+, #) or separator (/). ACL substitution aborted.", clientid);
			return NULL;
		}
	}

	if (has_usr) {
		if (strchr(username, '+') != NULL ||
		    strchr(username, '#') != NULL ||
		    strchr(username, '/') != NULL) {
			log_warn("Security: Username [%s] contains wildcards (+, #) or separator (/). ACL substitution aborted.", username);
			return NULL;
		}
	}

	size_t cid_len = has_cid ? strlen(clientid) : 0;
	size_t usr_len = has_usr ? strlen(username) : 0;

	// First pass: compute exact required memory length without negative subtractions
	size_t alloc_len = 0;
	const char *p = origin;
	while (*p != '\0') {
		if (has_cid && strncmp(p, cid_ph, cid_ph_len) == 0) {
			alloc_len += cid_len;
			p += cid_ph_len;
		} else if (has_usr && strncmp(p, usr_ph, usr_ph_len) == 0) {
			alloc_len += usr_len;
			p += usr_ph_len;
		} else {
			alloc_len++;
			p++;
		}
	}

	char *result = (char *) malloc(alloc_len + 1);
	if (result == NULL) {
		log_error("ACL topic placeholder memory allocation failed\n");
		return NULL;
	}

	// Second pass: linear copy without re-evaluating substituted content
	char *out = result;
	p = origin;
	while (*p != '\0') {
		if (has_cid && strncmp(p, cid_ph, cid_ph_len) == 0) {
			if (cid_len > 0) {
				memcpy(out, clientid, cid_len);
				out += cid_len;
			}
			p += cid_ph_len;
		} else if (has_usr && strncmp(p, usr_ph, usr_ph_len) == 0) {
			if (usr_len > 0) {
				memcpy(out, username, usr_len);
				out += usr_len;
			}
			p += usr_ph_len;
		} else {
			*out++ = *p++;
		}
	}
	*out = '\0';

	return result;
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
			nmq_trace(NMQ_TRACE_ACL,
			    "acl deny action=%s clientid=%s username=%s "
			    "topic=%s reason=no_hazard_slot",
			    act_type == ACL_SUB ? "subscribe" : "publish",
			    NMQ_TRACE_STR(conn_param_get_clientid(param)),
			    NMQ_TRACE_STR(conn_param_get_username(param)),
			    NMQ_TRACE_STR(topic));
			conn_param_free(param);
			return false;
		}
		acl = &config->acl;
	}

	bool   match       = false;
	bool   sub_match   = true;
	bool   result      = false;
	size_t matched_rule = 0;

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

		result       = rule->permit == ACL_ALLOW ? match : !match;
		matched_rule = i;

		break;
	}

	bool allowed = match
	    ? result
	    : (config->acl_nomatch == ACL_ALLOW ? true : result);

	// Emitted while the hazard pointer still protects the snapshot and
	// before the conn_param clone is dropped, so nothing it reads can have
	// been reclaimed. It names the rule that decided, because "denied" on
	// its own does not say whether a deny rule matched or nothing matched
	// and no_match took over, and those two are fixed in different places.
	char rule_desc[32] = "-";
	if (match) {
		snprintf(rule_desc, sizeof(rule_desc), "%zu", matched_rule);
	}
	nmq_trace(NMQ_TRACE_ACL,
	    "acl %s action=%s clientid=%s username=%s topic=%s reason=%s "
	    "rule=%s rules=%zu",
	    allowed ? "allow" : "deny",
	    act_type == ACL_SUB ? "subscribe" : "publish",
	    NMQ_TRACE_STR(conn_param_get_clientid(param)),
	    NMQ_TRACE_STR(conn_param_get_username(param)),
	    NMQ_TRACE_STR(topic), match ? "rule_match" : "no_match_policy",
	    rule_desc, acl->rule_count);

	// Done traversing the snapshot; release the hazard pointer so the writer
	// can reclaim this snapshot once it is retired.
	if (is_hp_held)
		nmq_acl_hazard_release();

	conn_param_free(param);

	return allowed;
}
#endif
