#if defined(SUPP_RULE_ENGINE)
#include "rule_ctrl.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/util/options.h"

struct work {
	enum { INIT, RECV, WAIT, SEND } state;
	nng_aio *aio;
	nng_msg *msg;
	nng_ctx  ctx;
};

enum options {
	OPT_HELP = 1,
	OPT_CREATE,
	OPT_UPDATE,
	OPT_LIST,
	OPT_SHOW,
	OPT_DELETE,
};

static nng_optspec cmd_opts[] = {
	{ .o_name = "help", .o_short = 'h', .o_val = OPT_HELP },
	{ .o_name = "list", .o_short = 'l', .o_val = OPT_LIST },
	{ .o_name = "show", .o_short = 's', .o_val = OPT_SHOW, .o_arg = true },
	{ .o_name    = "create",
	    .o_short = 'c',
	    .o_val   = OPT_CREATE,
	    .o_arg   = true },
	{ .o_name    = "update",
	    .o_short = 'u',
	    .o_val   = OPT_UPDATE,
	    .o_arg   = true },
	{ .o_name    = "delete",
	    .o_short = 'd',
	    .o_val   = OPT_DELETE,
	    .o_arg   = true },
	{ .o_name = NULL, .o_val = 0 },
};

static char help_info[] =
    "Usage: nanomq_cli rules [--action <rule>]\n\n"
    "  --create <Rule>                Create a rule \n"
    "  --update <RuleId>              Update a rule \n"
    "  --list                         List all rules \n"
    "  --show <RuleId>                Show a rule \n"
    "  --delete <RuleId>              Delete a rule \n";
// "rules list                                                            # List all rules\n"
// "rules show <RuleId>                                                   # Show a rule\n"
// "rules create                                                          # Create a rule\n"
// "rules delete <RuleId>                                                 # Delete a rule\n";

// Usage: emqx_ctl rules create [<sql>] [<actions>] [-i [<id>]]
//                              [-e [<enabled>]] [-g [<on_action_failed>]]
//                              [-d [<descr>]]
// 
//   <sql>                   Filter Condition SQL
//   <actions>               Action List in JSON format: [{"name":
//                           <action_name>, "params": {<key>: <value>}}]
//   -i, --id                The rule id. A random rule id will be used if
//                           not provided [default: ]
//   -e, --enabled           'true' or 'false' to enable or disable the rule
//                           [default: true]
//   -g, --on_action_failed  'continue' or 'stop' when an action in the rule
//                           fails [default: continue]
//   -d, --descr             Description [default: ]
// 
// {missing_required_option,sql}	



int
rules_parse_opts(int argc, char **argv)
{
	int   idx = 1;
	char *arg;
	int   val;
	int   rv;

	while ((rv = nng_opts_parse(argc, argv, cmd_opts, &val, &arg, &idx)) ==
	    0) {
		switch (val) {
		case OPT_HELP:
			printf("%s", help_info);
			exit(0);
			break;
		case OPT_CREATE:
			break;
		case OPT_UPDATE:
			break;
		case OPT_LIST:
			break;
		case OPT_SHOW:
			break;
		case OPT_DELETE:
			break;
		default:
			break;
		}
	}

	switch (rv) {
	case NNG_EINVAL:
		fprintf(stderr,
		    "Option %s is invalid.\nTry 'nanomq_cli rules --help' for "
		    "more information.\n",
		    argv[idx]);
		break;
	case NNG_EAMBIGUOUS:
		fprintf(stderr,
		    "Option %s is ambiguous (specify in full).\nTry 'nanomq_cli "
		    "rules --help' for more information.\n",
		    argv[idx]);
		break;
	case NNG_ENOARG:
		fprintf(stderr,
		    "Option %s requires argument.\nTry 'nanomq_cli rules "
		    "--help' "
		    "for more information.\n",
		    argv[idx]);
		break;
	default:
		break;
	}

	return rv == -1;
}

int rules_start(int argc, char **argv)
{
	// printf("%s", help_info);
	rules_parse_opts(argc, argv);
	// conf_gateway_parse(conf);
	// if (-1 != gateway_conf_check_and_set(conf)) {
	// 	zmq_gateway(conf);
	// }
	return 0;
}


int
rules_dflt(int argc, char **argv)
{
	printf("%s", help_info);
	return 0;
}

#endif