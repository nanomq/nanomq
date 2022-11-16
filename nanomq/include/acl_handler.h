#ifndef NANOMQ_ACL_HANDLER_H
#define NANOMQ_ACL_HANDLER_H

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/acl_conf.h"

extern bool auth_acl(
    conf *config, acl_action_type type, conn_param *param, const char *topic);

#endif
