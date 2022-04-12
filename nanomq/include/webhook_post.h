#ifndef WEBHOOK_POST_H
#define WEBHOOK_POST_H

#include "webhook_inproc.h"

extern int webhook_msg_publish(nng_socket *sock, conf_web_hook *hook_conf,
    pub_packet_struct *pub_packet, const char *username,
    const char *client_id);

#endif
