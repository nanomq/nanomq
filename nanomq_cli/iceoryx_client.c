//
// Copyright 2024 NanoMQ Team, Inc. <wangwei@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#if defined(SUPP_ICEORYX)

#include "nng/nng.h"
#include "nng/iceoryx_shm/iceoryx_shm.h"

#include <stdio.h>
#include <string.h>

static void
helper()
{
	printf("aaa");
}

void
iceoryx_suber(const char *subername, const char *service, const char *instance,
		const char *event)
{
	nng_aio *aio;
	nng_msg *msg;
	nng_socket sock;
	nng_iceoryx_suber *suber;

	nng_iceoryx_open(&sock, "Hello-Iceoryx");
	nng_iceoryx_sub(&sock, subername, service, instance, event, &suber);

	nng_aio_alloc(&aio, NULL, NULL);
	nng_aio_set_prov_data(aio, suber);
	nng_recv_aio(sock, aio);
	nng_aio_wait(aio);

	msg = nng_aio_get_msg(aio);
	printf("Address of msg received [%p]\n", nng_msg_body(msg));
	nng_msg_free(msg);
}

void
iceoryx_puber(const char *pubername, const char *service, const char *instance,
		const char *event, const char *txt)
{
	nng_aio *aio;
	nng_msg *msg;
	nng_socket sock;
	nng_iceoryx_puber *puber;

	nng_iceoryx_open(&sock, "Hello-NanoMQ");
	nng_iceoryx_pub(&sock, pubername, service, instance, event, &puber);

	nng_msg_alloc(&msg, 0);
	nng_msg_append(msg, txt, strlen(txt));

	nng_aio_alloc(&aio, NULL, NULL);
	nng_aio_set_prov_data(aio, puber);
	nng_send_aio(sock, aio);
	nng_aio_wait(aio);

	printf("Address of msg sent [%p]\n", nng_msg_body(msg));
}

int
iceoryx_start(int argc, char **argv)
{
	if (0 == strcmp(argv[1], "sub")) {
		iceoryx_suber(
			"test-nanomq-iceoryx-suber",
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topic");
	} else if (0 == strcmp(argv[1], "pub")) {
		iceoryx_puber(
			"test-nanomq-iceoryx-puber",
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topic", "AAAAAAAAAAAAAAAAAAA");
	} else {
		helper();
	}
	return 0;
}

#endif
