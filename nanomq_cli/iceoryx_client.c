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
#include <signal.h>
#include <stdlib.h>

static int bench_round = 100000;
static int bench_input = 0;

void
inthandler(int signal)
{
	(void) signal;
	printf("received msg counter %d\n", bench_input);
	exit(0);
}

static void
helper(char **argv)
{
	printf("Usage: %s sub \n", argv[0]);
	printf("       %s pub \n", argv[0]);
	printf("       %s benchsub \n", argv[0]);
	printf("       %s benchpub \n", argv[0]);
	printf("Release date. 20240411.\n");
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
	printf("Address of msg received [%p]\n", nng_msg_payload_ptr(msg));
	nng_msg_free(msg);
	nng_aio_free(aio);
	nng_free(suber, 0);
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
	nng_msg_clone(msg); // For print the address of payload

	nng_aio_alloc(&aio, NULL, NULL);
	nng_aio_set_prov_data(aio, puber);
	nng_aio_set_msg(aio, msg);
	nng_send_aio(sock, aio);
	nng_aio_wait(aio);

	printf("Address of msg sent [%p]\n", nng_msg_payload_ptr(msg));
	nng_msg_free(msg); // Pair to the clone before
	nng_aio_free(aio);
	nng_free(puber, 0);
}

void
iceoryx_bench_suber(const char *service, const char *instance,
		const char *eventsend, const char *eventrecv, const char *txt)
{
	signal(SIGINT, inthandler);
	signal(SIGTERM, inthandler);

	const char *sendername = "benchsuber-sender";
	const char *recvername = "benchsuber-recver";

	nng_aio *raio;
	nng_msg *rmsg;
	nng_socket sock;
	nng_iceoryx_suber *suber;

	nng_aio_alloc(&raio, NULL, NULL);
	nng_iceoryx_open(&sock, "Hello-Iceoryx");
	nng_iceoryx_sub(&sock, recvername, service, instance, eventrecv, &suber);

	nng_aio *saio;
	nng_msg *smsg;
	nng_iceoryx_puber *puber;

	nng_aio_alloc(&saio, NULL, NULL);
	nng_iceoryx_pub(&sock, sendername, service, instance, eventsend, &puber);

	for (;;) {
		nng_aio_set_prov_data(raio, suber);
		nng_recv_aio(sock, raio);
		nng_aio_wait(raio);
		rmsg = nng_aio_get_msg(raio);
		nng_msg_free(rmsg);

		nng_msg_alloc(&smsg, 0);
		nng_msg_append(smsg, txt, strlen(txt));
		nng_aio_set_prov_data(saio, puber);
		nng_aio_set_msg(saio, smsg);
		nng_send_aio(sock, saio);
		nng_aio_wait(saio);
		bench_input ++;
	}

	nng_aio_free(saio);
	nng_free(puber, 0);
	nng_aio_free(raio);
	nng_free(puber, 0);}

void
iceoryx_bench_puber(const char *service, const char *instance,
		const char *eventsend, const char *eventrecv, const char *txt)
{
	signal(SIGINT, inthandler);
	signal(SIGTERM, inthandler);

	const char *sendername = "benchpuber-sender";
	const char *recvername = "benchpuber-recver";

	nng_aio *saio;
	nng_msg *smsg;
	nng_socket sock;
	nng_iceoryx_puber *puber;

	nng_aio_alloc(&saio, NULL, NULL);
	nng_iceoryx_open(&sock, "Hello-NanoMQ");
	nng_iceoryx_pub(&sock, sendername, service, instance, eventsend, &puber);

	nng_aio *raio;
	nng_msg *rmsg;
	nng_iceoryx_suber *suber;

	nng_aio_alloc(&raio, NULL, NULL);
	nng_iceoryx_sub(&sock, recvername, service, instance, eventrecv, &suber);

	for (int i=0; i<bench_round; ++i) {
		nng_msg_alloc(&smsg, 0);
		nng_msg_append(smsg, txt, strlen(txt));
		nng_aio_set_prov_data(saio, puber);
		nng_aio_set_msg(saio, smsg);
		nng_send_aio(sock, saio);
		nng_aio_wait(saio);

		nng_aio_set_prov_data(raio, suber);
		nng_recv_aio(sock, raio);
		nng_aio_wait(raio);
		rmsg = nng_aio_get_msg(raio);
		nng_msg_free(rmsg);
		bench_input ++;
	}

	nng_aio_free(saio);
	nng_free(puber, 0);
	nng_aio_free(raio);
	nng_free(puber, 0);
}

int
iceoryx_start(int argc, char **argv)
{
	if (argc < 3) {
		helper(argv);
		return 0;
	}
	if (0 == strcmp(argv[2], "sub")) {
		iceoryx_suber(
			"test-nanomq-iceoryx-suber",
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topic");
	} else if (0 == strcmp(argv[2], "pub")) {
		iceoryx_puber(
			"test-nanomq-iceoryx-puber",
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topic", "AAAAAAAAAAAAAAAAAAA");
	} else if (0 == strcmp(argv[2], "benchsub")) {
		iceoryx_bench_suber(
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topicrecv",
			"test-iceoryx-topicsend",
			"AAAAAAAAAAAAAAAAAAA");
	} else if (0 == strcmp(argv[2], "benchpub")) {
		iceoryx_bench_puber(
			"test-iceoryx-service",
			"test-iceoryx-instance",
			"test-iceoryx-topicsend",
			"test-iceoryx-topicrecv",
			"AAAAAAAAAAAAAAAAAAA");
	} else {
		helper(argv);
	}
	return 0;
}

#endif
