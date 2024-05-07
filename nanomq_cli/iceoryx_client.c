//
// Copyright 2024 NanoMQ Team, Inc. <wangwei@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

// An example for communicating iceoryx client with nanomq.
//
// MQTT client -> NanoMQ -> iceoryx client.
// nanomq_cli pub -t ice/fwd -m aaa
// nanomq_cli iceoryx submqtt ss NanoMQ-Service NanoMQ-Instance ice/fwd
//
// iceoryx client -> NanoMQ -> MQTT client.
// nanomq_cli iceoryx pubmqtt pp NanoMQ-Service NanoMQ-Instance topic acc
// nanomq_cli sub -t topic

#if defined(SUPP_ICEORYX)

#include "nng/nng.h"
#include "nng/iceoryx_shm/iceoryx_shm.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

static int bench_round_max = 100000;
static int bench_round_cnt = 0;

void
inthandler(int signal)
{
	(void) signal;
	printf("echo round counter %d\n", bench_round_cnt);
	exit(0);
}

static void
helper(char **argv)
{
	printf("Usage: %s sub <subername> <service> <instance> <topic>\n", argv[0]);
	printf("       %s pub <pubername> <service> <instance> <topic> <msg>\n", argv[0]);
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
	printf("Get payload [%s]\n", nng_msg_payload_ptr(msg));

	nng_msg_iceoryx_free(msg, suber);
	nng_aio_free(aio);
	nng_free(suber, 0);
	nng_close(sock);
}

void
iceoryx_puber(const char *pubername, const char *service, const char *instance,
		const char *event, const char *txt, size_t sz)
{
	nng_aio *aio;
	nng_msg *msg;
	nng_socket sock;
	nng_iceoryx_puber *puber;

	nng_iceoryx_open(&sock, "Hello-NanoMQ");
	nng_iceoryx_pub(&sock, pubername, service, instance, event, &puber);

	nng_msg_iceoryx_alloc(&msg, puber, sz);
	nng_msg_iceoryx_append(msg, txt, sz);
	printf("Put payload [%s]\n", nng_msg_payload_ptr(msg));

	nng_aio_alloc(&aio, NULL, NULL);
	nng_aio_set_prov_data(aio, puber);
	nng_aio_set_msg(aio, msg);
	nng_send_aio(sock, aio);
	nng_aio_wait(aio);

	nng_aio_free(aio);
	nng_free(puber, 0);
	nng_close(sock);
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

	for (;bench_round_cnt < bench_round_max;) {
		nng_aio_set_prov_data(raio, suber);
		nng_recv_aio(sock, raio);
		nng_aio_wait(raio);
		rmsg = nng_aio_get_msg(raio);
		nng_msg_iceoryx_free(rmsg, suber);

		nng_msg_iceoryx_alloc(&smsg, puber, strlen(txt));
		nng_msg_iceoryx_append(smsg, txt, strlen(txt));
		nng_aio_set_prov_data(saio, puber);
		nng_aio_set_msg(saio, smsg);
		nng_send_aio(sock, saio);
		nng_aio_wait(saio);
		bench_round_cnt ++;
	}

	nng_aio_free(saio);
	nng_free(puber, 0);
	nng_aio_free(raio);
	nng_free(suber, 0);
	nng_close(sock);
}

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

	for (int i=0; i<bench_round_max; ++i) {
		nng_msg_iceoryx_alloc(&smsg, puber, strlen(txt));
		nng_msg_iceoryx_append(smsg, txt, strlen(txt));
		nng_aio_set_prov_data(saio, puber);
		nng_aio_set_msg(saio, smsg);
		nng_send_aio(sock, saio);
		nng_aio_wait(saio);

		nng_aio_set_prov_data(raio, suber);
		nng_recv_aio(sock, raio);
		nng_aio_wait(raio);
		rmsg = nng_aio_get_msg(raio);
		nng_msg_iceoryx_free(rmsg, suber);
		bench_round_cnt ++;
	}

	nng_aio_free(saio);
	nng_free(puber, 0);
	nng_aio_free(raio);
	nng_free(suber, 0);
	nng_close(sock);
}

void
iceoryx_submqtt(const char *subername, const char *service, const char *instance,
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

	char *pld = nng_msg_payload_ptr(msg);
	nng_msg *msg2;
	nng_msg_alloc(&msg2, 0);
	// Decode iceoryx msg
	uint8_t buf1[1];
	memcpy(buf1, pld, 1);
	printf("iceoryx msg len1: %d\n", buf1[0]);
	nng_msg_header_append(msg2, pld, buf1[0]);
	uint32_t buf2;
	{
		char *ptr = pld + 1 + buf1[0];
		buf2 = (((uint32_t)((uint8_t)(ptr)[0])) << 24u) +
		       (((uint32_t)((uint8_t)(ptr)[1])) << 16u) +
		       (((uint32_t)((uint8_t)(ptr)[2])) << 8u) +
		       (((uint32_t)(uint8_t)(ptr)[3]));
	}
	printf("iceoryx msg len2: %d\n", buf2);
	nng_msg_append(msg2, pld + 1 + buf1[0] + 4, buf2);

	uint16_t topicsz;
	{
		char *ptr = nng_msg_body(msg2);
		topicsz = (((uint32_t)((uint8_t)(ptr)[0])) << 8u) +
		          (((uint32_t)(uint8_t)(ptr)[1]));
		printf("mqtt topic: %.*s\n", topicsz, ptr + 2);
	}

	uint16_t pldsz = nng_msg_len(msg2) - 2 - topicsz;
	{
		char *ptr = nng_msg_body(msg2);
		ptr = ptr + 2 + topicsz;
		printf("mqtt topic %.*s\n", pldsz, ptr);
	}

	nng_msg_free(msg2);
	nng_msg_iceoryx_free(msg, suber);
	nng_aio_free(aio);
	nng_free(suber, 0);
	nng_close(sock);
}

void
iceoryx_pubmqtt(char **argv)
{
	char *pld = argv[7];
	char buf1[3] = {0x02, 0x30, 0x0a}; // Inner header 1B, MQTT Fixed header 2B
	char buf2[14] = {0x00, 0x00, 0x00, 0x0a, 0x00, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x74, 0x74, 0x74}; // Inner header 4B, MQTT utf8 string topic 7B, 3B Payload
	// copy pld
	memcpy(buf2+11, pld, 3);

	char bufall[17];
	memcpy(bufall, buf1, 3);
	memcpy(bufall + 3, buf2, 14);
	iceoryx_puber(argv[3], argv[4], argv[5], argv[6], bufall, 17);
}

int
iceoryx_start(int argc, char **argv)
{
	if (argc < 3) {
		helper(argv);
		return 0;
	}
	if (0 == strcmp(argv[2], "sub")) {
		if (argc != 7) {
			helper(argv);
			return 0;
		}
		iceoryx_suber(argv[3], argv[4], argv[5], argv[6]);
	} else if (0 == strcmp(argv[2], "pub")) {
		if (argc != 8) {
			helper(argv);
			return 0;
		}
		iceoryx_puber(argv[3], argv[4], argv[5], argv[6], argv[7], strlen(argv[7]));
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
	} else if (0 == strcmp(argv[2], "pubmqtt")) {
		if (argc != 8) {
			helper(argv);
			return 0;
		}
		iceoryx_pubmqtt(argv);
	} else if (0 == strcmp(argv[2], "submqtt")) {
		if (argc != 7) {
			helper(argv);
			return 0;
		}
		iceoryx_submqtt(argv[3], argv[4], argv[5], argv[6]);
	} else {
		helper(argv);
	}
	return 0;
}

#endif
