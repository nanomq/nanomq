// Verify the real broker callback does not rearm terminal receive errors.
#include "include/broker.h"

#include <stdio.h>
#include <stdlib.h>

extern void server_cb(void *);

#define CHECK(expr) do { if (!(expr)) abort(); } while (0)

static unsigned receives;

void
__wrap_nng_ctx_recv(nng_ctx ctx, nng_aio *aio)
{
	(void) ctx;
	(void) aio;
	receives++;
}

int
main(void)
{
	nano_work work = { .proto = PROTO_MQTT_BROKER };
	CHECK(nng_aio_alloc(&work.aio, NULL, NULL) == 0);
	int errors[] = { NNG_ECLOSED, NNG_ECANCELED, NNG_ESTATE, NNG_ETIMEDOUT };
	for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		work.state = RECV;
		receives = 0;
		nng_aio_finish(work.aio, errors[i]);
		nng_aio_wait(work.aio);
		server_cb(&work);
		CHECK(receives == (errors[i] == NNG_ETIMEDOUT ? 1u : 0u));
	}
	nng_aio_free(work.aio);
	nng_fini();
	puts("PASS terminal broker receive errors are not retried");
	return 0;
}
