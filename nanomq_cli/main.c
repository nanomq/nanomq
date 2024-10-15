#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "include/main.h"

typedef struct {
	char *name;
	int (*func)(int argc, char **argv);
} client_app;

static client_app apps[] = {
#if defined(SUPP_CLIENT)
	{
	    .name = "pub",
	    .func = publish_start,
	},
	{
	    .name = "sub",
	    .func = subscribe_start,
	},
	{
	    .name = "conn",
	    .func = connect_start,
	},
#endif

#if !defined(NANO_PLATFORM_WINDOWS) && defined(SUPP_BENCH)
	{
	    .name = "bench",
	    .func = bench_start,
	},
#endif

#if defined(SUPP_NNG_PROXY)
	{
	    .name = "nngproxy",
	    .func = nng_proxy_start,
	},
	{
	    .name = "nngcat",
	    .func = nng_cat_dflt,
	},
#endif

#if defined(SUPP_ZMQ_GATEWAY)
	{
	    .name = "zmq_gateway",
	    .func = gateway_start,
	},
#endif

#if defined(SUPP_VSOMEIP_GATEWAY)
	{
	    .name = "vsomeip_gateway",
	    .func = vsomeip_gateway_start,
	},
#endif

#if defined(SUPP_DDS_PROXY)
	{
	    .name = "dds",
	    .func = dds_proxy_start,
	},
#endif

#if defined(SUPP_RULE_ENGINE)
	{
	    .name = "rules",
	    .func = rules_start,
	},
#endif

#if defined(SUPP_NFTP)
	{
	    .name = "nftp",
	    .func = nftp_start,
	},
#endif

#if defined(SUPP_ICEORYX)
	{
	    .name = "iceoryx",
	    .func = iceoryx_start,
	},
#endif
	{
		.name = "encrypt",
		.func = encrypt_start,
	}
};

static void
print_avail_apps(void)
{
	printf("nanomq_cli {");
	size_t count = sizeof(apps) / sizeof(apps[0]);
	for (size_t i = 0; i < count; i++) {
		printf(" %s", apps[i].name);
		if (count > (i + 1)) {
			printf(" |");
		}
	}
	printf(" } [--help]\n");
	printf("\navailable tools:\n");
	for (size_t i = 0; i < count; i++) {
		printf("   * %s\n", apps[i].name);
	}
	printf("\n");
	printf("Copyright 2022 EMQ Edge Computing Team\n");
	printf("\n");
}

int
main(int argc, char **argv)
{
	if (argc <= 1) {
		goto usage;
	}

	char *app_name = argv[1];

	for (size_t i = 0; i < sizeof(apps) / sizeof(apps[0]); i++) {
		if (strcmp(app_name, apps[i].name) == 0) {
			return apps[i].func(argc, argv);
		}
	}

usage:
	print_avail_apps();

	return 0;
}
