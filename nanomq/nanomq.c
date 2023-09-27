//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/nanomq.h"
#include "include/broker.h"
#include "include/const_strings.h"
#include "include/process.h"
#include "include/version.h"
#include "nng/supplemental/nanolib/cmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NANO_PLATFORM_WINDOWS
#include <winsock2.h>
#else
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define NANO_BRAND "NanoMQ Messaging Engine for Edge Computing & Messaging bus"

#define NANO_DEBUG

struct cache_arg{
	int argc;
	char **argv;
};

typedef struct cache_arg cache_arg;

static cache_arg args = {0};

int
get_cache_argc()
{
	return args.argc;
}

char **
get_cache_argv()
{
	return args.argv;
}

static void
print_version(void)
{
	printf("\n%s v%d.%d.%d-%s\n", NANO_BRAND, NANO_VER_MAJOR,
	    NANO_VER_MINOR, NANO_VER_PATCH, NANO_VER_ID_SHORT);
	printf("Copyright 2023 EMQ Edge Computing Team\n");
	printf("\n");
}

static void
print_help(void)
{
	printf("\nUsage: nanomq { start | stop | restart | reload } [--help]\n");
	print_version();
}

#if defined(DEBUG_TRACE)
static int
check_trace(char *name)
{
	int pid, traced;

	switch (pid = fork()) {
	case 0:
		pid = getppid();

#ifdef NANO_PLATFORM_DARWIN
		traced = ptrace(PT_ATTACHEXC, pid, 0, 0);
#elif NANO_PLATFORM_LINUX
		traced = ptrace(PTRACE_ATTACH, pid, 0, 0);
#else
		printf("error: current platform do support\n");
#endif

		if (!traced) {
			process_send_signal(pid, SIGCONT);
			_exit(EXIT_SUCCESS);
		}

		perror(name);
		process_send_signal(pid, SIGKILL);
		goto err;
	case -1:
		break;
	default:
		if (pid == waitpid(pid, 0, 0))
			return EXIT_SUCCESS;

		break;
	}

	perror(name);
err:
	return -1;
}
#else
static int
check_trace(char *name)
{
	(void) name;
	return 0;
}
#endif

#if defined(SUPP_NANO_LIB)

#else
int
main(int argc, char **argv)
{
	int ret;
	ret = check_trace(argv[0]);
	if (ret < 0)
		return EXIT_FAILURE;

	args.argc = argc;
	args.argv = argv;

	if (argc < 2) {
		print_help();
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "start") == 0) {
		return broker_start(argc, argv);
	} else if (strcmp(argv[1], "stop") == 0) {
		return broker_stop(argc, argv);
	} else if (strcmp(argv[1], "restart") == 0) {
		return broker_restart(argc, argv);
	} else if (strcmp(argv[1], "reload") == 0) {
		return broker_reload(argc, argv);
	} else if (strcmp(argv[1], "--help") == 0) {
		return broker_dflt(argc, argv);
	} else {
		print_help();
		return EXIT_FAILURE;
	}

	return EXIT_FAILURE;
}

#endif
