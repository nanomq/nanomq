//
// Copyright 2021 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/nanomq.h"
#include "cmd.h"
#include "include/apps.h"
#include "include/const_strings.h"
#include "include/process.h"
#include "include/version.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef NANO_PLATFORM_WINDOWS
#include <winsock2.h>
#else 
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#define NANO_APP_NAME "nanomq"
#define NANO_BRAND "NanoMQ  Edge Computing Kit & Messaging bus"

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
	printf("\n%s v0.6.8-%s\n", NANO_BRAND, FW_EV_VER_ID_SHORT);
	printf("Copyright 2022 EMQ X Edge Team\n");
	printf("\n");
}

static int
print_avail_apps(void)
{
	const struct nanomq_app **nano_app;
	int app_count = 0;

	printf("\navailable applications:\n");

	for (nano_app = edge_apps; *nano_app; ++nano_app) {
		printf("   * %s\n", (*nano_app)->name);
		app_count++;
	}

	return (app_count);
}

static void
print_help(void)
{
	const struct nanomq_app **nano_app = edge_apps;

	printf("\nUsage: nanomq");
	while (1) {
		printf(" %s ", (*nano_app)->name);
		++nano_app;
		if (*nano_app) {
			printf("|");
		} else {
			printf("[--help]");
			break;
		}
	}
	printf("nanomq also provide MQTT bench tool and proxy module as protocol gateway"
		"to bridging nanomsg/nng msg to MQTT broker\n");
}

/* #if defined(DEBUG_TRACE)
static int check_trace(char *name)
{
        int pid, traced;

        switch(pid = fork()) {
                case  0:
                        pid = getppid();


#ifdef __APPLE__
                        traced = ptrace(PT_ATTACHEXC, pid, 0, 0);
#elif __linux__
                        traced = ptrace(PTRACE_ATTACH, pid, 0, 0);
#else
#   error "Unknown compiler"
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
#else */
static int
check_trace(char NANO_UNUSED(*name))
{
	return 0;
}
// #endif

static int
handle_app(int res)
{
	nano_cmd_cleanup();
	return res;
}

int
main(int argc, char **argv)
{
	const struct nanomq_app **nano_app;
	char *                    app_name;
	int                       ret;

	ret = check_trace(argv[0]);
	if (ret < 0)
		return EXIT_FAILURE;

	if ((argc > 1) && (strlen(argv[1]) > 1) && (argv[1][0] == '-') &&
	    (argv[1][1] == 'v')) {
		print_version();
		return EXIT_SUCCESS;
	}

	args.argc = argc;
	args.argv = argv;

#ifdef NANO_PLATFORM_WINDOWS
	app_name = strrchr(argv[0], '\\');
#else
	app_name = strrchr(argv[0], '/');
#endif
	debug_msg("argv %s %s app_name %s", argv[0], argv[1], app_name);
	app_name = (app_name ? app_name + 1 : argv[0]);

	if (strncmp(app_name, NANO_APP_NAME, strlen(NANO_APP_NAME)) == 0) {
		debug_msg("argc : %d", argc);
		if (argc == 1) {
			print_avail_apps();
			print_version();
			return (1);
		}

		app_name = argv[1];
		argv++;
		argc--;
	}

	for (nano_app = edge_apps; *nano_app; ++nano_app) {
		if (strncmp(app_name, (*nano_app)->name,
		        strlen((*nano_app)->name)) == 0)
			break;
	}

	if (!(*nano_app)) {
		printf("Error - the app '%s' was not found\n", app_name);
		print_help();
		print_version();
		return EXIT_FAILURE;
	}

	if (argc < 2) {
		if ((*nano_app)->dflt)
			return handle_app(
			    (*nano_app)->dflt(argc - 1, argv + 1));

		printf("Error - not enough arguments to run %s\n", app_name);
		goto err_param;
	}

	if ((strcmp(argv[1], "start") == 0) && (*nano_app)->start)
		return handle_app((*nano_app)->start(argc - 2, argv + 2));

	if ((strcmp(argv[1], "stop") == 0) && (*nano_app)->stop)
		return handle_app((*nano_app)->stop(argc - 2, argv + 2));

	if ((strcmp(argv[1], "restart") == 0) && (*nano_app)->restart)
		return handle_app((*nano_app)->restart(argc - 2, argv + 2));

	if ((*nano_app)->dflt)
		return handle_app((*nano_app)->dflt(argc - 1, argv + 1));

	printf("Error - unknown parameter: %s\n", argv[1]);

err_param:
	printf("Use one of the following parameters:\n");
	if ((*nano_app)->start)
		printf("   * start\n");
	if ((*nano_app)->stop)
		printf("   * stop\n");
	return EXIT_FAILURE;
}
