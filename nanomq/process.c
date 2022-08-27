//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "include/nanomq.h"
#include "include/process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nng/supplemental/nanolib/log.h"

#ifndef NANO_PLATFORM_WINDOWS
#include <paths.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

int
process_is_alive(int pid)
{
	if (pid < 1)
		return 0;

	return kill(pid, 0) == 0 ? 1 : 0;
}

int
process_send_signal(int pid, int signal)
{
	if (pid < 1)
		return 0;

	log_debug("pid = %i, signal = %i", pid, signal);
	return kill(pid, signal);
}

int
pidgrp_send_signal(int pid, int signal)
{
	pid_t gpid;

	if (pid < 1)
		return 0;

	gpid = getpgid(pid);
	if (gpid < 0) {
		log_debug("pid = %i: unable to retrieve gpid: %s", pid,
		    strerror(errno));
		return 0;
	}

	log_debug("pid = %i: gpid = %i, signal = %i", pid, gpid, signal);
	return kill(-gpid, signal);
}

int
process_daemonize(void)
{
	int fd;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
	}

	if (setsid() == -1)
		return EXIT_FAILURE;

	/* Make certain we are not a session leader, or else we might reacquire
	 * a controlling terminal
	 */
	if (fork())
		exit(EXIT_SUCCESS);

	chdir("/");

	fd = open(_PATH_DEVNULL, O_RDWR, 0);

	if (fd != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		if (fd > 2)
			close(fd);
	}

	return 0;
}

int
process_create_child(int (*child_run)(void *), void *data)
{
	pid_t pid;

	pid = fork();

	switch (pid) {
	case -1:
		return -1;
	case 0:
		exit(child_run(data));
	default:
		return pid;
	}
}

#else

int
process_is_alive(int pid)
{
	return 0;
}

int
process_send_signal(int pid, int signal)
{
	return 0;
}

int
process_daemonize(void)
{
	fprintf(stderr, "Not support on Windows\n");
	return -1;
}

int
process_create_child(int (*child_run)(void *), void *data)
{
	fprintf(stderr, "Not support on Windows\n");
	return -1;
}

#endif