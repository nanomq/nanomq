
#include "include/nanomq.h"

#include "include/process.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <paths.h>

int process_is_alive(int pid)
{
	if (pid < 1)
		return 0;

	return kill(pid, 0) == 0 ? 1 : 0;
}

int process_send_signal(int pid, int signal)
{
	if (pid < 1)
		return 0;

	debug_msg("pid = %i, signal = %i", pid, signal);
	return kill(pid, signal);
}

int pidgrp_send_signal(int pid, int signal)
{
	pid_t gpid;

	if (pid < 1)
		return 0;

	gpid = getpgid(pid);
	if (gpid < 0) {
		debug_msg("pid = %i: unable to retrieve gpid: %s", pid,
			  strerror(errno));
		return 0;
	}

	debug_msg("pid = %i: gpid = %i, signal = %i", pid, gpid, signal);
	return kill(-gpid, signal);
}

int process_daemonize(void)
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

int process_create_child(int(*child_run)(void *), void *data)
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
