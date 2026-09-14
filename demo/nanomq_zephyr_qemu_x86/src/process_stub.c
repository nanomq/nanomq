//
// Zephyr stand-in for nanomq/process.c.
//
// The upstream process.c is pure POSIX (fork/kill/chdir, <paths.h>) and
// cannot be built on Zephyr.  Its public symbols (nanomq/nanomq/
// include/process.h) are referenced from apps/broker.c but only behind
// `daemon == true` / CLI paths that are never taken by the embedded
// broker (conf_init defaults daemon=false; main.c calls broker() directly,
// bypassing broker_start()).  Provide error-returning stubs so the
// broker object links.
//
#include "include/process.h"

int
process_is_alive(int pid)
{
	(void) pid;
	return (-1);
}

int
process_send_signal(int pid, int signal)
{
	(void) pid;
	(void) signal;
	return (-1);
}

int
pidgrp_send_signal(int pid, int signal)
{
	(void) pid;
	(void) signal;
	return (-1);
}

int
process_daemonize(void)
{
	return (-1);
}

int
process_create_child(int (*child_run)(void *), void *data)
{
	(void) child_run;
	(void) data;
	return (-1);
}
