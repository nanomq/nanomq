#include "tests_api.h"

#ifndef NANO_PLATFORM_WINDOWS

static void
test_cleanup_preserves_reused_fd(bool nonblock)
{
	char *args[] = { "sh", "-c", "printf ready", NULL };
	int   outfd  = -1;
	pid_t pid;
	char  output[8] = { 0 };

	pid = nonblock ? popen_sub_with_cmd_nonblock(&outfd, args, "/bin/sh") :
	                 popen_with_cmd(&outfd, args, "/bin/sh");
	assert(pid > 0);
	assert(outfd >= 0);
	if (nonblock) {
		assert(test_env_wait_for_output(outfd, output, sizeof(output), 1000, 10));
	} else {
		assert(read(outfd, output, sizeof(output)) > 0);
	}
	close(outfd);

	int reused_fd = open("/dev/null", O_RDONLY);
	assert(reused_fd == outfd);

	test_env_test_cleanup();
	assert(fcntl(reused_fd, F_GETFD) != -1);
	close(reused_fd);
}

static void
test_child_closes_original_write_fd(bool nonblock)
{
	char *args[] = { "sh", "-c", "exec 1>&-; exec 2>&-; sleep 1", NULL };
	struct pollfd pollfd;
	int           outfd = -1;
	pid_t         pid;
	char          byte;

	pid = nonblock ? popen_sub_with_cmd_nonblock(&outfd, args, "/bin/sh") :
	                 popen_with_cmd(&outfd, args, "/bin/sh");
	assert(pid > 0);
	assert(outfd >= 0);
	pollfd.fd     = outfd;
	pollfd.events = POLLIN | POLLHUP;
	assert(poll(&pollfd, 1, 500) > 0);
	assert(read(outfd, &byte, sizeof(byte)) == 0);
	close(outfd);
	test_env_test_cleanup();
}

static void
test_reap_failed_popen_child(void)
{
	pid_t pid = fork();
	int   status;

	assert(pid >= 0);
	if (pid == 0) {
		for (;;) {
			pause();
		}
	}

	test_env_kill_and_reap(pid);
	errno = 0;
	assert(waitpid(pid, &status, WNOHANG) == -1);
	assert(errno == ECHILD);
}

static void
test_pclose_timeout_reaps_process_group(void)
{
	FILE *stream = test_env_popen("sleep 30", "r");

	assert(stream != NULL);
	assert(test_env_pclose_timeout(stream, 50) == -1);
}

int
main()
{
	test_cleanup_preserves_reused_fd(false);
	test_cleanup_preserves_reused_fd(true);
	test_child_closes_original_write_fd(false);
	test_child_closes_original_write_fd(true);
	test_reap_failed_popen_child();
	test_pclose_timeout_reaps_process_group();
	return 0;
}

#else

int
main()
{
	return 0;
}

#endif
