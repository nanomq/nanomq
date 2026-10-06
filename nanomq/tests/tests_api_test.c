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

typedef struct test_fake_wait_clock {
	nng_time now;
	unsigned sleep_calls;
	unsigned slept_ms;
} test_fake_wait_clock;

static nng_time
test_fake_wait_now(void *arg)
{
	return ((test_fake_wait_clock *) arg)->now;
}

static void
test_fake_wait_sleep(void *arg, unsigned sleep_ms)
{
	test_fake_wait_clock *clock = arg;
	clock->sleep_calls++;
	clock->slept_ms += sleep_ms;
	clock->now += sleep_ms;
}

static void
test_wait_contracts_use_monotonic_deadlines(void)
{
	test_fake_wait_clock fake = { 100, 0, 0 };
	test_env_wait_clock clock = {
		.now = test_fake_wait_now,
		.sleep = test_fake_wait_sleep,
		.arg = &fake,
	};
	char output[16] = { 0 };
	int  pipefd[2];

	assert(pipe(pipefd) == 0);
	assert(!test_env_wait_for_output_with_clock(
	    pipefd[0], output, sizeof(output), 5, 2, &clock));
	assert(fake.now == 105);
	assert(fake.sleep_calls == 3);
	assert(fake.slept_ms == 5);
	close(pipefd[0]);
	close(pipefd[1]);

	fake = (test_fake_wait_clock) { 200, 0, 0 };
	assert(pipe(pipefd) == 0);
	assert(write(pipefd[1], "ready", 5) == 5);
	assert(test_env_wait_for_output_with_clock(
	    pipefd[0], output, sizeof(output), 5, 2, &clock));
	assert(strcmp(output, "ready") == 0);
	assert(fake.sleep_calls == 0);
	close(pipefd[0]);
	close(pipefd[1]);

	fake = (test_fake_wait_clock) { 300, 0, 0 };
	assert(pipe(pipefd) == 0);
	assert(test_env_wait_for_no_output_with_clock(
	    pipefd[0], 5, 2, &clock));
	assert(fake.now == 305);
	assert(fake.slept_ms == 5);
	close(pipefd[0]);
	close(pipefd[1]);
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
	test_wait_contracts_use_monotonic_deadlines();
	return 0;
}

#else

int
main()
{
	return 0;
}

#endif
