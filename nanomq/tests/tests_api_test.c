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

int
main()
{
	test_cleanup_preserves_reused_fd(false);
	test_cleanup_preserves_reused_fd(true);
	return 0;
}

#else

int
main()
{
	return 0;
}

#endif
