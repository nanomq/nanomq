// This is a test only Scenario for advanced features of NanoMQ, like webhook, etc.
#define INPROC_TEST_URL "inproc://test"
#define REST_TEST_URL "http://127.0.0.1:%u/hook"
#define	ALL_FEATURE_CONF_PATH "../../../nanomq/tests/nanomq_test.conf"
#define	AUTH_ANON_CONF_PATH "../../../nanomq/tests/nanomq_test_anon.conf"
#define	BRIDGE_CONF_PATH "../../../nanomq/tests/nanomq_bridge_test.conf"
#define	BRIDGE_TLS_CONF_PATH "../../../nanomq/tests/nanomq_bridge_tls_test.conf"
#define	BRIDGE_AWS_CONF_PATH "../../../nanomq/tests/nanomq_aws_test.conf"
#define	BRIDGE_MUTI_CONF_PATH "../../../nanomq/tests/nanomq_muti_bridges_test.conf"

#define WEBHOOK_MESSAGE_TIMEOUT_MS 30000
#define TEST_ENV_PCLOSE_TIMEOUT_MS 5000

int webhook_msg_cnt = 0; // this is a silly signal to indicate whether the webhook tests pass

// This is a silly demo for test -- it listens on port 8888 (or $PORT if present),
// and accepts HTTP POST requests at /test
//
// These requests are converted into an NNG REQ message, and sent to an
// NNG REP server (builtin inproc_server, for test purposes only).
// The reply is obtained from the server, and sent back to the client via
// the HTTP server framework.

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/nanolib/cvector.h>
#include <nng/supplemental/util/platform.h>
#include <nng/supplemental/nanolib/conf.h>
#include <nng/supplemental/nanolib/utils.h>
#ifdef NNG_SUPP_TLS
#include <nng/supplemental/tls/tls.h>
#endif
#include "include/broker.h"
#include "include/rest_api.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <limits.h>

#ifndef NANO_PLATFORM_WINDOWS
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define TEST_ENV_MAX_TRACKED_POPEN 32
#define TEST_ENV_MAX_TRACKED_THREADS 32
#define TEST_ENV_MAX_TRACKED_CONF_FILES 16

static nng_socket test_inproc_socket;
static bool       test_inproc_socket_active = false;

#ifndef NANO_PLATFORM_WINDOWS
typedef struct test_env_tracked_proc {
	pid_t    pid;
	pid_t    pgid;
	int      outfd;
	FILE    *stream;
	bool     active;
} test_env_tracked_proc;

static test_env_tracked_proc test_env_tracked_procs[TEST_ENV_MAX_TRACKED_POPEN];
static size_t               test_env_tracked_proc_count = 0;
static nng_thread         *  test_env_tracked_threads[TEST_ENV_MAX_TRACKED_THREADS];
static bool                test_env_tracked_threads_active[TEST_ENV_MAX_TRACKED_THREADS];
static size_t              test_env_tracked_thread_count = 0;
static char               *test_env_tracked_conf_files[TEST_ENV_MAX_TRACKED_CONF_FILES];
static size_t              test_env_tracked_conf_file_count = 0;
static bool                 test_env_cleanup_registered  = false;

static void
test_env_track_conf_file(const char *conf_file)
{
	if (conf_file == NULL || conf_file[0] == '\0') {
		return;
	}
	if (test_env_tracked_conf_file_count >= TEST_ENV_MAX_TRACKED_CONF_FILES) {
		return;
	}
	test_env_tracked_conf_files[test_env_tracked_conf_file_count] =
	    nng_strdup(conf_file);
	if (test_env_tracked_conf_files[test_env_tracked_conf_file_count] == NULL) {
		return;
	}
	test_env_tracked_conf_file_count++;
}

static void
test_env_track_conf_cleanup(void)
{
	for (size_t i = 0; i < test_env_tracked_conf_file_count; ++i) {
		if (test_env_tracked_conf_files[i] == NULL) {
			continue;
		}
		unlink(test_env_tracked_conf_files[i]);
		nng_free(test_env_tracked_conf_files[i],
		    strlen(test_env_tracked_conf_files[i]) + 1);
		test_env_tracked_conf_files[i] = NULL;
	}
	test_env_tracked_conf_file_count = 0;
}

static char *
test_env_rewrite_conf_port(const char *source, const char *new_port)
{
	FILE   *fp = NULL;
	long    file_size;
	char   *source_buf = NULL;
	char   *target_buf = NULL;
	size_t  source_len;
	size_t  target_len;
	size_t  wrote = 0;
	int     fd = -1;
	char    tmp_path[] = "/tmp/nanomq-conf-XXXXXX";
	char    from_text[] = ":1881";
	char   *to_text = NULL;
	char   *new_path = NULL;
	size_t  replace_count = 0;
	size_t  to_len;
	const size_t from_len = sizeof(from_text) - 1;
	long   delta_len;

	if (source == NULL || new_port == NULL || new_port[0] == '\0') {
		return NULL;
	}
	to_len = strlen(new_port) + 2;
	to_text = nng_zalloc(to_len);
	if (to_text == NULL) {
		return NULL;
	}
	snprintf(to_text, to_len, ":%s", new_port);

	fp = fopen(source, "r");
	if (fp == NULL) {
		nng_free(to_text, to_len);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		nng_free(to_text, to_len);
		return NULL;
	}
	file_size = ftell(fp);
	if (file_size < 0) {
		fclose(fp);
		nng_free(to_text, to_len);
		return NULL;
	}
	rewind(fp);
	source_len = (size_t) file_size;
	source_buf = nng_zalloc(source_len + 1);
	if (source_buf == NULL) {
		fclose(fp);
		nng_free(to_text, to_len);
		return NULL;
	}
	if (fread(source_buf, 1, source_len, fp) != source_len) {
		fclose(fp);
		nng_free(source_buf, source_len + 1);
		nng_free(to_text, to_len);
		return NULL;
	}
	fclose(fp);

	for (size_t i = 0; i + from_len <= source_len; ++i) {
		if (strncmp(&source_buf[i], from_text, from_len) == 0) {
			replace_count++;
			i += from_len - 1;
		}
	}
	delta_len = (long) to_len - (long) from_len;
	if (delta_len < 0 &&
	    source_len < (size_t) (-(delta_len * (long) replace_count))) {
		nng_free(source_buf, source_len + 1);
		nng_free(to_text, to_len);
		return NULL;
	}
	target_len = source_len + (size_t) (delta_len * (long) replace_count);
	target_buf = nng_zalloc(target_len + 1);
	if (target_buf == NULL) {
		nng_free(source_buf, source_len + 1);
		nng_free(to_text, to_len);
		return NULL;
	}

	size_t offset = 0;
	for (size_t i = 0; i < source_len;) {
		if (i + from_len <= source_len &&
		    strncmp(&source_buf[i], from_text, from_len) == 0) {
			memcpy(&target_buf[offset], to_text, to_len - 1);
			offset += (to_len - 1);
			i += from_len;
			continue;
		}
		target_buf[offset++] = source_buf[i++];
	}
	target_buf[offset] = '\0';

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		nng_free(source_buf, source_len + 1);
		nng_free(target_buf, target_len + 1);
		nng_free(to_text, to_len);
		return NULL;
	}

	while (wrote < offset) {
		ssize_t wr = write(fd, target_buf + wrote, offset - wrote);
		if (wr < 0) {
			if (errno == EINTR) {
				continue;
			}
			close(fd);
			unlink(tmp_path);
			nng_free(source_buf, source_len + 1);
			nng_free(target_buf, target_len + 1);
			nng_free(to_text, to_len);
			return NULL;
		}
		wrote += (size_t) wr;
	}
	close(fd);
	nng_free(source_buf, source_len + 1);
	nng_free(target_buf, target_len + 1);
	nng_free(to_text, to_len);

	new_path = nng_strdup(tmp_path);
	return new_path;
}

static void
test_env_test_cleanup(void)
{
	// Stop the broker before joining its wrapper thread.  The broker owns
	// listener and webhook resources that otherwise keep the join blocked.
	broker_stop_for_test();

	for (size_t i = 0; i < test_env_tracked_thread_count; ++i) {
		if (!test_env_tracked_threads_active[i] ||
		    test_env_tracked_threads[i] == NULL) {
			continue;
		}
		nng_thread_destroy(test_env_tracked_threads[i]);
		test_env_tracked_threads[i] = NULL;
		test_env_tracked_threads_active[i] = false;
	}

	for (size_t i = 0; i < test_env_tracked_proc_count; ++i) {
		test_env_tracked_proc *proc = &test_env_tracked_procs[i];
		int                  status = 0;
		pid_t                pgid;
		pid_t                target;

		if (!proc->active || proc->pid <= 0) {
			continue;
		}

		if (kill(proc->pid, 0) == 0 || errno == EPERM) {
			pgid   = proc->pgid > 0 ? proc->pgid : proc->pid;
			target = (pgid > 0) ? -pgid : -proc->pid;

			kill(target, SIGTERM);
			for (size_t j = 0; j < 10; ++j) {
				if (kill(proc->pid, 0) != 0 && errno == ESRCH) {
					break;
				}
				nng_msleep(10);
			}
			if (kill(proc->pid, 0) == 0 || errno == EPERM) {
				kill(target, SIGKILL);
			}
			for (int j = 0; j < 10; ++j) {
				if (waitpid(proc->pid, &status, WNOHANG) > 0) {
					break;
				}
				nng_msleep(10);
			}
			waitpid(proc->pid, &status, 0);
		}
		if (proc->outfd >= 0) {
			close(proc->outfd);
			proc->outfd = -1;
		}
		proc->active = false;
	}
	test_env_tracked_proc_count = 0;
	test_env_tracked_thread_count = 0;
	test_env_track_conf_cleanup();
}

static void
test_env_register_cleanup(void)
{
	if (!test_env_cleanup_registered) {
		atexit(test_env_test_cleanup);
		test_env_cleanup_registered = true;
	}
}

static void
test_env_track_proc(pid_t pid, int outfd, FILE *stream)
{
	if (pid <= 0) {
		return;
	}
	if (test_env_tracked_proc_count >= TEST_ENV_MAX_TRACKED_POPEN) {
		return;
	}
	test_env_register_cleanup();
	test_env_tracked_procs[test_env_tracked_proc_count].pid    = pid;
	test_env_tracked_procs[test_env_tracked_proc_count].pgid   = pid;
	test_env_tracked_procs[test_env_tracked_proc_count].outfd  = outfd;
	test_env_tracked_procs[test_env_tracked_proc_count].stream = stream;
	test_env_tracked_procs[test_env_tracked_proc_count].active = true;
	test_env_tracked_proc_count++;
}

static void
test_env_track_thread(nng_thread *thread)
{
	if (thread == NULL) {
		return;
	}
	if (test_env_tracked_thread_count >= TEST_ENV_MAX_TRACKED_THREADS) {
		return;
	}
	test_env_register_cleanup();
	test_env_tracked_threads[test_env_tracked_thread_count]       = thread;
	test_env_tracked_threads_active[test_env_tracked_thread_count] = true;
	test_env_tracked_thread_count++;
}

static void
test_env_untrack_thread(nng_thread *thread)
{
	for (size_t i = 0; i < test_env_tracked_thread_count; ++i) {
		if (test_env_tracked_threads_active[i] &&
		    test_env_tracked_threads[i] == thread) {
			test_env_tracked_threads_active[i] = false;
			test_env_tracked_threads[i]       = NULL;
			return;
		}
	}
}

static void
test_env_kill_and_reap(pid_t pid)
{
	int status;

	if (pid <= 0) {
		return;
	}
	(void) kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
	}
}

static FILE *
test_env_popen(const char *command, const char *mode)
{
	int   pipefd[2];
	pid_t pid = -1;
	FILE *fp  = NULL;

	if (command == NULL || mode == NULL || mode[0] == '\0') {
		return NULL;
	}
	if (strcmp(mode, "r") == 0) {
		if (pipe(pipefd) != 0) {
			return NULL;
		}
		pid = fork();
		if (pid < 0) {
			close(pipefd[STDIN_FILENO]);
			close(pipefd[STDOUT_FILENO]);
			return NULL;
		}
		if (pid == 0) {
			(void) setpgid(0, 0);
			close(pipefd[STDIN_FILENO]);
			dup2(pipefd[STDOUT_FILENO], STDOUT_FILENO);
			close(pipefd[STDOUT_FILENO]);
			execlp("sh", "sh", "-c", command, (char *) NULL);
			exit(EXIT_FAILURE);
		}
		close(pipefd[STDOUT_FILENO]);
		(void) setpgid(pid, pid);
		fp = fdopen(pipefd[STDIN_FILENO], "r");
		if (fp == NULL) {
			close(pipefd[STDIN_FILENO]);
			test_env_kill_and_reap(pid);
			return NULL;
		}
		test_env_track_proc(pid, pipefd[STDIN_FILENO], fp);
		return fp;
	}
	if (strcmp(mode, "w") == 0) {
		if (pipe(pipefd) != 0) {
			return NULL;
		}
		pid = fork();
		if (pid < 0) {
			close(pipefd[STDIN_FILENO]);
			close(pipefd[STDOUT_FILENO]);
			return NULL;
		}
		if (pid == 0) {
			(void) setpgid(0, 0);
			close(pipefd[STDOUT_FILENO]);
			dup2(pipefd[STDIN_FILENO], STDIN_FILENO);
			close(pipefd[STDIN_FILENO]);
			execlp("sh", "sh", "-c", command, (char *) NULL);
			exit(EXIT_FAILURE);
		}
		close(pipefd[STDIN_FILENO]);
		(void) setpgid(pid, pid);
		fp = fdopen(pipefd[STDOUT_FILENO], "w");
		if (fp == NULL) {
			close(pipefd[STDOUT_FILENO]);
			test_env_kill_and_reap(pid);
			return NULL;
		}
		test_env_track_proc(pid, pipefd[STDOUT_FILENO], fp);
		return fp;
	}
	return NULL;
}

static int
test_env_pclose_timeout(FILE *stream, unsigned timeout_ms)
{
	test_env_tracked_proc *proc = NULL;
	pid_t                  pid;
	int                    status;
	unsigned               waited = 0;

	if (stream == NULL) {
		return -1;
	}
	for (size_t i = 0; i < test_env_tracked_proc_count; ++i) {
		if (test_env_tracked_procs[i].active &&
		    test_env_tracked_procs[i].stream == stream) {
			proc = &test_env_tracked_procs[i];
			proc->active = false;
			break;
		}
	}
	pid = proc == NULL ? -1 : proc->pid;
	fclose(stream);
	if (pid <= 0) {
		return -1;
	}

	for (;;) {
		pid_t wrc = waitpid(pid, &status, WNOHANG);
		if (wrc == pid) {
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		}
		if (wrc < 0 && errno != EINTR) {
			return -1;
		}
		if (waited >= timeout_ms) {
			break;
		}
		unsigned sleep_ms = timeout_ms - waited;
		if (sleep_ms > 10) {
			sleep_ms = 10;
		}
		nng_msleep(sleep_ms);
		waited += sleep_ms;
	}

	if (proc->pgid > 0) {
		(void) kill(-proc->pgid, SIGKILL);
	} else {
		(void) kill(pid, SIGKILL);
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
	}
	return -1;
}

static int
test_env_nng_thread_create(
    nng_thread **thread, void (*fn)(void *), void *arg)
{
	int rc = nng_thread_create(thread, fn, arg);
	if (rc == 0 && thread != NULL && *thread != NULL) {
		test_env_track_thread(*thread);
	}
	return rc;
}

static void
test_env_nng_thread_destroy(nng_thread *thread)
{
	test_env_untrack_thread(thread);
	nng_thread_destroy(thread);
}

static void
test_env_assert_failed(const char *expr, const char *file, int line)
{
	fprintf(stderr, "test environment test assertion failed: %s (%s:%d)\n", expr, file, line);
	test_env_test_cleanup();
	exit(EXIT_FAILURE);
}

static bool
test_env_report_bind_owner(uint16_t port)
{
#ifndef NANO_PLATFORM_WINDOWS
	char    cmd[96];
	char    pid_line[64];
	FILE   *fp;
	bool    has_listener = false;

	snprintf(cmd, sizeof(cmd), "lsof -nP -iTCP:%hu -sTCP:LISTEN -t", port);
	fp = test_env_popen(cmd, "r");
	if (fp == NULL) {
		return false;
	}
	while (fgets(pid_line, sizeof(pid_line), fp) != NULL) {
		char    *end;
		pid_t    pid = (pid_t) strtol(pid_line, &end, 10);
		int      wstatus;
		FILE    *cmd_fp;
		char     cmd_line[256];

		if (pid <= 0 || (end == pid_line)) {
			continue;
		}
		snprintf(cmd_line, sizeof(cmd_line), "ps -p %d -o comm=", pid);
		cmd_fp = test_env_popen(cmd_line, "r");
		if (cmd_fp != NULL) {
			char cmd_name[128] = { 0 };

			if (fgets(cmd_name, sizeof(cmd_name), cmd_fp) != NULL) {
				cmd_name[strcspn(cmd_name, "\n")] = '\0';
				fprintf(stderr,
				    "  port %hu in use by pid=%d command=%s\n", port, pid,
				    cmd_name[0] != '\0' ? cmd_name : "<unknown>");
			}
			test_env_pclose_timeout(cmd_fp, TEST_ENV_PCLOSE_TIMEOUT_MS);
		}
		has_listener = true;
		waitpid(pid, &wstatus, WNOHANG);
	}
	test_env_pclose_timeout(fp, TEST_ENV_PCLOSE_TIMEOUT_MS);
	if (!has_listener) {
		fprintf(stderr, "  no lsof owner output for port %hu\n", port);
	}
	return has_listener;
#endif
	return false;
}

#undef assert
#define assert(expr)                                                         \
	((expr) ? (void) 0 : test_env_assert_failed(#expr, __FILE__, __LINE__))
#define popen(cmd, mode) test_env_popen((cmd), (mode))
#define pclose(fp) test_env_pclose_timeout((fp), TEST_ENV_PCLOSE_TIMEOUT_MS)
#define nng_thread_create(thread, fn, arg) test_env_nng_thread_create((thread), (fn), (arg))
#define nng_thread_destroy(thread) test_env_nng_thread_destroy((thread))
#endif

static uint16_t test_env_test_port(void);

static bool
test_env_skip_network_bind_check(void)
{
	const char *skip_check = getenv("NANOMQ_SKIP_NETWORK_TEST_ENV_CHECK");

	return skip_check != NULL &&
	    (strcmp(skip_check, "1") == 0 || strcasecmp(skip_check, "true") == 0 ||
	        strcasecmp(skip_check, "yes") == 0 ||
	        strcasecmp(skip_check, "on") == 0);
}

static bool
test_env_allows_port_bind(uint16_t port)
{
#ifndef NANO_PLATFORM_WINDOWS
	int                sock;
	struct sockaddr_in addr;

	if (test_env_skip_network_bind_check()) {
		return true;
	}
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "test_env_allows_port_bind: socket() failed: %s\n",
		    strerror(errno));
		return false;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = htons(port);
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		int bind_errno = errno;

		test_env_report_bind_owner(port);
		fprintf(stderr,
		    "test_env_allows_port_bind: bind to 127.0.0.1:%hu failed: %s\n",
		    port, strerror(bind_errno));
		close(sock);
		return false;
	}
	close(sock);
#else
	(void) port;
#endif
	return true;
}

static bool
test_env_allows_network_binds(void)
{
#ifndef NANO_PLATFORM_WINDOWS
	const char *configured_port = getenv("NANOMQ_TEST_PORT");
	uint16_t    configured_port_value = 0;
	int         sock = -1;
	struct sockaddr_in addr;
	struct sockaddr_in bound_addr;
	socklen_t          bound_addr_len;
	char               test_port_text[16];
	char              *end = NULL;
	long               parsed_port;

	if (test_env_skip_network_bind_check()) {
		fprintf(stderr,
		    "test_env_allows_network_binds: bypassed by NANOMQ_SKIP_NETWORK_TEST_ENV_CHECK=1\n");
		return true;
	}

	if (configured_port != NULL && configured_port[0] != '\0') {
		parsed_port = strtol(configured_port, &end, 10);
		if (end == configured_port || *end != '\0' || parsed_port <= 0 ||
		    parsed_port > UINT16_MAX) {
			fprintf(stderr,
			    "test_env_allows_network_binds: invalid NANOMQ_TEST_PORT=%s\n",
			    configured_port);
			return false;
		}
		configured_port_value = (uint16_t) parsed_port;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "test_env_allows_network_binds: socket() failed: %s\n",
		    strerror(errno));
		return false;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port        = htons(configured_port_value);
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
		int bind_errno = errno;
		uint16_t failed_port = configured_port_value;
		if (failed_port != 0) {
			test_env_report_bind_owner(failed_port);
		}
		fprintf(stderr,
		    "test_env_allows_network_binds: bind to 127.0.0.1:%hu failed: %s\n",
		    failed_port, strerror(bind_errno));
		close(sock);
		return false;
	}

	if (configured_port_value == 0) {
		bound_addr_len = sizeof(bound_addr);
		if (getsockname(sock, (struct sockaddr *) &bound_addr,
		        &bound_addr_len) != 0 ||
		    bound_addr.sin_port == 0) {
			fprintf(stderr,
			    "test_env_allows_network_binds: getsockname() failed: %s\n",
			    strerror(errno));
			close(sock);
			return false;
		}
		configured_port_value = ntohs(bound_addr.sin_port);
		snprintf(test_port_text, sizeof(test_port_text), "%hu",
		    configured_port_value);
		if (setenv("NANOMQ_TEST_PORT", test_port_text, 1) != 0) {
			fprintf(stderr,
			    "test_env_allows_network_binds: setenv() failed: %s\n",
			    strerror(errno));
			close(sock);
			return false;
		}
	}
	close(sock);
	test_env_register_cleanup();
	return true;
#else
	return true;
#endif
}

static bool
test_env_has_executable(const char *name)
{
#ifndef NANO_PLATFORM_WINDOWS
	char *path = getenv("PATH");
	char *path_copy;
	char *saveptr = NULL;
	char *dir;
	char  fullpath[PATH_MAX];

	if (name == NULL || path == NULL) {
		return false;
	}
	if (strcmp(name, "") == 0) {
		return false;
	}

	path_copy = nng_strdup(path);
	if (path_copy == NULL) {
		return false;
	}

	dir = strtok_r(path_copy, ":", &saveptr);
	while (dir != NULL) {
		if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, name) > 0 &&
		    access(fullpath, X_OK) == 0) {
			nng_strfree(path_copy);
			return true;
		}
		dir = strtok_r(NULL, ":", &saveptr);
	}
	nng_strfree(path_copy);
	return false;
#else
	return true;
#endif
}

static bool
test_env_connects_to_host(const char *host, const char *port)
{
#ifndef NANO_PLATFORM_WINDOWS
	int                  rv;
	int                  sock = -1;
	struct addrinfo      hints;
	struct addrinfo *    res = NULL;
	struct addrinfo *    cur;
	bool                 can_connect = false;

	if (host == NULL || port == NULL) {
		return false;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	rv = getaddrinfo(host, port, &hints, &res);
	if (rv != 0) {
		return false;
	}

	for (cur = res; cur != NULL; cur = cur->ai_next) {
		int           flags;
		int           connect_error = 0;
		socklen_t     connect_error_size = sizeof(connect_error);
		struct pollfd pollfd;

		sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
		if (sock < 0) {
			continue;
		}

		flags = fcntl(sock, F_GETFL, 0);
		if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) != 0) {
			close(sock);
			continue;
		}
		rv = connect(sock, cur->ai_addr, cur->ai_addrlen);
		if (rv != 0 && errno == EINPROGRESS) {
			pollfd.fd      = sock;
			pollfd.events  = POLLOUT;
			pollfd.revents = 0;
			rv = poll(&pollfd, 1, 1000);
			if (rv > 0 && (pollfd.revents & POLLOUT) != 0 &&
			    getsockopt(sock, SOL_SOCKET, SO_ERROR, &connect_error,
			        &connect_error_size) == 0 && connect_error == 0) {
				rv = 0;
			} else {
				rv = -1;
			}
		}
		if (rv == 0) {
			can_connect = true;
			close(sock);
			break;
		}
		close(sock);
	}
	freeaddrinfo(res);
	return can_connect;
#else
	return true;
#endif
}

static bool
test_env_supports_tls(void)
{
#ifdef NNG_SUPP_TLS
	return true;
#else
	return false;
#endif
}

static uint16_t
test_env_test_port(void)
{
	const char *env_port = getenv("NANOMQ_TEST_PORT");
	if (env_port != NULL && env_port[0] != '\0') {
		char    *end = NULL;
		long    parsed = strtol(env_port, &end, 10);
		if (end != NULL && end != env_port && *end == '\0' &&
		    parsed > 0 && parsed <= UINT16_MAX) {
			return (uint16_t) parsed;
		}
	}
	return 1881;
}

static const char *
test_env_test_port_text(void)
{
	static char port_text[16];

	snprintf(port_text, sizeof(port_text), "%hu", test_env_test_port());
	return port_text;
}

static bool
test_env_wait_for_tcp_listener(uint16_t port, int timeout_ms)
{
#ifndef NANO_PLATFORM_WINDOWS
	nng_time deadline = nng_clock() + (nng_time) timeout_ms;

	while (nng_clock() < deadline) {
		int                fd;
		struct sockaddr_in addr;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd >= 0) {
			memset(&addr, 0, sizeof(addr));
			addr.sin_family      = AF_INET;
			addr.sin_port        = htons(port);
			addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
				close(fd);
				return true;
			}
			close(fd);
		}
		nng_msleep(25);
	}
#else
	(void) port;
	(void) timeout_ms;
	return true;
#endif
	fprintf(stderr, "[FAIL] TCP listener 127.0.0.1:%hu was not ready\n", port);
	return false;
}

static bool
test_env_supports_tls_runtime(void)
{
#ifdef NNG_SUPP_TLS
	nng_tls_config *cfg = NULL;

	if (nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT) != 0) {
		return false;
	}
	if (cfg == NULL) {
		return false;
	}
	nng_tls_config_free(cfg);
	return true;
#else
	return false;
#endif
}

static bool
test_env_has_file(const char *path)
{
	return (path != NULL) ? access(path, R_OK) == 0 : false;
}

typedef nng_time (*test_env_wait_now_fn)(void *arg);
typedef void (*test_env_wait_sleep_fn)(void *arg, unsigned sleep_ms);

typedef struct test_env_wait_clock {
	test_env_wait_now_fn   now;
	test_env_wait_sleep_fn sleep;
	void                  *arg;
} test_env_wait_clock;

typedef enum test_env_read_status {
	TEST_ENV_READ_TIMEOUT,
	TEST_ENV_READ_EOF,
	TEST_ENV_READ_OUTPUT,
	TEST_ENV_READ_FULL,
	TEST_ENV_READ_ERROR,
} test_env_read_status;

static nng_time
test_env_wait_now_real(void *arg)
{
	(void) arg;
	return nng_clock();
}

static void
test_env_wait_sleep_real(void *arg, unsigned sleep_ms)
{
	(void) arg;
	nng_msleep(sleep_ms);
}

static const test_env_wait_clock test_env_real_wait_clock = {
	.now = test_env_wait_now_real,
	.sleep = test_env_wait_sleep_real,
	.arg = NULL,
};

static test_env_read_status
test_env_read_fd_until(
    int outfd, char *buf, size_t buf_size, int timeout_ms, int poll_ms,
    bool stop_after_read, const test_env_wait_clock *clock, size_t *read_size)
{
	int       flags;
	int       original_flags;
	size_t    used = 0;
	nng_time  deadline;
	test_env_read_status status = TEST_ENV_READ_ERROR;

	if (read_size != NULL) {
		*read_size = 0;
	}
	if (buf == NULL || buf_size < 2 || outfd < 0 || clock == NULL ||
	    clock->now == NULL || clock->sleep == NULL) {
		return TEST_ENV_READ_ERROR;
	}
	flags = fcntl(outfd, F_GETFL, 0);
	if (flags == -1) {
		return TEST_ENV_READ_ERROR;
	}
	original_flags = flags;
	if ((flags & O_NONBLOCK) == 0 &&
	    fcntl(outfd, F_SETFL, flags | O_NONBLOCK) != 0) {
		return TEST_ENV_READ_ERROR;
	}
	if (poll_ms <= 0) {
		poll_ms = 25;
	}
	if (timeout_ms < 0) {
		timeout_ms = 0;
	}
	deadline = clock->now(clock->arg) + (nng_time) timeout_ms;

	for (;;) {
		ssize_t n;

		errno = 0;
		n = read(outfd, buf + used, buf_size - used - 1);
		if (n > 0) {
			used += (size_t) n;
			buf[used] = '\0';
			if (stop_after_read) {
				status = TEST_ENV_READ_OUTPUT;
				break;
			}
			if (used + 1 >= buf_size) {
				status = TEST_ENV_READ_FULL;
				break;
			}
			continue;
		}
		if (n == 0) {
			status = TEST_ENV_READ_EOF;
			break;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			status = TEST_ENV_READ_ERROR;
			break;
		}

		nng_time now = clock->now(clock->arg);
		if (now >= deadline) {
			status = TEST_ENV_READ_TIMEOUT;
			break;
		}
		nng_time remaining = deadline - now;
		unsigned sleep_ms = (unsigned) poll_ms;
		if (remaining < (nng_time) sleep_ms) {
			sleep_ms = (unsigned) remaining;
		}
		if (sleep_ms == 0) {
			status = TEST_ENV_READ_TIMEOUT;
			break;
		}
		clock->sleep(clock->arg, sleep_ms);
	}

	if ((original_flags & O_NONBLOCK) == 0) {
		(void) fcntl(outfd, F_SETFL, original_flags);
	}
	if (read_size != NULL) {
		*read_size = used;
	}
	return status;
}

static bool
test_env_wait_for_output_with_clock(
    int outfd, char *buf, size_t buf_size, int timeout_ms, int poll_ms,
    const test_env_wait_clock *clock)
{
	test_env_read_status status;
	size_t               read_size = 0;

	if (buf_size < 2 || buf == NULL || outfd < 0) {
		fprintf(stderr,
		    "[FAIL] test_env_wait_for_output: invalid file descriptor %d\n",
		    outfd);
		return false;
	}
	status = test_env_read_fd_until(outfd, buf, buf_size, timeout_ms, poll_ms,
	    true, clock, &read_size);
	if (status == TEST_ENV_READ_TIMEOUT) {
		fprintf(stderr,
		    "[FAIL] test_env_wait_for_output: no output from process "
		    "within %dms\n",
		    timeout_ms);
	}
	return status == TEST_ENV_READ_OUTPUT && read_size > 0;
}

static bool
test_env_wait_for_output(
    int outfd, char *buf, size_t buf_size, int timeout_ms, int poll_ms)
{
	return test_env_wait_for_output_with_clock(outfd, buf, buf_size, timeout_ms,
	    poll_ms, &test_env_real_wait_clock);
}

static bool
test_env_read_stream_timeout(
    FILE *stream, char *buf, size_t buf_size, int timeout_ms, int poll_ms)
{
	if (stream == NULL) {
		return false;
	}
	test_env_read_status status = test_env_read_fd_until(fileno(stream), buf,
	    buf_size, timeout_ms, poll_ms, false, &test_env_real_wait_clock, NULL);
	return status == TEST_ENV_READ_EOF || status == TEST_ENV_READ_FULL;
}

static bool
test_env_wait_for_no_output_with_clock(
    int outfd, int timeout_ms, int poll_ms, const test_env_wait_clock *clock)
{
	char                 buf[2] = { 0 };
	test_env_read_status status = test_env_read_fd_until(outfd, buf, sizeof(buf),
	    timeout_ms, poll_ms, true, clock, NULL);
	return status == TEST_ENV_READ_TIMEOUT || status == TEST_ENV_READ_EOF;
}

static bool
test_env_wait_for_no_output(int outfd, int timeout_ms, int poll_ms)
{
	return test_env_wait_for_no_output_with_clock(outfd, timeout_ms, poll_ms,
	    &test_env_real_wait_clock);
}

static bool
wait_for_webhook_message_count(int expected, int timeout_ms, int poll_ms)
{
	int waited_ms = 0;

	if (poll_ms <= 0) {
		poll_ms = 25;
	}

	while ((webhook_msg_cnt < expected) && (waited_ms < timeout_ms)) {
		nng_msleep(poll_ms);
		waited_ms += poll_ms;
	}

	// Webhook delivery can lag the test on a loaded runner; give the
	// remaining events one more grace window before failing.
	if (webhook_msg_cnt < expected && waited_ms >= timeout_ms) {
		waited_ms = 0;
		while ((webhook_msg_cnt < expected) && (waited_ms < timeout_ms)) {
			nng_msleep(poll_ms);
			waited_ms += poll_ms;
		}
	}

	if (webhook_msg_cnt < expected) {
		fprintf(stderr,
            "[FAIL] webhook_msg_cnt=%d, expected=%d after %dms\n",
            webhook_msg_cnt, expected, waited_ms);
		return false;
	}

	return true;
}


// This server acts as a proxy.  We take HTTP POST requests, convert them to
// REQ messages, and when the reply is received, send the reply back to
// the original HTTP client.
//
// The state flow looks like:
//
// 1. Receive HTTP request & headers
// 2. Receive HTTP request (POST) data
// 3. Send POST payload as REQ body
// 4. Receive REP reply (including payload)
// 5. Return REP message body to the HTTP server (which forwards to client)
// 6. Restart at step 1.
//
// The above flow is pretty linear, and so we use contexts (nng_ctx) to
// obtain parallelism.
typedef enum {
	ALL_FEATURE_CONF,
	BRIDGE_CONF,
	BRIDGE_TLS_CONF,
	BRIDGE_AWS_CONF,
	BRIDGE_MUTI_CONF,
	AUTH_ANON_CONF,
} conf_type;

#ifndef NNG_SUPP_TLS
static void
disable_tls_for_tests(conf *nmq_conf)
{
	conf_tls_list *tls_list = &nmq_conf->tls_list;

	if (nmq_conf->tls.enable || nmq_conf->tls.url != NULL
            || nmq_conf->tls.cafile != NULL || nmq_conf->tls.certfile != NULL
            || nmq_conf->tls.keyfile != NULL || nmq_conf->tls.ca != NULL
            || nmq_conf->tls.cert != NULL || nmq_conf->tls.key != NULL
            || nmq_conf->tls.key_password != NULL || nmq_conf->tls.sni != NULL
            || nmq_conf->websocket.tls_url != NULL
            || nmq_conf->websocket.tls_enable || tls_list->count > 0) {

		nmq_conf->tls.enable         = false;
		FREE_NONULL(nmq_conf->tls.url);
		FREE_NONULL(nmq_conf->tls.cafile);
		FREE_NONULL(nmq_conf->tls.certfile);
		FREE_NONULL(nmq_conf->tls.keyfile);
		FREE_NONULL(nmq_conf->tls.ca);
		FREE_NONULL(nmq_conf->tls.cert);
		FREE_NONULL(nmq_conf->tls.key);
		FREE_NONULL(nmq_conf->tls.key_password);
		FREE_NONULL(nmq_conf->tls.sni);
		nmq_conf->websocket.tls_enable = false;
		FREE_NONULL(nmq_conf->websocket.tls_url);

		for (size_t i = 0; i < tls_list->count; ++i) {
			conf_tls *node = tls_list->nodes[i];

			if (node == NULL) {
				continue;
			}
			FREE_NONULL(node->url);
			FREE_NONULL(node->cafile);
			FREE_NONULL(node->certfile);
			FREE_NONULL(node->keyfile);
			FREE_NONULL(node->ca);
			FREE_NONULL(node->cert);
			FREE_NONULL(node->key);
			FREE_NONULL(node->key_password);
			FREE_NONULL(node->sni);
			free(node);
		}
		FREE_NONULL(tls_list->nodes);
		tls_list->count = 0;
	}
}
#endif

typedef enum {
	SEND_REQ, // Sending REQ request
	RECV_REP, // Receiving REQ reply
} job_state;

typedef struct rest_job {
	nng_aio *        http_aio; // aio from HTTP we must reply to
	nng_http_res *   http_res; // HTTP response object
	job_state        state;    // 0 = sending, 1 = receiving
	nng_msg *        msg;      // request message
	nng_aio *        aio;      // request flow
	nng_ctx          ctx;      // context on the request socket
	struct rest_job *next;     // next on the freelist
} rest_job;

nng_socket req_sock;

// We maintain a queue of free jobs.  This way we don't have to
// deallocate them from the callback; we just reuse them.
nng_mtx * job_lock;
rest_job *job_freelist;

static void rest_job_cb(void *arg);

static void
rest_recycle_job(rest_job *job)
{
	if (job->http_res != NULL) {
		nng_http_res_free(job->http_res);
		job->http_res = NULL;
	}
	if (job->msg != NULL) {
		nng_msg_free(job->msg);
		job->msg = NULL;
	}
	if (nng_ctx_id(job->ctx) != 0) {
		nng_ctx_close(job->ctx);
	}

	nng_mtx_lock(job_lock);
	job->next    = job_freelist;
	job_freelist = job;
	nng_mtx_unlock(job_lock);
}

static rest_job *
rest_get_job(void)
{
	rest_job *job;

	nng_mtx_lock(job_lock);
	if ((job = job_freelist) != NULL) {
		job_freelist = job->next;
		nng_mtx_unlock(job_lock);
		job->next = NULL;
		return (job);
	}
	nng_mtx_unlock(job_lock);
	if ((job = calloc(1, sizeof(*job))) == NULL) {
		return (NULL);
	}
	if (nng_aio_alloc(&job->aio, rest_job_cb, job) != 0) {
		free(job);
		return (NULL);
	}
	return (job);
}

static void
rest_http_fatal(rest_job *job, const char *fmt, int rv)
{
	char          buf[128];
	nng_aio *     aio = job->http_aio;
	nng_http_res *res = job->http_res;

	job->http_res = NULL;
	job->http_aio = NULL;
	snprintf(buf, sizeof(buf), fmt, nng_strerror(rv));
	nng_http_res_set_status(res, NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR);
	nng_http_res_set_reason(res, buf);
	nng_aio_set_output(aio, 0, res);
	nng_aio_finish(aio, 0);
	rest_recycle_job(job);
}

static void
rest_job_cb(void *arg)
{
	rest_job *job = arg;
	nng_aio * aio = job->aio;
	int       rv;

	switch (job->state) {
	case SEND_REQ:
		if ((rv = nng_aio_result(aio)) != 0) {
			rest_http_fatal(job, "send REQ failed: %s", rv);
			return;
		}
		job->msg = NULL;
		// Message was sent, so now wait for the reply.
		nng_aio_set_msg(aio, NULL);
		job->state = RECV_REP;
		nng_ctx_recv(job->ctx, aio);
		break;
	case RECV_REP:
		if ((rv = nng_aio_result(aio)) != 0) {
			rest_http_fatal(job, "recv reply failed: %s", rv);
			return;
		}
		job->msg = nng_aio_get_msg(aio);
		if (nng_msg_len(job->msg) > 0) {
			// We got a reply, so give it back to the server.
			rv = nng_http_res_copy_data(job->http_res,
			    nng_msg_body(job->msg), nng_msg_len(job->msg));
			if (strcmp(nng_msg_body(job->msg), "ok") == 0) {
				nng_http_res_set_status(
				    job->http_res, NNG_HTTP_STATUS_OK);
			} else {
				nng_http_res_set_status(job->http_res,
				    NNG_HTTP_STATUS_UNAUTHORIZED);
			}
			if (rv != 0) {
				rest_http_fatal(
				    job, "nng_http_res_copy_data: %s", rv);
				return;
			}
		} else {
			nng_http_res_set_status(
			    job->http_res, NNG_HTTP_STATUS_BAD_REQUEST);
		}
		// if (nng_clock() % 2 == 0) {
		// 	nng_http_res_set_status(job->http_res, 404);
		// }
		// Set the output - the HTTP server will send it back to the
		// user agent with a 200 response.
		nng_aio_set_output(job->http_aio, 0, job->http_res);
		nng_aio_finish(job->http_aio, 0);
		job->http_aio = NULL;
		job->http_res = NULL;
		// We are done with the job.
		rest_recycle_job(job);
		return;
	default:
		nng_fatal("bad case", NNG_ESTATE);
		break;
	}
}

// Our rest server just takes the message body, creates a request ID
// for it, and sends it on.  This runs in raw mode, so
static void
rest_handle(nng_aio *aio)
{
	struct rest_job *job;
	nng_http_req *   req  = nng_aio_get_input(aio, 0);
	nng_http_conn *  conn = nng_aio_get_input(aio, 2);
	const char *     clen;
	size_t           sz = 0;
	nng_iov          iov;
	int              rv;
	void *           data;

	// printf("%s\n", __FUNCTION__);
	if ((job = rest_get_job()) == NULL) {
		nng_aio_finish(aio, NNG_ENOMEM);
		return;
	}
	if (((rv = nng_http_res_alloc(&job->http_res)) != 0) ||
	    ((rv = nng_ctx_open(&job->ctx, req_sock)) != 0)) {
		rest_recycle_job(job);
		nng_aio_finish(aio, rv);
		return;
	}
	const char *uri = nng_http_req_get_uri(req);
	const char *method = nng_http_req_get_method(req);
	const char *token = nng_http_req_get_header(req, "TOKEN");
	const char *content_type =
	    nng_http_req_get_header(req, "content-type");
	// printf("\r\n");
	// printf("uri: [%s]\n", uri);
	// printf("method: [%s]\n", method);
	// printf("header: token: [%s]\n", token);
	// printf("header: content-type: [%s]\n", content_type);

	if (strcasecmp(method, "get") == 0) {
		data = strchr(uri, '?');
		if (data) {

			data++;
			sz = strlen(data) + 1;
		}
	} else if (strcasecmp(method, "post") == 0) {
		nng_http_req_get_data(req, &data, &sz);
	} else {
		rest_http_fatal(job, "method not supported:%s", NNG_HTTP_STATUS_METHOD_NOT_ALLOWED);
	}

	job->http_aio = aio;

	if ((rv = nng_msg_alloc(&job->msg, sz)) != 0) {
		rest_http_fatal(job, "nng_msg_alloc: %s", rv);
		return;
	} else if (sz == 0) {
		rest_http_fatal(job, "%s", NNG_HTTP_STATUS_NO_CONTENT);
	}

	memcpy(nng_msg_body(job->msg), data, sz);
	nng_aio_set_msg(job->aio, job->msg);
	job->state = SEND_REQ;
	nng_ctx_send(job->ctx, job->aio);
}

void
test_rest_start(uint16_t port)
{
	nng_http_server * server;
	nng_http_handler *handler;
	char              rest_addr[128];
	nng_url *         url;
	int               rv;

	if ((rv = nng_mtx_alloc(&job_lock)) != 0) {
		nng_fatal("nng_mtx_alloc", rv);
	}
	job_freelist = NULL;

	// Set up some strings, etc.  We use the port number
	// from the argument list.
	snprintf(rest_addr, sizeof(rest_addr), REST_TEST_URL, port);
	if ((rv = nng_url_parse(&url, rest_addr)) != 0) {
		nng_fatal("nng_url_parse", rv);
	}

	// Create the REQ socket, and put it in raw mode, connected to
	// the remote REP server (our inproc server in this case).
	if ((rv = nng_req0_open(&req_sock)) != 0) {
		nng_fatal("nng_req0_open", rv);
	}
	if ((rv = nng_dial(req_sock, INPROC_TEST_URL, NULL, NNG_FLAG_NONBLOCK)) !=
	    0) {
		nng_fatal("nng_dial(" INPROC_TEST_URL ")", rv);
	}

	// Get a suitable HTTP server instance.  This creates one
	// if it doesn't already exist.
	if ((rv = nng_http_server_hold(&server, url)) != 0) {
		nng_fatal("nng_http_server_hold", rv);
	}

	// Allocate the handler - we use a dynamic handler for REST
	// using the function "rest_handle" declared above.
	rv = nng_http_handler_alloc(&handler, url->u_path, rest_handle);
	if (rv != 0) {
		nng_fatal("nng_http_handler_alloc", rv);
	}

	if ((rv = nng_http_handler_set_tree(handler)) != 0) {
		nng_fatal("nng_http_handler_set_tree", rv);
	}

	if ((rv = nng_http_handler_set_method(handler, NULL)) != 0) {
		nng_fatal("nng_http_handler_set_method", rv);
	}
	// We want to collect the body, and we (arbitrarily) limit this to
	// 128KB.  The default limit is 1MB.  You can explicitly collect
	// the data yourself with another HTTP read transaction by disabling
	// this, but that's a lot of work, especially if you want to handle
	// chunked transfers.
	if ((rv = nng_http_handler_collect_body(handler, true, 1024 * 128)) !=
	    0) {
		nng_fatal("nng_http_handler_collect_body", rv);
	}
	if ((rv = nng_http_server_add_handler(server, handler)) != 0) {
		nng_fatal("nng_http_handler_add_handler", rv);
	}
	if ((rv = nng_http_server_start(server)) != 0) {
		nng_fatal("nng_http_server_start", rv);
	}

	nng_url_free(url);
}

//
// inproc_server - this just is a simple REP server that listens for
// messages, and performs ROT13 on them before sending them.  This
// doesn't have to be in the same process -- it is hear for demonstration
// simplicity only.  (Most likely this would be somewhere else.)  Note
// especially that this uses inproc, so nothing can get to it directly
// from outside the process.
//
void
test_inproc_server(void *arg)
{
	nng_socket s;
	int        rv;
	nng_msg *  msg;

	if (((rv = nng_rep0_open(&s)) != 0) ||
	    ((rv = nng_listen(s, INPROC_TEST_URL, NULL, 0)) != 0)) {
		nng_fatal("unable to set up inproc", rv);
	}
	test_inproc_socket = s;
	test_inproc_socket_active = true;
	// This is simple enough that we don't need concurrency.  Plus it
	// makes for an easier demo.
	for (;;) {
		if ((rv = nng_recvmsg(s, &msg, 0)) != 0) {
			break;
		}
		// char *body = nng_msg_body(msg);
		// printf("\tReceived: %s\n", (char *) body);
		nng_msg_free(msg);
		webhook_msg_cnt++;

		char *res = "OK";
		if ((rv = nng_send(s, res, strlen(res), 0)) != 0) {
			nng_fatal("inproc sendmsg", rv);
		}
	}
}

static void
test_inproc_stop(void)
{
	if (test_inproc_socket_active) {
		test_inproc_socket_active = false;
		nng_close(test_inproc_socket);
	}
}

conf*
get_dflt_conf()
{
	conf               *nanomq_conf;
	char               test_env_test_addr[128];
	if ((nanomq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		fprintf(stderr,
		    "Cannot allocate storge for configuration, quit\n");
		exit(EXIT_FAILURE);
	}
	conf_init(nanomq_conf);
	nanomq_conf->url                    = NULL;
	snprintf(
	    test_env_test_addr, sizeof(test_env_test_addr), "nmq-tcp://127.0.0.1:%s",
	    test_env_test_port_text());
	nanomq_conf->url = nng_strdup(test_env_test_addr);
	nanomq_conf->conf_file              = NULL;
	nanomq_conf->daemon                 = false;
	nanomq_conf->num_taskq_thread       = 1;
	nanomq_conf->max_taskq_thread       = 1;
	nanomq_conf->parallel               = 10;
	nanomq_conf->property_size          = 32;
	nanomq_conf->max_packet_size        = 1024;
	nanomq_conf->client_max_packet_size = 1024;
	nanomq_conf->msq_len                = 32;
	nanomq_conf->qos_duration           = 2;

	nanomq_conf->sqlite.enable        = false;
	nanomq_conf->tls.enable           = false;
	nanomq_conf->websocket.enable     = false;
	nanomq_conf->websocket.tls_enable = false;
	nanomq_conf->http_server.enable   = false;
	nanomq_conf->web_hook.enable      = false;
	return nanomq_conf;
}

conf*
get_webhook_conf()
{
	conf *nanomq_conf = get_dflt_conf();
	conf_http_header   *header;
	conf_web_hook_rule *webhook_rule;

	// Mirror the ownership and cvector layout used by the configuration parser,
	// because the MQTT socket releases this configuration during shutdown.
	nanomq_conf->web_hook.enable         = true;
	nanomq_conf->web_hook.url            = nng_strdup("http://127.0.0.1:8888/hook");
	nanomq_conf->web_hook.encode_payload = plain;
	nanomq_conf->web_hook.pool_size      = 32;

	header        = calloc(1, sizeof(conf_http_header));
	header->key   = nng_strdup("content-type");
	header->value = nng_strdup("application/json");
	cvector_push_back(nanomq_conf->web_hook.headers, header);
	nanomq_conf->web_hook.header_count =
	    cvector_size(nanomq_conf->web_hook.headers);

	webhook_rule           = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event    = MESSAGE_PUBLISH;
	webhook_rule->rule_num = 1;
	webhook_rule->action   = nng_strdup("on_message_publish");
	cvector_push_back(nanomq_conf->web_hook.rules, webhook_rule);
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNECT;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = nng_strdup("on_client_connect");
	cvector_push_back(nanomq_conf->web_hook.rules, webhook_rule);
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNACK;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = nng_strdup("on_client_connack");
	cvector_push_back(nanomq_conf->web_hook.rules, webhook_rule);
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_CONNECTED;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = nng_strdup("on_client_connected");
	cvector_push_back(nanomq_conf->web_hook.rules, webhook_rule);
	webhook_rule                   = calloc(1, sizeof(conf_web_hook_rule));
	webhook_rule->event            = CLIENT_DISCONNECTED;
	webhook_rule->rule_num         = 1;
	webhook_rule->action           = nng_strdup("on_client_disconnected");
	cvector_push_back(nanomq_conf->web_hook.rules, webhook_rule);
	nanomq_conf->web_hook.rule_count = cvector_size(nanomq_conf->web_hook.rules);

	return nanomq_conf;
}

conf *
get_test_conf(conf_type type)
{
	// get conf from file
	conf *nmq_conf  = NULL;
	char *conf_path = NULL;
	char *resolved_conf_path = NULL;

	if ((nmq_conf = nng_zalloc(sizeof(conf))) == NULL) {
		return nmq_conf;
	}
	switch (type) {
	case ALL_FEATURE_CONF:
		conf_path = ALL_FEATURE_CONF_PATH;
		break;
	case BRIDGE_CONF:
		conf_path = BRIDGE_CONF_PATH;
		break;
	case BRIDGE_TLS_CONF:
		conf_path = BRIDGE_TLS_CONF_PATH;
		break;
	case BRIDGE_AWS_CONF:
		conf_path = BRIDGE_AWS_CONF_PATH;
		break;
	case BRIDGE_MUTI_CONF:
		conf_path = BRIDGE_MUTI_CONF_PATH;
		break;
	case AUTH_ANON_CONF:
		conf_path = AUTH_ANON_CONF_PATH;
		break;
	default:
		break;
	}
	if (conf_path != NULL && test_env_test_port_text() != NULL) {
		resolved_conf_path = test_env_rewrite_conf_port(conf_path, test_env_test_port_text());
		if (resolved_conf_path != NULL) {
			conf_path = resolved_conf_path;
			test_env_track_conf_file(resolved_conf_path);
		}
	}
	conf_init(nmq_conf);
	nmq_conf->conf_file = conf_path;
	conf_parse_ver2(nmq_conf, false);

#ifndef NNG_SUPP_TLS
	disable_tls_for_tests(nmq_conf);
#endif

	return nmq_conf;
}

pid_t
popen_with_cmd(int *outfp, char *arg[], char *cmd)
{
	int   fd_pipe[2];
	pid_t pid;

	if (outfp == NULL || arg == NULL || cmd == NULL) {
		return -1;
	}
	*outfp = -1;
	if (pipe(fd_pipe) != 0) {
		return -1;
	}

	pid = fork();

	if (pid < 0) {
		close(fd_pipe[STDIN_FILENO]);
		close(fd_pipe[STDOUT_FILENO]);
		return pid;
	}
	else if (pid == 0) {
		(void) setpgid(0, 0);
		// child only need to write
		close(fd_pipe[STDIN_FILENO]);
		if (dup2(fd_pipe[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			exit(EXIT_FAILURE);
		}
		if (fd_pipe[STDOUT_FILENO] != STDOUT_FILENO) {
			close(fd_pipe[STDOUT_FILENO]);
		}
		if (strchr(cmd, '/') != NULL) {
			execv(cmd, arg);
			cmd = strrchr(cmd, '/');
			if (cmd != NULL && cmd[1] != '\0') {
				execvp(cmd + 1, arg);
			}
		} else {
			execvp(cmd, arg);
		}
		exit(EXIT_FAILURE);
	} else {
		// parent only need to read
		close(fd_pipe[STDOUT_FILENO]);
		*outfp = fd_pipe[STDIN_FILENO];
		test_env_track_proc(pid, -1, NULL);
	}

	return pid;
}

pid_t
popen_sub_with_cmd_nonblock(int *outfp, char *arg[], char *cmd)
{
	int   fd_pipe[2];
	pid_t pid;

	if (outfp == NULL || arg == NULL || cmd == NULL) {
		return -1;
	}
	*outfp = -1;
	if (pipe(fd_pipe) != 0) {
		return -1;
	}

	pid = fork();

	if (pid < 0) {
		close(fd_pipe[STDIN_FILENO]);
		close(fd_pipe[STDOUT_FILENO]);
		return pid;
	}
	else if (pid == 0) {
		(void) setpgid(0, 0);
		// child only need to write
		close(fd_pipe[STDIN_FILENO]);
		if (dup2(fd_pipe[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			exit(EXIT_FAILURE);
		}
		if (dup2(fd_pipe[STDOUT_FILENO], STDERR_FILENO) == -1) {
			exit(EXIT_FAILURE);
		}
		if (fd_pipe[STDOUT_FILENO] != STDOUT_FILENO &&
		    fd_pipe[STDOUT_FILENO] != STDERR_FILENO) {
			close(fd_pipe[STDOUT_FILENO]);
		}
		if (strchr(cmd, '/') != NULL) {
			execv(cmd, arg);
			cmd = strrchr(cmd, '/');
			if (cmd != NULL && cmd[1] != '\0') {
				execvp(cmd + 1, arg);
			}
		} else {
			execvp(cmd, arg);
		}
		exit(EXIT_FAILURE);
	} else {
		// parent only need to read
		close(fd_pipe[STDOUT_FILENO]);
		if (fcntl(fd_pipe[STDIN_FILENO], F_SETFL, O_NONBLOCK) == -1) {
			close(fd_pipe[STDIN_FILENO]);
			*outfp = -1;
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
			return -1;
		}
		*outfp = fd_pipe[STDIN_FILENO];
		test_env_track_proc(pid, -1, NULL);
	}

	return pid;
}
