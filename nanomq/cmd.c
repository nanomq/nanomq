
#include "include/nanomq.h"
#include "include/cmd.h"
#include "include/file.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

char *cmd_output_buff = NULL;
int cmd_output_len = 0;

int cmd_run_status(const char *cmd)
{
	int error, pipes[2], stderr_fd = -1, ret = 0;
	unsigned int sock_opts;

	debug_msg("cmd = %s", cmd);
	/*file_append_string("/tmp/cmd.log", (char *)cmd);
	file_append_string("/tmp/cmd.log", "\n");*/

	if (!cmd_output_buff)
		cmd_output_buff = malloc(CMD_BUFF_LEN);

	if (!cmd_output_buff)
		return -1;

	error = pipe(pipes);
	if (error < 0) {
		debug_msg("Warning - could not create a pipe to '%s': %s",
			 cmd, strerror(errno));
		return -1;
	}

	/* save stderr */
	stderr_fd = dup(STDERR_FILENO);

	/* connect the commands output with the pipe for later logging */
	dup2(pipes[1], STDERR_FILENO);
	close(pipes[1]);

	error = system(cmd);

	/* copy stderr back */
	dup2(stderr_fd, STDERR_FILENO);
	close(stderr_fd);

	memset(cmd_output_buff, 0, CMD_BUFF_LEN);
	sock_opts = fcntl(pipes[0], F_GETFL, 0);
        fcntl(pipes[0], F_SETFL, sock_opts | O_NONBLOCK);
	cmd_output_len = read(pipes[0], cmd_output_buff, CMD_BUFF_LEN);

	if (error < 0)
		ret = error;
	else if (WIFEXITED(error) && WEXITSTATUS(error) != 0)
		ret = WEXITSTATUS(error);

	close(pipes[0]);
	return ret;
}

int cmd_run(const char *cmd)
{
	int error, ret = 0;

	error = cmd_run_status(cmd);

	if (error != 0) {
		debug_msg("Warning - command '%s' returned an error", cmd);

		if (cmd_output_len > 0)
			//debug_msg("          %s", cmd_output_buff);
			debug_msg("warning");

		ret = -1;
	}

	return ret;
}

int cmd_run_fd(int fd, const char *cmd)
{
	int error, stderr_fd = -1, ret = 0;

	debug_msg("fd = %i, cmd = %s", fd, cmd);
	/*file_append_string("/tmp/cmd.log", (char *)cmd);
	file_append_string("/tmp/cmd.log", "\n");*/

	/* save stderr */
	stderr_fd = dup(STDERR_FILENO);

	/* connect the commands output with the pipe for later logging */
	dup2(fd, STDERR_FILENO);

	error = system(cmd);

	/* copy stderr back */
	dup2(stderr_fd, STDERR_FILENO);
	close(stderr_fd);

	if ((error < 0) || (WEXITSTATUS(error) != 0)) {
		debug_msg("Warning - command '%s' returned an error", cmd);
		ret = -1;
	}

	return ret;
}

int cmd_frun(const char *format, ...)
{
	va_list args;
	char *cmd;
	int ret;

	cmd = malloc(512);
	if (!cmd)
		return -1;

	va_start(args, format);
	vsprintf(cmd, format, args);
	va_end(args);

	ret = cmd_run(cmd);
	free(cmd);
	return ret;
}

int cmd_frun_fd(int fd, const char *format, ...)
{
	va_list args;
	char *cmd;
	int ret;

	cmd = malloc(512);
	if (!cmd)
		return -1;

	va_start(args, format);
	vsprintf(cmd, format, args);
	va_end(args);

	ret = cmd_run_fd(fd, cmd);
	free(cmd);
	return ret;
}

int cmd_pipe(const char *cmd)
{
	int fd[2], ret;
	pid_t pid;

	debug_msg("cmd_pipe: cmd = %s", cmd);
	ret = pipe(fd);

	if (ret < 0) {
		debug_msg("cmd_pipe: could not create pipe to '%s': %s", cmd, strerror(errno));
		goto err;
	}

	pid = fork();

	switch (pid) {
	case -1:
		goto err;
	case 0:
		close(fd[1]);
		if (fd[0] != STDIN_FILENO) {
			if (dup2(fd[0], STDIN_FILENO) != STDIN_FILENO)
				exit(EXIT_FAILURE);

			close(fd[0]);
		}
		signal(SIGINT, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
		execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
		exit(0);
	default:
		close(fd[0]);
		return fd[1];
	}

err:
	return -1;
}

int cmd_fpipe(const char *format, ...)
{
	va_list args;
	char *cmd;
	int ret;

	cmd = malloc(512);
	if (!cmd)
		return -1;

	va_start(args, format);
	vsprintf(cmd, format, args);
	va_end(args);

	ret = cmd_pipe(cmd);
	free(cmd);
	return ret;
}

pid_t cmd_create_read_pipe(int *fd, const char *cmd, ...)
{
	const char *cmd_run;
	char **args = NULL;
	int pipes[2];
	va_list ap;
	pid_t pid;
	char *str;
	int n;

	va_start(ap, cmd);

	if ((str = va_arg(ap, char *)) == NULL) {
		cmd_run = "/bin/sh";
		args = malloc(sizeof(char *) * 4);
		args[0] = "/bin/sh";
		args[1] = "-c";
		args[2] = (char *)cmd;
		args[3] = NULL;
	} else {
		cmd_run = cmd;
		args = malloc(sizeof(char *));
		args[0] = malloc(strlen(cmd) + 1);
		strcpy(args[0], cmd);
		n = 1;

		do {
			args = realloc(args, sizeof(char *) * (n + 1));
			args[n] = malloc(strlen(str) + 1);
			strcpy(args[n], str);
			n++;
		} while ((str = va_arg(ap, char *)) != NULL);

		args = realloc(args, sizeof(char *) * (n + 1));
		args[n] = NULL;
	}

	va_end(ap);

	if (pipe(pipes) < 0) {
		debug_msg("%s: count not create pipe to '%s' : %s",
			cmd, strerror(errno));
		goto err;
	}

	pid = fork();

	switch (pid) {
	case -1:
		goto err;
	case 0:
		close(pipes[0]);

		if (pipes[1] != STDOUT_FILENO) {
			if (dup2(pipes[1], STDOUT_FILENO) != STDOUT_FILENO)
				exit(EXIT_FAILURE);
			close(pipes[1]);
		}

		signal(SIGPIPE, SIG_IGN);
		execv(cmd_run, args);
		free(args);

		if (str)
			free(str);

		exit(0);
	default:
		close(pipes[1]);
		*fd = dup(pipes[0]);

		if(args)
			free(args);

		if(str)
			free(str);

		return pid;
	}

err:
	return -1;
}

void cmd_cleanup(void)
{
	if (!cmd_output_buff)
		return;

	free(cmd_output_buff);
	cmd_output_buff = NULL;
}
