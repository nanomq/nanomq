#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "include/broker.h"

pid_t
popen_sub(int *outfp)
{
	int   fd_pipe[2];
	pid_t pid;

	if (pipe(fd_pipe) != 0)
		return -1;

	pid = fork();

	if (pid < 0)
		return pid;
	else if (pid == 0) {
		// child only need to write
		close(fd_pipe[STDIN_FILENO]);
		dup2(fd_pipe[STDOUT_FILENO], STDOUT_FILENO);

		// TODO: use a more flexible way instead of hard coding.
		// char cmd_sub[] = "mosquitto_sub -h 127.0.0.1 -p 1883 -t "
		//                  "topic1 -t topic2 -U topic2 -q 2";

		// char *b[50];
		// int   i     = 0;
		// char *token = strtok(cmd_sub, " ");
		// while (token != NULL) {
		// 	b[i++] = token;
		// 	strcpy(b[i++], token); 
		// 	printf("%s\n", token);
		// 	token = strtok(NULL, " ");
		// }
		// execv("/bin/mosquitto_sub", b);

		char *arg[] = { "mosquitto_sub", "-t", "topic1", "-t",
			"topic2", "-U", "topic2", "-h", "127.0.0.1", "-p",
			"1883", "-q", "2", NULL };
		execv("/bin/mosquitto_sub", arg);
		exit(1);
	} else {
		// parent only need to read
		close(fd_pipe[STDOUT_FILENO]);
		*outfp = fd_pipe[STDIN_FILENO];
	}

	return pid;
}

int
main()
{
	int rv = 0;

	// char *cmd_sub = "mosquitto_sub -h 127.0.0.1 -p 1883 -t topic1 -t topic2 -U topic2 -q 2";
	char *cmd_pub = "mosquitto_pub -h 127.0.0.1 -p 1883 -t topic1 -m message -q 2";

	// char *cmd_sub = "mosquitto_sub -h 116.205.239.134 -p 1883 -t topic -q 1";
	// char *cmd_pub = "mosquitto_pub -h 116.205.239.134 -p 1883 -t topic -m massage -q 1";

	nng_thread *nmq;
	pid_t pid_sub;
	FILE *p_pub = NULL;

	int buf_size = 128;
	char buf[buf_size];
	int infp, outfp;

	// create nmq thread
	nng_thread_create(&nmq, broker_start, NULL);
	nng_msleep(50); // wait a while before sub

	// pipe to sub
	pid_sub = popen_sub(&outfp);
	nng_msleep(50); // pub should be slightly behind sub
	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	assert(read(outfp, buf, buf_size) != -1);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);
	close(outfp);

	assert(broker_dflt(0, NULL) == 0);
	nng_thread_destroy(nmq);

	return 0;
}