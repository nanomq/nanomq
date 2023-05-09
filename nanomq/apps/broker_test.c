#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>

#include "include/broker.h"

#define READ 0
#define WRITE 1

pid_t
popen2(const char *command, int *infp, int *outfp)
{
	int   p_stdin[2], p_stdout[2];
	pid_t pid;

	if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
		return -1;

	pid = fork();

	if (pid < 0)
		return pid;
	else if (pid == 0) {
		close(p_stdin[WRITE]);
		dup2(p_stdin[READ], READ);
		close(p_stdout[READ]);
		dup2(p_stdout[WRITE], WRITE);

		execl("/bin/mosquitto_sub", "mosquitto_sub", "-t", "topic1", "-t",
	    "topic2", "-U", "topic2", "-h", "127.0.0.1", "-p", "1883", "-q",
	    "2", NULL);
		perror("execl");
		exit(1);
	}

	if (infp == NULL)
		close(p_stdin[WRITE]);
	else
		*infp = p_stdin[WRITE];

	if (outfp == NULL)
		close(p_stdout[READ]);
	else
		*outfp = p_stdout[READ];

	return pid;
}

int
main()
{
	int rv = 0;

	// broker_stop(0, NULL);

	char *cmd_sub = "mosquitto_sub -h 127.0.0.1 -p 1883 -t topic1 -t topic2 -U topic2 -q 2";
	char *cmd_pub = "mosquitto_pub -h 127.0.0.1 -p 1883 -t topic1 -m message -q 2";

	// char *cmd_sub = "mosquitto_sub -h 116.205.239.134 -p 1883 -t topic -q 1";
	// char *cmd_pub = "mosquitto_pub -h 116.205.239.134 -p 1883 -t topic -m massage -q 1";

	pthread_t nmq, re_nmq, stop_nmq;
	pid_t pid_sub, pid_unsub;
	FILE *p_pub = NULL;

	int buf_size = 128;
	char buf[buf_size];
	int infp, outfp;


	// pthread_create(&nmq, NULL, broker_stop, NULL);

	// create nmq thread
	pthread_create(&nmq, NULL, broker_start, NULL);
	nng_msleep(50); // wait a while before sub

	// pipe to sub
	pid_sub = popen2(cmd_sub, &infp, &outfp);
	nng_msleep(50); // pub should be slightly behind sub
	// pipe to pub
	p_pub   = popen(cmd_pub, "r");

	// check recv msg
	read(outfp, buf, buf_size);
	assert(strncmp(buf, "message", 7) == 0);

	kill(pid_sub, SIGKILL);
	pclose(p_pub);

	assert(broker_dflt(0, NULL) == 0);

	return 0;
}