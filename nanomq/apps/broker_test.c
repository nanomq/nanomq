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
    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;

    pid = fork();

    if (pid < 0)
        return pid;
    else if (pid == 0)
    {
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);

	execl("/bin/mosquitto_sub", "mosquitto_sub", "-t", "topic", "-h", "127.0.0.1", "-p", "1883", "-q", "1", NULL);
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

int main()
{
	int rv = 0;

	// char *nmq_start =
	//     "nanomq start --url tls+nmq-tcp://0.0.0.0:8883 --http --cacert "
	//     "etc/certs/cacert.pem --cert etc/certs/cert.pem --key "
	//     "etc/certs/key.pem --qos_duration 1 --log_level debug  "
	//     "--log_stdout false";
	// int    argc      = 4;
	// char **nmq_start = { "nanomq", "start", "--url",
	// 	"tls+nmq-tcp://0.0.0.0:8883" };

	char *cli_sub = "mosquitto_sub -h 127.0.0.1 -p 1883 -t topic -q 1";
	char *cli_pub = "mosquitto_pub -h 127.0.0.1 -p 1883 -t topic -m message -q 1";


	// char *cli_sub = "mosquitto_sub -h 116.205.239.134 -p 1883 -t topic -q 1";
	// char *cli_pub = "mosquitto_pub -h 116.205.239.134 -p 1883 -t topic -m massage -q 1";

	int buf_size = 32;
	char buf[buf_size];

	int infp, outfp;

	pthread_t tidp;
	pid_t subpid, pubpid;
	pthread_create(&tidp, NULL, broker_start, NULL);
	nng_msleep(20);

	FILE *p_file, *p_subfile, *p_pubfile, *p_unsubfile = NULL;
	printf("aaaaaaaa\n");
	// p_file      = popen(nmq_start, "r");
	subpid = popen2(cli_sub, &infp, &outfp);
	// p_subfile   = popen(cli_sub, "r");
	printf("aaaaaaaa\n");
	p_pubfile   = popen(cli_pub, "r");
	// system(cli_sub);
	// printf("aaaaaaaa\n");
	// system(cli_pub);

	printf("aaaaaaaa\n");
	nng_msleep(1000);
	// pthread_kill(tidp, 0);
	// pthread_cancel(tidp);

	// if(fgets(buf, buf_size, p_subfile) != NULL) {
	// 	assert(strncmp(buf, "message", 7) == 0);
	// 	fprintf(stdout, "----------------------------%s", buf);
	// }

	// write(infp, "hello\n", 4);
	// close(infp);
	// *buf = '\0';
	read(outfp, buf, buf_size);

	printf("\t%d\n", subpid);

	// assert(strncmp(buf, "message", 7) == 0);
	fprintf(stdout, "----------------------------%s\n", buf);

	// pthread_join(tidp, NULL);
	printf("aaaaaaaa\n");
	nng_msleep(200);

	kill(subpid, SIGKILL);
	// kill(subpid, SIGKILL);

	pclose(p_pubfile);
	printf("aaaaaaaa\n");
	// pclose(p_subfile);
	// printf("aaaaaaaa\n");
	// pthread_exit(&rv);

	// pthreaddes
	
	// pclose(p_file);

	// rv = broker_start(0, NULL);
	// broker_stop(0, NULL);
	// assert(rv == 0);

	// broker_stop(0, NULL);

	// // broker_reload() is not supported since internal ipc is disabled
	// // default.

	// //  rv = broker_reload(0, NULL);
	// //  assert(rv == 0);

	// rv = broker_dflt(0, NULL);
	// assert(rv == 0);

	return 0;
}