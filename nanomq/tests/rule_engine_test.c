#include "tests_api.h"

int
main()
{
	int rv = 0;

	char *cmd_pub = "mosquitto_pub -h 127.0.0.1 -p 1881 -t abc -m rule_message -q 2";
	nng_thread *nmq;
	FILE *p_pub = NULL;
	conf       *nmq_conf = NULL;

	// create nmq thread
	nmq_conf = get_test_conf(ALL_FEATURE_CONF);
	assert(nmq_conf != NULL);
	nng_thread_create(&nmq, (void *) broker_start_with_conf, (void *) nmq_conf);
	nng_msleep(50); // wait a while before sub

	p_pub   = popen(cmd_pub, "r");
	nng_msleep(100);// time for nmq to finish the job.

	pclose(p_pub);
	nng_thread_destroy(nmq);

	return rv;
}