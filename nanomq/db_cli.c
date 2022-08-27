#if defined(SUPP_RULE_ENGINE)
#include "db_cli.h"
#include "nanomq.h"
#include "nng/supplemental/nanolib/log.h"

void* runNetwork(void *arg) {
	fdb_error_t err = fdb_run_network();
	 if (err) {
		 log_error("Run network error: %s", fdb_get_error(err));
		 exit(1);
	 }
	return NULL;
}

//TODO change to nng_thread
FDBDatabase* openDatabase(pthread_t* netThread) {
	 fdb_error_t err = fdb_setup_network();
	 if (err) {
		 log_error("Setup network error: %s", fdb_get_error(err));
		 exit(1);
	 }
	pthread_create(netThread, NULL, runNetwork, NULL);
	FDBDatabase* db;
	err = fdb_create_database(NULL, &db);
	if (err) {
		log_error("create database error: %s", fdb_get_error(err));
		exit(1);
	}
	return db;
}

#endif