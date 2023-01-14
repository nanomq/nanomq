#ifndef NANOMQ_CLI_DDS_UTILS_H
#define NANOMQ_CLI_DDS_UTILS_H

#include "nng/nng.h"
#include "nng/supplemental/util/options.h"

typedef enum {
	DDS_PUB,
	DDS_SUB,
	DDS_PROXY,
} dds_client_type;

typedef struct {
	dds_client_type cli_type;
	uint32_t        domain_id;
	char *          topic;
	bool            shm_mode;
	char *          shm_log_level;
} dds_client_opts;

void  dds_handle_cmd(int argc, char **argv, dds_client_opts *opts);
int   dds_cmd_parse_opts(int argc, char **argv, dds_client_opts *opts);
void  dds_client_opts_fini(dds_client_opts *opts);
char *dds_shm_xml(bool enable, const char *log_level);
void dds_set_shm_mode(dds_client_opts *opts);

#endif
