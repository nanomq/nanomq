#ifndef NANOMQ_CLI_DDS_UTILS_H
#define NANOMQ_CLI_DDS_UTILS_H

#include "nng/nng.h"
#include "nng/supplemental/util/options.h"
#include "nng/supplemental/nanolib/conf.h"
#include "idl_convert.h"

typedef enum {
	DDS_PUB,
	DDS_SUB,
	DDS_PROXY,
} dds_client_type;

typedef struct {
	dds_client_type cli_type;
	uint32_t        domain_id;
	char *          topic;
	char *          struct_name;
	cJSON *         msg;
	bool            shm_mode;
	char *          shm_log_level;
	char *          partition;
} dds_client_opts;

// It should not be changed
typedef struct fixed_mqtt_msg {
	char    *payload;
	uint32_t len;
} fixed_mqtt_msg;

void  dds_handle_cmd(int argc, char **argv, dds_client_opts *opts);
int   dds_cmd_parse_opts(int argc, char **argv, dds_client_opts *opts);
void  dds_client_opts_fini(dds_client_opts *opts);
char *dds_shm_xml(bool enable, const char *log_level);
void  dds_set_shm_mode(dds_client_opts *opts);
dds_handler_set *dds_get_handler(const char *struct_name);

#endif
