#ifndef NANOMQ_CMD_PROC_H
#define NANOMQ_CMD_PROC_H

#define CMD_IPC_URL "ipc:///tmp/nanomq_cmd.ipc"
// #define CMD_IPC_URL "tcp://127.0.0.1:10000"

#include "nng/nng.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/nanolib/conf.h"

extern void start_cmd_server(conf *config);
extern void start_cmd_client(const char *cmd);

#endif //NANOMQ_CMD_PROC_H