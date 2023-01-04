#ifndef VSOMEIP_GATEWAY_H
#define VSOMEIP_GATEWAY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "nng/supplemental/nanolib/conf.h"

extern int vsomeip_gateway(vsomeip_gateway_conf *conf);
extern int vsomeip_gateway_start(int argc, char **argv);
extern int vsomeip_gateway_dflt(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif