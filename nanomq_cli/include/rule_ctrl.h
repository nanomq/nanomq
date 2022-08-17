#ifndef CTRL_H
#define CTRL_H

#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/supplemental/util/platform.h"
#include "nng/supplemental/nanolib/conf.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

extern int rules_start(int argc, char **argv);
extern int rules_dflt(int argc, char **argv);

#endif