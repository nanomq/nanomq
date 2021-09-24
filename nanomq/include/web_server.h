//
// Copyright 2020 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int start_rest_server(uint16_t port);

extern void stop_rest_server(void);

#endif
