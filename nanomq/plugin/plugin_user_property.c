//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#include <stdio.h>
#include <stdlib.h>
#include "include/plugin.h"

/*
 * How to compile:
 * gcc -I../ -fPIC -shared plugin_user_property.c -o plugin_user_property.so
 * or
 * gcc -I.. -I../../nng/include -fPIC -shared plugin_user_property.c -o plugin_user_property.so
 */

int cb(void *data)
{
	char **property = data;
	if (property != NULL) {
		property[0] = malloc(strlen("alpha") + 1);
		strcpy(property[0], "alpha");
		property[1] = malloc(strlen("beta") + 1);
		strcpy(property[1], "beta");
	}

	return 0;
}

int nano_plugin_init()
{
	plugin_hook_register(HOOK_USER_PROPERTY, cb);
	return 0;
}
