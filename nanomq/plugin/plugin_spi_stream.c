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
#include "nng/exchange/stream/stream.h"

#define SPI_STREAM_NAME "spi"
#define SPI_STREAM_ID	0x2

void *decode(void *data, uint32_t size, uint32_t *new_size)
{
	printf("\nrhack: decode: spi\n");
	*new_size = size;
	return data;
}

void *encode(void *data, uint32_t size, uint32_t *new_size)
{
	printf("\nhack: decode: spi\n");
	*new_size = size;
	return data;
}

int nano_plugin_init()
{
	char *name = NULL;
	name = (char *)malloc(strlen(SPI_STREAM_NAME) + 1);
	if (name == NULL) {
		return -1;
	}

	strcpy(name, SPI_STREAM_NAME);

	stream_register(name, SPI_STREAM_ID, decode, encode);

	return 0;
}
