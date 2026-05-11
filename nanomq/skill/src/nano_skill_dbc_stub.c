// SPDX-License-Identifier: MIT

#include "nano_skill.h"

#include <errno.h>
#include <stddef.h>

nano_skill_dbc *
nano_skill_dbc_load(const char *path)
{
	(void) path;
	return NULL;
}

int
nano_skill_dbc_decode(nano_skill_dbc *dbc, uint32_t can_id,
    const uint8_t *data, uint8_t dlc,
    nano_skill_dbc_signal *out, uint32_t cap, uint32_t *outn)
{
	(void) dbc;
	(void) can_id;
	(void) data;
	(void) dlc;
	(void) out;
	(void) cap;
	if (outn) *outn = 0;
	return -ENOSYS;
}

void
nano_skill_dbc_free(nano_skill_dbc *dbc)
{
	(void) dbc;
}

