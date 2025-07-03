#ifndef NANOMQ_LICENSE_STD_H
#define NANOMQ_LICENSE_STD_H

#include <stdint.h>

#define LICENSE_KEY_TYPE        "tobedone"
#define LICENSE_KEY_LIMIT_CONNS "tobedone"

int lic_std_init(const char *path);
int lic_std_update(uint32_t addon);

typedef struct lic_std lic_std;

#endif
