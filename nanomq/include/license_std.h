#ifndef NANOMQ_LICENSE_STD_H
#define NANOMQ_LICENSE_STD_H

#include <stdint.h>

int lic_std_init(const char *path);
int lic_std_update(uint32_t addon);
int lic_std_renew(const char *path);
int lic_std_info(char **info);

typedef struct lic_std lic_std;

#endif
