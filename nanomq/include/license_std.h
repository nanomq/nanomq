#ifndef NANOMQ_LICENSE_STD_H
#define NANOMQ_LICENSE_STD_H

#include <stdint.h>

#define LICENSE_KEY_LIMIT_CONNS  "1.3.6.1.4.1.52509.1"
#define LICENSE_KEY_PLUGINS      "1.3.6.1.4.1.52509.2" // unused
#define LICENSE_KEY_TYPE         "1.3.6.1.4.1.52509.3"
#define LICENSE_KEY_COMPANY_TYPE "1.3.6.1.4.1.52509.4" // unused

int lic_std_init(const char *path);
int lic_std_update(uint32_t addon);

typedef struct lic_std lic_std;

#endif
