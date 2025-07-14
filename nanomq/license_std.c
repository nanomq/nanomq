#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include "include/license_std.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/supplemental/util/platform.h"
#include "nng/nng.h"

#include <openssl/stack.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

int
lic_std_init(const char *path)
{
	int    rv = 0;
	(void) path;
	return rv;
}

int
lic_std_update(uint32_t addon)
{
	(void) addon;
}
