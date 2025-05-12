#include <stdlib.h>
#include <string.h>

#include "aes_gcm.h"
#include "include/license.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/nng.h"

static char *lic_path = NULL;

static int
lic_dec(char *data, size_t sz, uint64_t *total, uint64_t *cur,
		uint64_t *nstart, uint64_t *nend)
{
}

static int
lic_enc(uint64_t &total, uint64_t &cur, uint64_t &nstart, uint64_t &nend,
		char *cipher, size_t *sz)
{
}

int
lic_init(const char *path)
{
	if (lic_path == NULL) {
		lic_path = path;
	}
	int    rv;
	char  *data;
	size_t sz;
	if (0 != (rv = nng_file_get(lic_path, &data, &sz))) {
		log_error("license(%s) read failed %d", lic_path, rv);
		return -1;
	}
	if (data == NULL || sz == 0) {
		log_error("license(%s) empty", lic_path);
		return -1;
	}
	uint64_t nstart = 0, nend = 0, cur = 0, total = 0;
	if (0 != lic_dec(data, sz, &total, &cur, &nstart, &nend)) {
		log_error("license(%s) is malformed", lic_path);
		return -1;
	}
	if (cur > total || nstart > nend) {
		log_error("license(%s) expires", lic_path);
		return -2;
	}
	return 0;
}

int
lic_update(size_t addon)
{
	if (lic_path == NULL) {
		log_error("license not exists");
		return -1;
	}
	// READ license
	int    rv;
	char  *data;
	size_t sz;
	if (0 != (rv = nng_file_get(lic_path, &data, &sz))) {
		log_error("license(%s) read failed rv%d", lic_path, rv);
		return -1;
	}
	if (data == NULL || sz == 0) {
		log_error("license(%s) empty", lic_path);
		return -1;
	}
	uint64_t nstart = 0, nend = 0, cur = 0, total = 0;
	if (0 != (rv = lic_dec(data, sz, &total, &cur, &nstart, &nend))) {
		log_error("license(%s) decode failed rv%d", lic_path, rv);
		return -1;
	}

	cur += addon;

	if (cur > total || nstart > nend) {
		log_error("license(%s) expires", lic_path);
		return -2;
	}

	// WRITE license
	char  *cipher = nng_alloc(sz + 2);
	size_t cipher_sz;
	if (0 != (rv = lic_enc(total, cur, nstart, nend, cipher, &cipher_sz))) {
		nng_free(cipher, sz + 2);
		log_error("license(%s) encode failed rv%d", lic_path, rv);
		return -3;
	}
	if (0 != (rv = nng_file_put(lic_path, cipher, cipher_sz))) {
		nng_free(cipher, sz + 2);
		log_error("license(%s) write failed rv%d", lic_path, rv);
		return -3;
	}
	return 0;
}

