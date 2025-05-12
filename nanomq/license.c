#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aes_gcm.h"
#include "include/license.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/nng.h"

static const char *lic_path = NULL;
static char *lic_key = "202505121520dcba";

static int
lic_dec(char *data, size_t sz,
		uint64_t *total, uint64_t *cur, uint64_t *nstart, uint64_t *nend)
{
	char *out = NULL;
	int   out_sz;
	char *tag = data;
	if (NULL == (out = aes_gcm_decrypt(data, sz, lic_key, tag, &out_sz))) {
		log_error("license dec failed");
		return -1;
	}
	uint64_t d1, d2, d3, d4;
	int num = sscanf(out, "%d,%d,%d,%d", &d1, &d2, &d3, &d4);
	if (num != 4) {
		nng_free(out, 0);
		log_error("license content is malformed rv%d", num);
		return -2;
	}
	nng_free(out, 0);
	*total = d1;
	*cur = d2;
	*nstart = d3;
	*nend = d4;
	return 0;
}

static int
lic_enc(uint64_t total, uint64_t cur, uint64_t nstart, uint64_t nend,
		char *cipher, size_t *sz)
{
	char  buf[64];
	char *tag;
	int   out_sz;
	char *out = NULL;
	sprintf(buf, "%d,%d,%d,%d", total, cur, nstart, nend);
	if (NULL == (out = aes_gcm_encrypt(buf, strlen(buf), lic_key, &tag, &out_sz))) {
		log_error("license enc failed");
		return -1;
	}
	memcpy(cipher, out, (size_t)out_sz);
	nng_free(out, out_sz);
	return 0;
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
	if (0 != (rv = nng_file_get(lic_path, (void **)&data, &sz))) {
		log_error("license(%s) read failed %d", lic_path, rv);
		return -1;
	}
	log_info("license(%s) sz%d", lic_path, sz);
	if (data == NULL || sz == 0 || sz > 128 || sz < 36) {
		log_error("license(%s) empty or file has a invalid sz%d", lic_path, sz);
		return -1;
	}
	uint64_t nstart = 0, nend = 0, cur = 0, total = 0;
	if (0 != lic_dec(data, sz, &total, &cur, &nstart, &nend)) {
		nng_free(data, 0);
		log_error("license(%s) is malformed", lic_path);
		return -1;
	}
	nng_free(data, 0);
	if (cur > total || nstart > nend) {
		log_error("license(%s) expires", lic_path);
		return -2;
	} else {
#if defined(DEBUG)
		log_info("license is active %ld/%ld", cur, total);
#else
		log_info("license is active");
#endif
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
	if (0 != (rv = nng_file_get(lic_path, (void **)&data, &sz))) {
		log_error("license(%s) read failed rv%d", lic_path, rv);
		return -1;
	}
	if (data == NULL || sz == 0) {
		log_error("license(%s) empty", lic_path);
		return -1;
	}
	uint64_t nstart = 0, nend = 0, cur = 0, total = 0;
	if (0 != (rv = lic_dec(data, sz, &total, &cur, &nstart, &nend))) {
		nng_free(data, 0);
		log_error("license(%s) decode failed rv%d", lic_path, rv);
		return -1;
	}
	nng_free(data, 0);

	cur += addon;

#if defined(DEBUG)
	log_info("license updated %ld/%ld", cur, total);
#endif

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
	nng_free(cipher, sz + 2);
	return 0;
}

