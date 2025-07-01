#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "aes_gcm.h"
#include "include/license.h"
#include "nng/supplemental/nanolib/log.h"
#include "nng/nng.h"

static const char *lic_path = NULL;
static char *lic_key = "202505121520dcba";

#define MAX_LIC_BUF_LEN 430

static int
lic_dec(char *data, size_t sz,
		uint32_t *vm, uint32_t *um, char *st, char *mode,
		char *name, char *email, char *dc, uint32_t *lc)
{
	char *out = NULL;
	int   out_sz;
	char *tag = data;
	if (NULL == (out = aes_gcm_decrypt(data, sz, lic_key, tag, &out_sz))) {
		log_error("license dec failed");
		return -1;
	}
	//log_info("(%d)%s", out_sz, out);
	// valid minutes,used minutes,start time,trial/official,name,email,dc,limit connections
	//int num = sscanf(out, "%u,%u,%s,%s,%s,%s,%s,%u", vm, um, st, mode, name, email, dc, lc);
	int num = sscanf(out, "%u,%u,%[^,],%[^,],%[^,],%[^,],%[^,],%u", vm, um, st, mode, name, email, dc, lc);
	if (num != 8) {
		nng_free(out, 0);
		log_error("license content is malformed rv%d", num);
		return -2;
	}
	nng_free(out, 0);
	return 0;
}

static int
lic_enc(uint32_t vm, uint32_t um, char *st, char *mode,
		char *name, char *email, char *dc, uint32_t lc,
		char *cipher, size_t *sz)
{
	char  buf[MAX_LIC_BUF_LEN];
	char *tag;
	int   out_sz;
	char *out = NULL;
	sprintf(buf, "%u,%u,%s,%s,%s,%s,%s,%u\n", vm, um, st, mode, name, email, dc, lc);
	if (NULL == (out = aes_gcm_encrypt(buf, strlen(buf), lic_key, &tag, &out_sz))) {
		log_error("license enc failed");
		return -1;
	}
	memcpy(cipher, out, (size_t)out_sz);
	nng_free(out, out_sz);
	nng_free(tag, 0);
	*sz = out_sz;
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
		log_error("license(%s) read failed %d(%s)", lic_path, rv, nng_strerror(rv));
		return -1;
	}
	// max 12 + 12 + 8 + 8 + 128 + 128 + 128 + 6
	if (data == NULL || sz == 0 || sz > MAX_LIC_BUF_LEN || sz < 20) {
		log_error("license(%s) empty or file has a invalid sz%ld", lic_path, sz);
		return -1;
	}
	uint32_t vm = 0, um = 0, lc = 0;
	char st[9] = {0};
	char mode[9] = {0};
	char name[129] = {0};
	char email[129] = {0};
	char dc[129] = {0};
	if (0 != lic_dec(data, sz, &vm, &um, st, mode, name, email, dc, &lc)) {
		nng_free(data, 0);
		log_error("license(%s) is malformed", lic_path);
		return -1;
	}
	nng_free(data, 0);
	if (um > vm) {
		log_error("license(%s) is expired", lic_path);
		return -2;
	} else {
#if defined(DEBUG)
		log_info("license is active %ld/%ld", um, vm);
#else
		log_info("license is active");
#endif
	}
	return 0;
}

int
lic_update(uint32_t addon)
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
		log_error("license(%s) read failed rv%d(%s)", lic_path, rv, nng_strerror(rv));
		return -1;
	}
	// max 12 + 12 + 8 + 8 + 128 + 128 + 128 + 6
	if (data == NULL || sz == 0 || sz > 430 || sz < 20) {
		log_error("license(%s) empty or file has a invalid sz%ld", lic_path, sz);
		return -1;
	}
	uint32_t vm = 0, um = 0, lc = 0;
	char st[9], mode[9], name[129], email[129], dc[129];
	if (0 != (rv = lic_dec(data, sz, &vm, &um, st, mode, name, email, dc, &lc))) {
		log_error("license(%s) decode failed rv%d", lic_path, rv);
		return -1;
	}
	nng_free(data, 0);

	um += addon;

#if defined(DEBUG)
	log_debug("license updated %ld/%ld st:%s mode:%s %s-%s-%s lc:%d",
			um, vm, st, mode, name, email, dc, lc);
#endif

	// WRITE license
	char  *cipher = nng_alloc(sz + 2);
	size_t cipher_sz;

	if (0 != (rv = lic_enc(vm, um, st, mode, name, email, dc, lc, cipher, &cipher_sz))) {
		nng_free(cipher, sz + 2);
		log_error("license(%s) encode failed rv%d", lic_path, rv);
		return -3;
	}
	if (0 != (rv = nng_file_put(lic_path, cipher, cipher_sz))) {
		nng_free(cipher, sz + 2);
		log_error("license(%s) write failed rv%d(%s)", lic_path, rv, nng_strerror(rv));
		return -3;
	}
	nng_free(cipher, sz + 2);

	if (um > vm) {
		log_error("license(%s) is expired", lic_path);
		return -2;
	}

	return 0;
}

