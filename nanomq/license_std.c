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

// from kernel
static int
base64_decode(const char *src, int srclen, uint8_t *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	uint8_t *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64_table, src[i]);

		if (src[i] == '=') {
			ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
			continue;
		}
		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (uint8_t)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

static char *
readfile(const char *fname, int *sz)
{
	FILE *fp;
	char  ch;

	fp = fopen(fname, "r");

	if (NULL == fp) {
		log_error("file can't be opened \n");
		return NULL;
	}

	// Get file length
	fseek(fp, 0, SEEK_END);
	int cap = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	int   pos = 0;
	char *str = malloc(sizeof(char) * cap + 1);
	memset(str, 0, cap + 1);
	if (str == NULL) {
		log_error("No more memory");
		fclose(fp);
		return NULL;
	}

	pos = fread(str, 1, cap, fp);
	if (pos != cap) {
		log_error("Failed to read file");
		free(str);
		fclose(fp);
		return NULL;
	}

	fclose(fp);

	*sz = pos;
	return str;
}

static int
split_lic_str(const char *data, const char **lic_args, const char **lic_sign)
{
	int split_idx = 0;
	for (split_idx = 0; split_idx<strlen(data); ++split_idx)
		if (data[split_idx] == '.')
			break;
	if (split_idx <= 0 || split_idx >= strlen(data))
		return NNG_EINVAL;
	*lic_args = strndup(data + 0, split_idx);
	*lic_sign = strdup(data + split_idx + 1);
	return 0;
}

static int
parse_lic_str(const char *data, const char *pubk, lic_std *lic)
{
	int   rv      = 0;

	const char * lic_args_b64 = NULL;
	const char * lic_sign_b64 = NULL;
	if (0 != (rv = split_lic_str(data, &lic_args_b64, &lic_sign_b64))) {
		log_warn("invalid lic format");
		return rv;
	}

	const char * lic_args = nng_alloc(sizeof(char) * strlen(lic_args_b64));
	const char * lic_sign = nng_alloc(sizeof(char) * strlen(lic_sign_b64));
	const int lic_args_sz;
	const int lic_sign_sz;
	if (!lic_args || !lic_sign) {
		return NNG_ENOMEM;
	}

	if ((lic_args_sz = base64_decode(lic_args, strlen(lic_args_b64), lic_args)) <= 0) {
		log_warn("invalid lic content");
		return NNG_EINVAL;
	}
	if ((lic_sign_sz = base64_decode(lic_sign, strlen(lic_sign_b64), lic_sign)) <= 0) {
		log_warn("invalid lic content");
		return NNG_EINVAL;
	}
	log_info("args: [%s] sign: [%.*s]", lic_args, lic_sign_sz, lic_sign);

	return lic_verify(lic, lic_sign_sz, lic_sign, pubk);
}

static int
parse_lic_file(const char *fname, const char *pubk, lic_std *lic)
{
	int   rv = 0;
	char *fbuf;
	int   fsz;

	if ((fbuf = readfile(fname, &fsz)) == NULL) {
		log_warn("failed to readfile %s", fname);
		return NNG_EINVAL;
	}

	rv = parse_lic_str(fbuf, pubk, lic);

	free(fbuf);
	return rv;
}

int
lic_std_init(const char *path)
{
	int         rv = 0;
	const char *pubk = root_pubk;
	g_lic = nng_alloc(sizeof(struct lic_std));
	rv = parse_lic_file(path);
	if (rv != 0)
		log_error("failed to parse license %s, rv%d", path, rv);
	else
		rv = lic_std_update(0);

	return rv;
}

int
lic_std_update(uint32_t addon)
{
	(void) addon;
}
