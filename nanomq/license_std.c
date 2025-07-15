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

static const char *g_lic_path;

struct lic_std {
	int  vd;     // valid days // unavailable in STD mode
	int  lc;     // limit connections
	uint64_t st; // start time
	uint64_t et; // end time
	char st_str[128];
	char et_str[128];
	char ltype[9];
	char name[129];
	char email[129];
	char dc[129]; // deployment code // unavailable in STD mode

	int   args_sz;
	char *args;
	int   sign_sz;
	char *sign;
};

static lic_std *g_lic = NULL;

static char root_pubk[] =
"-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE3bWmTSFCUSb6fIHVJK2Wj51Y3Us\n\
rDDMt2tZMToi1Xf3zQJ583b5tKRNHMTdD16Wc/xrEEZf9MLmHZptOwrx0A==\n\
-----END PUBLIC KEY-----";

// from kernel
static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
		printf("file can't be opened %s\n", fname);
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
		printf("No more memory\n");
		fclose(fp);
		return NULL;
	}

	pos = fread(str, 1, cap, fp);
	if (pos != cap) {
		printf("Failed to read file\n");
		free(str);
		fclose(fp);
		return NULL;
	}

	fclose(fp);

	*sz = pos;
	return str;
}

static uint64_t
date2ts(int yyyymmdd)
{
	int year  = yyyymmdd / 10000;
	int month = (yyyymmdd / 100) % 100;
	int day   = yyyymmdd % 100;

	struct tm t = { 0 };
	t.tm_year   = year - 1900; // tm_year is years since 1900
	t.tm_mon    = month - 1;   // tm_mon is months since January [0–11]
	t.tm_mday   = day;
	t.tm_hour   = 0;
	t.tm_min    = 0;
	t.tm_sec    = 0;

	// Convert to timestamp (seconds since Unix epoch)
	time_t timestamp = mktime(&t);

	return (uint64_t) timestamp;
}

static int
split_lic_str(const char *data, char **lic_args, char **lic_sign)
{
	int split_idx = 0;
	for (split_idx = 0; split_idx<strlen(data); ++split_idx)
		if (data[split_idx] == '.')
			break;
	if (split_idx <= 0 || split_idx >= strlen(data))
		return NNG_EINVAL;
	*lic_args = strndup(data + 0, split_idx);
	*lic_sign = strndup(data + split_idx + 1, strlen(data + split_idx + 1) - 1);
	return 0;
}

static int
split_lic_args(const char *lic_args, int lic_args_sz, struct lic_std *lic)
{
	char *start = (char *)lic_args;
	int   cnt = 0;
	int   args_idx = 0;
	char *args[9];
	int   max_args = 9;
	for (int i=0; i<max_args; ++i) args[i] = NULL;
	for (int i=0; i<lic_args_sz; ++i) {
		if (lic_args[i] == '\n') {
			if (args_idx < max_args)
				args[args_idx++] = strndup(start, cnt);
			else
				return -1;
			start += (cnt + 1);
			cnt = 0;
		} else {
			cnt ++;
		}
	}
	if (args_idx != max_args) {
		printf("wrong argu number%d\n", args_idx);
		return -1;
	}
	if (0 != strcmp(args[0], "220111")) {
		printf("wrong vercode %s\n", args[0]);
		return -2;
	}
	if (1 != strlen(args[1])) {
		printf("wrong ltype %s\n", args[1]);
		return -2;
	}
	switch (args[1][0]) {
	case '0':
		strcpy(lic->ltype, "trial");break;
	case '1':
		strcpy(lic->ltype, "official");break;
	default:
		return NNG_EINVAL;
	}
	// ignore ctype
	strcpy(lic->name, args[3]);
	strcpy(lic->email, args[4]);
	strcpy(lic->dc, args[5]);
	strcpy(lic->st_str, args[6]);
	// TODO convert st_str to st
	lic->st = date2ts(atoi(lic->st_str));
	int vdays = atoi(args[7]);
	lic->et = lic->st + vdays*24*60*60;
	lic->lc = atoi(args[8]);
	printf("ltype:%s name:%s email:%s dc:%s st:%lld et:%lld lc:%d\n",
			lic->ltype, lic->name, lic->email, lic->dc, lic->st, lic->et, lic->lc);
	for (int i=0; i<max_args; ++i)
		if (args[i] != NULL)
			free(args[i]);
	return 0;
}

static int
lic_verify_sign(struct lic_std *lic, EVP_PKEY *pkey)
{
	int         rv      = 0;
	EVP_MD_CTX *context = NULL;

	if ((context = EVP_MD_CTX_new()) == NULL) {
		rv = NNG_ENOMEM;
		goto end;
	}
	if (!EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, pkey)) {
		printf("EVP_DigestVerifyInit failed.\n");
		rv = NNG_ECRYPTO;
		goto end;
	}
	if (!EVP_DigestVerifyUpdate(context, lic->args, lic->args_sz)) {
		printf("EVP_DigestVerifyUpdate failed.\n");
		rv = NNG_ECRYPTO;
		goto end;
	}
	if (EVP_DigestVerifyFinal(context, lic->sign, lic->sign_sz) <=
	    0) {
		printf("EVP_DigestVerifyFinal failed.\n");
		rv = NNG_ECRYPTO;
		goto end;
	}

end:
	if (context)
		EVP_MD_CTX_free(context);
	return rv;
}

static int
parse_lic_str(const char *data, const char *pubk, lic_std *lic)
{
	int  rv  = 0;
	BIO* bio = BIO_new_mem_buf(pubk, strlen(pubk));
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

	char * lic_args_b64 = NULL;
	char * lic_sign_b64 = NULL;
	if (0 != (rv = split_lic_str(data, &lic_args_b64, &lic_sign_b64))) {
		printf("invalid lic format\n");
		BIO_free(bio);
		EVP_PKEY_free(pkey);
		return rv;
	}

	char * lic_args = nng_alloc(sizeof(char) * strlen(lic_args_b64));
	char * lic_sign = nng_alloc(sizeof(char) * strlen(lic_sign_b64));
	memset(lic_args, 0, strlen(lic_args_b64));
	memset(lic_sign, 0, strlen(lic_sign_b64));
	int lic_args_sz;
	int lic_sign_sz;
	if (!lic_args || !lic_sign) {
		BIO_free(bio);
		EVP_PKEY_free(pkey);
		nng_free(lic_args_b64, 0);
		nng_free(lic_sign_b64, 0);
		return NNG_ENOMEM;
	}

	if ((lic_args_sz = base64_decode(lic_args_b64, strlen(lic_args_b64), lic_args)) <= 0) {
		printf("invalid lic args content\n");
		rv = NNG_EINVAL;
	}
	if ((lic_sign_sz = base64_decode(lic_sign_b64, strlen(lic_sign_b64), lic_sign)) <= 0) {
		printf("invalid lic sign content\n");
		rv = NNG_EINVAL;
	}

	if (rv == 0) {
		lic->args    = lic_args;
		lic->args_sz = lic_args_sz;
		lic->sign    = lic_sign;
		lic->sign_sz = lic_sign_sz;
		printf("args: [%s] sign: [%.*s]\n", lic_args, lic_sign_sz, lic_sign);
		rv = lic_verify_sign(lic, pkey);
	}

	if (lic_args_b64)
		nng_free(lic_args_b64, 0);
	if (lic_sign_b64)
		nng_free(lic_sign_b64, 0);
	if (rv && lic_args)
		nng_free(lic_args, 0);
	if (rv && lic_sign)
		nng_free(lic_sign, 0);
	BIO_free(bio);
	EVP_PKEY_free(pkey);
	return rv;
}

static int
parse_lic_file(const char *fname, const char *pubk, lic_std *lic)
{
	int   rv = 0;
	char *fbuf;
	int   fsz;

	if ((fbuf = readfile(fname, &fsz)) == NULL) {
		printf("failed to readfile %s\n", fname);
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
	g_lic_path = path;
	g_lic = nng_alloc(sizeof(struct lic_std));
	rv = parse_lic_file(path, pubk, g_lic);
	if (rv != 0) {
		printf("failed to parse license %s, rv%d\n", path, rv);
	} else {
		if (0 != split_lic_args(g_lic->args, g_lic->args_sz, g_lic)) {
			printf("failed to parse license in\n", path);
		}
		rv = lic_std_update(0);
	}

	return rv;
}

int
lic_std_update(uint32_t addon)
{
	(void) addon;
	return 0;
}
