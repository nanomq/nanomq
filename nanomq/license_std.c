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
	BIO  *certbio = NULL;
	X509 *cert    = NULL;

	const char * lic_args = NULL;
	const char * lic_sign = NULL;
	if (0 != (rv = split_lic_str(data, &lic_args, &lic_sign))) {
		log_warn("invalid lic format");
		return rv;
	}

	if (NULL == (certbio = BIO_new(BIO_s_mem()))) {
		return NNG_ENOMEM;
	}
	if (0 >= BIO_puts(certbio, data)) {
		BIO_free_all(certbio);
		return NNG_EINVAL;
	}
	if (!(cert = PEM_read_bio_X509(certbio, NULL, NULL, NULL))) {
		log_warn("failed to load certificate data into memory");
		BIO_free_all(certbio);
		return NNG_EINVAL;
	}

	rv = parse_lic(cert, pubk, lic);

	X509_free(cert);
	BIO_free_all(certbio);
	return rv;
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
