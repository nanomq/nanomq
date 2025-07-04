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

static const uint32_t mon_yday[2][12] = {
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 },
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335 },
};

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
};

static lic_std *g_lic = NULL;

static int isleap(int year)
{
    return (year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0);
}

static uint64_t mktimestamp(struct tm dt)
{
    uint64_t ret;
    int      i = 0;

    ret = ((uint64_t) dt.tm_year - 1970) * 365 * 24 * 3600;
    ret +=
        (mon_yday[isleap(dt.tm_year)][dt.tm_mon] + dt.tm_mday - 1) * 24 * 3600;
    ret += dt.tm_hour * 3600 + dt.tm_min * 60 + dt.tm_sec;

    for (i = 1970; i < dt.tm_year; i++) {
        if (isleap(i)) {
            ret += 24 * 3600;
        }
    }
    if (ret > 4107715199) { // 2100-02-29 23:59:59
        ret += 24 * 3600;
    }
    return (ret);
}

static uint64_t
get_asn1_ts(ASN1_TIME *time, char *ts_str)
{
	struct tm   t;
	const char *str = (const char *) time->data;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) { /* two digit year */
		sscanf(str, "%2d%2d%2d%2d%2d%2dZ", &t.tm_year, &t.tm_mon,
		    &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec);
		t.tm_year += 2000;
	} else if (time->type ==
	    V_ASN1_GENERALIZEDTIME) { /* four digit year */
		sscanf(str, "%4d%2d%2d%2d%2d%2dZ", &t.tm_year, &t.tm_mon,
		    &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec);
	}

	sprintf(ts_str, "%4d-%02d-%02d %02d:%02d:%02d", t.tm_year, t.tm_mon,
	    t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);

	t.tm_mon -= 1;

	/* Note: we did not adjust the time based on time zone information */
	return mktimestamp(t);
}

static int
parse_lic(X509 *cert, const char *pubk, lic_std *lic)
{
	BIO                 *keybio = NULL;
	X509_NAME           *subj   = NULL;
	X509_NAME           *issuer = NULL;
	X509_NAME_ENTRY     *entry  = NULL;
	EVP_PKEY            *pkey   = NULL;
	ASN1_OBJECT         *obj;
	ASN1_STRING         *str;
	ASN1_TIME           *not_before, *not_after;
	X509_EXTENSION      *ext;
	char                 buf[128];
	const unsigned char *value;
	int                  i;
	int                  rv = 0;
	const STACK_OF(X509_EXTENSION) * ext_list;

	OpenSSL_add_all_algorithms();

	/* load public key */
	keybio = BIO_new(BIO_s_mem());
	BIO_puts(keybio, pubk);
	if (!(pkey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL))) {
		log_warn("failed to load pubkey into memory");
		rv = NNG_EINVAL;
		goto final;
	}

	/* Verify the certificates */
	if (X509_verify(cert, pkey) == 0) {
		log_warn("certification verification failure");
		rv = NNG_ECRYPTO;
		goto final;
	}

	not_before = X509_get_notBefore(cert);
	not_after  = X509_get_notAfter(cert);
	lic->st    = get_asn1_ts(not_before, lic->st_str);
	lic->et    = get_asn1_ts(not_after,  lic->et_str);
	log_info("certificate date range: %s-%s (%ld-%ld)",
			lic->st_str, lic->et_str, lic->st, lic->et);

	bool has_email_address = false;

	subj = X509_get_subject_name(cert);
	for (i = 0; i < X509_NAME_entry_count(subj); i++) {
		entry = X509_NAME_get_entry(subj, i);
		obj   = X509_NAME_ENTRY_get_object(entry);
		str   = X509_NAME_ENTRY_get_data(entry);
		i2t_ASN1_OBJECT(buf, sizeof(buf), obj);
		value = ASN1_STRING_get0_data(str);
		log_info("certificate subject %s: %s", buf, value);

		const char *val = (char *) value;

		if (0 == strcmp(buf, "organizationName")) {
			snprintf(lic->name, sizeof(lic->name), "%s", val);
		} else if (!has_email_address &&
		    0 == strcmp(buf, "commonName")) {
			snprintf(lic->email, sizeof(lic->email), "%s", val);
		} else if (0 == strcmp(buf, "emailAddress")) {
			has_email_address = true;
			snprintf(lic->email, sizeof(lic->email), "%s", val);
		}
	}

	issuer = X509_get_issuer_name(cert);
	for (i = 0; i < X509_NAME_entry_count(issuer); i++) {
		entry = X509_NAME_get_entry(issuer, i);
		str   = X509_NAME_ENTRY_get_data(entry);
		value = ASN1_STRING_get0_data(str);
		log_info("certificate issuer: %s", value);
	}

	/* extract the certificate's extensions */
	ext_list = X509_get0_extensions(cert);
	int ext_count = X509_get_ext_count(cert); // TODO Alter of sk_X509_EXTENSION_num maybe error
	//if (sk_X509_EXTENSION_num(ext_list) <= 0) {
	if (ext_count <= 0) {
		rv = NNG_ECRYPTO;
		goto final;
	}

	unsigned mark = 0;
	for (i = 0; i < ext_count; i++) {
		//ext = sk_X509_EXTENSION_value(ext_list, i);
		ext = X509_get_ext(cert, i); // TODO Alter of sk_X509_EXTENSION_value maybe error
		obj = X509_EXTENSION_get_object(ext);
		str = X509_EXTENSION_get_data(ext);
		OBJ_obj2txt(buf, sizeof buf, obj, 1);
		value = ASN1_STRING_get0_data(str);
		log_info("certificate OID: %s => %s", buf, &value[2]);

		const char *val = (char *) &value[2];

		if (0 == strcmp(buf, LICENSE_KEY_TYPE)) {
			int ltype_max_sz = strlen(val) > 8 ? 8 : strlen(val);
			strncpy(lic->ltype, val, ltype_max_sz);
			mark |= 0x01;
		} else if (0 == strcmp(buf, LICENSE_KEY_LIMIT_CONNS)) { // TODO
			lic->lc = atoi(val);
			mark |= 0x02;
		}
	}

	if (0x03 == (mark & 0xFF)) {
		log_info("certification verification success");
	} else {
		rv = NNG_EINVAL;
		log_error("missing license key fields, mark:%u", mark);
	}

final:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (keybio)
		BIO_free_all(keybio);
	return rv;
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
parse_lic_str(const char *data, const char *pubk, lic_std *lic)
{
	int   rv      = 0;
	BIO  *certbio = NULL;
	X509 *cert    = NULL;

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

static int
lic_validate(lic_std *lic, uint64_t now)
{
    if (lic->st == 0 || lic->et == 0 || lic->lc == 0) {
		log_error("License init failed");
		return NNG_EINVAL;
    }

    if (now < lic->st || now > lic->et) {
		log_warn("License expired");
        return NNG_ETIMEDOUT;
    }

	// TODO mismatch
    return 0;
}

int
lic_std_init(const char *path)
{
	int           rv = 0;
	const char *pubk = NULL;
	g_lic = nng_alloc(sizeof(struct lic_std));
	rv = parse_lic_file(path, pubk, g_lic);
	if (rv != 0)
		log_error("failed to parse license %s, rv%d", path, rv);
	return rv;
}

int
lic_std_update(uint32_t addon)
{
	(void)addon;
    nng_time now = nng_timestamp() / 1000; // second
    return lic_validate(g_lic, now);
}
