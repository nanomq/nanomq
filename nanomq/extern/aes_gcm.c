#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "nng/supplemental/nanolib/log.h"

static const char aes_gcm_aad[] =
{0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
 0x7f, 0xec, 0x78, 0xde};
static const int  aes_gcm_aad_sz = 16;
static const char aes_gcm_iv[] =
{0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84};

char*
aes_gcm_decrypt(char *cipher, int cipher_len, char *key, int *plain_lenp)
{
	const EVP_CIPHER *cipher_handle;
	switch (strlen(key) * 8) {
	case 128:
		cipher_handle = EVP_aes_128_gcm();
		break;
	case 192:
		cipher_handle = EVP_aes_192_gcm();
		break;
	case 256:
		cipher_handle = EVP_aes_256_gcm();
		break;
	default:
		log_error("Unsupported aes key length");
		return NULL;
	}

	if (cipher_len <= 32) {
		log_error("cipher text sz%d is invalid (too short)", cipher_len);
		return NULL;
	}

	char tag[32];
	memcpy(tag, cipher, 32);
	// skip tag part
	cipher += 32;
	cipher_len -= 32;

	EVP_CIPHER_CTX *ctx;
	int   len;
	int   plain_len;
	char *plain = NULL;
	int   res;

	/* Create and initialise the context */
	if((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		res = -1;
		log_error("error in new ctx");
		goto out;
	}

	/* Initialise the decryption operation. */
	if((res = EVP_DecryptInit_ex(ctx, cipher_handle, NULL, NULL, NULL)) != 1) {
		log_error("error in init ctx");
		goto out;
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(aes_gcm_iv), NULL)) != 1) {
		log_error("error in ctx ctrl");
		goto out;
	}

	/* Initialise key and IV */
	if((res = EVP_DecryptInit_ex(ctx, NULL, NULL, key, aes_gcm_iv)) != 1) {
		log_error("error in decrypted init");
		goto out;
	}

	/* Provide any AAD data. This can be called zero or more times as required */
	if((res = EVP_DecryptUpdate(ctx, NULL, &len, aes_gcm_aad, aes_gcm_aad_sz)) != 1) {
		log_error("error in decrypted update1");
		goto out;
	}

	plain = malloc(sizeof(char) * (cipher_len+32));
	memset(plain, '\0', cipher_len + 32);
    /*
     * Provide the message to be decrypted, and obtain the plain output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
	if((res = EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len)) != 1) {
		log_error("error in decrypted update1");
		goto out;
	}
	plain_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) != 1) {
		log_error("error in ctx ctrl2");
		goto out;
	}

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plain is not trustworthy.
	 */
	res = EVP_DecryptFinal_ex(ctx, plain + len, &len);
out:
	/* Clean up */
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if(res > 0) {
		/* Success */
		plain_len += len;
		*plain_lenp = plain_len;
		return plain;
	}
	/* Verify failed */
	log_error("AES GCM error code decryption %d", res);
	if (plain)
		free(plain);
	return NULL;
}

char *
aes_gcm_encrypt(char *plain, int plainsz, char *key, int *cipher_lenp)
{
	const EVP_CIPHER *cipher_handle;
	switch (strlen(key) * 8) {
	case 128:
		cipher_handle = EVP_aes_128_gcm();
		break;
	case 192:
		cipher_handle = EVP_aes_192_gcm();
		break;
	case 256:
		cipher_handle = EVP_aes_256_gcm();
		break;
	default:
		log_error("Unsupported aes key length");
		return NULL;
	}

	int res = 0;
	char *buf = malloc(sizeof(char) * (plainsz+40));
	int cipher_len, len;

	EVP_CIPHER_CTX *ctx;
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
		res = -1;
		log_error("aes error ctx new");
		goto out;
	}
	if ((res = EVP_EncryptInit_ex(ctx, cipher_handle, NULL, NULL, NULL)) != 1) {
		log_error("aes error encryption init ex1");
		goto out;
	}
	if ((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
					sizeof(aes_gcm_iv), NULL)) != 1) {
		log_error("aes error ctx ctrl");
		goto out;
	}
	if ((res = EVP_EncryptInit_ex(ctx, NULL, NULL, key, aes_gcm_iv)) != 1) {
		log_error("aes error encryption init ex2");
		goto out;
	}
	if ((res = EVP_EncryptUpdate(ctx, NULL, &len, aes_gcm_aad, aes_gcm_aad_sz)) != 1) {
		log_error("aes error encryption update1");
		goto out;
	}
	if ((res = EVP_EncryptUpdate(ctx, buf + 32, &len, plain, plainsz)) != 1) {
		log_error("aes error encryption update2");
		goto out;
	}
	cipher_len = len;
	if ((res = EVP_EncryptFinal_ex(ctx, buf + 32 + cipher_len, &len)) != 1) {
		log_error("aes error encryption final");
		goto out;
	}
	cipher_len += len;

	char tag[32] = {0};
	if((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) != 1) {
		log_error("aes error ctx ctrl");
		goto out;
	}
	memcpy(buf, tag, 32);

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if (res > 0) {
		*cipher_lenp = (cipher_len + 32);
		return buf;
	}
	log_error("AES GCM error code %d", res);
	if (buf)
		free(buf);
    return NULL;
}

