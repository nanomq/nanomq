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
aes_gcm_decrypt(char *ciphertext, int ciphertext_len,
		char *key, char *tag, int *plaintext_lenp)
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

	// skip tag part
	ciphertext += 32;
	ciphertext_len -= 32;

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		log_error("error in new ctx");
		return NULL;
	}

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, cipher_handle, NULL, NULL, NULL)) {
		log_error("error in init ctx");
		return NULL;
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(aes_gcm_iv), NULL)) {
		log_error("error in ctx ctrl");
		return NULL;
	}

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, aes_gcm_iv)) {
		log_error("error in decrypted init");
		return NULL;
	}

	/* Provide any AAD data. This can be called zero or more times as required */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aes_gcm_aad, aes_gcm_aad_sz)) {
		log_error("error in decrypted update1");
		return NULL;
	}

	char *plaintext = malloc(sizeof(char) * (ciphertext_len+32));
	memset(plaintext, '\0', ciphertext_len + 32);
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		log_error("error in decrypted update1");
		return NULL;
	}
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
		log_error("error in ctx ctrl2");
		return NULL;
	}

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		*plaintext_lenp = plaintext_len;
		return plaintext;
	} else {
		/* Verify failed */
		log_error("error in decryption %d", ret);
		free(plaintext);
		return NULL;
	}
}

char *
aes_gcm_encrypt(char *plain, int plainsz, char *key, char **tagp, int *cipher_lenp)
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
		goto err;
	}
	if ((res = EVP_EncryptInit_ex(ctx, cipher_handle, NULL, NULL, NULL)) != 1) {
		log_error("aes error encryption init ex1");
		goto err;
	}
	if ((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
					sizeof(aes_gcm_iv), NULL)) != 1) {
		log_error("aes error ctx ctrl");
		goto err;
	}
	if ((res = EVP_EncryptInit_ex(ctx, NULL, NULL, key, aes_gcm_iv)) != 1) {
		log_error("aes error encryption init ex2");
		goto err;
	}
	if ((res = EVP_EncryptUpdate(ctx, NULL, &len, aes_gcm_aad, aes_gcm_aad_sz)) != 1) {
		log_error("aes error encryption update1");
		goto err;
	}
	if ((res = EVP_EncryptUpdate(ctx, buf + 32, &len, plain, plainsz)) != 1) {
		log_error("aes error encryption update2");
		goto err;
	}
	cipher_len = len;
	if ((res = EVP_EncryptFinal_ex(ctx, buf + 32 + cipher_len, &len)) != 1) {
		log_error("aes error encryption final");
		goto err;
	}
	cipher_len += len;

	char *tag = malloc(sizeof(char) * 32);
	memset(tag, '\0', 32);
	if((res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) != 1) {
		log_error("aes error ctx ctrl");
		goto err;
	}
	*tagp = tag;
	memcpy(buf, tag, 32);

	EVP_CIPHER_CTX_free(ctx);
	*cipher_lenp = (cipher_len + 32);

	return buf;
err:
	log_error("AES GCM error code %d", res);

    EVP_CIPHER_CTX_free(ctx);

    return NULL;
}

