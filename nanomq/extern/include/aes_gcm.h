#ifndef NANO_EXTERN_AES_GCM
#define NANO_EXTERN_AES_GCM

char *aes_gcm_decrypt(char *ciphertext, int ciphertext_len,
		char *key, char *tag, int *plaintext_lenp);
char *aes_gcm_encrypt(char *plain, int plainsz, char *key, char **tagp, int *cipher_lenp);

#endif
