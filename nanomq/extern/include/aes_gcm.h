#ifndef NANO_EXTERN_AES_GCM
#define NANO_EXTERN_AES_GCM

char *aes_gcm_decrypt(char *cipher, int cipher_len, char *key, int *plain_lenp);
char *aes_gcm_encrypt(char *plain, int plain_len, char *key, int *cipher_lenp);

#endif
