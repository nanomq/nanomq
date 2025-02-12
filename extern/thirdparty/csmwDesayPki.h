#ifndef _CSMWDESAYPKI_H_
#define _CSMWDESAYPKI_H_

#include <stdint.h>
#ifdef _cplusplus
extern "C" {
#endif

int getAeskeyToDecrypt(const char* alias, const uint8_t* data, int data_len, uint8_t* out, int outlen_chk, int paddingAlgorithm);
int getCertificateFromKeystore(const char* alias, uint8_t* out, int outlen_chk);
int getPrivatekeyToSign(const char* alias, const uint8_t* data, int data_len, uint8_t* out, int outlen_chk);

#ifdef _cplusplus
}
#endif
#endif // _CSMWDESAYPKI_H_
