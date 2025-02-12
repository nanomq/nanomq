#ifndef _TEE_INTERFACE_H_
#define _TEE_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

//#include <iostream>
//#include "teeInterfacePrivatekeyMethod.h"
void teeGetKeyAndIv(char* buffer);
std::string teeGetTeeRootCert();
std::string teeGetTeeX509Cert();
std::string teeGetTeeX509CertPrivateKey();
std::string teeGetTeeX509CertPrivateKeyPasswd();
std::vector<uint8_t> teeGetTeeP12Cert();
std::string teeGetTeeP12CertPasswd();

#ifdef __cplusplus
}
#endif

#endif // _TEE_INTERFACE_H_
