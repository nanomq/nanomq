#ifndef TEE_INTERFACE_H
#define TEE_INTERFACE_H

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>

//#include "teeInterfacePrivatekeyMethod.h"
void teeGetKeyAndIv(char* buffer);
std::string teeGetTeeRootCert();
std::string teeGetTeeX509Cert();
std::string teeGetTeeX509CertPrivateKey();
std::string teeGetTeeX509CertPrivateKeyPasswd();
std::vector<uint8_t> teeGetTeeP12Cert();
std::string teeGetTeeP12CertPasswd();

#endif // TEE_INTERFACE_H
