#pragma once

#include "ossl_raii.hpp"

namespace sec {

struct Encapsulation {
    vector<uint8_t> kem_ct;
    SecureBytes shared_secret;
};

Encapsulation encapsulate(EVP_PKEY *recipientPublicKey);
SecureBytes decapsulate(EVP_PKEY *recipientPrivateKey, const vector<uint8_t> &kem_ct);

SecureBytes deriveAesKey(const SecureBytes &Z,
                         const vector<uint8_t> &keyId,
                         const vector<uint8_t> &kem_ct);

void encryptFileKem(const string &pubKeyPath,
                    const string &inFilePath,
                    const string &outPkgPath,
                    bool force);

void decryptFileKem(const string &privKeyPath,
                    const string &inPkgPath,
                    const string &outFilePath,
                    bool force);

void runKemSelftest(const string &pubKeyPath, const string &privKeyPath);

} // namespace sec

namespace edu {

sec::Encapsulation rsasveEncapsulate(const EVP_PKEY *recipientPublicKey);
SecureBytes rsasveDecapsulate(const EVP_PKEY *recipientPrivateKey, const vector<uint8_t> &kem_ct);

} // namespace edu
