#pragma once

#include "ossl_raii.hpp"
#include "package.hpp"

namespace sec {

vector<uint8_t> oaepWrapKey(const EVP_PKEY *recipientPubKey, const SecureBytes &symmetricKey);
SecureBytes oaepUnwrapKey(const EVP_PKEY *recipientPrivKey, const vector<uint8_t> &wrappedKey);

void encryptFileOaep(const string &pubKeyPath,
                     const string &inFilePath,
                     const string &outPkgPath,
                     bool force);

void decryptFileOaep(const string &privKeyPath,
                     const string &inPkgPath,
                     const string &outFilePath,
                     bool force);

} // namespace sec
