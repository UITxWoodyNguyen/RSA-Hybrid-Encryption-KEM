#pragma once

#include "ossl_raii.hpp"

namespace sec {

enum class KeyType {
    Public,
    Private
};

enum class KeyEncoding {
    PEM,
    DER
};

EvpPkeyPtr generateProductionRsaKey(int bits);
void savePrivateKey(const EVP_PKEY *key, const string &path, KeyEncoding encoding, bool force);
void savePublicKey(const EVP_PKEY *key, const string &path, KeyEncoding encoding, bool force);
EvpPkeyPtr loadKeyStrict(const string &path, KeyType expectedType, KeyEncoding *detectedEncoding = nullptr);
vector<uint8_t> computeKeyId(const EVP_PKEY *key);
string formatKeyIdHex(const EVP_PKEY *key);
bool compareKeysMatch(const EVP_PKEY *privKey, const EVP_PKEY *pubKey);
bool validateKeyStructure(const EVP_PKEY *key, KeyType type);

} // namespace sec
