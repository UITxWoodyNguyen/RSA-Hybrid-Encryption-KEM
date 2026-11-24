#pragma once

#include "ossl_raii.hpp"

namespace sec {

constexpr size_t GCM_KEY_LEN = 32;
constexpr size_t GCM_NONCE_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;
constexpr size_t CHUNK_SIZE = 65536;

void gcmEncryptStream(const SecureBytes &key,
                      const vector<uint8_t> &nonce,
                      const vector<uint8_t> &aad,
                      istream &inStream,
                      ostream &outStream,
                      vector<uint8_t> &tagOut);

bool gcmDecryptStream(const SecureBytes &key,
                      const vector<uint8_t> &nonce,
                      const vector<uint8_t> &aad,
                      istream &inStream,
                      uint64_t cipherLen,
                      const vector<uint8_t> &expectedTag,
                      ostream &outStream);

} // namespace sec
