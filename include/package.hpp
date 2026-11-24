#pragma once

#include "ossl_raii.hpp"

namespace sec {

constexpr uint8_t MAGIC[4] = {'L', '2', 'P', 'K'};
constexpr uint8_t FORMAT_VERSION_1 = 0x01;
constexpr uint8_t MODE_OAEP_TRANSPORT = 0x01;
constexpr uint8_t MODE_KEM_PROFILE = 0x02;
constexpr uint64_t MAX_CIPHERTEXT_SIZE = 1ULL * 1024 * 1024 * 1024;

struct PackageHeader {
    uint8_t version = 1;
    uint8_t mode = 1;
    uint16_t reserved = 0;
    uint16_t klen = 0;
    vector<uint8_t> wrapped_key_or_ct;
    vector<uint8_t> key_id;
    vector<uint8_t> nonce;
    uint64_t ct_len = 0;
    vector<uint8_t> raw_header;

    vector<uint8_t> serialize() const;
    static PackageHeader parseFromStream(istream &stream, uint64_t totalFileSize, uint16_t expectedKlen);
};

} // namespace sec
