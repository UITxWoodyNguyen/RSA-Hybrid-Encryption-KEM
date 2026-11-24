#pragma once

#include "common_defs.hpp"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>

using namespace std;

struct BnDeleter {
    void operator()(BIGNUM *bn) const {
        if (bn != nullptr) {
            BN_clear_free(bn);
        }
    }
};

struct BnCtxDeleter {
    void operator()(BN_CTX *ctx) const {
        if (ctx != nullptr) {
            BN_CTX_free(ctx);
        }
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY *key) const {
        if (key != nullptr) {
            EVP_PKEY_free(key);
        }
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *pctx) const {
        if (pctx != nullptr) {
            EVP_PKEY_CTX_free(pctx);
        }
    }
};

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX *cctx) const {
        if (cctx != nullptr) {
            EVP_CIPHER_CTX_free(cctx);
        }
    }
};

struct BioDeleter {
    void operator()(BIO *b) const {
        if (b != nullptr) {
            BIO_free(b);
        }
    }
};

struct EvpKdfDeleter {
    void operator()(EVP_KDF *kdf) const {
        if (kdf != nullptr) {
            EVP_KDF_free(kdf);
        }
    }
};

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX *kctx) const {
        if (kctx != nullptr) {
            EVP_KDF_CTX_free(kctx);
        }
    }
};

struct OpensslMemDeleter {
    void operator()(void *ptr) const {
        if (ptr != nullptr) {
            OPENSSL_free(ptr);
        }
    }
};

using BignumPtr = unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = unique_ptr<BN_CTX, BnCtxDeleter>;
using EvpPkeyPtr = unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpCipherCtxPtr = unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using BioPtr = unique_ptr<BIO, BioDeleter>;
using EvpKdfPtr = unique_ptr<EVP_KDF, EvpKdfDeleter>;
using EvpKdfCtxPtr = unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;
using OpensslStrPtr = unique_ptr<char, OpensslMemDeleter>;

inline BignumPtr makeBignum() {
    BIGNUM *bn = BN_new();
    if (bn == nullptr) {
        throw LabException(StatusCodes::InternalError, "BN_new() failed to allocate memory");
    }
    return BignumPtr(bn);
}

inline BnCtxPtr makeBnCtx() {
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == nullptr) {
        throw LabException(StatusCodes::InternalError, "BN_CTX_new() failed to allocate context");
    }
    return BnCtxPtr(ctx);
}

class SecureBytes {
private:
    vector<uint8_t> buffer;

public:
    SecureBytes() = default;
    explicit SecureBytes(size_t size, uint8_t val = 0) : buffer(size, val) {}
    SecureBytes(const uint8_t *src, size_t len) : buffer(src, src + len) {}
    SecureBytes(const SecureBytes &other) = default;
    SecureBytes(SecureBytes &&other) noexcept = default;
    SecureBytes& operator=(const SecureBytes &other) = default;
    SecureBytes& operator=(SecureBytes &&other) noexcept = default;

    ~SecureBytes() {
        cleanse();
    }

    void cleanse() {
        if (!buffer.empty()) {
            OPENSSL_cleanse(buffer.data(), buffer.size());
        }
    }

    void resize(size_t new_size, uint8_t val = 0) {
        buffer.resize(new_size, val);
    }

    void assign(size_t count, uint8_t val) {
        cleanse();
        buffer.assign(count, val);
    }

    void assign(const uint8_t *first, const uint8_t *last) {
        cleanse();
        buffer.assign(first, last);
    }

    void clear() {
        cleanse();
        buffer.clear();
    }

    uint8_t *data() noexcept { return buffer.data(); }
    const uint8_t *data() const noexcept { return buffer.data(); }
    size_t size() const noexcept { return buffer.size(); }
    bool empty() const noexcept { return buffer.empty(); }

    uint8_t& operator[](size_t idx) { return buffer[idx]; }
    const uint8_t& operator[](size_t idx) const { return buffer[idx]; }

    auto begin() noexcept { return buffer.begin(); }
    auto end() noexcept { return buffer.end(); }
    auto begin() const noexcept { return buffer.begin(); }
    auto end() const noexcept { return buffer.end(); }

    const vector<uint8_t>& rawVector() const noexcept { return buffer; }
    vector<uint8_t>& rawVector() noexcept { return buffer; }
};

namespace sec {
    using SecureBytes = ::SecureBytes;
}

namespace edu {
    using SecureBytes = ::SecureBytes;
}

string drainOpenSslErrors();
