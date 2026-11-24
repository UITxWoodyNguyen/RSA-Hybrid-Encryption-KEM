#include "rsa_encoding.hpp"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <algorithm>

namespace edu {

BignumPtr os2ip(const vector<uint8_t> &octets) {
    if (octets.empty()) {
        BignumPtr zero = makeBignum();
        BN_zero(zero.get());
        return zero;
    }
    BIGNUM *bn = BN_bin2bn(octets.data(), static_cast<int>(octets.size()), nullptr);
    if (bn == nullptr) {
        throw LabException(StatusCodes::InternalError, "BN_bin2bn failed to convert octets to integer");
    }
    return BignumPtr(bn);
}

bool i2osp(const BIGNUM *x, size_t target_len, vector<uint8_t> &out) {
    if (x == nullptr) return false;
    out.assign(target_len, 0);
    int written = BN_bn2binpad(x, out.data(), static_cast<int>(target_len));
    return (written >= 0);
}

BignumPtr textbookEncrypt(const BIGNUM *m, const BIGNUM *e, const BIGNUM *n, BN_CTX *ctx) {
    if (m == nullptr || e == nullptr || n == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null operand in textbookEncrypt");
    }
    if (BN_is_negative(m) || BN_cmp(m, n) >= 0) {
        throw LabException(StatusCodes::CryptoFailure, "Message representative out of range (must satisfy 0 <= m < n)");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr c = makeBignum();
    if (BN_mod_exp(c.get(), m, e, n, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_exp failed in textbookEncrypt");
    }
    return c;
}

BignumPtr textbookDecrypt(const BIGNUM *c, const BIGNUM *d, const BIGNUM *n, BN_CTX *ctx) {
    if (c == nullptr || d == nullptr || n == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null operand in textbookDecrypt");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr m = makeBignum();
    if (BN_mod_exp(m.get(), c, d, n, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_exp failed in textbookDecrypt");
    }
    return m;
}

static vector<uint8_t> mgf1Sha256(const vector<uint8_t> &seed, size_t maskLen) {
    vector<uint8_t> mask;
    mask.reserve(maskLen + 32);
    uint32_t counter = 0;
    while (mask.size() < maskLen) {
        vector<uint8_t> inputBlock = seed;
        inputBlock.pb(static_cast<uint8_t>((counter >> 24) & 0xff));
        inputBlock.pb(static_cast<uint8_t>((counter >> 16) & 0xff));
        inputBlock.pb(static_cast<uint8_t>((counter >> 8) & 0xff));
        inputBlock.pb(static_cast<uint8_t>(counter & 0xff));

        uint8_t hashBuf[SHA256_DIGEST_LENGTH];
        SHA256(inputBlock.data(), inputBlock.size(), hashBuf);
        mask.insert(mask.end(), hashBuf, hashBuf + SHA256_DIGEST_LENGTH);
        ++counter;
    }
    mask.resize(maskLen);
    return mask;
}

vector<uint8_t> educationalOaepEncode(const vector<uint8_t> &msg, size_t k) {
    constexpr size_t hLen = SHA256_DIGEST_LENGTH;
    if (msg.size() > k - 2 * hLen - 2) {
        throw LabException(StatusCodes::UsageOrInputError, "Message too long for RSA-OAEP encoding");
    }

    vector<uint8_t> lHash(hLen);
    SHA256(nullptr, 0, lHash.data());

    vector<uint8_t> db = lHash;
    size_t psLen = k - msg.size() - 2 * hLen - 2;
    db.insert(db.end(), psLen, 0x00);
    db.pb(0x01);
    db.insert(db.end(), msg.begin(), msg.end());

    vector<uint8_t> seed(hLen);
    if (RAND_bytes(seed.data(), static_cast<int>(hLen)) != 1) {
        throw LabException(StatusCodes::InternalError, "RAND_bytes failed for OAEP seed");
    }

    vector<uint8_t> dbMask = mgf1Sha256(seed, k - hLen - 1);
    vector<uint8_t> maskedDB(db.size());
    REP(i, 0, static_cast<int>(db.size())) {
        maskedDB[i] = db[i] ^ dbMask[i];
    }

    vector<uint8_t> seedMask = mgf1Sha256(maskedDB, hLen);
    vector<uint8_t> maskedSeed(hLen);
    REP(i, 0, static_cast<int>(hLen)) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    vector<uint8_t> em;
    em.reserve(k);
    em.pb(0x00);
    em.insert(em.end(), maskedSeed.begin(), maskedSeed.end());
    em.insert(em.end(), maskedDB.begin(), maskedDB.end());
    return em;
}

bool educationalOaepDecode(const vector<uint8_t> &em, size_t k, vector<uint8_t> &msg) {
    constexpr size_t hLen = SHA256_DIGEST_LENGTH;
    if (em.size() != k || k < 2 * hLen + 2) {
        return false;
    }

    uint8_t y = em[0];
    vector<uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + hLen);
    vector<uint8_t> maskedDB(em.begin() + 1 + hLen, em.end());

    vector<uint8_t> seedMask = mgf1Sha256(maskedDB, hLen);
    vector<uint8_t> seed(hLen);
    REP(i, 0, static_cast<int>(hLen)) {
        seed[i] = maskedSeed[i] ^ seedMask[i];
    }

    vector<uint8_t> dbMask = mgf1Sha256(seed, k - hLen - 1);
    vector<uint8_t> db(maskedDB.size());
    REP(i, 0, static_cast<int>(maskedDB.size())) {
        db[i] = maskedDB[i] ^ dbMask[i];
    }

    vector<uint8_t> expectedLHash(hLen);
    SHA256(nullptr, 0, expectedLHash.data());

    bool valid = (y == 0x00);
    bool hashMatches = equal(expectedLHash.begin(), expectedLHash.end(), db.begin());
    valid = valid && hashMatches;

    size_t idx = hLen;
    while (idx < db.size() && db[idx] == 0x00) {
        ++idx;
    }
    bool separatorFound = (idx < db.size() && db[idx] == 0x01);
    valid = valid && separatorFound;

    if (valid) {
        msg.assign(db.begin() + idx + 1, db.end());
    }
    return valid;
}

} // namespace edu
