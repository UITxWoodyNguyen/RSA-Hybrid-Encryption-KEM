#include "rsa_kem.hpp"
#include "key_io.hpp"
#include "package.hpp"
#include "aead.hpp"
#include "utils.hpp"
#include "rsa_encoding.hpp"
#include "bn_math.hpp"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <fstream>
#include <cassert>

namespace sec {

Encapsulation encapsulate(EVP_PKEY *recipientPublicKey) {
    if (recipientPublicKey == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null recipient public key in encapsulate");
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, recipientPublicKey, nullptr));
    if (!ctx) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_CTX_new_from_pkey failed: " + drainOpenSslErrors());
    }

    if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encapsulate_init failed: " + drainOpenSslErrors());
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx.get(), "RSASVE") <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_CTX_set_kem_op failed: " + drainOpenSslErrors());
    }

    size_t ctLen = 0;
    size_t zLen = 0;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ctLen, nullptr, &zLen) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encapsulate size query failed: " + drainOpenSslErrors());
    }

    Encapsulation result;
    result.kem_ct.resize(ctLen);
    result.shared_secret.resize(zLen);

    if (EVP_PKEY_encapsulate(ctx.get(), result.kem_ct.data(), &ctLen,
                             result.shared_secret.data(), &zLen) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encapsulate failed: " + drainOpenSslErrors());
    }
    result.kem_ct.resize(ctLen);
    result.shared_secret.resize(zLen);

    return result;
}

SecureBytes decapsulate(EVP_PKEY *recipientPrivateKey, const vector<uint8_t> &kem_ct) {
    if (recipientPrivateKey == nullptr) {
        return SecureBytes();
    }

    BIGNUM *rawN = nullptr;
    if (EVP_PKEY_get_bn_param(recipientPrivateKey, OSSL_PKEY_PARAM_RSA_N, &rawN) != 1 || rawN == nullptr) {
        return SecureBytes();
    }
    BignumPtr n(rawN);
    size_t k = static_cast<size_t>(BN_num_bytes(n.get()));
    if (kem_ct.size() != k) {
        return SecureBytes();
    }

    BIGNUM *rawC = BN_bin2bn(kem_ct.data(), static_cast<int>(kem_ct.size()), nullptr);
    if (rawC == nullptr) {
        return SecureBytes();
    }
    BignumPtr c(rawC);

    if (BN_is_zero(c.get()) || BN_cmp(c.get(), n.get()) >= 0) {
        return SecureBytes();
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, recipientPrivateKey, nullptr));
    if (!ctx) {
        return SecureBytes();
    }

    if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
        return SecureBytes();
    }

    if (EVP_PKEY_CTX_set_kem_op(ctx.get(), "RSASVE") <= 0) {
        return SecureBytes();
    }

    size_t zLen = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &zLen, kem_ct.data(), kem_ct.size()) <= 0) {
        ERR_clear_error();
        return SecureBytes();
    }

    SecureBytes Z(zLen);
    if (EVP_PKEY_decapsulate(ctx.get(), Z.data(), &zLen, kem_ct.data(), kem_ct.size()) <= 0) {
        ERR_clear_error();
        return SecureBytes();
    }
    Z.resize(zLen);
    return Z;
}

SecureBytes deriveAesKey(const SecureBytes &Z,
                         const vector<uint8_t> &keyId,
                         const vector<uint8_t> &kem_ct) {
    if (Z.empty() || keyId.size() != 32 || kem_ct.empty()) {
        throw LabException(StatusCodes::UsageOrInputError, "Invalid parameters to deriveAesKey");
    }

    const char label[] = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1";
    vector<uint8_t> info(label, label + strlen(label));
    info.pb(0x00);
    info.insert(info.end(), keyId.begin(), keyId.end());

    uint16_t k = static_cast<uint16_t>(kem_ct.size());
    info.pb(static_cast<uint8_t>((k >> 8) & 0xff));
    info.pb(static_cast<uint8_t>(k & 0xff));
    info.insert(info.end(), kem_ct.begin(), kem_ct.end());

    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        throw LabException(StatusCodes::InternalError, "EVP_KDF_fetch HKDF failed: " + drainOpenSslErrors());
    }

    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        throw LabException(StatusCodes::InternalError, "EVP_KDF_CTX_new failed");
    }

    char digestName[] = "SHA256";
    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digestName, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(Z.data()), Z.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size());
    *p = OSSL_PARAM_construct_end();

    SecureBytes aesKey(32);
    if (EVP_KDF_derive(kctx.get(), aesKey.data(), 32, params) != 1) {
        throw LabException(StatusCodes::InternalError, "EVP_KDF_derive failed: " + drainOpenSslErrors());
    }

    return aesKey;
}

void encryptFileKem(const string &pubKeyPath,
                    const string &inFilePath,
                    const string &outPkgPath,
                    bool force) {
    if (!force && utils::fileExists(outPkgPath)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + outPkgPath);
    }

    EvpPkeyPtr pubKey = loadKeyStrict(pubKeyPath, KeyType::Public);
    size_t k = static_cast<size_t>(EVP_PKEY_get_size(pubKey.get()));
    vector<uint8_t> kid = computeKeyId(pubKey.get());

    Encapsulation enc = encapsulate(pubKey.get());
    SecureBytes aesKey = deriveAesKey(enc.shared_secret, kid, enc.kem_ct);

    vector<uint8_t> nonce(12);
    if (RAND_bytes(nonce.data(), 12) != 1) {
        throw LabException(StatusCodes::InternalError, "RAND_bytes failed for nonce");
    }

    uint64_t fileSize = utils::getFileLength(inFilePath);
    PackageHeader header;
    header.version = FORMAT_VERSION_1;
    header.mode = MODE_KEM_PROFILE;
    header.reserved = 0x0000;
    header.klen = static_cast<uint16_t>(k);
    header.wrapped_key_or_ct = enc.kem_ct;
    header.key_id = kid;
    header.nonce = nonce;
    header.ct_len = fileSize;

    vector<uint8_t> serializedHeader = header.serialize();

    ifstream inStream(inFilePath, ios::binary);
    if (!inStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open input plaintext file: " + inFilePath);
    }

    string tempOutPkg = outPkgPath + ".part";
    utils::deleteFileIfExists(tempOutPkg);

    ofstream outStream(tempOutPkg, ios::binary | ios::trunc);
    if (!outStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open temporary output package file: " + tempOutPkg);
    }

    outStream.write(reinterpret_cast<const char *>(serializedHeader.data()), serializedHeader.size());

    vector<uint8_t> tag;
    gcmEncryptStream(aesKey, nonce, serializedHeader, inStream, outStream, tag);

    outStream.write(reinterpret_cast<const char *>(tag.data()), tag.size());
    outStream.close();
    inStream.close();

    utils::safeAtomicRename(tempOutPkg, outPkgPath, force);
}

void decryptFileKem(const string &privKeyPath,
                    const string &inPkgPath,
                    const string &outFilePath,
                    bool force) {
    if (!force && utils::fileExists(outFilePath)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + outFilePath);
    }

    EvpPkeyPtr privKey = loadKeyStrict(privKeyPath, KeyType::Private);
    uint16_t expectedK = static_cast<uint16_t>(EVP_PKEY_get_size(privKey.get()));
    vector<uint8_t> myKeyId = computeKeyId(privKey.get());

    uint64_t totalFileSize = utils::getFileLength(inPkgPath);
    ifstream inPkgStream(inPkgPath, ios::binary);
    if (!inPkgStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open package file: " + inPkgPath);
    }

    PackageHeader header = PackageHeader::parseFromStream(inPkgStream, totalFileSize, expectedK);
    if (header.mode != MODE_KEM_PROFILE) {
        throw LabException(StatusCodes::DataError, "Package mode mismatch (expected Mode 0x02 RSASVE KEM)");
    }

    if (CRYPTO_memcmp(header.key_id.data(), myKeyId.data(), 32) != 0) {
        throw LabException(StatusCodes::CryptoFailure, "decryption failed: recipient key ID mismatch");
    }

    inPkgStream.seekg(static_cast<streamoff>(totalFileSize - 16), ios::beg);
    vector<uint8_t> expectedTag(16);
    inPkgStream.read(reinterpret_cast<char *>(expectedTag.data()), 16);

    inPkgStream.seekg(static_cast<streamoff>(header.raw_header.size()), ios::beg);

    SecureBytes Z = decapsulate(privKey.get(), header.wrapped_key_or_ct);
    if (Z.empty()) {
        throw LabException(StatusCodes::CryptoFailure, "decryption failed");
    }

    SecureBytes aesKey = deriveAesKey(Z, header.key_id, header.wrapped_key_or_ct);

    string tempOutPath = outFilePath + ".part";
    utils::deleteFileIfExists(tempOutPath);

    ofstream outPlainStream(tempOutPath, ios::binary | ios::trunc);
    if (!outPlainStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot create temporary decrypted output file: " + tempOutPath);
    }

    bool verified = gcmDecryptStream(aesKey, header.nonce, header.raw_header, inPkgStream,
                                     header.ct_len, expectedTag, outPlainStream);
    outPlainStream.close();
    inPkgStream.close();

    if (!verified) {
        utils::deleteFileIfExists(tempOutPath);
        throw LabException(StatusCodes::CryptoFailure, "decryption failed");
    }

    utils::safeAtomicRename(tempOutPath, outFilePath, force);
}

void runKemSelftest(const string &pubKeyPath, const string &privKeyPath) {
    cout << "== KEM Self-Test Suite ==\n";
    EvpPkeyPtr pubKey = loadKeyStrict(pubKeyPath, KeyType::Public);
    EvpPkeyPtr privKey = loadKeyStrict(privKeyPath, KeyType::Private);

    bool et1Pass = true;
    vector<vector<uint8_t>> previousCts;
    previousCts.reserve(100);

    REP(i, 0, 100) {
        Encapsulation enc = encapsulate(pubKey.get());
        SecureBytes zDec = decapsulate(privKey.get(), enc.kem_ct);
        if (zDec.size() != enc.shared_secret.size() ||
            CRYPTO_memcmp(zDec.data(), enc.shared_secret.data(), zDec.size()) != 0) {
            et1Pass = false;
        }
        for (const auto &prev : previousCts) {
            if (prev == enc.kem_ct) {
                et1Pass = false;
            }
        }
        previousCts.pb(enc.kem_ct);
    }
    cout << "  [" << (et1Pass ? "PASS" : "FAIL") << "] E-T1: 100 EVP encapsulate/decapsulate rounds\n";

    bool et2Pass = true;
    {
        Encapsulation eduEnc = edu::rsasveEncapsulate(pubKey.get());
        SecureBytes evpZ = decapsulate(privKey.get(), eduEnc.kem_ct);
        if (evpZ.size() != eduEnc.shared_secret.size() ||
            CRYPTO_memcmp(evpZ.data(), eduEnc.shared_secret.data(), evpZ.size()) != 0) {
            et2Pass = false;
        }

        Encapsulation evpEnc = encapsulate(pubKey.get());
        SecureBytes eduZ = edu::rsasveDecapsulate(privKey.get(), evpEnc.kem_ct);
        if (eduZ.size() != evpEnc.shared_secret.size() ||
            CRYPTO_memcmp(eduZ.data(), evpEnc.shared_secret.data(), eduZ.size()) != 0) {
            et2Pass = false;
        }
    }
    cout << "  [" << (et2Pass ? "PASS" : "FAIL") << "] E-T2: Interop edu <-> EVP\n";

    bool et3Pass = false;
    {
        SecureBytes ikm(22, 0x0b);
        vector<uint8_t> salt;
        REP(i, 0, 13) salt.pb(static_cast<uint8_t>(i));
        vector<uint8_t> info;
        FOR(i, 0xf0, 0xf9) info.pb(static_cast<uint8_t>(i));

        const string expectedOkmHex =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
        EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
        char digest[] = "SHA256";
        OSSL_PARAM params[5];
        OSSL_PARAM *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size());
        *p = OSSL_PARAM_construct_end();

        vector<uint8_t> okm(42);
        if (EVP_KDF_derive(kctx.get(), okm.data(), 42, params) == 1) {
            string derivedHex = utils::bytesToHex(okm);
            if (derivedHex == expectedOkmHex) {
                et3Pass = true;
            }
        }
    }
    cout << "  [" << (et3Pass ? "PASS" : "FAIL") << "] E-T3: HKDF RFC 5869 Test Case 1\n";

    bool et4Pass = false;
    {
        Encapsulation testEnc = encapsulate(pubKey.get());
        vector<uint8_t> kid = computeKeyId(pubKey.get());
        SecureBytes key1 = deriveAesKey(testEnc.shared_secret, kid, testEnc.kem_ct);

        vector<uint8_t> modifiedKid = kid;
        modifiedKid[0] ^= 0x01;
        SecureBytes key2 = deriveAesKey(testEnc.shared_secret, modifiedKid, testEnc.kem_ct);

        if (CRYPTO_memcmp(key1.data(), key2.data(), 32) != 0) {
            et4Pass = true;
        }
    }
    cout << "  [" << (et4Pass ? "PASS" : "FAIL") << "] E-T4: Context binding protects against parameter substitution\n";

    if (!et1Pass || !et2Pass || !et3Pass || !et4Pass) {
        throw LabException(StatusCodes::CryptoFailure, "One or more KEM self-tests failed");
    }
}

} // namespace sec

namespace edu {

sec::Encapsulation rsasveEncapsulate(const EVP_PKEY *recipientPublicKey) {
    if (recipientPublicKey == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null public key in rsasveEncapsulate");
    }
    BIGNUM *rawN = nullptr;
    BIGNUM *rawE = nullptr;
    if (EVP_PKEY_get_bn_param(recipientPublicKey, OSSL_PKEY_PARAM_RSA_N, &rawN) != 1 ||
        EVP_PKEY_get_bn_param(recipientPublicKey, OSSL_PKEY_PARAM_RSA_E, &rawE) != 1) {
        throw LabException(StatusCodes::InternalError, "Failed to get public parameters (n, e)");
    }
    BignumPtr n(rawN);
    BignumPtr e(rawE);
    size_t k = static_cast<size_t>(BN_num_bytes(n.get()));

    BnCtxPtr ctx = makeBnCtx();
    BignumPtr range = makeBignum();
    BignumPtr z = makeBignum();
    BignumPtr c = makeBignum();

    BN_copy(range.get(), n.get());
    BN_sub_word(range.get(), 3);
    if (BN_rand_range(z.get(), range.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_rand_range failed");
    }
    BN_add_word(z.get(), 2);

    if (BN_mod_exp(c.get(), z.get(), e.get(), n.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_exp failed in rsasveEncapsulate");
    }

    sec::Encapsulation enc;
    enc.kem_ct.assign(k, 0);
    i2osp(c.get(), k, enc.kem_ct);

    vector<uint8_t> zBytes(k, 0);
    i2osp(z.get(), k, zBytes);
    enc.shared_secret.assign(zBytes.data(), zBytes.data() + zBytes.size());
    OPENSSL_cleanse(zBytes.data(), zBytes.size());

    return enc;
}

SecureBytes rsasveDecapsulate(const EVP_PKEY *recipientPrivateKey, const vector<uint8_t> &kem_ct) {
    if (recipientPrivateKey == nullptr) {
        return SecureBytes();
    }
    BIGNUM *rawN = nullptr;
    BIGNUM *rawD = nullptr;
    if (EVP_PKEY_get_bn_param(recipientPrivateKey, OSSL_PKEY_PARAM_RSA_N, &rawN) != 1 ||
        EVP_PKEY_get_bn_param(recipientPrivateKey, OSSL_PKEY_PARAM_RSA_D, &rawD) != 1) {
        return SecureBytes();
    }
    BignumPtr n(rawN);
    BignumPtr d(rawD);
    size_t k = static_cast<size_t>(BN_num_bytes(n.get()));

    if (kem_ct.size() != k) {
        return SecureBytes();
    }

    BignumPtr c = os2ip(kem_ct);
    if (BN_is_zero(c.get()) || BN_cmp(c.get(), n.get()) >= 0) {
        return SecureBytes();
    }

    BnCtxPtr ctx = makeBnCtx();
    BignumPtr z = makeBignum();
    if (BN_mod_exp(z.get(), c.get(), d.get(), n.get(), ctx.get()) != 1) {
        return SecureBytes();
    }

    vector<uint8_t> zBytes(k, 0);
    i2osp(z.get(), k, zBytes);
    SecureBytes Z(zBytes.data(), zBytes.size());
    OPENSSL_cleanse(zBytes.data(), zBytes.size());
    return Z;
}

} // namespace edu
