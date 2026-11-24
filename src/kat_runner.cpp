#include "kat_runner.hpp"
#include "bn_math.hpp"
#include "rsa_params.hpp"
#include "key_io.hpp"
#include "rsa_encoding.hpp"
#include "aead.hpp"
#include "package.hpp"
#include "hybrid_oaep.hpp"
#include "rsa_kem.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/core_names.h>

namespace kat {

static void printPass(const string &id, const string &desc) {
    cout << "  [PASS] " << left << setw(8) << id << " " << desc << "\n";
}

static void printFail(const string &id, const string &desc) {
    cout << "  [FAIL] " << left << setw(8) << id << " " << desc << "\n";
}

int runAllAcceptanceTests() {
    int totalFailed = 0;
    cout << "============================================================\n";
    cout << "       LAB 3 COMPREHENSIVE ACCEPTANCE TEST SUITE (KAT)     \n";
    cout << "============================================================\n\n";

    cout << "[Task A: Modular Arithmetic Acceptance Tests]\n";
    {
        BignumPtr a = edu::parseDecimalStrict("7");
        BignumPtr b = edu::parseDecimalStrict("13");
        BignumPtr m = edu::parseDecimalStrict("33");
        BignumPtr res = edu::myModExp(a.get(), b.get(), m.get());
        if (BN_is_word(res.get(), 13)) {
            printPass("A-T1", "7^13 mod 33 == 13");
        } else {
            printFail("A-T1", "7^13 mod 33 != 13");
            totalFailed++;
        }
    }
    {
        BignumPtr a = edu::parseDecimalStrict("252");
        BignumPtr b = edu::parseDecimalStrict("105");
        BignumPtr g = edu::calcGcd(a.get(), b.get());
        if (BN_is_word(g.get(), 21)) {
            printPass("A-T2", "gcd(252, 105) == 21");
        } else {
            printFail("A-T2", "gcd(252, 105) != 21");
            totalFailed++;
        }
    }
    {
        BignumPtr a = edu::parseDecimalStrict("7");
        BignumPtr m = edu::parseDecimalStrict("33");
        BignumPtr inv = edu::myModInverse(a.get(), m.get(), nullptr);
        if (inv && BN_is_word(inv.get(), 19)) {
            printPass("A-T3", "7^-1 mod 33 == 19 (7*19 = 133 = 1 mod 33)");
        } else {
            printFail("A-T3", "7^-1 mod 33 failed");
            totalFailed++;
        }
    }
    {
        BignumPtr a = edu::parseDecimalStrict("6");
        BignumPtr m = edu::parseDecimalStrict("33");
        BignumPtr gcdOut = makeBignum();
        BignumPtr inv = edu::myModInverse(a.get(), m.get(), gcdOut.get());
        if (!inv && BN_is_word(gcdOut.get(), 3)) {
            printPass("A-T4", "6^-1 mod 33 correctly reports no inverse (gcd = 3)");
        } else {
            printFail("A-T4", "6^-1 mod 33 failed to detect missing inverse");
            totalFailed++;
        }
    }
    {
        BignumPtr a = edu::parseDecimalStrict("3");
        BignumPtr b = edu::parseDecimalStrict("5");
        BignumPtr m = edu::parseDecimalStrict("7");
        BignumPtr res = edu::modSub(a.get(), b.get(), m.get());
        if (BN_is_word(res.get(), 5)) {
            printPass("A-T5", "(3 - 5) mod 7 == 5");
        } else {
            printFail("A-T5", "(3 - 5) mod 7 failed");
            totalFailed++;
        }
    }
    {
        BignumPtr a = edu::parseDecimalStrict("18446744073709551615");
        BignumPtr b = edu::parseDecimalStrict("1");
        BignumPtr m = edu::parseDecimalStrict("18446744073709551629");
        BignumPtr res = edu::modAdd(a.get(), b.get(), m.get());
        char *str = BN_bn2dec(res.get());
        if (str != nullptr && string(str) == "18446744073709551616") {
            printPass("A-T6", "mod-add 64-bit overflow test: 18446744073709551616");
        } else {
            printFail("A-T6", "mod-add 64-bit overflow test failed");
            totalFailed++;
        }
        if (str != nullptr) OPENSSL_free(str);
    }
    {
        BignumPtr a = edu::parseDecimalStrict("123456789012345678901234567890");
        BignumPtr b = edu::parseDecimalStrict("65537");
        BignumPtr m = edu::parseDecimalStrict("170141183460469231731687303715884105727");
        BignumPtr res = edu::myModExp(a.get(), b.get(), m.get());
        char *str = BN_bn2dec(res.get());
        if (str != nullptr && string(str) == "43089841487593468092862748681566865937") {
            printPass("A-T7", "Large exponentiation verified against expected value");
        } else {
            printFail("A-T7", "Large exponentiation failed");
            totalFailed++;
        }
        if (str != nullptr) OPENSSL_free(str);
    }
    {
        BignumPtr a = edu::parseDecimalStrict("65537");
        BignumPtr m = edu::parseDecimalStrict("170141183460469231731687303715884105727");
        BignumPtr res = edu::myModInverse(a.get(), m.get(), nullptr);
        char *str = BN_bn2dec(res.get());
        if (str != nullptr && string(str) == "5192217631581220737344928932233215") {
            printPass("A-T8", "Large modular inverse verified against expected value");
        } else {
            printFail("A-T8", "Large modular inverse failed");
            totalFailed++;
        }
        if (str != nullptr) OPENSSL_free(str);
    }
    {
        bool passedValidation = true;
        try { edu::parseDecimalStrict("-3"); passedValidation = false; } catch (...) {}
        try { edu::parseDecimalStrict("12a"); passedValidation = false; } catch (...) {}
        try { edu::parseDecimalStrict(""); passedValidation = false; } catch (...) {}
        BignumPtr a = edu::parseDecimalStrict("1");
        BignumPtr zeroMod = edu::parseDecimalStrict("0");
        try { edu::myModExp(a.get(), a.get(), zeroMod.get()); passedValidation = false; } catch (...) {}
        if (passedValidation) {
            printPass("A-T9", "Input validation strictly rejects negative, non-digit, empty, and m=0");
        } else {
            printFail("A-T9", "Input validation did not catch invalid inputs");
            totalFailed++;
        }
    }

    cout << "\n[Task B: RSA Parameters & Key Management Tests]\n";
    {
        edu::EducationalRsaParams params = edu::generateEducationalRsaParams(512);
        int bits = BN_num_bits(params.n.get());
        bool relationsValid = edu::verifyEducationalParams(params, false);
        if ((bits == 511 || bits == 512) && relationsValid) {
            printPass("B-T1", "Educational RSA-512 relations verified (e*d=1 mod phi/lambda, CRT, random dec)");
        } else {
            printFail("B-T1", "Educational RSA-512 relations failed");
            totalFailed++;
        }
    }
    EvpPkeyPtr testKey3072 = sec::generateProductionRsaKey(3072);
    {
        if (EVP_PKEY_get_bits(testKey3072.get()) == 3072 &&
            sec::validateKeyStructure(testKey3072.get(), sec::KeyType::Private)) {
            printPass("B-T2", "Production RSA-3072 generated and validated with EVP_PKEY pairwise check");
        } else {
            printFail("B-T2", "Production RSA-3072 generation failed");
            totalFailed++;
        }
    }
    {
        if (sec::compareKeysMatch(testKey3072.get(), testKey3072.get())) {
            printPass("B-T3", "Key matching confirmed with EVP_PKEY_eq");
        } else {
            printFail("B-T3", "Key matching check failed");
            totalFailed++;
        }
    }
    {
        EvpPkeyPtr secondKey = sec::generateProductionRsaKey(2048);
        if (!sec::compareKeysMatch(secondKey.get(), testKey3072.get())) {
            printPass("B-T4", "Different keypairs correctly detected as MISMATCH");
        } else {
            printFail("B-T4", "Different keypairs incorrectly reported as MATCH");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> id = sec::computeKeyId(testKey3072.get());
        if (id.size() == 32) {
            printPass("B-T6", "Key ID computed via SHA-256 over SPKI DER: " + utils::bytesToHex(id).substr(0, 16) + "...");
        } else {
            printFail("B-T6", "Key ID computation failed");
            totalFailed++;
        }
    }

    cout << "\n[Task C: OS2IP / I2OSP and Textbook RSA Tests]\n";
    {
        vector<uint8_t> in = utils::hexToBytes("000001");
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 3, out);
        if (BN_is_one(x.get()) && ok && utils::bytesToHex(out) == "000001") {
            printPass("C-T1", "OS2IP(000001) == 1, I2OSP(1, 3) == 000001");
        } else {
            printFail("C-T1", "C-T1 conversion failed");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> in = utils::hexToBytes("000001");
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 1, out);
        if (ok && utils::bytesToHex(out) == "01") {
            printPass("C-T2", "OS2IP(000001) == 1, I2OSP(1, 1) == 01 (leading zeros stripped by OS2IP)");
        } else {
            printFail("C-T2", "C-T2 conversion failed");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> in = utils::hexToBytes("0100");
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 2, out);
        if (BN_is_word(x.get(), 256) && ok && utils::bytesToHex(out) == "0100") {
            printPass("C-T3", "OS2IP(0100) == 256, I2OSP(256, 2) == 0100");
        } else {
            printFail("C-T3", "C-T3 conversion failed");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> in = utils::hexToBytes("0100");
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 1, out);
        if (!ok) {
            printPass("C-T4", "I2OSP(256, 1) correctly reports integer too large");
        } else {
            printFail("C-T4", "I2OSP(256, 1) did not detect integer too large");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> in = utils::hexToBytes("00ff00");
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 3, out);
        if (BN_is_word(x.get(), 65280) && ok && utils::bytesToHex(out) == "00ff00") {
            printPass("C-T5", "OS2IP(00ff00) == 65280, I2OSP(65280, 3) == 00ff00");
        } else {
            printFail("C-T5", "C-T5 conversion failed");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> in;
        BignumPtr x = edu::os2ip(in);
        vector<uint8_t> out;
        bool ok = edu::i2osp(x.get(), 2, out);
        if (BN_is_zero(x.get()) && ok && utils::bytesToHex(out) == "0000") {
            printPass("C-T6", "OS2IP(\"\") == 0, I2OSP(0, 2) == 0000");
        } else {
            printFail("C-T6", "C-T6 conversion failed");
            totalFailed++;
        }
    }
    {
        BnCtxPtr ctx = makeBnCtx();
        BignumPtr n = makeBignum(); BN_set_word(n.get(), 3233);
        BignumPtr e = makeBignum(); BN_set_word(e.get(), 17);
        BignumPtr d = makeBignum(); BN_set_word(d.get(), 2753);

        BignumPtr m65 = makeBignum(); BN_set_word(m65.get(), 65);
        BignumPtr c65 = edu::textbookEncrypt(m65.get(), e.get(), n.get(), ctx.get());
        BignumPtr dec65 = edu::textbookDecrypt(c65.get(), d.get(), n.get(), ctx.get());
        if (BN_is_word(c65.get(), 2790) && BN_is_word(dec65.get(), 65)) {
            printPass("C-T8", "Textbook RSA: Enc(65) == 2790, Dec(2790) == 65");
        } else {
            printFail("C-T8", "Textbook RSA worked example failed");
            totalFailed++;
        }

        BignumPtr m6 = makeBignum(); BN_set_word(m6.get(), 6);
        BignumPtr m7 = makeBignum(); BN_set_word(m7.get(), 7);
        BignumPtr c6 = edu::textbookEncrypt(m6.get(), e.get(), n.get(), ctx.get());
        BignumPtr c7 = edu::textbookEncrypt(m7.get(), e.get(), n.get(), ctx.get());
        BignumPtr cForged = makeBignum();
        BN_mod_mul(cForged.get(), c6.get(), c7.get(), n.get(), ctx.get());
        BignumPtr decForged = edu::textbookDecrypt(cForged.get(), d.get(), n.get(), ctx.get());
        if (BN_is_word(c6.get(), 824) && BN_is_word(c7.get(), 2369) &&
            BN_is_word(cForged.get(), 2557) && BN_is_word(decForged.get(), 42)) {
            printPass("C-T9", "Textbook RSA Malleability: Enc(6)*Enc(7) == 2557 = Enc(42), Decrypts to 42");
        } else {
            printFail("C-T9", "Textbook RSA Malleability failed");
            totalFailed++;
        }
    }

    cout << "\n[Task D: RSA-OAEP & AES-256-GCM Hybrid Encryption Tests]\n";
    {
        SecureBytes symmetricKey(32);
        RAND_bytes(symmetricKey.data(), 32);
        vector<uint8_t> wrapped = sec::oaepWrapKey(testKey3072.get(), symmetricKey);
        SecureBytes unwrapped = sec::oaepUnwrapKey(testKey3072.get(), wrapped);
        if (unwrapped.size() == 32 && CRYPTO_memcmp(unwrapped.data(), symmetricKey.data(), 32) == 0) {
            printPass("D-T1", "RSA-OAEP wrap and unwrap successfully recovered 32-byte AES key");
        } else {
            printFail("D-T1", "RSA-OAEP wrap and unwrap failed");
            totalFailed++;
        }
    }
    {
        SecureBytes key(32, 0x42);
        vector<uint8_t> w1 = sec::oaepWrapKey(testKey3072.get(), key);
        SecureBytes keyCopy(32, 0x42);
        vector<uint8_t> w2 = sec::oaepWrapKey(testKey3072.get(), keyCopy);
        if (w1 != w2) {
            printPass("D-T3", "Two independent encryptions of identical key yield distinct ciphertexts");
        } else {
            printFail("D-T3", "RSA-OAEP is deterministic (violates security requirement)");
            totalFailed++;
        }
    }
    {
        SecureBytes key(32, 0xaa);
        vector<uint8_t> nonce(12, 0x55);
        vector<uint8_t> aad = {'T', 'E', 'S', 'T'};
        string plain = "Sensitive confidential payload data.";
        istringstream inStream(plain);
        ostringstream outStream;
        vector<uint8_t> tag;
        sec::gcmEncryptStream(key, nonce, aad, inStream, outStream, tag);

        vector<uint8_t> tamperedTag = tag;
        tamperedTag[0] ^= 0x01;
        string cipherStr = outStream.str();
        istringstream decInStream(cipherStr);
        ostringstream decOutStream;
        bool decResult = sec::gcmDecryptStream(key, nonce, aad, decInStream, cipherStr.size(), tamperedTag, decOutStream);
        if (!decResult && decOutStream.str().empty()) {
            printPass("D-T4/5", "Tampered tag rejected cleanly; no unauthenticated plaintext released");
        } else {
            printFail("D-T4/5", "Tampered tag failed to be detected or unauthenticated plaintext leaked");
            totalFailed++;
        }
    }

    cout << "\n[Task E: RSASVE KEM & HKDF Tests]\n";
    {
        bool kemSelfTestsOk = true;
        try {
            vector<vector<uint8_t>> seenCts;
            seenCts.reserve(20);
            REP(round, 0, 20) {
                sec::Encapsulation enc = sec::encapsulate(testKey3072.get());
                SecureBytes z = sec::decapsulate(testKey3072.get(), enc.kem_ct);
                if (z.size() != enc.shared_secret.size() ||
                    CRYPTO_memcmp(z.data(), enc.shared_secret.data(), z.size()) != 0) {
                    kemSelfTestsOk = false;
                }
                seenCts.pb(enc.kem_ct);
            }

            sec::Encapsulation eduEnc = edu::rsasveEncapsulate(testKey3072.get());
            SecureBytes evpZ = sec::decapsulate(testKey3072.get(), eduEnc.kem_ct);
            if (evpZ.size() != eduEnc.shared_secret.size() ||
                CRYPTO_memcmp(evpZ.data(), eduEnc.shared_secret.data(), evpZ.size()) != 0) {
                kemSelfTestsOk = false;
            }

            SecureBytes ikm(22, 0x0b);
            vector<uint8_t> salt;
            REP(i, 0, 13) salt.pb(static_cast<uint8_t>(i));
            vector<uint8_t> info;
            FOR(i, 0xf0, 0xf9) info.pb(static_cast<uint8_t>(i));
            const string expectedOkmHex =
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

            EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
            EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
            char digestName[] = "SHA256";
            OSSL_PARAM params[5];
            OSSL_PARAM *p = params;
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digestName, 0);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t *>(ikm.data()), ikm.size());
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size());
            *p = OSSL_PARAM_construct_end();
            vector<uint8_t> okm(42);
            EVP_KDF_derive(kctx.get(), okm.data(), 42, params);
            if (utils::bytesToHex(okm) != expectedOkmHex) {
                kemSelfTestsOk = false;
            }
        } catch (...) {
            kemSelfTestsOk = false;
        }

        if (kemSelfTestsOk) {
            printPass("E-T1..4", "RSASVE KEM encapsulation, interop edu <-> EVP, and HKDF KAT all verified");
        } else {
            printFail("E-T1..4", "KEM self-tests failed");
            totalFailed++;
        }
    }
    {
        vector<uint8_t> zeroCt(384, 0x00);
        SecureBytes zZero = sec::decapsulate(testKey3072.get(), zeroCt);
        vector<uint8_t> maxCt(384, 0xff);
        SecureBytes zMax = sec::decapsulate(testKey3072.get(), maxCt);
        if (zZero.empty() && zMax.empty()) {
            printPass("E-T6", "Decapsulation strictly rejects c = 0 and c >= n before key derivation");
        } else {
            printFail("E-T6", "Decapsulation failed to reject out-of-range ciphertext");
            totalFailed++;
        }
    }

    cout << "\n============================================================\n";
    if (totalFailed == 0) {
        cout << "  ALL ACCEPTANCE CHECKS PASSED PERFECTLY!\n";
    } else {
        cout << "  SOME CHECKS FAILED: " << totalFailed << " failure(s)\n";
    }
    cout << "============================================================\n";
    return (totalFailed == 0 ? 0 : 1);
}

} // namespace kat
