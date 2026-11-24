// task_c_oaep.cpp -- Lab 3 Task C: OS2IP / I2OSP, Tinh de uon nan cua Textbook RSA va Dem OAEP

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdlib>
#include <cstring>

static int g_failures = 0;

static void assertCheck(const char *name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
    if (!ok) ++g_failures;
}

static BIGNUM *bytesToInteger(const std::vector<uint8_t> &bytes) {
    if (bytes.empty()) {
        BIGNUM *z = BN_new();
        BN_zero(z);
        return z;
    }
    return BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr);
}

static bool integerToBytes(const BIGNUM *x, size_t len, std::vector<uint8_t> &out) {
    out.assign(len, 0);
    return (BN_bn2binpad(x, out.data(), static_cast<int>(len)) >= 0);
}

static std::string toHex(const std::vector<uint8_t> &data) {
    std::string s;
    const char *hexChars = "0123456789abcdef";
    for (uint8_t b : data) {
        s.push_back(hexChars[(b >> 4) & 0x0f]);
        s.push_back(hexChars[b & 0x0f]);
    }
    return s;
}

static std::vector<uint8_t> fromHex(const std::string &hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char buf[3] = {hex[i], hex[i + 1], 0};
        out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return out;
}

int main() {
    std::cout << "=== Part 1: Kiem thu chuyen doi OS2IP va I2OSP ===\n";
    struct TestCase {
        const char *id;
        const char *hexInput;
        size_t targetLen;
        const char *expectedHex;
    };

    const TestCase cases[] = {
        {"C-T1", "000001", 3, "000001"},
        {"C-T2", "000001", 1, "01"},
        {"C-T3", "0100", 2, "0100"},
        {"C-T4", "0100", 1, nullptr}, // Qua lon doi voi 1 byte
        {"C-T5", "00ff00", 3, "00ff00"},
        {"C-T6", "", 2, "0000"}
    };

    for (const auto &tc : cases) {
        std::vector<uint8_t> inBytes = fromHex(tc.hexInput);
        BIGNUM *bn = bytesToInteger(inBytes);
        std::vector<uint8_t> outBytes;
        bool fits = integerToBytes(bn, tc.targetLen, outBytes);

        if (tc.expectedHex != nullptr) {
            assertCheck(tc.id, fits && toHex(outBytes) == tc.expectedHex);
        } else {
            assertCheck(tc.id, !fits); // Bat loi integer too large
        }
        BN_free(bn);
    }

    std::cout << "\n=== Part 2: Textbook RSA - Tinh de uon nan (Malleability) ===\n";
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(); BN_set_word(n, 3233);
    BIGNUM *e = BN_new(); BN_set_word(e, 17);
    BIGNUM *d = BN_new(); BN_set_word(d, 2753);

    // Ma hoa m = 65
    BIGNUM *m = BN_new(); BN_set_word(m, 65);
    BIGNUM *c = BN_new();
    BN_mod_exp(c, m, e, n, ctx);
    BIGNUM *dec = BN_new();
    BN_mod_exp(dec, c, d, n, ctx);
    assertCheck("Enc(65) == 2790 va giai ma nguoc lai 65", BN_is_word(c, 2790) && BN_is_word(dec, 65));

    // Tan cong uon nan: c_forged = Enc(6) * Enc(7) mod n
    BIGNUM *m6 = BN_new(); BN_set_word(m6, 6);
    BIGNUM *m7 = BN_new(); BN_set_word(m7, 7);
    BIGNUM *c6 = BN_new(); BN_mod_exp(c6, m6, e, n, ctx);
    BIGNUM *c7 = BN_new(); BN_mod_exp(c7, m7, e, n, ctx);
    BIGNUM *cForged = BN_new();
    BN_mod_mul(cForged, c6, c7, n, ctx);
    BIGNUM *decForged = BN_new();
    BN_mod_exp(decForged, cForged, d, n, ctx);

    assertCheck("Tan cong tinh de uon nan: Dec(Enc(6)*Enc(7) mod n) == 42",
                BN_is_word(c6, 824) && BN_is_word(c7, 2369) &&
                BN_is_word(cForged, 2557) && BN_is_word(decForged, 42));

    BN_free(n); BN_free(e); BN_free(d); BN_free(m); BN_free(c); BN_free(dec);
    BN_free(m6); BN_free(m7); BN_free(c6); BN_free(c7); BN_free(cForged); BN_free(decForged);
    BN_CTX_free(ctx);

    std::cout << "\n=== Part 3: RSA-OAEP chong lai tinh de uon nan ===\n";
    EVP_PKEY *realKey = EVP_RSA_gen(2048);
    EVP_PKEY_CTX *encCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, realKey, nullptr);
    EVP_PKEY_encrypt_init(encCtx);
    EVP_PKEY_CTX_set_rsa_padding(encCtx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(encCtx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(encCtx, EVP_sha256());

    std::vector<uint8_t> plain = {'H', 'E', 'L', 'L', 'O'};
    size_t outLen = 0;
    EVP_PKEY_encrypt(encCtx, nullptr, &outLen, plain.data(), plain.size());
    std::vector<uint8_t> ct1(outLen);
    EVP_PKEY_encrypt(encCtx, ct1.data(), &outLen, plain.data(), plain.size());

    // Ma hoa lai cung thong diep
    std::vector<uint8_t> ct2(outLen);
    EVP_PKEY_encrypt(encCtx, ct2.data(), &outLen, plain.data(), plain.size());
    assertCheck("RSA-OAEP sinh 2 ban ma khac nhau cho cung ban ro", ct1 != ct2);

    // Kiem tra gia mao
    ct1[10] ^= 0x01;
    EVP_PKEY_CTX *decCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, realKey, nullptr);
    EVP_PKEY_decrypt_init(decCtx);
    EVP_PKEY_CTX_set_rsa_padding(decCtx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(decCtx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(decCtx, EVP_sha256());

    std::vector<uint8_t> recovered(outLen);
    size_t recLen = outLen;
    bool decOk = (EVP_PKEY_decrypt(decCtx, recovered.data(), &recLen, ct1.data(), ct1.size()) > 0);
    assertCheck("Ban ma bi sua 1 bit bi tu choi giai ma", !decOk);

    EVP_PKEY_CTX_free(encCtx);
    EVP_PKEY_CTX_free(decCtx);
    EVP_PKEY_free(realKey);

    if (g_failures == 0) {
        std::cout << "\nALL CHECKS PASSED\n";
        return 0;
    } else {
        std::cout << "\nSOME CHECKS FAILED\n";
        return 1;
    }
}
