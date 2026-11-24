// task_e_kem.cpp -- Lab 3 Task E: Co che dong goi khoa (RSASVE KEM) va HKDF

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

static int g_failures = 0;

static void recordCheck(const char *name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
    if (!ok) ++g_failures;
}

int main() {
    std::cout << "=== TASK E: RSASVE KEM va HKDF-SHA-256 ===\n";

    EVP_PKEY *key = EVP_RSA_gen(2048);
    if (!key) {
        std::cerr << "Loi sinh khoa RSA\n";
        return 1;
    }

    // 1. Dong goi RSASVE KEM bang OpenSSL EVP API
    EVP_PKEY_CTX *encCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    EVP_PKEY_encapsulate_init(encCtx, nullptr);
    EVP_PKEY_CTX_set_kem_op(encCtx, "RSASVE");

    size_t ctLen = 0, zLen = 0;
    EVP_PKEY_encapsulate(encCtx, nullptr, &ctLen, nullptr, &zLen);
    std::vector<uint8_t> kemCt(ctLen);
    std::vector<uint8_t> secretZ(zLen);
    EVP_PKEY_encapsulate(encCtx, kemCt.data(), &ctLen, secretZ.data(), &zLen);
    EVP_PKEY_CTX_free(encCtx);

    recordCheck("RSASVE Encapsulate sinh thanh cong C_kem va bi mat Z", ctLen == 256 && zLen == 256);

    // 2. Mo goi RSASVE KEM
    EVP_PKEY_CTX *decCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    EVP_PKEY_decapsulate_init(decCtx, nullptr);
    EVP_PKEY_CTX_set_kem_op(decCtx, "RSASVE");

    size_t decZLen = 0;
    EVP_PKEY_decapsulate(decCtx, nullptr, &decZLen, kemCt.data(), kemCt.size());
    std::vector<uint8_t> recoveredZ(decZLen);
    EVP_PKEY_decapsulate(decCtx, recoveredZ.data(), &decZLen, kemCt.data(), kemCt.size());
    EVP_PKEY_CTX_free(decCtx);

    bool zMatch = (CRYPTO_memcmp(secretZ.data(), recoveredZ.data(), zLen) == 0);
    recordCheck("RSASVE Decapsulate khoi phuc bi mat Z chinh xac", zMatch);

    // 3. Dan xuat khoa bang HKDF-SHA-256
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    char digest[] = "SHA256";
    std::string infoStr = "LAB02-RSASVE-HKDF-SHA256-AES256GCM-v1-TEST";

    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", secretZ.data(), secretZ.size());
    *p++ = OSSL_PARAM_construct_octet_string("info", const_cast<char *>(infoStr.data()), infoStr.size());
    *p = OSSL_PARAM_construct_end();

    std::vector<uint8_t> derivedAesKey(32);
    int deriveOk = EVP_KDF_derive(kctx, derivedAesKey.data(), 32, params);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    recordCheck("HKDF-SHA-256 dan xuat thanh cong khoa AES 32 bytes", deriveOk == 1);

    EVP_PKEY_free(key);

    if (g_failures == 0) {
        std::cout << "\nALL CHECKS PASSED\n";
        return 0;
    } else {
        std::cout << "\nSOME CHECKS FAILED\n";
        return 1;
    }
}
