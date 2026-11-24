// task_d_hybrid.cpp -- Lab 3 Task D: Ma hoa lai tep tin voi RSA-OAEP + AES-256-GCM

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>

static int g_failures = 0;

static void report(const char *name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
    if (!ok) ++g_failures;
}

int main() {
    std::cout << "=== TASK D: Demo Ma hoa lai RSA-OAEP + AES-256-GCM ===\n";

    // 1. Sinh cap khoa RSA-2048
    EVP_PKEY *key = EVP_RSA_gen(2048);
    if (!key) {
        std::cerr << "Loi sinh khoa RSA\n";
        return 1;
    }

    // 2. Tao khoa AES-256 ngau nhien va Nonce 12 bytes
    std::vector<uint8_t> aesKey(32);
    std::vector<uint8_t> nonce(12);
    RAND_bytes(aesKey.data(), 32);
    RAND_bytes(nonce.data(), 12);

    // 3. Dong goi khoa AES bang RSA-OAEP SHA-256
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr);
    EVP_PKEY_encrypt_init(pctx);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());

    size_t wrappedLen = 0;
    EVP_PKEY_encrypt(pctx, nullptr, &wrappedLen, aesKey.data(), aesKey.size());
    std::vector<uint8_t> wrappedKey(wrappedLen);
    EVP_PKEY_encrypt(pctx, wrappedKey.data(), &wrappedLen, aesKey.data(), aesKey.size());
    EVP_PKEY_CTX_free(pctx);

    report("Dong goi khoa AES-256 bang RSA-OAEP thanh cong", wrappedLen == 256);

    // 4. Ma hoa du lieu bang AES-256-GCM voi AAD
    std::vector<uint8_t> aad = {'L', '2', 'P', 'K', 0x01, 0x01};
    std::string secretMessage = "Du lieu bao mat cap cao cua phong thi nghiem NT219";
    std::vector<uint8_t> plaintext(secretMessage.begin(), secretMessage.end());

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(cctx, EVP_aes_256_gcm(), aesKey.data(), nonce.data(), nullptr);

    int outl = 0;
    EVP_EncryptUpdate(cctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size())); // AAD

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int ctLen = 0;
    EVP_EncryptUpdate(cctx, ciphertext.data(), &outl, plaintext.data(), static_cast<int>(plaintext.size()));
    ctLen = outl;
    EVP_EncryptFinal_ex(cctx, ciphertext.data() + ctLen, &outl);
    ctLen += outl;
    ciphertext.resize(ctLen);

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(cctx);

    report("Ma hoa AES-256-GCM va sinh Tag thanh cong", tag.size() == 16);

    // 5. Giai ma hop le
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex2(dctx, EVP_aes_256_gcm(), aesKey.data(), nonce.data(), nullptr);
    EVP_DecryptUpdate(dctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));

    std::vector<uint8_t> recovered(ciphertext.size());
    EVP_DecryptUpdate(dctx, recovered.data(), &outl, ciphertext.data(), static_cast<int>(ciphertext.size()));
    int recLen = outl;

    EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
    bool authOk = (EVP_DecryptFinal_ex(dctx, recovered.data() + recLen, &outl) == 1);
    EVP_CIPHER_CTX_free(dctx);

    report("Xac thuc Tag thanh cong va giai ma nguyen ven", authOk && (recovered == plaintext));

    // 6. Kiem tra can thiep vao Ciphertext
    std::vector<uint8_t> badCt = ciphertext;
    badCt[0] ^= 0x01;
    EVP_CIPHER_CTX *tamperCtx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex2(tamperCtx, EVP_aes_256_gcm(), aesKey.data(), nonce.data(), nullptr);
    EVP_DecryptUpdate(tamperCtx, nullptr, &outl, aad.data(), static_cast<int>(aad.size()));
    EVP_DecryptUpdate(tamperCtx, recovered.data(), &outl, badCt.data(), static_cast<int>(badCt.size()));
    EVP_CIPHER_CTX_ctrl(tamperCtx, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
    bool tamperDetected = (EVP_DecryptFinal_ex(tamperCtx, recovered.data() + outl, &outl) != 1);
    EVP_CIPHER_CTX_free(tamperCtx);

    report("Phat hien va tu choi ciphertext bi can thiep", tamperDetected);

    EVP_PKEY_free(key);

    if (g_failures == 0) {
        std::cout << "\nALL CHECKS PASSED\n";
        return 0;
    } else {
        std::cout << "\nSOME CHECKS FAILED\n";
        return 1;
    }
}
