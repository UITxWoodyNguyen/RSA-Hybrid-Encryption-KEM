// task_b_rsa_keys.cpp -- Lab 3 Task B: Tham so RSA, sinh khoa va luu tru PEM/DER

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

static int g_failures = 0;

static void verifyResult(const char *title, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << title << "\n";
    if (!ok) ++g_failures;
}

// Sinh so nguyen to thoa man gcd(e, p - 1) = 1
static int drawProbablePrime(BIGNUM *primeOut, BIGNUM *pMinus1Out, const BIGNUM *e, int bitCount, BN_CTX *ctx) {
    BIGNUM *gcdVal = BN_new();
    int drawTries = 0;
    do {
        ++drawTries;
        BN_generate_prime_ex2(primeOut, bitCount, 0, nullptr, nullptr, nullptr, ctx);
        BN_copy(pMinus1Out, primeOut);
        BN_sub_word(pMinus1Out, 1);
        BN_gcd(gcdVal, e, pMinus1Out, ctx);
    } while (!BN_is_one(gcdVal));
    BN_free(gcdVal);
    return drawTries;
}

static void runEducationalRsaDemo(int totalBits) {
    std::cout << "=== Part 1: Educational RSA Key Parameters (" << totalBits << " bits) ===\n";
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *pMinus1 = BN_new();
    BIGNUM *qMinus1 = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *lambda = BN_new();
    BIGNUM *gcdPQ = BN_new();

    BN_set_word(e, 65537);
    int halfBits = totalBits / 2;

    int draws = drawProbablePrime(p, pMinus1, e, halfBits, ctx);
    do {
        draws += drawProbablePrime(q, qMinus1, e, halfBits, ctx);
    } while (BN_cmp(p, q) == 0);

    std::cout << "  So lan sinh nguyen to: " << draws << "\n";

    // n = p * q
    BN_mul(n, p, q, ctx);
    // phi = (p - 1)(q - 1)
    BN_mul(phi, pMinus1, qMinus1, ctx);
    // lambda = lcm(p-1, q-1) = phi / gcd(p-1, q-1)
    BN_gcd(gcdPQ, pMinus1, qMinus1, ctx);
    BN_div(lambda, nullptr, phi, gcdPQ, ctx);

    // Hai so mu giai ma hop le
    BIGNUM *dPhi = BN_mod_inverse(nullptr, e, phi, ctx);
    BIGNUM *dLam = BN_mod_inverse(nullptr, e, lambda, ctx);

    // Tham so CRT (Garner)
    BIGNUM *dP = BN_new();
    BIGNUM *dQ = BN_new();
    BN_nnmod(dP, dLam, pMinus1, ctx);
    BN_nnmod(dQ, dLam, qMinus1, ctx);
    BIGNUM *qInv = BN_mod_inverse(nullptr, q, p, ctx);

    // Kiem tra e * d = 1 mod phi va mod lambda
    BIGNUM *checkVal = BN_new();
    BN_mod_mul(checkVal, e, dPhi, phi, ctx);
    verifyResult("e * d_phi == 1 (mod phi)", BN_is_one(checkVal));

    BN_mod_mul(checkVal, e, dLam, lambda, ctx);
    verifyResult("e * d_lambda == 1 (mod lambda)", BN_is_one(checkVal));

    // Thu giai ma 20 ban ro ngau nhien
    bool allRecovered = true;
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *decPhi = BN_new();
    BIGNUM *decLam = BN_new();
    BIGNUM *m1 = BN_new();
    BIGNUM *m2 = BN_new();
    BIGNUM *h = BN_new();
    BIGNUM *hq = BN_new();
    BIGNUM *decCrt = BN_new();

    for (int i = 0; i < 20; ++i) {
        BN_rand_range(m, n);
        BN_mod_exp(c, m, e, n, ctx);

        BN_mod_exp(decPhi, c, dPhi, n, ctx);
        BN_mod_exp(decLam, c, dLam, n, ctx);

        // Garner CRT:
        BN_mod_exp(m1, c, dP, p, ctx);
        BN_mod_exp(m2, c, dQ, q, ctx);
        BN_mod_sub(h, m1, m2, p, ctx);
        BN_mod_mul(h, qInv, h, p, ctx);
        BN_mul(hq, h, q, ctx);
        BN_add(decCrt, m2, hq);

        if (BN_cmp(decPhi, m) != 0 || BN_cmp(decLam, m) != 0 || BN_cmp(decCrt, m) != 0) {
            allRecovered = false;
        }
    }
    verifyResult("20 thong diep ngau nhien giai ma chinh xac voi d_phi, d_lambda va CRT", allRecovered);

    BN_clear_free(e); BN_clear_free(p); BN_clear_free(q);
    BN_clear_free(pMinus1); BN_clear_free(qMinus1); BN_clear_free(n);
    BN_clear_free(phi); BN_clear_free(lambda); BN_clear_free(gcdPQ);
    BN_clear_free(dPhi); BN_clear_free(dLam); BN_clear_free(dP); BN_clear_free(dQ);
    BN_clear_free(qInv); BN_clear_free(checkVal);
    BN_clear_free(m); BN_clear_free(c); BN_clear_free(decPhi); BN_clear_free(decLam);
    BN_clear_free(m1); BN_clear_free(m2); BN_clear_free(h); BN_clear_free(hq); BN_clear_free(decCrt);
    BN_CTX_free(ctx);
    std::cout << "\n";
}

int main(int argc, char **argv) {
    int bits = (argc > 1) ? std::atoi(argv[1]) : 512;
    runEducationalRsaDemo(bits);

    std::cout << "=== Part 2: Sinh khoa san xuat voi EVP_PKEY ===\n";
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY *key = nullptr;
    EVP_PKEY_generate(pctx, &key);
    EVP_PKEY_CTX_free(pctx);

    verifyResult("Khoa RSA-2048 sinh thanh cong", key != nullptr);
    if (key != nullptr) {
        verifyResult("Pairwise key consistency check hop le", EVP_PKEY_pairwise_check(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)) == 1);
        EVP_PKEY_free(key);
    }

    if (g_failures == 0) {
        std::cout << "ALL CHECKS PASSED\n";
        return 0;
    } else {
        std::cout << "SOME CHECKS FAILED\n";
        return 1;
    }
}
