#include "rsa_params.hpp"
#include "bn_math.hpp"
#include <openssl/rand.h>

namespace edu {

static int sampleRsaPrime(BIGNUM *primeOut, BIGNUM *primeMinusOneOut, const BIGNUM *e,
                          int halfBits, BN_CTX *ctx) {
    BignumPtr gcdResult = makeBignum();
    int drawCount = 0;
    while (true) {
        ++drawCount;
        if (BN_generate_prime_ex2(primeOut, halfBits, 0, nullptr, nullptr, nullptr, ctx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_generate_prime_ex2 failed to generate prime");
        }
        if (BN_copy(primeMinusOneOut, primeOut) == nullptr) {
            throw LabException(StatusCodes::InternalError, "BN_copy failed");
        }
        if (BN_sub_word(primeMinusOneOut, 1) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_sub_word failed");
        }
        if (BN_gcd(gcdResult.get(), e, primeMinusOneOut, ctx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_gcd failed during prime test");
        }
        if (BN_is_one(gcdResult.get())) {
            break;
        }
    }
    return drawCount;
}

EducationalRsaParams generateEducationalRsaParams(int bits) {
    if (bits < 128 || bits > 1024 || bits % 2 != 0) {
        throw LabException(StatusCodes::UsageOrInputError,
                           "Educational RSA key size must be an even integer between 128 and 1024 bits");
    }

    EducationalRsaParams params;
    params.modulus_bits = bits;
    params.p = makeBignum();
    params.q = makeBignum();
    params.n = makeBignum();
    params.e = makeBignum();
    params.phi = makeBignum();
    params.lambda = makeBignum();

    BnCtxPtr ctx = makeBnCtx();

    if (BN_set_word(params.e.get(), 65537) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_set_word failed for e");
    }

    BignumPtr pMinus1 = makeBignum();
    BignumPtr qMinus1 = makeBignum();
    int halfBits = bits / 2;

    int totalDraws = sampleRsaPrime(params.p.get(), pMinus1.get(), params.e.get(), halfBits, ctx.get());
    do {
        totalDraws += sampleRsaPrime(params.q.get(), qMinus1.get(), params.e.get(), halfBits, ctx.get());
    } while (BN_cmp(params.p.get(), params.q.get()) == 0);

    params.prime_draws = totalDraws;

    if (BN_mul(params.n.get(), params.p.get(), params.q.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mul failed for n");
    }

    if (BN_mul(params.phi.get(), pMinus1.get(), qMinus1.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mul failed for phi");
    }

    BignumPtr gcdPQ = makeBignum();
    if (BN_gcd(gcdPQ.get(), pMinus1.get(), qMinus1.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_gcd failed for (p-1, q-1)");
    }
    if (BN_div(params.lambda.get(), nullptr, params.phi.get(), gcdPQ.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_div failed for lambda");
    }

    params.d_phi = myModInverse(params.e.get(), params.phi.get(), nullptr, ctx.get());
    params.d_lambda = myModInverse(params.e.get(), params.lambda.get(), nullptr, ctx.get());
    if (!params.d_phi || !params.d_lambda) {
        throw LabException(StatusCodes::InternalError, "Failed to compute private exponents d_phi or d_lambda");
    }

    params.dP = makeBignum();
    params.dQ = makeBignum();
    if (BN_nnmod(params.dP.get(), params.d_lambda.get(), pMinus1.get(), ctx.get()) != 1 ||
        BN_nnmod(params.dQ.get(), params.d_lambda.get(), qMinus1.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "Failed to compute CRT exponents dP, dQ");
    }

    params.qInv = myModInverse(params.q.get(), params.p.get(), nullptr, ctx.get());
    if (!params.qInv) {
        throw LabException(StatusCodes::InternalError, "Failed to compute CRT qInv = q^-1 mod p");
    }

    return params;
}

bool verifyEducationalParams(const EducationalRsaParams &params, bool printDetails) {
    BnCtxPtr ctx = makeBnCtx();
    bool allChecksPass = true;

    auto reportCheck = [&](const string &title, bool passed) {
        if (printDetails) {
            cout << "  [" << (passed ? "PASS" : "FAIL") << "] " << title << "\n";
        }
        if (!passed) allChecksPass = false;
    };

    BignumPtr testProd1 = makeBignum();
    if (BN_mod_mul(testProd1.get(), params.e.get(), params.d_phi.get(), params.phi.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_mul failed in check (i)");
    }
    reportCheck("e * d_phi == 1 (mod phi)", BN_is_one(testProd1.get()));

    BignumPtr testProd2 = makeBignum();
    if (BN_mod_mul(testProd2.get(), params.e.get(), params.d_lambda.get(), params.lambda.get(), ctx.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_mul failed in check (ii)");
    }
    reportCheck("e * d_lambda == 1 (mod lambda)", BN_is_one(testProd2.get()));

    BignumPtr dPhiReduced = makeBignum();
    BN_nnmod(dPhiReduced.get(), params.d_phi.get(), params.lambda.get(), ctx.get());
    reportCheck("d_phi mod lambda == d_lambda", BN_cmp(dPhiReduced.get(), params.d_lambda.get()) == 0);

    bool randomDecryptPass = true;
    bool crtMatchesDirectPass = true;

    BignumPtr msg = makeBignum();
    BignumPtr cipher = makeBignum();
    BignumPtr decPhi = makeBignum();
    BignumPtr decLam = makeBignum();
    BignumPtr m1 = makeBignum();
    BignumPtr m2 = makeBignum();
    BignumPtr h = makeBignum();
    BignumPtr hq = makeBignum();
    BignumPtr decCrt = makeBignum();

    FOR(iter, 1, 20) {
        if (BN_rand_range(msg.get(), params.n.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_rand_range failed");
        }
        if (BN_mod_exp(cipher.get(), msg.get(), params.e.get(), params.n.get(), ctx.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "Encryption failed in verification");
        }
        if (BN_mod_exp(decPhi.get(), cipher.get(), params.d_phi.get(), params.n.get(), ctx.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "Decryption with d_phi failed");
        }
        if (BN_mod_exp(decLam.get(), cipher.get(), params.d_lambda.get(), params.n.get(), ctx.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "Decryption with d_lambda failed");
        }
        if (BN_cmp(decPhi.get(), msg.get()) != 0 || BN_cmp(decLam.get(), msg.get()) != 0) {
            randomDecryptPass = false;
        }

        BN_mod_exp(m1.get(), cipher.get(), params.dP.get(), params.p.get(), ctx.get());
        BN_mod_exp(m2.get(), cipher.get(), params.dQ.get(), params.q.get(), ctx.get());
        BN_mod_sub(h.get(), m1.get(), m2.get(), params.p.get(), ctx.get());
        BN_mod_mul(h.get(), params.qInv.get(), h.get(), params.p.get(), ctx.get());
        BN_mul(hq.get(), h.get(), params.q.get(), ctx.get());
        BN_add(decCrt.get(), m2.get(), hq.get());

        if (BN_cmp(decCrt.get(), msg.get()) != 0 || BN_cmp(decCrt.get(), decLam.get()) != 0) {
            crtMatchesDirectPass = false;
        }
    }

    reportCheck("20 random messages decrypt correctly with d_phi and d_lambda", randomDecryptPass);
    reportCheck("CRT decryption equals direct decryption", crtMatchesDirectPass);

    return allChecksPass;
}

} // namespace edu
