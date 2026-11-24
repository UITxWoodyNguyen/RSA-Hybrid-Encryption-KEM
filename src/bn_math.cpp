#include "bn_math.hpp"

namespace edu {

BignumPtr parseDecimalStrict(const string &str) {
    if (str.empty()) {
        throw LabException(StatusCodes::UsageOrInputError, "Number string is empty");
    }
    if (str.length() > 10000) {
        throw LabException(StatusCodes::UsageOrInputError, "Input integer exceeds maximum length of 10000 digits");
    }
    for (char c : str) {
        if (c < '0' || c > '9') {
            throw LabException(StatusCodes::UsageOrInputError, "Invalid decimal character in input: '" + string(1, c) + "'");
        }
    }
    BIGNUM *rawBn = nullptr;
    int parsedChars = BN_dec2bn(&rawBn, str.c_str());
    if (parsedChars <= 0 || static_cast<size_t>(parsedChars) != str.length() || rawBn == nullptr) {
        if (rawBn != nullptr) BN_free(rawBn);
        throw LabException(StatusCodes::UsageOrInputError, "Failed to parse entire decimal string with BN_dec2bn");
    }
    return BignumPtr(rawBn);
}

BignumPtr myModExp(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    if (a == nullptr || b == nullptr || m == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null operand in myModExp");
    }
    if (BN_is_zero(m) || BN_is_negative(m)) {
        throw LabException(StatusCodes::UsageOrInputError, "Modulus must be positive (m >= 1)");
    }

    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }

    BignumPtr res = makeBignum();
    if (BN_is_one(m)) {
        BN_zero(res.get());
        return res;
    }

    BignumPtr base = makeBignum();
    if (BN_nnmod(base.get(), a, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_nnmod failed during base reduction");
    }

    if (BN_is_zero(b)) {
        if (BN_one(res.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_one failed");
        }
        return res;
    }

    if (BN_one(res.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_one failed");
    }

    int bitLength = BN_num_bits(b);
    FORD(i, bitLength - 1, 0) {
        if (BN_mod_sqr(res.get(), res.get(), m, activeCtx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_mod_sqr failed");
        }
        if (BN_is_bit_set(b, i)) {
            if (BN_mod_mul(res.get(), res.get(), base.get(), m, activeCtx) != 1) {
                throw LabException(StatusCodes::InternalError, "BN_mod_mul failed");
            }
        }
    }

    return res;
}

BignumPtr myModInverse(const BIGNUM *a, const BIGNUM *m, BIGNUM *gcdOut, BN_CTX *ctx) {
    if (a == nullptr || m == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null operand in myModInverse");
    }
    BignumPtr two = makeBignum();
    BN_set_word(two.get(), 2);
    if (BN_cmp(m, two.get()) < 0) {
        throw LabException(StatusCodes::UsageOrInputError, "Modular inverse requires modulus m >= 2");
    }

    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }

    BignumPtr r0 = makeBignum();
    BignumPtr r1 = makeBignum();
    BignumPtr t0 = makeBignum();
    BignumPtr t1 = makeBignum();
    BignumPtr q = makeBignum();
    BignumPtr rem = makeBignum();
    BignumPtr prod = makeBignum();

    if (BN_copy(r0.get(), m) == nullptr) {
        throw LabException(StatusCodes::InternalError, "BN_copy failed");
    }
    if (BN_nnmod(r1.get(), a, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_nnmod failed");
    }
    BN_zero(t0.get());
    if (BN_one(t1.get()) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_one failed");
    }

    while (!BN_is_zero(r1.get())) {
        if (BN_div(q.get(), rem.get(), r0.get(), r1.get(), activeCtx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_div failed in extended Euclidean");
        }
        BN_swap(r0.get(), r1.get());
        BN_swap(r1.get(), rem.get());

        if (BN_mul(prod.get(), q.get(), t1.get(), activeCtx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_mul failed in extended Euclidean");
        }
        if (BN_sub(rem.get(), t0.get(), prod.get()) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_sub failed in extended Euclidean");
        }
        BN_swap(t0.get(), t1.get());
        BN_swap(t1.get(), rem.get());
    }

    if (gcdOut != nullptr) {
        if (BN_copy(gcdOut, r0.get()) == nullptr) {
            throw LabException(StatusCodes::InternalError, "BN_copy failed for gcdOut");
        }
    }

    if (BN_is_one(r0.get())) {
        BignumPtr inverse = makeBignum();
        if (BN_nnmod(inverse.get(), t0.get(), m, activeCtx) != 1) {
            throw LabException(StatusCodes::InternalError, "BN_nnmod failed normalizing inverse");
        }
        return inverse;
    }

    return nullptr;
}

BignumPtr modAdd(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    if (BN_is_zero(m) || BN_is_negative(m)) {
        throw LabException(StatusCodes::UsageOrInputError, "Modulus must be >= 1");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr r = makeBignum();
    if (BN_mod_add(r.get(), a, b, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_add failed");
    }
    return r;
}

BignumPtr modSub(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    if (BN_is_zero(m) || BN_is_negative(m)) {
        throw LabException(StatusCodes::UsageOrInputError, "Modulus must be >= 1");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr r = makeBignum();
    if (BN_mod_sub(r.get(), a, b, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_sub failed");
    }
    return r;
}

BignumPtr modMul(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    if (BN_is_zero(m) || BN_is_negative(m)) {
        throw LabException(StatusCodes::UsageOrInputError, "Modulus must be >= 1");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr r = makeBignum();
    if (BN_mod_mul(r.get(), a, b, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_mul failed");
    }
    return r;
}

BignumPtr libModExp(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    if (BN_is_zero(m) || BN_is_negative(m)) {
        throw LabException(StatusCodes::UsageOrInputError, "Modulus must be >= 1");
    }
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr r = makeBignum();
    if (BN_mod_exp(r.get(), a, b, m, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_mod_exp failed");
    }
    return r;
}

BignumPtr calcGcd(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    BnCtxPtr localCtx;
    BN_CTX *activeCtx = ctx;
    if (activeCtx == nullptr) {
        localCtx = makeBnCtx();
        activeCtx = localCtx.get();
    }
    BignumPtr r = makeBignum();
    if (BN_is_zero(a) && BN_is_zero(b)) {
        BN_zero(r.get());
        return r;
    }
    if (BN_gcd(r.get(), a, b, activeCtx) != 1) {
        throw LabException(StatusCodes::InternalError, "BN_gcd failed");
    }
    return r;
}

} // namespace edu
