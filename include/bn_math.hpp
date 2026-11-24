#pragma once

#include "ossl_raii.hpp"

namespace edu {

BignumPtr parseDecimalStrict(const string &str);
BignumPtr myModExp(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx = nullptr);
BignumPtr myModInverse(const BIGNUM *a, const BIGNUM *m, BIGNUM *gcdOut, BN_CTX *ctx = nullptr);
BignumPtr modAdd(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx = nullptr);
BignumPtr modSub(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx = nullptr);
BignumPtr modMul(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx = nullptr);
BignumPtr libModExp(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx = nullptr);
BignumPtr calcGcd(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx = nullptr);

} // namespace edu
