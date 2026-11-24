#pragma once

#include "ossl_raii.hpp"

namespace edu {

BignumPtr os2ip(const vector<uint8_t> &octets);
bool i2osp(const BIGNUM *x, size_t target_len, vector<uint8_t> &out);
BignumPtr textbookEncrypt(const BIGNUM *m, const BIGNUM *e, const BIGNUM *n, BN_CTX *ctx = nullptr);
BignumPtr textbookDecrypt(const BIGNUM *c, const BIGNUM *d, const BIGNUM *n, BN_CTX *ctx = nullptr);
vector<uint8_t> educationalOaepEncode(const vector<uint8_t> &msg, size_t k);
bool educationalOaepDecode(const vector<uint8_t> &em, size_t k, vector<uint8_t> &msg);

} // namespace edu
