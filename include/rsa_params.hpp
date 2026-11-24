#pragma once

#include "ossl_raii.hpp"

namespace edu {

struct EducationalRsaParams {
    int modulus_bits = 0;
    BignumPtr p;
    BignumPtr q;
    BignumPtr n;
    BignumPtr e;
    BignumPtr phi;
    BignumPtr lambda;
    BignumPtr d_phi;
    BignumPtr d_lambda;
    BignumPtr dP;
    BignumPtr dQ;
    BignumPtr qInv;
    int prime_draws = 0;
};

EducationalRsaParams generateEducationalRsaParams(int bits);
bool verifyEducationalParams(const EducationalRsaParams &params, bool printDetails = true);

} // namespace edu
