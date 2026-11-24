// task_a_bignum.cpp -- Lab 3 Task A: Trien khai so hoc modulo voi OpenSSL BIGNUM

#include <openssl/bn.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

static int g_testFailures = 0;

static void reportTest(const char *name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
    if (!ok) ++g_testFailures;
}

static void showBn(const char *label, const BIGNUM *num) {
    char *decStr = BN_bn2dec(num);
    if (decStr != nullptr) {
        std::cout << "  " << label << " = " << decStr << "\n";
        OPENSSL_free(decStr);
    }
}

// Chuyển chuỗi thập phân thành BIGNUM có kiểm tra ràng buộc nghiêm ngặt:
// - Không nhận dấu âm (-), không nhận khoảng trắng, không nhận chữ cái
// - Độ dài từ 1 đến 10000 chữ số
static BIGNUM *parseDecimal(const char *str) {
    if (str == nullptr) return nullptr;
    size_t len = std::strlen(str);
    if (len == 0 || len > 10000) {
        std::cerr << "Loi: Do dai chuoi khong hop le (yeu cau 1..10000 chu so)\n";
        std::exit(1);
    }
    for (size_t i = 0; i < len; ++i) {
        if (str[i] < '0' || str[i] > '9') {
            std::cerr << "Loi: Chuoi chua ky tu khong phai chu so thap phan\n";
            std::exit(1);
        }
    }
    BIGNUM *res = nullptr;
    int consumed = BN_dec2bn(&res, str);
    if (consumed <= 0 || static_cast<size_t>(consumed) != len || res == nullptr) {
        std::cerr << "Loi: BN_dec2bn khong the doc toan bo chuoi\n";
        std::exit(1);
    }
    return res;
}

// Thuật toán Square-and-Multiply (Bình phương và nhân từ trái qua phải)
// Tính r = a^b mod m
static BIGNUM *calcSquareAndMultiply(const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
    BIGNUM *res = BN_new();
    BIGNUM *base = BN_new();
    if (!res || !base) {
        std::cerr << "Loi cap phat bo nho BIGNUM\n";
        std::exit(1);
    }

    if (BN_is_one(m)) {
        BN_zero(res);
        BN_free(base);
        return res;
    }

    // Thu nhỏ cơ số: base = a mod m
    BN_nnmod(base, a, m, ctx);
    BN_one(res);

    int bitLength = BN_num_bits(b);
    for (int i = bitLength - 1; i >= 0; --i) {
        // Bình phương: res = res^2 mod m
        BN_mod_sqr(res, res, m, ctx);
        // Nếu bit thứ i là 1, nhân với cơ số: res = res * base mod m
        if (BN_is_bit_set(b, i)) {
            BN_mod_mul(res, res, base, m, ctx);
        }
    }

    BN_free(base);
    return res;
}

// Thuật toán Euclid mở rộng: Tìm a^-1 mod m
// Trả về BIGNUM nghịch đảo nếu gcd(a, m) = 1, ngược lại trả về nullptr và gán gcdOut
static BIGNUM *calcExtendedEuclidInverse(const BIGNUM *a, const BIGNUM *m, BIGNUM *gcdOut, BN_CTX *ctx) {
    BIGNUM *r0 = BN_dup(m);
    BIGNUM *r1 = BN_new();
    BIGNUM *t0 = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *quotient = BN_new();
    BIGNUM *remainder = BN_new();
    BIGNUM *product = BN_new();

    BN_nnmod(r1, a, m, ctx);
    BN_zero(t0);
    BN_one(t1);

    while (!BN_is_zero(r1)) {
        // quotient = r0 / r1, remainder = r0 % r1
        BN_div(quotient, remainder, r0, r1, ctx);
        BN_swap(r0, r1);
        BN_swap(r1, remainder);

        // product = quotient * t1, remainder = t0 - product
        BN_mul(product, quotient, t1, ctx);
        BN_sub(remainder, t0, product);
        BN_swap(t0, t1);
        BN_swap(t1, remainder);
    }

    if (gcdOut != nullptr) {
        BN_copy(gcdOut, r0);
    }

    BIGNUM *inv = nullptr;
    if (BN_is_one(r0)) {
        inv = BN_new();
        BN_nnmod(inv, t0, m, ctx); // Đảm bảo giá trị dương trong [1, m)
    }

    BN_free(r0); BN_free(r1); BN_free(t0); BN_free(t1);
    BN_free(quotient); BN_free(remainder); BN_free(product);
    return inv;
}

static void testVectorCase(const char *sa, const char *sb, const char *sm,
                           const char *expectedExp, const char *expectedInv) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = parseDecimal(sa);
    BIGNUM *b = parseDecimal(sb);
    BIGNUM *m = parseDecimal(sm);

    std::cout << "Kiem tra voi: a=" << sa << ", b=" << sb << ", m=" << sm << "\n";

    // 1. Kiem tra tinh luy thua
    BIGNUM *libExp = BN_new();
    BN_mod_exp(libExp, a, b, m, ctx);
    BIGNUM *myExp = calcSquareAndMultiply(a, b, m, ctx);

    showBn("a^b mod m (OpenSSL)", libExp);
    reportTest("Square-and-Multiply khop voi BN_mod_exp", BN_cmp(libExp, myExp) == 0);

    if (expectedExp != nullptr) {
        BIGNUM *expExpected = parseDecimal(expectedExp);
        reportTest("Gia tri luy thua khop vector kiem thu", BN_cmp(myExp, expExpected) == 0);
        BN_free(expExpected);
    }

    // 2. Kiem tra tinh nghich dao
    if (!BN_is_one(m)) {
        BIGNUM *gcdVal = BN_new();
        BIGNUM *myInv = calcExtendedEuclidInverse(a, m, gcdVal, ctx);
        BIGNUM *libInv = BN_mod_inverse(nullptr, a, m, ctx);
        if (!libInv) ERR_clear_error();

        if (myInv != nullptr) {
            showBn("a^-1 mod m", myInv);
            reportTest("Euclid mo rong khop voi BN_mod_inverse", libInv && BN_cmp(myInv, libInv) == 0);
            if (expectedInv != nullptr) {
                BIGNUM *invExpected = parseDecimal(expectedInv);
                reportTest("Nghich dao khop vector kiem thu", BN_cmp(myInv, invExpected) == 0);
                BN_free(invExpected);
            }
            BN_free(myInv);
        } else {
            showBn("Khong co nghich dao, gcd(a,m)", gcdVal);
            reportTest("BN_mod_inverse cung bao khong co nghich dao", libInv == nullptr);
        }

        if (libInv) BN_free(libInv);
        BN_free(gcdVal);
    }

    BN_free(a); BN_free(b); BN_free(m);
    BN_free(libExp); BN_free(myExp);
    BN_CTX_free(ctx);
    std::cout << "\n";
}

int main(int argc, char **argv) {
    if (argc == 4) {
        testVectorCase(argv[1], argv[2], argv[3], nullptr, nullptr);
        return g_testFailures ? 1 : 0;
    }

    std::cout << "=== TASK A: Kiem thu so hoc modulo tu trien khai ===\n\n";

    // A-T1, A-T3
    testVectorCase("7", "13", "33", "13", "19");

    // A-T4: gcd(6, 33) = 3 -> khong co nghich dao
    testVectorCase("6", "2", "33", "3", nullptr);

    // A-T7: So mu lon
    testVectorCase("123456789012345678901234567890", "65537",
                   "170141183460469231731687303715884105727",
                   "43089841487593468092862748681566865937", nullptr);

    // A-T8: Nghich dao voi modulus lon (2^127 - 1)
    testVectorCase("65537", "1",
                   "170141183460469231731687303715884105727",
                   "65537", "5192217631581220737344928932233215");

    if (g_testFailures == 0) {
        std::cout << "ALL CHECKS PASSED\n";
        return 0;
    } else {
        std::cout << "SOME CHECKS FAILED\n";
        return 1;
    }
}
