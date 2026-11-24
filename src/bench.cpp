#include "bench.hpp"
#include "bn_math.hpp"
#include "rsa_params.hpp"
#include "key_io.hpp"
#include "hybrid_oaep.hpp"
#include "rsa_kem.hpp"
#include "aead.hpp"
#include "utils.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h>

namespace bench {

void runBenchmarks() {
    cout << "============================================================\n";
    cout << "      CRYPTOGRAPHIC PERFORMANCE BENCHMARKS (Lab 3)          \n";
    cout << "============================================================\n\n";

    cout << "--- 1. Decryption Speedup: Direct ModExp vs Garner's CRT ---\n";
    cout << "Generating 1024-bit test key for 500-iteration timing...\n";

    edu::EducationalRsaParams params = edu::generateEducationalRsaParams(1024);
    BnCtxPtr ctx = makeBnCtx();

    BignumPtr m = makeBignum();
    BignumPtr c = makeBignum();
    BignumPtr rDirect = makeBignum();
    BignumPtr rCrt = makeBignum();
    BignumPtr m1 = makeBignum();
    BignumPtr m2 = makeBignum();
    BignumPtr h = makeBignum();
    BignumPtr hq = makeBignum();

    BN_rand_range(m.get(), params.n.get());
    BN_mod_exp(c.get(), m.get(), params.e.get(), params.n.get(), ctx.get());

    int iterations = 500;

    auto startDirect = chrono::high_resolution_clock::now();
    REP(i, 0, iterations) {
        BN_mod_exp(rDirect.get(), c.get(), params.d_lambda.get(), params.n.get(), ctx.get());
    }
    auto endDirect = chrono::high_resolution_clock::now();
    double timeDirectMs = chrono::duration<double, milli>(endDirect - startDirect).count();

    auto startCrt = chrono::high_resolution_clock::now();
    REP(i, 0, iterations) {
        BN_mod_exp(m1.get(), c.get(), params.dP.get(), params.p.get(), ctx.get());
        BN_mod_exp(m2.get(), c.get(), params.dQ.get(), params.q.get(), ctx.get());
        BN_mod_sub(h.get(), m1.get(), m2.get(), params.p.get(), ctx.get());
        BN_mod_mul(h.get(), params.qInv.get(), h.get(), params.p.get(), ctx.get());
        BN_mul(hq.get(), h.get(), params.q.get(), ctx.get());
        BN_add(rCrt.get(), m2.get(), hq.get());
    }
    auto endCrt = chrono::high_resolution_clock::now();
    double timeCrtMs = chrono::duration<double, milli>(endCrt - startCrt).count();

    double speedup = timeDirectMs / (timeCrtMs > 0.0001 ? timeCrtMs : 0.0001);
    cout << "  Direct Exponentiation (c^d mod n) : " << fixed << setprecision(2)
         << timeDirectMs << " ms (" << (timeDirectMs / iterations) << " ms/op)\n";
    cout << "  Garner CRT Decryption             : " << fixed << setprecision(2)
         << timeCrtMs << " ms (" << (timeCrtMs / iterations) << " ms/op)\n";
    cout << "  Measured Speedup Factor           : " << fixed << setprecision(2)
         << speedup << "x faster (Theoretical limit: ~4.0x)\n\n";

    cout << "--- 2. Production RSA Key Generation Latency ---\n";
    int keySizes[] = {2048, 3072};
    for (int bits : keySizes) {
        auto startKeygen = chrono::high_resolution_clock::now();
        EvpPkeyPtr k = sec::generateProductionRsaKey(bits);
        auto endKeygen = chrono::high_resolution_clock::now();
        double latencyMs = chrono::duration<double, milli>(endKeygen - startKeygen).count();
        cout << "  RSA-" << bits << " Key Generation : " << fixed << setprecision(2)
             << latencyMs << " ms\n";
    }

    cout << "\n--- 3. RSA-OAEP Wrap vs RSASVE KEM Encapsulation Latency ---\n";
    EvpPkeyPtr benchKey = sec::generateProductionRsaKey(2048);
    sec::SecureBytes symmetricKey(32);
    RAND_bytes(symmetricKey.data(), 32);

    int cryptoIterations = 100;
    auto startOaep = chrono::high_resolution_clock::now();
    REP(i, 0, cryptoIterations) {
        vector<uint8_t> w = sec::oaepWrapKey(benchKey.get(), symmetricKey);
        (void)w;
    }
    auto endOaep = chrono::high_resolution_clock::now();
    double timeOaepMs = chrono::duration<double, milli>(endOaep - startOaep).count();

    auto startKem = chrono::high_resolution_clock::now();
    REP(i, 0, cryptoIterations) {
        sec::Encapsulation enc = sec::encapsulate(benchKey.get());
        (void)enc;
    }
    auto endKem = chrono::high_resolution_clock::now();
    double timeKemMs = chrono::duration<double, milli>(endKem - startKem).count();

    cout << "  RSA-OAEP Key Wrap   : " << fixed << setprecision(2)
         << (timeOaepMs / cryptoIterations) << " ms/op\n";
    cout << "  RSASVE KEM Encaps   : " << fixed << setprecision(2)
         << (timeKemMs / cryptoIterations) << " ms/op\n";

    cout << "\n--- 4. AES-256-GCM Streaming Encryption Throughput ---\n";
    size_t payloadSize = 5 * 1024 * 1024;
    vector<uint8_t> payload(payloadSize, 0x3c);
    vector<uint8_t> nonce(12, 0x01);
    vector<uint8_t> aad(30, 0x02);
    vector<uint8_t> tag;

    istringstream inStream(string(payload.begin(), payload.end()));
    ostringstream outStream;

    auto startGcm = chrono::high_resolution_clock::now();
    sec::gcmEncryptStream(symmetricKey, nonce, aad, inStream, outStream, tag);
    auto endGcm = chrono::high_resolution_clock::now();
    double gcmTimeMs = chrono::duration<double, milli>(endGcm - startGcm).count();
    double throughputMBps = (static_cast<double>(payloadSize) / (1024.0 * 1024.0)) / (gcmTimeMs / 1000.0);

    cout << "  Payload Size : 5.0 MiB in 64 KiB chunks\n";
    cout << "  Duration     : " << fixed << setprecision(2) << gcmTimeMs << " ms\n";
    cout << "  Throughput   : " << fixed << setprecision(2) << throughputMBps << " MB/s\n\n";

    cout << "============================================================\n";
    cout << "                 BENCHMARK COMPLETE                         \n";
    cout << "============================================================\n";
}

} // namespace bench
