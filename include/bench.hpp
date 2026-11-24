#pragma once

#include "common_defs.hpp"

namespace bench {

// Runs performance benchmarks:
// 1. RSA Direct Modular Exponentiation vs CRT Decryption speedup
// 2. RSA Key Generation Latency (2048, 3072, 4096 bits)
// 3. RSA-OAEP Key Wrapping vs RSASVE KEM Encapsulation/Decapsulation
// 4. AES-256-GCM Streaming Throughput (1 MiB, 10 MiB, 50 MiB)
void runBenchmarks();

} // namespace bench
