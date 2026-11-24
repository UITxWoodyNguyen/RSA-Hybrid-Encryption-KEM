#include "bn_math.hpp"
#include "rsa_params.hpp"
#include "key_io.hpp"
#include "rsa_encoding.hpp"
#include "hybrid_oaep.hpp"
#include "rsa_kem.hpp"
#include "kat_runner.hpp"
#include "bench.hpp"
#include "utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <openssl/rand.h>

static void printGlobalHelp() {
    cout << "Usage: lab02 <subcommand> [options] [arguments]\n\n"
         << "Task A: Modular Arithmetic with OpenSSL BIGNUM\n"
         << "  mod-add <a> <b> <m> [--hex]     Compute (a + b) mod m\n"
         << "  mod-sub <a> <b> <m> [--hex]     Compute (a - b) mod m\n"
         << "  mod-mul <a> <b> <m> [--hex]     Compute (a * b) mod m\n"
         << "  mod-exp <a> <b> <m> [--hex]     Compute a^b mod m\n"
         << "  gcd <a> <b> [--hex]             Compute gcd(a, b)\n"
         << "  mod-inverse <a> <m> [--hex]     Compute a^-1 mod m\n\n"
         << "Task B: RSA Parameters, Key Generation, PEM/DER\n"
         << "  rsa-params --bits <N> [--show-private]\n"
         << "                                  Educational RSA key parameters (128 <= N <= 1024)\n"
         << "  keygen --bits <N> --out-dir <dir> [--force]\n"
         << "                                  Generate production RSA key (2048, 3072, 4096)\n"
         << "  key-convert --type <public|private> --in <file> --out <file> --outform <PEM|DER> [--inform <PEM|DER>] [--force]\n"
         << "                                  Convert key between PEM and DER encodings\n"
         << "  key-info --pub <file>           Display key algorithm, bits, e, and SHA-256 Key ID\n"
         << "  key-check --priv <file> --pub <file>\n"
         << "                                  Check if private and public keys match\n\n"
         << "Task C: OS2IP / I2OSP and Textbook RSA\n"
         << "  os2ip --hex <hexstring>         Convert big-endian hex octets to integer\n"
         << "  i2osp --int <decimal> --len <L> Convert integer to exactly L big-endian bytes\n"
         << "  raw-rsa --bits <N>              Demonstrate textbook RSA determinism & malleability\n"
         << "  oaep-demo --pub <pub> --priv <priv>\n"
         << "                                  Demonstrate RSA-OAEP randomized padding\n\n"
         << "Task D: Hybrid Encryption (RSA-OAEP + AES-256-GCM, Mode 0x01)\n"
         << "  encrypt --pub <key> --in <file> --out <package> [--force]\n"
         << "  decrypt --priv <key> --in <package> --out <file> [--force]\n\n"
         << "Task E: Key Encapsulation (RSASVE KEM + HKDF + AES-256-GCM, Mode 0x02)\n"
         << "  kem-encrypt --pub <key> --in <file> --out <package> [--force]\n"
         << "  kem-decrypt --priv <key> --in <package> --out <file> [--force]\n"
         << "  kem-selftest --pub <key> --priv <key>\n\n"
         << "Testing & Verification Tools\n"
         << "  kat                             Run all acceptance tests A-T1 to E-T9\n"
         << "  bench                           Run performance benchmarks (speedup, keygen, throughput)\n";
}

static void printResultBn(const BIGNUM *bn, bool hexFormat) {
    if (hexFormat) {
        char *s = BN_bn2hex(bn);
        if (s != nullptr) {
            cout << s << "\n";
            OPENSSL_free(s);
        }
    } else {
        char *s = BN_bn2dec(bn);
        if (s != nullptr) {
            cout << s << "\n";
            OPENSSL_free(s);
        }
    }
}

struct ParsedArgs {
    map<string, string> flags;
    vector<string> positionals;

    bool hasFlag(const string &name) const {
        return flags.find(name) != flags.end();
    }

    string getFlag(const string &name, const string &defVal = "") const {
        auto it = flags.find(name);
        if (it != flags.end()) return it->second;
        return defVal;
    }
};

static ParsedArgs parseArgs(int argc, char **argv, int startIdx) {
    ParsedArgs args;
    for (int i = startIdx; i < argc; ++i) {
        string token = argv[i];
        if (token.rfind("--", 0) == 0 || (token.rfind("-", 0) == 0 && token.length() > 1 && token[1] != '0' && token[1] != '1' && token[1] != '2' && token[1] != '3' && token[1] != '4' && token[1] != '5' && token[1] != '6' && token[1] != '7' && token[1] != '8' && token[1] != '9')) {
            string flagName = token;
            while (!flagName.empty() && flagName[0] == '-') {
                flagName.erase(0, 1);
            }
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.flags[flagName] = argv[i + 1];
                ++i;
            } else {
                args.flags[flagName] = "true";
            }
        } else {
            args.positionals.pb(token);
        }
    }
    return args;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printGlobalHelp();
        return StatusCodes::UsageOrInputError;
    }

    string subcommand = argv[1];
    if (subcommand == "help" || subcommand == "--help" || subcommand == "-h") {
        printGlobalHelp();
        return StatusCodes::Success;
    }

    ParsedArgs args = parseArgs(argc, argv, 2);
    bool hexOutput = args.hasFlag("hex");

    try {
        if (subcommand == "mod-add") {
            if (args.positionals.size() < 3) throw LabException(StatusCodes::UsageOrInputError, "Usage: mod-add <a> <b> <m> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr b = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr m = edu::parseDecimalStrict(args.positionals[2]);
            BignumPtr res = edu::modAdd(a.get(), b.get(), m.get());
            printResultBn(res.get(), hexOutput);
            return StatusCodes::Success;
        }
        if (subcommand == "mod-sub") {
            if (args.positionals.size() < 3) throw LabException(StatusCodes::UsageOrInputError, "Usage: mod-sub <a> <b> <m> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr b = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr m = edu::parseDecimalStrict(args.positionals[2]);
            BignumPtr res = edu::modSub(a.get(), b.get(), m.get());
            printResultBn(res.get(), hexOutput);
            return StatusCodes::Success;
        }
        if (subcommand == "mod-mul") {
            if (args.positionals.size() < 3) throw LabException(StatusCodes::UsageOrInputError, "Usage: mod-mul <a> <b> <m> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr b = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr m = edu::parseDecimalStrict(args.positionals[2]);
            BignumPtr res = edu::modMul(a.get(), b.get(), m.get());
            printResultBn(res.get(), hexOutput);
            return StatusCodes::Success;
        }
        if (subcommand == "mod-exp") {
            if (args.positionals.size() < 3) throw LabException(StatusCodes::UsageOrInputError, "Usage: mod-exp <a> <b> <m> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr b = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr m = edu::parseDecimalStrict(args.positionals[2]);
            BignumPtr res = edu::myModExp(a.get(), b.get(), m.get());
            printResultBn(res.get(), hexOutput);
            return StatusCodes::Success;
        }
        if (subcommand == "gcd") {
            if (args.positionals.size() < 2) throw LabException(StatusCodes::UsageOrInputError, "Usage: gcd <a> <b> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr b = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr res = edu::calcGcd(a.get(), b.get());
            printResultBn(res.get(), hexOutput);
            return StatusCodes::Success;
        }
        if (subcommand == "mod-inverse") {
            if (args.positionals.size() < 2) throw LabException(StatusCodes::UsageOrInputError, "Usage: mod-inverse <a> <m> [--hex]");
            BignumPtr a = edu::parseDecimalStrict(args.positionals[0]);
            BignumPtr m = edu::parseDecimalStrict(args.positionals[1]);
            BignumPtr gcdOut = makeBignum();
            BignumPtr inv = edu::myModInverse(a.get(), m.get(), gcdOut.get());
            if (!inv) {
                OpensslStrPtr gStr(BN_bn2dec(gcdOut.get()));
                cout << "no inverse: gcd(a,m) = " << gStr.get() << "\n";
                return StatusCodes::CryptoFailure;
            }
            printResultBn(inv.get(), hexOutput);
            return StatusCodes::Success;
        }

        if (subcommand == "rsa-params") {
            string bitsStr = args.getFlag("bits");
            if (bitsStr.empty() && !args.positionals.empty()) bitsStr = args.positionals[0];
            if (bitsStr.empty()) throw LabException(StatusCodes::UsageOrInputError, "Missing required flag: --bits <N>");
            int bits = stoi(bitsStr);
            bool showPrivate = args.hasFlag("show-private");

            cout << "=== EDUCATIONAL KEY - NOT FOR USE ===\n";
            edu::EducationalRsaParams params = edu::generateEducationalRsaParams(bits);
            cout << "Modulus length : " << BN_num_bits(params.n.get()) << " bits\n";
            OpensslStrPtr nHex(BN_bn2hex(params.n.get()));
            OpensslStrPtr eDec(BN_bn2dec(params.e.get()));
            cout << "Modulus (n)    : 0x" << nHex.get() << "\n";
            cout << "Public exp (e) : " << eDec.get() << "\n";

            if (showPrivate) {
                OpensslStrPtr pHex(BN_bn2hex(params.p.get()));
                OpensslStrPtr qHex(BN_bn2hex(params.q.get()));
                OpensslStrPtr dPhiHex(BN_bn2hex(params.d_phi.get()));
                OpensslStrPtr dLamHex(BN_bn2hex(params.d_lambda.get()));
                cout << "Prime (p)      : 0x" << pHex.get() << "\n";
                cout << "Prime (q)      : 0x" << qHex.get() << "\n";
                cout << "d (mod phi)    : 0x" << dPhiHex.get() << "\n";
                cout << "d (mod lambda) : 0x" << dLamHex.get() << "\n";
            }

            bool ok = edu::verifyEducationalParams(params, true);
            return ok ? StatusCodes::Success : StatusCodes::CryptoFailure;
        }
        if (subcommand == "keygen") {
            int bits = 3072;
            if (args.hasFlag("bits")) bits = stoi(args.getFlag("bits"));
            string outDir = args.getFlag("out-dir", ".");
            bool force = args.hasFlag("force");

            filesystem::create_directories(outDir);
            EvpPkeyPtr key = sec::generateProductionRsaKey(bits);

            filesystem::path dirPath(outDir);
            sec::savePrivateKey(key.get(), (dirPath / "private.pem").string(), sec::KeyEncoding::PEM, force);
            sec::savePrivateKey(key.get(), (dirPath / "private.der").string(), sec::KeyEncoding::DER, force);
            sec::savePublicKey(key.get(), (dirPath / "public.pem").string(), sec::KeyEncoding::PEM, force);
            sec::savePublicKey(key.get(), (dirPath / "public.der").string(), sec::KeyEncoding::DER, force);

            cout << "Generated RSA-" << bits << " keypair.\n"
                 << "Wrote:\n"
                 << "  " << (dirPath / "private.pem").string() << "\n"
                 << "  " << (dirPath / "private.der").string() << "\n"
                 << "  " << (dirPath / "public.pem").string() << "\n"
                 << "  " << (dirPath / "public.der").string() << "\n";
            return StatusCodes::Success;
        }
        if (subcommand == "key-convert") {
            string typeStr = args.getFlag("type");
            string inPath = args.getFlag("in");
            string outPath = args.getFlag("out");
            string outformStr = args.getFlag("outform");
            bool force = args.hasFlag("force");

            if (typeStr.empty() || inPath.empty() || outPath.empty() || outformStr.empty()) {
                throw LabException(StatusCodes::UsageOrInputError,
                                   "Usage: key-convert --type <public|private> --in <file> --out <file> --outform <PEM|DER>");
            }
            sec::KeyType keyType = (typeStr == "private") ? sec::KeyType::Private : sec::KeyType::Public;
            sec::KeyEncoding outEncoding = (outformStr == "DER") ? sec::KeyEncoding::DER : sec::KeyEncoding::PEM;

            EvpPkeyPtr key = sec::loadKeyStrict(inPath, keyType);
            if (keyType == sec::KeyType::Private) {
                sec::savePrivateKey(key.get(), outPath, outEncoding, force);
            } else {
                sec::savePublicKey(key.get(), outPath, outEncoding, force);
            }
            cout << "Converted key successfully to " << outPath << "\n";
            return StatusCodes::Success;
        }
        if (subcommand == "key-info") {
            string pubPath = args.getFlag("pub");
            if (pubPath.empty() && !args.positionals.empty()) pubPath = args.positionals[0];
            if (pubPath.empty()) throw LabException(StatusCodes::UsageOrInputError, "Usage: key-info --pub <file>");

            EvpPkeyPtr pubKey = sec::loadKeyStrict(pubPath, sec::KeyType::Public);
            int bits = EVP_PKEY_get_bits(pubKey.get());
            BIGNUM *rawE = nullptr;
            EVP_PKEY_get_bn_param(pubKey.get(), OSSL_PKEY_PARAM_RSA_E, &rawE);
            BignumPtr e(rawE);
            OpensslStrPtr eDec(BN_bn2dec(e.get()));
            string kidHex = sec::formatKeyIdHex(pubKey.get());

            cout << "Algorithm : RSA\n"
                 << "Modulus   : " << bits << " bits\n"
                 << "Exponent  : " << eDec.get() << "\n"
                 << "Key ID    : " << kidHex << "\n";
            return StatusCodes::Success;
        }
        if (subcommand == "key-check") {
            string privPath = args.getFlag("priv");
            string pubPath = args.getFlag("pub");
            if (privPath.empty() || pubPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: key-check --priv <file> --pub <file>");
            }

            EvpPkeyPtr privKey = sec::loadKeyStrict(privPath, sec::KeyType::Private);
            EvpPkeyPtr pubKey = sec::loadKeyStrict(pubPath, sec::KeyType::Public);

            bool privValid = sec::validateKeyStructure(privKey.get(), sec::KeyType::Private);
            bool pubValid = sec::validateKeyStructure(pubKey.get(), sec::KeyType::Public);
            bool match = sec::compareKeysMatch(privKey.get(), pubKey.get());

            if (privValid && pubValid && match) {
                cout << "MATCH\n";
                return StatusCodes::Success;
            } else {
                cout << "MISMATCH\n";
                return StatusCodes::CryptoFailure;
            }
        }

        if (subcommand == "os2ip") {
            string hexStr = args.getFlag("hex");
            if (hexStr.empty() && !args.positionals.empty()) hexStr = args.positionals[0];
            vector<uint8_t> bytes = utils::hexToBytes(hexStr);
            BignumPtr x = edu::os2ip(bytes);
            OpensslStrPtr decStr(BN_bn2dec(x.get()));
            cout << decStr.get() << "\n";
            return StatusCodes::Success;
        }
        if (subcommand == "i2osp") {
            string intStr = args.getFlag("int");
            string lenStr = args.getFlag("len");
            if (intStr.empty() || lenStr.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: i2osp --int <decimal> --len <L>");
            }
            BignumPtr x = edu::parseDecimalStrict(intStr);
            size_t targetLen = stoull(lenStr);
            vector<uint8_t> out;
            if (!edu::i2osp(x.get(), targetLen, out)) {
                cerr << "error: integer too large\n";
                return StatusCodes::UsageOrInputError;
            }
            cout << utils::bytesToHex(out) << "\n";
            return StatusCodes::Success;
        }
        if (subcommand == "raw-rsa") {
            string bitsStr = args.getFlag("bits", "512");
            int bits = stoi(bitsStr);
            if (bits < 512 || bits > 1024) {
                throw LabException(StatusCodes::UsageOrInputError, "raw-rsa requires 512 <= bits <= 1024");
            }

            cout << "=== EDUCATIONAL - INSECURE ===\n";
            edu::EducationalRsaParams params = edu::generateEducationalRsaParams(bits);
            BnCtxPtr ctx = makeBnCtx();

            vector<uint8_t> testMsg = {'A', 'T', 'T', 'A', 'C', 'K'};
            BignumPtr m = edu::os2ip(testMsg);
            BignumPtr c = edu::textbookEncrypt(m.get(), params.e.get(), params.n.get(), ctx.get());
            BignumPtr mRecovered = edu::textbookDecrypt(c.get(), params.d_lambda.get(), params.n.get(), ctx.get());
            vector<uint8_t> recoveredBytes;
            edu::i2osp(mRecovered.get(), testMsg.size(), recoveredBytes);
            bool roundTripPass = (recoveredBytes == testMsg);
            cout << "  [" << (roundTripPass ? "PASS" : "FAIL") << "] (i) Round-trip recovery matches original bytes\n";

            bool rangeRejected = false;
            try {
                edu::textbookEncrypt(params.n.get(), params.e.get(), params.n.get(), ctx.get());
            } catch (const LabException &) {
                rangeRejected = true;
            }
            cout << "  [" << (rangeRejected ? "PASS" : "FAIL") << "] (ii) Input m >= n strictly rejected before exponentiation\n";

            BignumPtr c1 = edu::textbookEncrypt(m.get(), params.e.get(), params.n.get(), ctx.get());
            BignumPtr c2 = edu::textbookEncrypt(m.get(), params.e.get(), params.n.get(), ctx.get());
            bool deterministic = (BN_cmp(c1.get(), c2.get()) == 0);
            cout << "  [" << (deterministic ? "PASS" : "FAIL") << "] (iii) Deterministic: identical message yields identical ciphertext\n";

            BignumPtr m6 = makeBignum(); BN_set_word(m6.get(), 6);
            BignumPtr m7 = makeBignum(); BN_set_word(m7.get(), 7);
            BignumPtr c6 = edu::textbookEncrypt(m6.get(), params.e.get(), params.n.get(), ctx.get());
            BignumPtr c7 = edu::textbookEncrypt(m7.get(), params.e.get(), params.n.get(), ctx.get());
            BignumPtr cMult = makeBignum();
            BN_mod_mul(cMult.get(), c6.get(), c7.get(), params.n.get(), ctx.get());
            BignumPtr decMult = edu::textbookDecrypt(cMult.get(), params.d_lambda.get(), params.n.get(), ctx.get());
            bool malleablePass = BN_is_word(decMult.get(), 42);
            cout << "  [" << (malleablePass ? "PASS" : "FAIL") << "] (iv) Malleable: Dec(Enc(6)*Enc(7) mod n) == 42 without knowing d\n";
            return StatusCodes::Success;
        }
        if (subcommand == "oaep-demo") {
            string pubPath = args.getFlag("pub");
            string privPath = args.getFlag("priv");
            if (pubPath.empty() || privPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: oaep-demo --pub <key> --priv <key>");
            }
            EvpPkeyPtr pubKey = sec::loadKeyStrict(pubPath, sec::KeyType::Public);
            EvpPkeyPtr privKey = sec::loadKeyStrict(privPath, sec::KeyType::Private);

            size_t k = static_cast<size_t>(EVP_PKEY_get_size(pubKey.get()));
            constexpr size_t hLen = 32;
            size_t maxMsgLen = k - 2 * hLen - 2;

            cout << "=== RSA-OAEP Randomization & Redundancy Demo ===\n";
            sec::SecureBytes sampleKey(32, 0x5a);
            vector<uint8_t> ct1 = sec::oaepWrapKey(pubKey.get(), sampleKey);
            sec::SecureBytes sampleKeyCopy(32, 0x5a);
            vector<uint8_t> ct2 = sec::oaepWrapKey(pubKey.get(), sampleKeyCopy);
            bool randomized = (ct1 != ct2);
            cout << "  [" << (randomized ? "PASS" : "FAIL") << "] Randomized: Encrypting identical message yields distinct ciphertexts\n";

            sec::SecureBytes dec1 = sec::oaepUnwrapKey(privKey.get(), ct1);
            sec::SecureBytes dec2 = sec::oaepUnwrapKey(privKey.get(), ct2);
            bool decOk = (dec1.size() == 32 && dec2.size() == 32 &&
                          CRYPTO_memcmp(dec1.data(), sampleKey.data(), 32) == 0 &&
                          CRYPTO_memcmp(dec2.data(), sampleKey.data(), 32) == 0);
            cout << "  [" << (decOk ? "PASS" : "FAIL") << "] Both distinct ciphertexts decrypt to the original plaintext\n";

            cout << "  Modulus length: " << k << " bytes, Max OAEP message payload: " << maxMsgLen << " bytes\n";
            sec::SecureBytes maxMsg(maxMsgLen, 'A');
            bool maxAccepted = false;
            try {
                vector<uint8_t> wrappedMax = sec::oaepWrapKey(pubKey.get(), maxMsg);
                sec::SecureBytes unwrappedMax = sec::oaepUnwrapKey(privKey.get(), wrappedMax);
                maxAccepted = (unwrappedMax.size() == maxMsgLen);
            } catch (...) {}
            cout << "  [" << (maxAccepted ? "PASS" : "FAIL") << "] Maximum message payload (" << maxMsgLen << " bytes) accepted\n";

            sec::SecureBytes overflowMsg(maxMsgLen + 1, 'B');
            bool overflowRejected = false;
            try {
                sec::oaepWrapKey(pubKey.get(), overflowMsg);
            } catch (...) {
                overflowRejected = true;
            }
            cout << "  [" << (overflowRejected ? "PASS" : "FAIL") << "] Message exceeding limit (" << (maxMsgLen + 1) << " bytes) strictly rejected\n";

            vector<uint8_t> tamperedCt = ct1;
            tamperedCt[10] ^= 0x01;
            sec::SecureBytes tamperedDec = sec::oaepUnwrapKey(privKey.get(), tamperedCt);
            cout << "  [" << (tamperedDec.empty() ? "PASS" : "FAIL") << "] Tampered ciphertext rejected (padding integrity check succeeds)\n";
            return StatusCodes::Success;
        }

        if (subcommand == "encrypt") {
            string pubPath = args.getFlag("pub");
            string inPath = args.getFlag("in");
            string outPath = args.getFlag("out");
            bool force = args.hasFlag("force");

            if (pubPath.empty() || inPath.empty() || outPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: encrypt --pub <key> --in <file> --out <pkg> [--force]");
            }
            sec::encryptFileOaep(pubPath, inPath, outPath, force);
            cout << "Encrypted " << inPath << " -> " << outPath << " (Mode 0x01 RSA-OAEP + AES-256-GCM)\n";
            return StatusCodes::Success;
        }
        if (subcommand == "decrypt") {
            string privPath = args.getFlag("priv");
            string inPath = args.getFlag("in");
            string outPath = args.getFlag("out");
            bool force = args.hasFlag("force");

            if (privPath.empty() || inPath.empty() || outPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: decrypt --priv <key> --in <pkg> --out <file> [--force]");
            }
            sec::decryptFileOaep(privPath, inPath, outPath, force);
            cout << "Decrypted " << inPath << " -> " << outPath << " successfully.\n";
            return StatusCodes::Success;
        }

        if (subcommand == "kem-encrypt") {
            string pubPath = args.getFlag("pub");
            string inPath = args.getFlag("in");
            string outPath = args.getFlag("out");
            bool force = args.hasFlag("force");

            if (pubPath.empty() || inPath.empty() || outPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: kem-encrypt --pub <key> --in <file> --out <pkg> [--force]");
            }
            sec::encryptFileKem(pubPath, inPath, outPath, force);
            cout << "Encrypted " << inPath << " -> " << outPath << " (Mode 0x02 RSASVE KEM + HKDF + AES-256-GCM)\n";
            return StatusCodes::Success;
        }
        if (subcommand == "kem-decrypt") {
            string privPath = args.getFlag("priv");
            string inPath = args.getFlag("in");
            string outPath = args.getFlag("out");
            bool force = args.hasFlag("force");

            if (privPath.empty() || inPath.empty() || outPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: kem-decrypt --priv <key> --in <pkg> --out <file> [--force]");
            }
            sec::decryptFileKem(privPath, inPath, outPath, force);
            cout << "Decrypted " << inPath << " -> " << outPath << " successfully.\n";
            return StatusCodes::Success;
        }
        if (subcommand == "kem-selftest") {
            string pubPath = args.getFlag("pub");
            string privPath = args.getFlag("priv");
            if (pubPath.empty() || privPath.empty()) {
                throw LabException(StatusCodes::UsageOrInputError, "Usage: kem-selftest --pub <key> --priv <key>");
            }
            sec::runKemSelftest(pubPath, privPath);
            return StatusCodes::Success;
        }

        if (subcommand == "kat") {
            return kat::runAllAcceptanceTests();
        }
        if (subcommand == "bench") {
            bench::runBenchmarks();
            return StatusCodes::Success;
        }

        cerr << "Unknown subcommand: " << subcommand << "\n";
        printGlobalHelp();
        return StatusCodes::UsageOrInputError;

    } catch (const LabException &ex) {
        cerr << "Error: " << ex.what() << "\n";
        return ex.exit_code;
    } catch (const exception &ex) {
        cerr << "Unexpected exception: " << ex.what() << "\n";
        return StatusCodes::InternalError;
    }
}
