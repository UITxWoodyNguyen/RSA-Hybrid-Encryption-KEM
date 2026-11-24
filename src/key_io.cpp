#include "key_io.hpp"
#include "utils.hpp"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>

namespace sec {

EvpPkeyPtr generateProductionRsaKey(int bits) {
    if (bits != 2048 && bits != 3072 && bits != 4096) {
        throw LabException(StatusCodes::UsageOrInputError,
                           "Production RSA key modulus bits must be one of: 2048, 3072, 4096");
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
    if (!ctx) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_CTX_new_from_name failed: " + drainOpenSslErrors());
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_keygen_init failed: " + drainOpenSslErrors());
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_CTX_set_rsa_keygen_bits failed: " + drainOpenSslErrors());
    }

    EVP_PKEY *rawKey = nullptr;
    if (EVP_PKEY_generate(ctx.get(), &rawKey) <= 0 || rawKey == nullptr) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_generate failed: " + drainOpenSslErrors());
    }

    return EvpPkeyPtr(rawKey);
}

void savePrivateKey(const EVP_PKEY *key, const string &path, KeyEncoding encoding, bool force) {
    if (key == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null key passed to savePrivateKey");
    }
    if (!force && utils::fileExists(path)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + path);
    }

    BioPtr bio(BIO_new_file(path.c_str(), "wb"));
    if (!bio) {
        throw LabException(StatusCodes::IOError, "Cannot open private key file for writing: " + path);
    }

    if (encoding == KeyEncoding::PEM) {
        if (PEM_write_bio_PrivateKey(bio.get(), const_cast<EVP_PKEY *>(key), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw LabException(StatusCodes::InternalError, "PEM_write_bio_PrivateKey failed: " + drainOpenSslErrors());
        }
    } else {
        if (i2d_PKCS8PrivateKey_bio(bio.get(), const_cast<EVP_PKEY *>(key), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw LabException(StatusCodes::InternalError, "i2d_PKCS8PrivateKey_bio failed: " + drainOpenSslErrors());
        }
    }

    bio.reset();
    utils::setStrictFilePermissions(path);
}

void savePublicKey(const EVP_PKEY *key, const string &path, KeyEncoding encoding, bool force) {
    if (key == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null key passed to savePublicKey");
    }
    if (!force && utils::fileExists(path)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + path);
    }

    BioPtr bio(BIO_new_file(path.c_str(), "wb"));
    if (!bio) {
        throw LabException(StatusCodes::IOError, "Cannot open public key file for writing: " + path);
    }

    if (encoding == KeyEncoding::PEM) {
        if (PEM_write_bio_PUBKEY(bio.get(), const_cast<EVP_PKEY *>(key)) != 1) {
            throw LabException(StatusCodes::InternalError, "PEM_write_bio_PUBKEY failed: " + drainOpenSslErrors());
        }
    } else {
        if (i2d_PUBKEY_bio(bio.get(), const_cast<EVP_PKEY *>(key)) != 1) {
            throw LabException(StatusCodes::InternalError, "i2d_PUBKEY_bio failed: " + drainOpenSslErrors());
        }
    }
}

static void verifyDerNoTrailingBytes(const EVP_PKEY *key, const vector<uint8_t> &rawBytes, KeyType type) {
    unsigned char *derBuf = nullptr;
    int derLen = 0;
    if (type == KeyType::Public) {
        derLen = i2d_PUBKEY(key, &derBuf);
    } else {
        BioPtr memBio(BIO_new(BIO_s_mem()));
        if (i2d_PKCS8PrivateKey_bio(memBio.get(), const_cast<EVP_PKEY *>(key), nullptr, nullptr, 0, nullptr, nullptr) == 1) {
            BUF_MEM *bptr = nullptr;
            BIO_get_mem_ptr(memBio.get(), &bptr);
            if (bptr != nullptr) {
                derLen = static_cast<int>(bptr->length);
            }
        }
    }
    if (derBuf != nullptr) {
        OPENSSL_free(derBuf);
    }

    if (derLen > 0 && static_cast<size_t>(derLen) != rawBytes.size()) {
        throw LabException(StatusCodes::DataError, "DER file contains trailing or mismatched data");
    }
}

EvpPkeyPtr loadKeyStrict(const string &path, KeyType expectedType, KeyEncoding *detectedEncoding) {
    if (!utils::fileExists(path)) {
        throw LabException(StatusCodes::IOError, "Key file not found: " + path);
    }

    vector<uint8_t> fileBytes = utils::readAllBytes(path);
    if (fileBytes.empty()) {
        throw LabException(StatusCodes::DataError, "Key file is empty: " + path);
    }

    string textContent(fileBytes.begin(), fileBytes.end());
    bool isPem = (textContent.find("-----BEGIN ") != string::npos);

    if (detectedEncoding != nullptr) {
        *detectedEncoding = isPem ? KeyEncoding::PEM : KeyEncoding::DER;
    }

    if (isPem) {
        if (expectedType == KeyType::Public) {
            if (textContent.find("-----BEGIN PUBLIC KEY-----") == string::npos) {
                if (textContent.find("BEGIN RSA") != string::npos) {
                    throw LabException(StatusCodes::DataError, "PKCS#1 RSA public key rejected (SPKI required)");
                }
                if (textContent.find("PRIVATE KEY") != string::npos) {
                    throw LabException(StatusCodes::DataError, "Private key provided where public key was expected");
                }
                throw LabException(StatusCodes::DataError, "Malformed or unsupported PEM public key structure");
            }
        } else {
            if (textContent.find("-----BEGIN PRIVATE KEY-----") == string::npos) {
                if (textContent.find("BEGIN RSA") != string::npos) {
                    throw LabException(StatusCodes::DataError, "PKCS#1 RSA private key rejected (PKCS#8 required)");
                }
                if (textContent.find("PUBLIC KEY") != string::npos) {
                    throw LabException(StatusCodes::DataError, "Public key provided where private key was expected");
                }
                throw LabException(StatusCodes::DataError, "Malformed or unsupported PEM private key structure");
            }
        }
    }

    BioPtr bio(BIO_new_mem_buf(fileBytes.data(), static_cast<int>(fileBytes.size())));
    if (!bio) {
        throw LabException(StatusCodes::InternalError, "BIO_new_mem_buf failed");
    }

    EVP_PKEY *rawKey = nullptr;
    if (isPem) {
        if (expectedType == KeyType::Public) {
            rawKey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        } else {
            rawKey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        }
    } else {
        const unsigned char *pData = fileBytes.data();
        if (expectedType == KeyType::Public) {
            rawKey = d2i_PUBKEY(nullptr, &pData, static_cast<long>(fileBytes.size()));
            if (rawKey != nullptr && pData != fileBytes.data() + fileBytes.size()) {
                EVP_PKEY_free(rawKey);
                throw LabException(StatusCodes::DataError, "DER public key contains trailing bytes");
            }
        } else {
            const unsigned char *pPrivData = fileBytes.data();
            PKCS8_PRIV_KEY_INFO *p8inf = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &pPrivData, static_cast<long>(fileBytes.size()));
            if (p8inf != nullptr) {
                if (pPrivData != fileBytes.data() + fileBytes.size()) {
                    PKCS8_PRIV_KEY_INFO_free(p8inf);
                    throw LabException(StatusCodes::DataError, "DER private key contains trailing bytes");
                }
                rawKey = EVP_PKCS82PKEY(p8inf);
                PKCS8_PRIV_KEY_INFO_free(p8inf);
            } else {
                rawKey = d2i_PKCS8PrivateKey_bio(bio.get(), nullptr, nullptr, nullptr);
            }
        }
    }

    if (rawKey == nullptr) {
        string errStr = drainOpenSslErrors();
        throw LabException(StatusCodes::DataError, "Failed to decode key: " + errStr);
    }

    EvpPkeyPtr key(rawKey);

    if (EVP_PKEY_is_a(key.get(), "RSA") != 1) {
        throw LabException(StatusCodes::DataError, "Key is not an RSA key");
    }

    int keyBits = EVP_PKEY_get_bits(key.get());
    if (keyBits < 2048) {
        throw LabException(StatusCodes::DataError,
                           "Insecure RSA key length (" + to_string(keyBits) + " bits). Minimum required is 2048 bits");
    }

    if (!isPem) {
        verifyDerNoTrailingBytes(key.get(), fileBytes, expectedType);
    }

    return key;
}

vector<uint8_t> computeKeyId(const EVP_PKEY *key) {
    if (key == nullptr) {
        throw LabException(StatusCodes::UsageOrInputError, "Null key in computeKeyId");
    }
    unsigned char *derBytes = nullptr;
    int derLen = i2d_PUBKEY(key, &derBytes);
    if (derLen <= 0 || derBytes == nullptr) {
        throw LabException(StatusCodes::InternalError, "i2d_PUBKEY failed to serialize public key: " + drainOpenSslErrors());
    }

    vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(derBytes, static_cast<size_t>(derLen), digest.data());
    OPENSSL_free(derBytes);
    return digest;
}

string formatKeyIdHex(const EVP_PKEY *key) {
    vector<uint8_t> kid = computeKeyId(key);
    return utils::bytesToHex(kid);
}

bool compareKeysMatch(const EVP_PKEY *privKey, const EVP_PKEY *pubKey) {
    if (privKey == nullptr || pubKey == nullptr) return false;
    return (EVP_PKEY_eq(privKey, pubKey) == 1);
}

bool validateKeyStructure(const EVP_PKEY *key, KeyType type) {
    if (key == nullptr) return false;
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY *>(key), nullptr));
    if (!ctx) return false;

    if (type == KeyType::Public) {
        return (EVP_PKEY_public_check(ctx.get()) == 1);
    } else {
        if (EVP_PKEY_private_check(ctx.get()) != 1) return false;
        return (EVP_PKEY_pairwise_check(ctx.get()) == 1);
    }
}

} // namespace sec
