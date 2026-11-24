#include "hybrid_oaep.hpp"
#include "key_io.hpp"
#include "aead.hpp"
#include "utils.hpp"
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <fstream>

namespace sec {

static void setupRsaOaepCtx(EVP_PKEY_CTX *ctx) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        throw LabException(StatusCodes::InternalError, "Failed to set RSA_PKCS1_OAEP_PADDING");
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        throw LabException(StatusCodes::InternalError, "Failed to set RSA OAEP MD to SHA-256");
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        throw LabException(StatusCodes::InternalError, "Failed to set RSA MGF1 MD to SHA-256");
    }
}

vector<uint8_t> oaepWrapKey(const EVP_PKEY *recipientPubKey, const SecureBytes &symmetricKey) {
    if (recipientPubKey == nullptr || symmetricKey.size() != 32) {
        throw LabException(StatusCodes::UsageOrInputError, "Invalid parameters to oaepWrapKey");
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY *>(recipientPubKey), nullptr));
    if (!ctx) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_CTX_new_from_pkey failed: " + drainOpenSslErrors());
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encrypt_init failed: " + drainOpenSslErrors());
    }

    setupRsaOaepCtx(ctx.get());

    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outLen, symmetricKey.data(), symmetricKey.size()) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encrypt size query failed: " + drainOpenSslErrors());
    }

    vector<uint8_t> wrapped(outLen);
    if (EVP_PKEY_encrypt(ctx.get(), wrapped.data(), &outLen, symmetricKey.data(), symmetricKey.size()) <= 0) {
        throw LabException(StatusCodes::InternalError, "EVP_PKEY_encrypt failed: " + drainOpenSslErrors());
    }
    wrapped.resize(outLen);
    return wrapped;
}

SecureBytes oaepUnwrapKey(const EVP_PKEY *recipientPrivKey, const vector<uint8_t> &wrappedKey) {
    if (recipientPrivKey == nullptr || wrappedKey.empty()) {
        return SecureBytes();
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, const_cast<EVP_PKEY *>(recipientPrivKey), nullptr));
    if (!ctx) {
        return SecureBytes();
    }

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        return SecureBytes();
    }

    setupRsaOaepCtx(ctx.get());

    size_t outLen = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outLen, wrappedKey.data(), wrappedKey.size()) <= 0) {
        ERR_clear_error();
        return SecureBytes();
    }

    SecureBytes unwrapped(outLen);
    if (EVP_PKEY_decrypt(ctx.get(), unwrapped.data(), &outLen, wrappedKey.data(), wrappedKey.size()) <= 0) {
        ERR_clear_error();
        return SecureBytes();
    }

    unwrapped.resize(outLen);
    return unwrapped;
}

void encryptFileOaep(const string &pubKeyPath,
                     const string &inFilePath,
                     const string &outPkgPath,
                     bool force) {
    if (!force && utils::fileExists(outPkgPath)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + outPkgPath);
    }

    EvpPkeyPtr pubKey = loadKeyStrict(pubKeyPath, KeyType::Public);
    size_t k = static_cast<size_t>(EVP_PKEY_get_size(pubKey.get()));

    SecureBytes aesKey(32);
    vector<uint8_t> nonce(12);
    if (RAND_bytes(aesKey.data(), 32) != 1 || RAND_bytes(nonce.data(), 12) != 1) {
        throw LabException(StatusCodes::InternalError, "RAND_bytes failed to generate symmetric parameters");
    }

    vector<uint8_t> wrappedKey = oaepWrapKey(pubKey.get(), aesKey);

    uint64_t fileSize = utils::getFileLength(inFilePath);
    PackageHeader header;
    header.version = FORMAT_VERSION_1;
    header.mode = MODE_OAEP_TRANSPORT;
    header.reserved = 0x0000;
    header.klen = static_cast<uint16_t>(k);
    header.wrapped_key_or_ct = wrappedKey;
    header.nonce = nonce;
    header.ct_len = fileSize;

    vector<uint8_t> serializedHeader = header.serialize();

    ifstream inStream(inFilePath, ios::binary);
    if (!inStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open input plaintext file: " + inFilePath);
    }

    string tempOutPkg = outPkgPath + ".part";
    utils::deleteFileIfExists(tempOutPkg);

    ofstream outStream(tempOutPkg, ios::binary | ios::trunc);
    if (!outStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open temporary output package file: " + tempOutPkg);
    }

    outStream.write(reinterpret_cast<const char *>(serializedHeader.data()), serializedHeader.size());

    vector<uint8_t> tag;
    gcmEncryptStream(aesKey, nonce, serializedHeader, inStream, outStream, tag);

    outStream.write(reinterpret_cast<const char *>(tag.data()), tag.size());
    outStream.close();
    inStream.close();

    utils::safeAtomicRename(tempOutPkg, outPkgPath, force);
}

void decryptFileOaep(const string &privKeyPath,
                     const string &inPkgPath,
                     const string &outFilePath,
                     bool force) {
    if (!force && utils::fileExists(outFilePath)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force: " + outFilePath);
    }

    EvpPkeyPtr privKey = loadKeyStrict(privKeyPath, KeyType::Private);
    uint16_t expectedK = static_cast<uint16_t>(EVP_PKEY_get_size(privKey.get()));

    uint64_t totalFileSize = utils::getFileLength(inPkgPath);
    ifstream inPkgStream(inPkgPath, ios::binary);
    if (!inPkgStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open package file: " + inPkgPath);
    }

    PackageHeader header = PackageHeader::parseFromStream(inPkgStream, totalFileSize, expectedK);
    if (header.mode != MODE_OAEP_TRANSPORT) {
        throw LabException(StatusCodes::DataError, "Package mode mismatch (expected Mode 0x01 RSA-OAEP)");
    }

    inPkgStream.seekg(static_cast<streamoff>(totalFileSize - 16), ios::beg);
    vector<uint8_t> expectedTag(16);
    inPkgStream.read(reinterpret_cast<char *>(expectedTag.data()), 16);

    size_t headerLen = header.raw_header.size();
    inPkgStream.seekg(static_cast<streamoff>(headerLen), ios::beg);

    SecureBytes aesKey = oaepUnwrapKey(privKey.get(), header.wrapped_key_or_ct);
    if (aesKey.size() != 32) {
        throw LabException(StatusCodes::CryptoFailure, "decryption failed");
    }

    string tempOutPath = outFilePath + ".part";
    utils::deleteFileIfExists(tempOutPath);

    ofstream outPlainStream(tempOutPath, ios::binary | ios::trunc);
    if (!outPlainStream.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot create temporary decrypted output file: " + tempOutPath);
    }

    bool verified = gcmDecryptStream(aesKey, header.nonce, header.raw_header, inPkgStream,
                                     header.ct_len, expectedTag, outPlainStream);
    outPlainStream.close();
    inPkgStream.close();

    if (!verified) {
        utils::deleteFileIfExists(tempOutPath);
        throw LabException(StatusCodes::CryptoFailure, "decryption failed");
    }

    utils::safeAtomicRename(tempOutPath, outFilePath, force);
}

} // namespace sec
