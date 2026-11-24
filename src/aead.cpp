#include "aead.hpp"
#include <openssl/evp.h>

namespace sec {

void gcmEncryptStream(const SecureBytes &key,
                      const vector<uint8_t> &nonce,
                      const vector<uint8_t> &aad,
                      istream &inStream,
                      ostream &outStream,
                      vector<uint8_t> &tagOut) {
    if (key.size() != GCM_KEY_LEN || nonce.size() != GCM_NONCE_LEN) {
        throw LabException(StatusCodes::UsageOrInputError, "Invalid AES-GCM key or nonce dimensions");
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw LabException(StatusCodes::InternalError, "EVP_CIPHER_CTX_new failed: " + drainOpenSslErrors());
    }

    if (EVP_EncryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) != 1) {
        throw LabException(StatusCodes::InternalError, "EVP_EncryptInit_ex2 failed: " + drainOpenSslErrors());
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
            throw LabException(StatusCodes::InternalError, "EVP_EncryptUpdate (AAD) failed: " + drainOpenSslErrors());
        }
    }

    vector<uint8_t> inBuf(CHUNK_SIZE);
    vector<uint8_t> outBuf(CHUNK_SIZE + 16);

    while (inStream.good()) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), CHUNK_SIZE);
        streamsize bytesRead = inStream.gcount();
        if (bytesRead > 0) {
            if (EVP_EncryptUpdate(ctx.get(), outBuf.data(), &len, inBuf.data(), static_cast<int>(bytesRead)) != 1) {
                throw LabException(StatusCodes::InternalError, "EVP_EncryptUpdate failed: " + drainOpenSslErrors());
            }
            if (len > 0) {
                outStream.write(reinterpret_cast<const char *>(outBuf.data()), len);
                if (!outStream.good()) {
                    throw LabException(StatusCodes::IOError, "Failed to write ciphertext chunk to output stream");
                }
            }
        }
    }

    if (EVP_EncryptFinal_ex(ctx.get(), outBuf.data(), &len) != 1) {
        throw LabException(StatusCodes::InternalError, "EVP_EncryptFinal_ex failed: " + drainOpenSslErrors());
    }
    if (len > 0) {
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), len);
    }

    tagOut.assign(GCM_TAG_LEN, 0);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(GCM_TAG_LEN), tagOut.data()) != 1) {
        throw LabException(StatusCodes::InternalError, "Failed to retrieve AES-GCM authentication tag");
    }
}

bool gcmDecryptStream(const SecureBytes &key,
                      const vector<uint8_t> &nonce,
                      const vector<uint8_t> &aad,
                      istream &inStream,
                      uint64_t cipherLen,
                      const vector<uint8_t> &expectedTag,
                      ostream &outStream) {
    if (key.size() != GCM_KEY_LEN || nonce.size() != GCM_NONCE_LEN || expectedTag.size() != GCM_TAG_LEN) {
        return false;
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return false;
    }

    if (EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) != 1) {
        return false;
    }

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
            return false;
        }
    }

    vector<uint8_t> decryptedPlaintext;
    decryptedPlaintext.reserve(cipherLen);

    uint64_t remaining = cipherLen;
    vector<uint8_t> inBuf(CHUNK_SIZE);
    vector<uint8_t> outBuf(CHUNK_SIZE + 16);

    while (remaining > 0) {
        size_t toRead = static_cast<size_t>(min<uint64_t>(remaining, CHUNK_SIZE));
        inStream.read(reinterpret_cast<char *>(inBuf.data()), toRead);
        streamsize bytesRead = inStream.gcount();
        if (bytesRead <= 0) {
            return false;
        }
        if (EVP_DecryptUpdate(ctx.get(), outBuf.data(), &len, inBuf.data(), static_cast<int>(bytesRead)) != 1) {
            return false;
        }
        if (len > 0) {
            decryptedPlaintext.insert(decryptedPlaintext.end(), outBuf.data(), outBuf.data() + len);
        }
        remaining -= static_cast<uint64_t>(bytesRead);
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(GCM_TAG_LEN),
                            const_cast<uint8_t *>(expectedTag.data())) != 1) {
        OPENSSL_cleanse(decryptedPlaintext.data(), decryptedPlaintext.size());
        return false;
    }

    bool authSuccess = (EVP_DecryptFinal_ex(ctx.get(), outBuf.data(), &len) == 1);
    if (authSuccess) {
        if (len > 0) {
            decryptedPlaintext.insert(decryptedPlaintext.end(), outBuf.data(), outBuf.data() + len);
        }
        if (!decryptedPlaintext.empty()) {
            outStream.write(reinterpret_cast<const char *>(decryptedPlaintext.data()), decryptedPlaintext.size());
            if (!outStream.good()) {
                throw LabException(StatusCodes::IOError, "Failed to write verified plaintext to output file");
            }
        }
    } else {
        OPENSSL_cleanse(decryptedPlaintext.data(), decryptedPlaintext.size());
        ERR_clear_error();
    }

    return authSuccess;
}

} // namespace sec
