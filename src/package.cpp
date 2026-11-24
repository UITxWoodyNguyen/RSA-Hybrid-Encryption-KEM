#include "package.hpp"
#include "utils.hpp"
#include <cstring>

namespace sec {

static void appendBigEndian16(vector<uint8_t> &dest, uint16_t val) {
    dest.pb(static_cast<uint8_t>((val >> 8) & 0xff));
    dest.pb(static_cast<uint8_t>(val & 0xff));
}

static void putU64(vector<uint8_t> &dest, uint64_t val) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        dest.pb(static_cast<uint8_t>((val >> shift) & 0xff));
    }
}

static uint16_t readU16(const uint8_t *ptr) {
    return static_cast<uint16_t>((static_cast<uint16_t>(ptr[0]) << 8) | ptr[1]);
}

static uint64_t readU64(const uint8_t *ptr) {
    uint64_t v = 0;
    REP(i, 0, 8) {
        v = (v << 8) | ptr[i];
    }
    return v;
}

vector<uint8_t> PackageHeader::serialize() const {
    vector<uint8_t> hdr;
    hdr.insert(hdr.end(), MAGIC, MAGIC + 4);
    hdr.pb(version);
    hdr.pb(mode);
    appendBigEndian16(hdr, reserved);
    appendBigEndian16(hdr, klen);
    hdr.insert(hdr.end(), wrapped_key_or_ct.begin(), wrapped_key_or_ct.end());
    if (mode == MODE_KEM_PROFILE) {
        hdr.insert(hdr.end(), key_id.begin(), key_id.end());
    }
    hdr.insert(hdr.end(), nonce.begin(), nonce.end());
    putU64(hdr, ct_len);
    return hdr;
}

PackageHeader PackageHeader::parseFromStream(istream &stream, uint64_t totalFileSize, uint16_t expectedKlen) {
    if (totalFileSize < 10) {
        throw LabException(StatusCodes::DataError, "Package file too short to contain header prefix");
    }

    uint8_t prefix[10];
    stream.read(reinterpret_cast<char *>(prefix), 10);
    if (stream.gcount() != 10) {
        throw LabException(StatusCodes::DataError, "Failed to read header prefix");
    }

    if (memcmp(prefix, MAGIC, 4) != 0) {
        throw LabException(StatusCodes::DataError, "Invalid package magic (expected 'L2PK')");
    }

    uint8_t ver = prefix[4];
    if (ver != FORMAT_VERSION_1) {
        throw LabException(StatusCodes::DataError, "Unsupported package format version: " + to_string(ver));
    }

    uint8_t modeVal = prefix[5];
    if (modeVal != MODE_OAEP_TRANSPORT && modeVal != MODE_KEM_PROFILE) {
        throw LabException(StatusCodes::DataError, "Unsupported or unknown package mode: " + to_string(modeVal));
    }

    uint16_t resField = readU16(prefix + 6);
    if (resField != 0x0000) {
        throw LabException(StatusCodes::DataError, "Reserved header bytes must be zero");
    }

    uint16_t keyLen = readU16(prefix + 8);
    if (expectedKlen > 0 && keyLen != expectedKlen) {
        throw LabException(StatusCodes::DataError, "Package klen (" + to_string(keyLen) +
                                                      ") does not match recipient key modulus size (" +
                                                      to_string(expectedKlen) + ")");
    }

    size_t varPartLen = keyLen + (modeVal == MODE_KEM_PROFILE ? 32 : 0) + 12 + 8;
    size_t fullHeaderLen = 10 + varPartLen;

    if (totalFileSize < fullHeaderLen + 16) {
        throw LabException(StatusCodes::DataError, "Package file is truncated, cannot contain full header and tag");
    }

    vector<uint8_t> varBuf(varPartLen);
    stream.read(reinterpret_cast<char *>(varBuf.data()), static_cast<streamsize>(varPartLen));
    if (static_cast<size_t>(stream.gcount()) != varPartLen) {
        throw LabException(StatusCodes::DataError, "Incomplete read of variable header fields");
    }

    PackageHeader parsed;
    parsed.version = ver;
    parsed.mode = modeVal;
    parsed.reserved = resField;
    parsed.klen = keyLen;

    const uint8_t *curr = varBuf.data();
    parsed.wrapped_key_or_ct.assign(curr, curr + keyLen);
    curr += keyLen;

    if (modeVal == MODE_KEM_PROFILE) {
        parsed.key_id.assign(curr, curr + 32);
        curr += 32;
    }

    parsed.nonce.assign(curr, curr + 12);
    curr += 12;

    parsed.ct_len = readU64(curr);

    if (parsed.ct_len > MAX_CIPHERTEXT_SIZE) {
        throw LabException(StatusCodes::DataError, "Package ciphertext length exceeds allowed limit (1 GiB)");
    }

    if (totalFileSize != fullHeaderLen + parsed.ct_len + 16) {
        throw LabException(StatusCodes::DataError, "Exact file size mismatch: expected " +
                                                      to_string(fullHeaderLen + parsed.ct_len + 16) +
                                                      " bytes, found " + to_string(totalFileSize) + " bytes");
    }

    parsed.raw_header.assign(prefix, prefix + 10);
    parsed.raw_header.insert(parsed.raw_header.end(), varBuf.begin(), varBuf.end());

    return parsed;
}

} // namespace sec
