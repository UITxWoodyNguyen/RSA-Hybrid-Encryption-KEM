#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace utils {

string bytesToHex(const uint8_t *data, size_t len) {
    if (data == nullptr || len == 0) {
        return "";
    }
    string hexStr;
    hexStr.reserve(len * 2);
    const char *digits = "0123456789abcdef";
    REP(i, 0, static_cast<int>(len)) {
        uint8_t byteVal = data[i];
        hexStr.pb(digits[(byteVal >> 4) & 0x0f]);
        hexStr.pb(digits[byteVal & 0x0f]);
    }
    return hexStr;
}

string bytesToHex(const vector<uint8_t> &data) {
    return bytesToHex(data.data(), data.size());
}

vector<uint8_t> hexToBytes(const string &hexStr) {
    string trimmed = trim(hexStr);
    if (trimmed.empty()) {
        return {};
    }
    if (trimmed.length() % 2 != 0) {
        throw LabException(StatusCodes::UsageOrInputError, "Hex string must have an even length");
    }
    vector<uint8_t> bytes;
    bytes.reserve(trimmed.length() / 2);

    auto hexCharToNibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    int nPairs = static_cast<int>(trimmed.length()) / 2;
    REP(idx, 0, nPairs) {
        size_t i = static_cast<size_t>(idx) * 2;
        int high = hexCharToNibble(trimmed[i]);
        int low = hexCharToNibble(trimmed[i + 1]);
        if (high < 0 || low < 0) {
            throw LabException(StatusCodes::UsageOrInputError, "Invalid hexadecimal character encountered");
        }
        bytes.pb(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

bool isAllDigits(const string &str) {
    if (str.empty()) return false;
    for (char c : str) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

string trim(const string &str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

vector<uint8_t> readAllBytes(const string &filePath) {
    ifstream file(filePath, ios::binary | ios::ate);
    if (!file.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open input file: " + filePath);
    }
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<uint8_t> buf(static_cast<size_t>(size));
    if (size > 0) {
        if (!file.read(reinterpret_cast<char *>(buf.data()), size)) {
            throw LabException(StatusCodes::IOError, "Failed to read data from: " + filePath);
        }
    }
    return buf;
}

void writeAllBytes(const string &filePath, const uint8_t *data, size_t len, bool force) {
    if (!force && fileExists(filePath)) {
        throw LabException(StatusCodes::IOError, "Output file already exists, use --force to overwrite: " + filePath);
    }
    ofstream file(filePath, ios::binary | ios::trunc);
    if (!file.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot open output file for writing: " + filePath);
    }
    if (len > 0 && data != nullptr) {
        file.write(reinterpret_cast<const char *>(data), static_cast<streamsize>(len));
        if (!file.good()) {
            throw LabException(StatusCodes::IOError, "Failed while writing data to: " + filePath);
        }
    }
}

uint64_t getFileLength(const string &filePath) {
    ifstream file(filePath, ios::binary | ios::ate);
    if (!file.is_open()) {
        throw LabException(StatusCodes::IOError, "Cannot determine size for non-existent file: " + filePath);
    }
    return static_cast<uint64_t>(file.tellg());
}

bool fileExists(const string &filePath) {
    ifstream file(filePath);
    return file.good();
}

void safeAtomicRename(const string &tempPath, const string &finalPath, bool force) {
    if (fileExists(finalPath)) {
        if (!force) {
            deleteFileIfExists(tempPath);
            throw LabException(StatusCodes::IOError, "Destination file already exists, use --force: " + finalPath);
        }
        deleteFileIfExists(finalPath);
    }
    if (rename(tempPath.c_str(), finalPath.c_str()) != 0) {
        deleteFileIfExists(tempPath);
        throw LabException(StatusCodes::IOError, "Failed to rename temporary file to destination");
    }
}

void deleteFileIfExists(const string &filePath) {
    if (fileExists(filePath)) {
        remove(filePath.c_str());
    }
}

void setStrictFilePermissions(const string &filePath) {
#if !defined(_WIN32)
    chmod(filePath.c_str(), S_IRUSR | S_IWUSR);
#else
    (void)filePath;
#endif
}

} // namespace utils
