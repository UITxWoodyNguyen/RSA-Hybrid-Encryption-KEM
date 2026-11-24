#pragma once

#include "common_defs.hpp"

namespace utils {

string bytesToHex(const uint8_t *data, size_t len);
string bytesToHex(const vector<uint8_t> &data);
vector<uint8_t> hexToBytes(const string &hexStr);

bool isAllDigits(const string &str);
string trim(const string &str);

vector<uint8_t> readAllBytes(const string &filePath);
void writeAllBytes(const string &filePath, const uint8_t *data, size_t len, bool force);
uint64_t getFileLength(const string &filePath);
bool fileExists(const string &filePath);
void safeAtomicRename(const string &tempPath, const string &finalPath, bool force);
void deleteFileIfExists(const string &filePath);
void setStrictFilePermissions(const string &filePath);

} // namespace utils
