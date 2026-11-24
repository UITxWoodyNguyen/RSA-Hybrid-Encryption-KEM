#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <utility>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>

using namespace std;

#define FOR(i, a, b) for (int i = a, _b = (b); i <= _b; ++i)
#define REP(i, a, b) for (int i = a, _b = (b); i < _b; ++i)
#define FORD(i, b, a) for (int i = (b), _a = (a); i >= _a; --i)
#define nl cout << '\n'
#define all(x) (x).begin(), (x).end()
#define allr(x) (x).rbegin(), (x).rend()
#define pb push_back
#define eb emplace_back
#define ll int64_t
#define pii pair<int, int>
#define pll pair<ll, ll>
#define X first
#define Y second

namespace StatusCodes {
    constexpr int Success = 0;
    constexpr int UsageOrInputError = 1;
    constexpr int IOError = 2;
    constexpr int DataError = 3;
    constexpr int CryptoFailure = 4;
    constexpr int InternalError = 5;
}

class LabException : public runtime_error {
public:
    int exit_code;
    LabException(int code, const string &msg)
        : runtime_error(msg), exit_code(code) {}
};
