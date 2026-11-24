#include "ossl_raii.hpp"

string drainOpenSslErrors() {
    ostringstream oss;
    unsigned long errCode = 0;
    char errBuf[256];
    while ((errCode = ERR_get_error()) != 0) {
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        oss << errBuf << "; ";
    }
    return oss.str();
}
