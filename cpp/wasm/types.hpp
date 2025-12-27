#pragma once

#include <string>
#include <cstdint>

namespace turnkey {

struct ParseTransactionRequest {
    std::string raw_transaction;
    std::string chain;
    std::string organization_id;
    std::string public_key;
    std::string private_key;
};

struct ParseTransactionResponse {
    std::string signable_payload;
    int error_code;
    std::string error_message;
};

// Error codes
constexpr int SUCCESS = 0;
constexpr int ERROR_INVALID_ARGS = 1;
constexpr int ERROR_HTTP_FAILED = 2;
constexpr int ERROR_CRYPTO_FAILED = 3;
constexpr int ERROR_JSON_PARSE = 4;

} // namespace turnkey
