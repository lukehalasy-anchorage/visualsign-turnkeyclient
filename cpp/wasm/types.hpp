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

// Buffer sizes
constexpr size_t SIGNATURE_BUFFER_SIZE = 256;
constexpr size_t HTTP_RESPONSE_BUFFER_SIZE = 65536;  // 64KB
constexpr size_t ERROR_BUFFER_SIZE = 1024;
constexpr size_t SHA256_HASH_SIZE = 32;

// API endpoints
constexpr const char* API_BASE_URL = "https://api.turnkey.com";
constexpr const char* CREATE_SIGNABLE_PAYLOAD_PATH = "/api/v1/create-signable-payload";

// JSON field names
namespace json_fields {
    constexpr const char* UNSIGNED_PAYLOAD = "unsignedPayload";
    constexpr const char* CHAIN = "chain";
    constexpr const char* SIGNABLE_PAYLOAD = "signablePayload";
}

// Crypto constants
namespace crypto {
    constexpr char STAMP_SEPARATOR = ';';
    constexpr char STAMP_FORMAT_SEPARATOR = '.';
}

// HTTP headers
namespace http_headers {
    constexpr const char* CONTENT_TYPE = "Content-Type";
    constexpr const char* APPLICATION_JSON = "application/json";
    constexpr const char* X_ORG_ID = "X-Organization-Id";
    constexpr const char* X_STAMP = "X-Stamp";
}

} // namespace turnkey
