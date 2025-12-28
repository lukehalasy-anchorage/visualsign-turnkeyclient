#include "types.hpp"
#include "http_client.hpp"
#include "crypto.hpp"
#include <cstring>
#include <sstream>

// Simple JSON parser/builder for minimal dependencies
namespace json {

std::string escape_string(const std::string& str) {
    std::string result;
    for (char c : str) {
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else result += c;
    }
    return result;
}

std::string build_request(const std::string& unsigned_payload, const std::string& chain) {
    std::ostringstream oss;
    oss << "{"
        << "\"" << turnkey::json_fields::UNSIGNED_PAYLOAD << "\":\"" << escape_string(unsigned_payload) << "\","
        << "\"" << turnkey::json_fields::CHAIN << "\":\"" << escape_string(chain) << "\""
        << "}";
    return oss.str();
}

// Simple JSON parser to extract signablePayload field
std::string extract_signable_payload(const std::string& json_response) {
    // Look for "signablePayload":"..."
    std::string field_name = std::string("\"") + turnkey::json_fields::SIGNABLE_PAYLOAD + "\"";
    size_t start = json_response.find(field_name);
    if (start == std::string::npos) {
        return "";
    }

    start = json_response.find("\"", start + field_name.length());
    if (start == std::string::npos) {
        return "";
    }
    start++; // Skip opening quote

    size_t end = start;
    while (end < json_response.length()) {
        if (json_response[end] == '"' && (end == 0 || json_response[end-1] != '\\')) {
            break;
        }
        end++;
    }

    if (end >= json_response.length()) {
        return "";
    }

    return json_response.substr(start, end - start);
}

} // namespace json

using namespace turnkey;

// Main parseTransaction function - exported to JavaScript
extern "C" {

__attribute__((export_name("parseTransaction")))
int parseTransaction(
    const char* raw_transaction,
    const char* chain,
    const char* organization_id,
    const char* public_key,
    const char* private_key,
    char* out_result,
    int* out_result_len,
    char* out_error,
    int* out_error_len
) {
    // Validate inputs
    if (!raw_transaction || !chain || !organization_id || !public_key || !private_key) {
        constexpr const char* err = "Invalid arguments: all parameters required";
        *out_error_len = strlen(err);
        strncpy(out_error, err, *out_error_len);
        return ERROR_INVALID_ARGS;
    }

    // Build request body
    std::string request_body = json::build_request(raw_transaction, chain);

    // Generate API stamp for authentication
    constexpr const char* http_method = "POST";
    std::string path = CREATE_SIGNABLE_PAYLOAD_PATH;
    std::string stamp = crypto::generate_stamp(
        http_method,
        path,
        request_body,
        private_key,
        public_key
    );

    if (stamp.empty()) {
        constexpr const char* err = "Failed to generate authentication stamp";
        *out_error_len = strlen(err);
        strncpy(out_error, err, *out_error_len);
        return ERROR_CRYPTO_FAILED;
    }

    // Prepare HTTP request
    http::HttpRequest request;
    request.method = http_method;
    request.url = std::string(API_BASE_URL) + path;
    request.headers[http_headers::CONTENT_TYPE] = http_headers::APPLICATION_JSON;
    request.headers[http_headers::X_ORG_ID] = organization_id;
    request.headers[http_headers::X_STAMP] = stamp;
    request.body = request_body;

    // Perform HTTP request
    http::HttpResponse response = http::fetch(request);

    if (!response.error.empty()) {
        *out_error_len = response.error.length();
        strncpy(out_error, response.error.c_str(), *out_error_len);
        return ERROR_HTTP_FAILED;
    }

    constexpr int http_ok = 200;
    if (response.status_code != http_ok) {
        std::string err = "HTTP error: " + std::to_string(response.status_code);
        *out_error_len = err.length();
        strncpy(out_error, err.c_str(), *out_error_len);
        return ERROR_HTTP_FAILED;
    }

    // Parse response to extract signablePayload
    std::string signable_payload = json::extract_signable_payload(response.body);

    if (signable_payload.empty()) {
        constexpr const char* err = "Failed to parse signablePayload from response";
        *out_error_len = strlen(err);
        strncpy(out_error, err, *out_error_len);
        return ERROR_JSON_PARSE;
    }

    // Return result
    *out_result_len = signable_payload.length();
    strncpy(out_result, signable_payload.c_str(), *out_result_len);

    return SUCCESS;
}

// Memory allocation helpers for JS
__attribute__((export_name("malloc")))
void* wasm_malloc(size_t size) {
    return malloc(size);
}

__attribute__((export_name("free")))
void wasm_free(void* ptr) {
    free(ptr);
}

} // extern "C"
