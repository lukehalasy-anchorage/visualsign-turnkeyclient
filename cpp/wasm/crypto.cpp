#include "crypto.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

// NOTE: For WASM build, we'll use JS crypto imports rather than linking OpenSSL
// This keeps the binary size minimal

extern "C" {
    // Imported from JavaScript
    // These functions will be provided by the JS host environment
    extern void js_sign_message(
        const char* message, int message_len,
        const char* private_key, int key_len,
        char* out_signature, int* out_len
    );

    extern void js_sha256(
        const char* data, int data_len,
        uint8_t* out_hash
    );
}

namespace turnkey {
namespace crypto {

std::string hex_encode(const std::vector<uint8_t>& data) {
    constexpr int hex_width = 2;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(hex_width) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
    constexpr size_t hex_chars_per_byte = 2;
    constexpr int hex_base = 16;
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += hex_chars_per_byte) {
        std::string byte_str = hex.substr(i, hex_chars_per_byte);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, hex_base));
        result.push_back(byte);
    }
    return result;
}

std::string sign_message(
    const std::string& message,
    const std::string& private_key_hex
) {
    constexpr size_t sig_buffer_size = 256;
    char signature_buf[sig_buffer_size];
    int sig_len = 0;

    js_sign_message(
        message.c_str(), message.length(),
        private_key_hex.c_str(), private_key_hex.length(),
        signature_buf, &sig_len
    );

    if (sig_len <= 0) {
        return "";
    }

    return std::string(signature_buf, sig_len);
}

std::string generate_stamp(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    const std::string& private_key_hex,
    const std::string& public_key_hex
) {
    // Create stamp message: METHOD;PATH;BODY_HASH
    constexpr size_t hash_size = 32;
    constexpr char stamp_sep = ';';
    uint8_t body_hash[hash_size];
    js_sha256(body.c_str(), body.length(), body_hash);

    std::string body_hash_hex = hex_encode(
        std::vector<uint8_t>(body_hash, body_hash + hash_size)
    );

    std::string stamp_message = method + std::string(1, stamp_sep) + path + std::string(1, stamp_sep) + body_hash_hex;

    // Sign the stamp message
    std::string signature = sign_message(stamp_message, private_key_hex);

    if (signature.empty()) {
        return "";
    }

    // Return formatted stamp: {publicKey}.{signature}
    constexpr char stamp_format_sep = '.';
    return public_key_hex + std::string(1, stamp_format_sep) + signature;
}

} // namespace crypto
} // namespace turnkey
