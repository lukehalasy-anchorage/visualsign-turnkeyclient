#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace turnkey {
namespace crypto {

// ECDSA P-256 signature generation
// Returns signature as hex string, or empty string on error
std::string sign_message(
    const std::string& message,
    const std::string& private_key_hex
);

// Generate API stamp for Turnkey authentication
// Format: X-Stamp header value
std::string generate_stamp(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    const std::string& private_key_hex,
    const std::string& public_key_hex
);

// Hex encoding/decoding utilities
std::string hex_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> hex_decode(const std::string& hex);

} // namespace crypto
} // namespace turnkey
