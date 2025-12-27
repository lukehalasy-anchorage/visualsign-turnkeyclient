#include "http_client.hpp"
#include <cstring>

extern "C" {
    // Imported from JavaScript
    // JS will provide fetch implementation
    extern int js_fetch(
        const char* method,
        const char* url,
        const char* headers_json,
        const char* body,
        int body_len,
        char* out_response_body,
        int* out_response_len,
        int* out_status_code,
        char* out_error,
        int* out_error_len
    );
}

namespace turnkey {
namespace http {

HttpResponse fetch(const HttpRequest& request) {
    HttpResponse response;

    // Convert headers to JSON string
    std::string headers_json = "{";
    bool first = true;
    for (const auto& [key, value] : request.headers) {
        if (!first) headers_json += ",";
        headers_json += "\"" + key + "\":\"" + value + "\"";
        first = false;
    }
    headers_json += "}";

    // Buffers for response
    char response_body[65536];  // 64KB buffer
    int response_len = 0;
    int status_code = 0;
    char error_buf[1024];
    int error_len = 0;

    int result = js_fetch(
        request.method.c_str(),
        request.url.c_str(),
        headers_json.c_str(),
        request.body.c_str(),
        request.body.length(),
        response_body,
        &response_len,
        &status_code,
        error_buf,
        &error_len
    );

    if (result != 0) {
        response.error = std::string(error_buf, error_len);
        response.status_code = 0;
        return response;
    }

    response.status_code = status_code;
    response.body = std::string(response_body, response_len);

    return response;
}

} // namespace http
} // namespace turnkey
