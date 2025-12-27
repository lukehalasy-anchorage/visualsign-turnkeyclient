#pragma once

#include <string>
#include <map>

namespace turnkey {
namespace http {

struct HttpRequest {
    std::string method;
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string error;
};

// Perform HTTP request using JS fetch API
HttpResponse fetch(const HttpRequest& request);

} // namespace http
} // namespace turnkey
