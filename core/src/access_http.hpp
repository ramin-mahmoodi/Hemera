#pragma once

// The engine side of zerotrust.hpp's AccessHttp: AccessRequest in, AccessResponse out, over
// https_runtime::send. Redirects are followed when the request asks (reqwest's method rules,
// capped), cookies are jarred per host when it asks, and the TLS fingerprint is the core's.
// Dropped lines: https::send's dial/EC-retry notes have no sink on this seam, so a caller that
// wants them must watch the request shape instead (redacted()).
//
// What is NOT here: plain-http URLs are refused -- every Access URL in the flow is https, and
// silently downgrading is not a fallback.

#include "settings.hpp"
#include "zerotrust.hpp"

#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>

namespace aether::core {

// Split "https://host[:port][/path]" into host, port and path. Anything else is refused: the
// flow only ever produces https URLs, and a downgrade is not a fallback.
struct SplitUrl {
    std::string host;
    std::uint16_t port = 443;
    std::string path = "/";
};

[[nodiscard]] std::expected<SplitUrl, std::string> split_url(std::string_view url);

// The next hop after a 301/302/303/307/308 with a Location, reqwest's rules: 303 always
// becomes GET, 301/302 turn a POST/PUT into one, 307/308 keep the method. Absolute https
// targets stand; server-relative ones stay on the host; anything else is refused.
[[nodiscard]] std::expected<std::pair<std::string, std::string>, std::string> resolve_redirect(
    std::string_view current_url, std::uint16_t status, std::string_view method,
    std::string_view location);

// One client for the whole flow: the jar lives across requests the way reqwest's cookie store
// does, scoped per host so a cookie set by one host never travels to another.
class AccessClient {
public:
    explicit AccessClient(const Settings* settings = nullptr);

    [[nodiscard]] std::expected<zerotrust::AccessResponse, std::string> exchange(
        const zerotrust::AccessRequest& request);

private:
    const Settings* settings_ = nullptr;
    // host -> (name -> value), the jar.
    std::map<std::string, std::map<std::string, std::string>> jars_;
};

// The Hooks.http seam: a fresh client per call, which is a fresh jar per call. The flow builds
// its sessions (EmailSignIn holds one http_) around repeated calls, so a jar that lived longer
// would cross session boundaries -- Rust builds one client per flow too (through_upstream).
[[nodiscard]] zerotrust::AccessHttp access_http(const Settings& settings);

} // namespace aether::core
