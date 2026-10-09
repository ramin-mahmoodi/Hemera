// AccessHttp over https_runtime::send: one exchange per call, redirects and cookies per the
// request's own flags. Blocking, like the rest of this port.

#include "access_http.hpp"

#include "consts.hpp"
#include "dns.hpp"
#include "https_runtime.hpp"
#include "socks.hpp"
#include "tls.hpp"

#include <cctype>
#include <map>

namespace hemera::core {

namespace {

constexpr int kMaxRedirects = 10;

[[nodiscard]] std::string lower_of(std::string_view text) {
    std::string out(text);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

[[nodiscard]] std::string trim_of(std::string_view text) {
    return std::string(trim(text));
}

} // namespace

std::expected<SplitUrl, std::string> split_url(std::string_view url) {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme)) {
        return std::unexpected("access http: refusing non-https url");
    }
    const std::string_view rest = url.substr(scheme.size());
    const std::string_view authority = rest.substr(0, rest.find('/'));
    std::string path =
        rest.size() > authority.size() ? std::string(rest.substr(authority.size())) : std::string("/");
    const auto host_port = host_and_port(authority, 443);
    if (!host_port.has_value()) {
        return std::unexpected("access http: bad authority in url");
    }
    return SplitUrl{host_port->first, host_port->second, std::move(path)};
}

std::expected<std::pair<std::string, std::string>, std::string> resolve_redirect(
    std::string_view current_url, std::uint16_t status, std::string_view method,
    std::string_view location) {
    std::string next;
    if (location.starts_with("https://")) {
        next = std::string(location);
    } else if (location.starts_with("/")) {
        auto split = split_url(current_url);
        if (!split.has_value()) return std::unexpected(split.error());
        next = "https://" + split->host + std::string(location);
    } else {
        return std::unexpected("access http: refusing relative redirect target");
    }
    std::string next_method = std::string(method);
    if (status == 303 || ((status == 301 || status == 302) && (method == "POST" || method == "PUT"))) {
        next_method = "GET";
    }
    return std::pair{std::move(next), std::move(next_method)};
}

namespace {

[[nodiscard]] std::string form_escape(std::string_view value) {
    // upstream.cpp's percent_encode, repeated because that one lives in an anonymous namespace:
    // everything outside RFC 3986's unreserved set comes back as %XX with uppercase hex.
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (const char raw : value) {
        const auto byte = static_cast<std::uint8_t>(raw);
        if ((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
            byte == '~') {
            out += raw;
        } else {
            out += '%';
            out += digits[byte >> 4];
            out += digits[byte & 0x0f];
        }
    }
    return out;
}

[[nodiscard]] std::string form_body(const std::vector<zerotrust::AccessField>& form) {
    std::string out;
    for (const auto& field : form) {
        if (!out.empty()) out += '&';
        out += form_escape(field.name);
        out += '=';
        out += form_escape(field.value);
    }
    return out;
}

void jar_cookies(std::map<std::string, std::map<std::string, std::string>>& jars,
                 const std::string& host,
                 const std::vector<std::pair<std::string, std::string>>& headers,
                 std::vector<std::string>& set_cookie) {
    for (const auto& [name, value] : headers) {
        if (lower_of(name) != "set-cookie") continue;
        set_cookie.push_back(value);
        const std::string_view first = std::string_view(value).substr(0, value.find(';'));
        const std::size_t eq = first.find('=');
        if (eq == std::string_view::npos) continue;
        jars[host][trim_of(first.substr(0, eq))] = trim_of(first.substr(eq + 1));
    }
}

[[nodiscard]] std::string cookie_header(const std::map<std::string, std::string>& jar) {
    std::string out;
    for (const auto& [name, value] : jar) {
        if (!out.empty()) out += "; ";
        out += name + "=" + value;
    }
    return out;
}

} // namespace

AccessClient::AccessClient(const Settings* settings) : settings_(settings) {}

std::expected<zerotrust::AccessResponse, std::string> AccessClient::exchange(
    const zerotrust::AccessRequest& request) {
    std::string method = request.method;
    std::string url = request.url;
    std::string body = form_body(request.form);
    const bool has_body = !request.form.empty();

    for (int hops = 0; hops <= kMaxRedirects; ++hops) {
        auto split = split_url(url);
        if (!split.has_value()) return std::unexpected(split.error());
        const std::string host = split->host;

        https::Request outgoing;
        outgoing.method = method;
        outgoing.host = host;
        outgoing.port = split->port;
        outgoing.address = std::nullopt; // the connection goes to the URL's own host
        outgoing.sni = {};
        outgoing.path = split->path;

        std::vector<std::pair<std::string, std::string>> fields;
        fields.emplace_back("User-Agent", std::string(UA_REGISTER));
        fields.emplace_back("Accept", "text/html,application/json,*/*");
        for (const auto& header : request.headers) {
            fields.emplace_back(header.name, header.value);
        }
        if (request.keep_cookies) {
            const auto jar = jars_.find(host);
            if (jar != jars_.end() && !jar->second.empty()) {
                fields.emplace_back("Cookie", cookie_header(jar->second));
            }
        }
        if (has_body && method != "GET") {
            fields.emplace_back("Content-Type", "application/x-www-form-urlencoded");
        }
        outgoing.headers = fields;
        const std::vector<std::uint8_t> body_bytes(body.begin(), body.end());
        outgoing.body = (has_body && method != "GET")
                            ? std::optional<std::span<const std::uint8_t>>(std::span(body_bytes))
                            : std::nullopt;

        const Fingerprint fingerprint = settings_ != nullptr
                                            ? Fingerprint::configured(*settings_)
                                            : Fingerprint{};
        https::Call call;
        call.settings = settings_;
        auto answered = https::send(outgoing, fingerprint, nullptr,
                                    std::chrono::milliseconds(zerotrust::AUTH_TIMEOUT_MS), call);
        if (!answered.has_value()) return std::unexpected(answered.error());
        const https::Response& response = *answered;

        zerotrust::AccessResponse out;
        out.status = response.status;
        out.final_url = url;
        out.body = socks::utf8_lossy(std::span<const std::uint8_t>(response.body));
        jar_cookies(jars_, host, response.headers, out.set_cookie);

        // Redirects, reqwest's rules: 303 always becomes GET, 301/302 turn a POST into one,
        // 307/308 keep the method. Relative targets stay on the same host.
        const bool redirect = (response.status == 301 || response.status == 302 ||
                               response.status == 303 || response.status == 307 ||
                               response.status == 308);
        std::string location;
        for (const auto& [name, value] : response.headers) {
            if (lower_of(name) == "location") {
                location = trim_of(value);
                break;
            }
        }
        if (request.follow_redirects && redirect && !location.empty()) {
            if (hops == kMaxRedirects) {
                return std::unexpected("access http: too many redirects");
            }
            auto next = resolve_redirect(url, response.status, method, location);
            if (!next.has_value()) return std::unexpected(next.error());
            const bool became_get = next->second == "GET" && method != "GET";
            url = std::move(next->first);
            method = std::move(next->second);
            if (became_get) body.clear();
            continue;
        }
        return out;
    }
    return std::unexpected("access http: too many redirects");
}

zerotrust::AccessHttp access_http(const Settings& settings) {
    return [client = AccessClient(&settings)](const zerotrust::AccessRequest& request) mutable
               -> std::expected<zerotrust::AccessResponse, std::string> {
        return client.exchange(request);
    };
}

} // namespace hemera::core
