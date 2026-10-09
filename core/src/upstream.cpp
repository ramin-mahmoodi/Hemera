#include "upstream.hpp"

#include "encoding.hpp"
#include "routing.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <variant>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace hemera::core::upstream {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// Rust's u16::from_str: one or more ASCII digits behind an optional '+', no spaces, no '-',
// no overflow. Leading zeros are read, so "0080" is 80, matching the Rust parse exactly; the
// running value may not exceed 65535, which is also the final test since digits only add.
std::optional<std::uint16_t> parse_u16(std::string_view text) {
    if (!text.empty() && text.front() == '+') text.remove_prefix(1);
    if (text.empty()) return std::nullopt;
    std::uint32_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + static_cast<std::uint32_t>(c - '0');
        if (value > 65535) return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

bool is_hex(std::uint8_t byte) {
    return (byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') ||
           (byte >= 'A' && byte <= 'F');
}

std::uint32_t hex_value(std::uint8_t byte) {
    if (byte >= '0' && byte <= '9') return byte - '0';
    return static_cast<std::uint8_t>(std::tolower(byte)) - 'a' + 10;
}

// Rust's percent_encode: everything outside RFC 3986's unreserved set comes back as %XX with
// uppercase hex.
std::string percent_encode(std::string_view value) {
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

// The front of `bytes` as one UTF-8 sequence, or one maximal subpart of a broken one: the byte
// count to skip, and whether what was skipped was valid. This is the rule String::from_utf8_lossy
// follows, so a decoded credential that is no UTF-8 degrades exactly as Rust's would.
std::pair<std::size_t, bool> utf8_scan(std::span<const std::uint8_t> bytes) {
    const std::uint32_t lead = bytes[0];
    if (lead < 0x80) return {1, true};

    std::uint8_t need = 0;
    std::uint8_t low = 0x80;
    std::uint8_t high = 0xbf;
    if (lead >= 0xc2 && lead <= 0xdf) {
        need = 1;
    } else if (lead >= 0xe0 && lead <= 0xef) {
        need = 2;
        if (lead == 0xe0) low = 0xa0;
        else if (lead == 0xed) high = 0x9f;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
        need = 3;
        if (lead == 0xf0) low = 0x90;
        else if (lead == 0xf4) high = 0x8f;
    } else {
        return {1, false}; // a stray continuation byte, 0xc0/0xc1, or a lead past 0xf4
    }

    std::size_t used = 1;
    for (std::uint8_t round = 0; round < need; ++round) {
        const std::uint8_t from = round == 0 ? low : 0x80;
        const std::uint8_t to = round == 0 ? high : 0xbf;
        if (used >= bytes.size()) break;                 // the sequence ran out
        if (bytes[used] < from || bytes[used] > to) break; // this byte cannot continue it
        ++used;
    }
    if (used == 1 + static_cast<std::size_t>(need)) return {used, true};
    return {used, false};
}

std::string utf8_lossy(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (std::size_t at = 0; at < bytes.size();) {
        const auto [used, valid] = utf8_scan(bytes.subspan(at));
        if (valid) out.append(reinterpret_cast<const char*>(bytes.data() + at), used);
        else out += "\xef\xbf\xbd"; // U+FFFD, one per maximal subpart, as Rust does
        at += used;
    }
    return out;
}

std::string percent_decode(std::string_view value) {
    std::vector<std::uint8_t> out;
    out.reserve(value.size());
    const auto bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    std::size_t at = 0;
    while (at < value.size()) {
        // Rust takes the two bytes after a '%' only when both are there (at + 2 < len) and read
        // as u8 hex; a pair it refuses stays in the value literally.
        if (bytes[at] == '%' && at + 2 < value.size() && is_hex(bytes[at + 1]) &&
            is_hex(bytes[at + 2])) {
            out.push_back(
                static_cast<std::uint8_t>((hex_value(bytes[at + 1]) << 4) | hex_value(bytes[at + 2])));
            at += 3;
            continue;
        }
        out.push_back(bytes[at]);
        ++at;
    }
    return utf8_lossy(out);
}

// Rust's {:?} of a str and of an Option<str>, which is what the debug display and the
// name-refusal message print.
std::string debug_quote(std::string_view text) {
    std::string out = "\"";
    for (const char raw : text) {
        const auto byte = static_cast<std::uint8_t>(raw);
        switch (byte) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            default:
                if (byte < 0x20 || byte == 0x7f) {
                    static constexpr char digits[] = "0123456789abcdef";
                    std::string hex;
                    std::uint32_t value = byte;
                    while (value > 0) {
                        hex.insert(hex.begin(), digits[value & 0xf]);
                        value >>= 4;
                    }
                    out += "\\u{" + hex + "}";
                } else {
                    out += raw; // printable ASCII, and UTF-8 bytes, pass through as Rust's do
                }
        }
    }
    out += '"';
    return out;
}

std::string debug_option(const std::optional<std::string>& value) {
    return value ? "Some(" + debug_quote(*value) + ")" : "None";
}

// An IPv6 host has to be bracketed before a port is written after it; url() and psiphon_url()
// both do this, and Rust keys it on the host holding a ':' at all.
std::string bracketed(const std::string& host) {
    return host.find(':') == std::string::npos ? host : "[" + host + "]";
}

bool ip_is_unspecified(const IpAddress& ip) {
    for (const std::uint8_t byte : ip.bytes) {
        if (byte != 0) return false;
    }
    return true;
}

bool ip_is_loopback(const IpAddress& ip) {
    if (ip.v4) return ip.bytes[12] == 127;
    for (std::size_t i = 0; i < 15; ++i) {
        if (ip.bytes[i] != 0) return false;
    }
    return ip.bytes[15] == 1;
}

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return std::vector<std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                     reinterpret_cast<const std::uint8_t*>(text.data()) +
                                         text.size());
}

void push_be16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint16_t read_be16(const std::uint8_t* at) {
    return static_cast<std::uint16_t>((at[0] << 8) | at[1]);
}

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c;
    // Rust's split_whitespace is Unicode-aware; HTTP status lines are ASCII, and this is that
    // subset.
}

} // namespace

std::string_view label(Kind kind) {
    switch (kind) {
        case Kind::Socks5: return "socks5";
        case Kind::Http: return "http";
    }
    return "socks5";
}

std::expected<Upstream, std::string> Upstream::parse(std::string_view raw,
                                                     std::vector<std::string>& notes) {
    // Deviation: Rust's trim and to_lowercase are Unicode-aware; these are the ASCII pair,
    // which is all a URL scheme and a shell setting ever carry in practice.
    raw = trim(raw);

    std::string scheme;
    std::string_view rest = raw;
    if (const auto at = raw.find("://"); at != std::string_view::npos) {
        scheme = lowered(raw.substr(0, at));
        rest = raw.substr(at + 3);
    } else {
        scheme = "socks5"; // a bare host:port is taken as socks5, as Rust defaults it
    }

    Kind kind;
    if (scheme == "socks5" || scheme == "socks5h" || scheme == "socks") {
        kind = Kind::Socks5;
    } else if (scheme == "http" || scheme == "https") {
        kind = Kind::Http;
    } else {
        // The message carries the lower-cased scheme only — never the rest of the URL, so a
        // credential written before the endpoint cannot reach a log through it.
        return std::unexpected(scheme + " is not an upstream proxy kind hemera understands");
    }

    // The last '@' of the rest splits credentials from the endpoint, so an unescaped '@' in a
    // password would pull the endpoint under the credentials and be refused as no host:port
    // rather than dialed at a wrong address; RFC 3986 wants it encoded as %40, and Rust's
    // percent_decode turns that back into an '@' in the password.
    std::optional<std::string_view> credentials;
    std::string_view endpoint = rest;
    if (const auto at = rest.rfind('@'); at != std::string_view::npos) {
        credentials = rest.substr(0, at);
        endpoint = rest.substr(at + 1);
    }

    if (scheme == "https") {
        if (credentials) {
            return std::unexpected(std::string(
                "an https:// upstream with a password is refused: hemera talks to its upstream "
                "over plain http, which would send the password in the clear; use http:// only "
                "if that is acceptable, or socks5://"));
        }
        notes.push_back("[-] the upstream is written as https:// but hemera talks to it over "
                        "plain http; the tunnel inside stays encrypted");
    }

    // trim_end_matches('/'): every trailing slash comes off, not just one.
    while (!endpoint.empty() && endpoint.back() == '/') endpoint.remove_suffix(1);

    const auto split = split_endpoint(endpoint);
    if (!split) return std::unexpected(split.error());

    Upstream upstream;
    upstream.kind = kind;
    upstream.host = split->host;
    upstream.port = split->port;
    if (credentials) {
        // The first ':' splits user from password; a password holding one keeps it, because
        // only the first colon is taken.
        if (const auto colon = credentials->find(':'); colon != std::string_view::npos) {
            upstream.user = percent_decode(credentials->substr(0, colon));
            upstream.password = percent_decode(credentials->substr(colon + 1));
        } else {
            upstream.user = percent_decode(*credentials);
        }
    }
    return upstream;
}

std::expected<Upstream, std::string> Upstream::parse(std::string_view raw) {
    std::vector<std::string> ignored;
    return parse(raw, ignored);
}

std::string Upstream::endpoint() const {
    // As Rust formats it: the host stays unbracketed even for IPv6, which makes the text of a
    // timeout message ambiguous about an IPv6 proxy exactly as the Rust one is.
    return host + ":" + std::to_string(port);
}

std::string Upstream::url() const {
    const std::string_view scheme = kind == Kind::Socks5 ? "socks5h" : "http";
    return std::string(scheme) + "://" + bracketed(host) + ":" + std::to_string(port);
}

std::string Upstream::psiphon_url() const {
    std::string credentials;
    if (user) {
        credentials = percent_encode(*user);
        if (password) {
            credentials += ":";
            credentials += percent_encode(*password);
        }
        credentials += "@";
    }
    const std::string_view scheme = kind == Kind::Socks5 ? "socks5" : "http";
    return std::string(scheme) + "://" + credentials + bracketed(host) + ":" + std::to_string(port);
}

std::optional<SocketTarget> Upstream::socks_address() const {
    // tor's outbound proxy takes an address and no password: a name it would have to resolve
    // itself and a user it cannot send are both refused here rather than half-supported.
    if (kind != Kind::Socks5 || user) return std::nullopt;
    const auto ip = parse_address(host);
    if (!ip) return std::nullopt;
    return SocketTarget{{}, *ip, port};
}

std::optional<std::string> Upstream::proxy_authorization() const {
    if (!user) return std::nullopt;
    // The password is sent empty when the URL gave none, as Rust's unwrap_or_default does.
    const std::string pair = *user + ":" + password.value_or(std::string{});
    return "Proxy-Authorization: Basic " + base64_encode(bytes_of(pair)) + "\r\n";
}

std::string Upstream::display() const {
    // The password half is replaced by "<redacted>" before anything is formatted, so no path
    // through this function can print a secret. The user stays visible: Rust shows it, and
    // support needs to see which account a proxy logs in as.
    std::string out = "Upstream { kind: ";
    out += kind == Kind::Socks5 ? "Socks5" : "Http";
    out += ", host: " + debug_quote(host);
    out += ", port: " + std::to_string(port);
    out += ", user: " + debug_option(user);
    out += ", password: ";
    out += password ? "Some(\"<redacted>\")" : "None";
    out += " }";
    return out;
}

std::optional<Upstream> from_value(std::string_view raw, std::vector<std::string>& notes) {
    const std::string_view trimmed = trim(raw);
    if (trimmed.empty()) return std::nullopt; // a blank setting is no proxy, and says nothing

    auto parsed = Upstream::parse(trimmed, notes);
    if (!parsed) {
        // The error names the endpoint or the scheme, never the credentials: the whole
        // credential half is cut off before anything that can fail with it in hand.
        notes.push_back("[-] the upstream proxy setting was ignored: " + parsed.error());
        return std::nullopt;
    }
    notes.push_back("[+] dialling out through the " + std::string(label(parsed->kind)) +
                    " proxy at " + parsed->host + ":" + std::to_string(parsed->port));
    return *parsed;
}

std::optional<Upstream> remembered(Seen& seen, std::string_view raw,
                                   std::vector<std::string>& notes) {
    // Looked up on every call rather than once, but parsed, and announced, only when the
    // setting changed — which is why an edge named only after an earlier look still finds it.
    if (seen && seen->first == raw) return seen->second;
    auto upstream = from_value(raw, notes);
    seen = std::pair<std::string, std::optional<Upstream>>(std::string(raw), upstream);
    return upstream;
}

std::optional<Upstream> configured(const Settings& settings, std::vector<std::string>& notes) {
    // Deviation: Rust reads the process environment here; this core routes every setting,
    // --upstream included, through the Settings map, and the value is copied because the memo
    // has to outlive the view.
    static std::mutex guard;
    static Seen seen;

    const std::string raw(settings.get("HEMERA_UPSTREAM").value_or(std::string_view{}));
    const std::lock_guard<std::mutex> held(guard);
    return remembered(seen, raw, notes);
}

std::optional<Upstream> from_settings(const Settings& settings, std::vector<std::string>& notes) {
    // Rust's from_env: no setting at all answers None without a word; a set one goes through
    // the announcing parse every time it is asked.
    const auto raw = settings.get("HEMERA_UPSTREAM");
    if (!raw) return std::nullopt;
    return from_value(*raw, notes);
}

std::expected<SocketTarget, std::string> split_endpoint(std::string_view endpoint) {
    const auto malformed = [endpoint] {
        return std::unexpected(std::string(endpoint) +
                               " is not a host and port an upstream proxy can live at");
    };

    if (!endpoint.empty() && endpoint.front() == '[') {
        const std::string_view rest = endpoint.substr(1);
        const auto close = rest.find(']'); // split_once(']'): the first bracket closes it
        if (close == std::string_view::npos) return malformed();
        const std::string_view host = rest.substr(0, close);
        const std::string_view tail = rest.substr(close + 1);
        if (!tail.starts_with(':')) return malformed();
        const auto port = parse_u16(tail.substr(1));
        if (!port) return malformed();
        if (host.empty() || *port == 0) return malformed();
        return SocketTarget{std::string(host), {}, *port};
    }

    const auto colon = endpoint.rfind(':'); // rsplit_once(':'): the last colon is the port's
    if (colon == std::string_view::npos) return malformed();
    const auto port = parse_u16(endpoint.substr(colon + 1));
    if (!port) return malformed();
    const std::string_view host = endpoint.substr(0, colon);
    if (host.empty() || *port == 0) return malformed();
    return SocketTarget{std::string(host), {}, *port};
}

bool bypasses_upstream(const IpAddress& peer) {
    // Rust's attach_detour_via: a local peer is reached without the upstream proxy.
    return routing::is_private(peer);
}

std::string connect_timed_out(const Upstream& proxy) {
    return "the upstream proxy at " + proxy.endpoint() + " did not answer in time";
}

std::string relay_timed_out(const Upstream& proxy) {
    return "the upstream proxy at " + proxy.endpoint() + " never opened a udp relay";
}

std::vector<std::uint8_t> greet_request(bool wants_auth) {
    return {VER, 1, wants_auth ? AUTH_USERPASS : AUTH_NONE};
}

std::expected<void, std::string> check_greeting(bool wants_auth,
                                                std::span<const std::uint8_t> answer) {
    if (answer.size() < 2) {
        // Deviation: Rust's read_exact turns a short answer into an io error before any of
        // these words exist; the engine owns the socket and its reads, and this keeps the
        // module honest about the bytes it was actually given.
        return std::unexpected("the upstream proxy sent a short socks5 greeting answer");
    }
    if (answer[0] != VER) return std::unexpected("the upstream proxy did not speak socks5");

    if (answer[1] == AUTH_NONE) {
        if (wants_auth) {
            // Credentials were configured and the proxy proposes to skip authentication; the
            // tunnel would go out unauthenticated, so the handshake stops here.
            return std::unexpected(
                "the upstream proxy skipped authentication even though credentials are configured");
        }
        return {};
    }
    if (answer[1] == AUTH_USERPASS) return {}; // go on and send the login
    if (answer[1] == AUTH_REJECTED) {
        return std::unexpected("the upstream proxy rejected every authentication method offered");
    }
    return std::unexpected("the upstream proxy asked for authentication method " +
                           std::to_string(static_cast<unsigned>(answer[1])) +
                           ", which hemera cannot do");
}

std::expected<std::vector<std::uint8_t>, std::string>
authenticate_request(const std::optional<std::string>& user, const std::optional<std::string>& password) {
    const std::string name = user.value_or(std::string{});
    const std::string secret = password.value_or(std::string{});
    if (name.size() > MAX_SOCKS_CREDENTIAL_LEN || secret.size() > MAX_SOCKS_CREDENTIAL_LEN) {
        // Refused, not truncated: a quietly shortened password would be checked against the
        // proxy and fail there, or worse succeed with less entropy than was configured.
        return std::unexpected("the upstream proxy credentials are longer than socks5 allows");
    }

    std::vector<std::uint8_t> message;
    message.reserve(3 + name.size() + secret.size());
    // Named locals: bytes_of(name).begin() and bytes_of(name).end() would be two different
    // temporaries, so the range would cross containers (and dangle once both die).
    const std::vector<std::uint8_t> name_bytes = bytes_of(name);
    const std::vector<std::uint8_t> secret_bytes = bytes_of(secret);
    message.push_back(USERPASS_VERSION);
    message.push_back(static_cast<std::uint8_t>(name.size()));
    message.insert(message.end(), name_bytes.begin(), name_bytes.end());
    message.push_back(static_cast<std::uint8_t>(secret.size()));
    message.insert(message.end(), secret_bytes.begin(), secret_bytes.end());
    return message;
}

std::expected<void, std::string> check_auth_answer(std::span<const std::uint8_t> answer) {
    if (answer.size() < 2) {
        return std::unexpected("the upstream proxy sent a short password answer"); // see check_greeting
    }
    if (answer[0] != USERPASS_VERSION) {
        return std::unexpected(
            "the upstream proxy answered the password negotiation with the wrong version");
    }
    if (answer[1] != 0x00) {
        return std::unexpected("the upstream proxy refused the credentials supplied");
    }
    return {};
}

std::expected<std::uint8_t, std::string> check_reply_head(std::span<const std::uint8_t> head) {
    if (head.size() < 4) {
        return std::unexpected("the upstream proxy sent a short reply head"); // see check_greeting
    }
    if (head[0] != VER) {
        return std::unexpected("the upstream proxy answered with something other than socks5");
    }
    if (head[1] != REP_OK) {
        return std::unexpected("the upstream proxy refused the request with code " +
                               std::to_string(static_cast<unsigned>(head[1])));
    }
    switch (head[3]) {
        case ATYP_V4:
        case ATYP_NAME:
        case ATYP_V6: return head[3];
        default: break;
    }
    return std::unexpected("the upstream proxy sent address type " +
                           std::to_string(static_cast<unsigned>(head[3])) +
                           ", which hemera cannot read");
}

std::vector<std::uint8_t> encode_address(const SocketTarget& target) {
    // The engine hands this a resolved target; a name belongs to encode_name_request, which is
    // the only way the proxy is asked to resolve anything. The fallback keeps a name that came
    // in as an address text working, as Rust's SocketAddr would have.
    const IpAddress address =
        target.ip ? *target.ip : parse_address(target.host).value_or(IpAddress{});

    std::vector<std::uint8_t> out;
    out.reserve(19);
    if (address.v4) {
        out.push_back(ATYP_V4);
        out.insert(out.end(), address.bytes.begin() + 12, address.bytes.end());
    } else {
        out.push_back(ATYP_V6);
        out.insert(out.end(), address.bytes.begin(), address.bytes.end());
    }
    push_be16(out, target.port);
    return out;
}

std::vector<std::uint8_t> encode_request(std::uint8_t command, const SocketTarget& target) {
    std::vector<std::uint8_t> out;
    out.reserve(22);
    out.push_back(VER);
    out.push_back(command);
    out.push_back(0x00);
    const auto address = encode_address(target);
    out.insert(out.end(), address.begin(), address.end());
    return out;
}

std::expected<std::vector<std::uint8_t>, std::string>
encode_name_request(std::uint8_t command, std::string_view name, std::uint16_t port) {
    if (name.empty() || name.size() > MAX_SOCKS_NAME_LEN) {
        // An empty or over-long name is refused, not clipped to the length byte. The name was
        // asked for by the client and is not a credential, so the message can quote it.
        return std::unexpected(debug_quote(name) +
                               " is no name a socks5 proxy can be asked for");
    }

    std::vector<std::uint8_t> out;
    out.reserve(7 + name.size());
    out.insert(out.end(), {VER, command, 0x00, ATYP_NAME, static_cast<std::uint8_t>(name.size())});
    out.insert(out.end(), name.begin(), name.end());
    push_be16(out, port);
    return out;
}

std::vector<std::uint8_t> encode_udp_header(const SocketTarget& target) {
    std::vector<std::uint8_t> out;
    out.reserve(22);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    const auto address = encode_address(target);
    out.insert(out.end(), address.begin(), address.end());
    return out;
}

std::optional<std::pair<SocketTarget, std::size_t>>
decode_udp_header(std::span<const std::uint8_t> buf) {
    if (buf.size() < 4 || buf[2] != 0x00) return std::nullopt; // the reserved byte must be zero

    const auto push_target = [](IpAddress ip, std::uint16_t port) {
        return SocketTarget{{}, ip, port};
    };

    switch (buf[3]) {
        case ATYP_V4: {
            if (buf.size() < 10) return std::nullopt;
            IpAddress ip;
            ip.v4 = true;
            std::copy(buf.begin() + 4, buf.begin() + 8, ip.bytes.begin() + 12);
            return std::pair{push_target(ip, read_be16(&buf[8])), std::size_t{10}};
        }
        case ATYP_V6: {
            if (buf.size() < 22) return std::nullopt;
            IpAddress ip;
            std::copy(buf.begin() + 4, buf.begin() + 20, ip.bytes.begin());
            return std::pair{push_target(ip, read_be16(&buf[20])), std::size_t{22}};
        }
        case ATYP_NAME: {
            if (buf.size() < 5) return std::nullopt;
            const std::size_t length = buf[4];
            const std::size_t end = 5 + length;
            if (buf.size() < end + 2) return std::nullopt;
            const std::string_view name(reinterpret_cast<const char*>(&buf[5]), length);
            // Rust insists the name is valid UTF-8 and then parses it as an IP address; only
            // ASCII ever survives that parse, so parse_address alone reproduces both refusals.
            const auto ip = parse_address(name);
            if (!ip) return std::nullopt;
            return std::pair{push_target(*ip, read_be16(&buf[end])), end + 2};
        }
        default: return std::nullopt;
    }
}

std::variant<SocketTarget, HostLookup> relay_address(const SocketTarget& bound,
                                                     std::string_view proxy_host,
                                                     std::uint16_t proxy_port) {
    // A reply that carries a real address and a real port is the relay, as given.
    if (bound.ip && !ip_is_unspecified(*bound.ip) && bound.port != 0) return bound;

    const std::uint16_t relay_port = bound.port == 0 ? proxy_port : bound.port;
    if (const auto ip = parse_address(proxy_host)) return SocketTarget{{}, *ip, relay_port};
    return HostLookup{std::string(proxy_host), relay_port};
}

bool from_detoured_socket(const SocketTarget& client, const SocketTarget& origin) {
    if (!client.ip || !origin.ip || origin.port != client.port) return false;
    if (*origin.ip == *client.ip) return true;
    // A client bound to the wildcard sees its own datagrams come back from loopback.
    return ip_is_unspecified(*client.ip) && ip_is_loopback(*origin.ip);
}

std::optional<IpAddress> sockaddr_to_ip(const sockaddr_storage& storage) {
    const auto family = storage.ss_family;
    if (family == AF_INET) {
        IpAddress ip;
        ip.v4 = true;
        std::memcpy(ip.bytes.data() + 12,
                    &reinterpret_cast<const sockaddr_in*>(&storage)->sin_addr.s_addr, 4);
        return ip;
    }
    if (family == AF_INET6) {
        IpAddress ip;
        std::memcpy(ip.bytes.data(),
                    &reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_addr, 16);
        return ip;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// The detour table (upstream.rs:500-544).

namespace {

// dns.hpp gives SocketAddr equality but no ordering, and the table needs one to be a map. Family,
// then the sixteen address bytes, then the port is a total order over every address the type can
// hold, so a find answers exactly what Rust's HashMap::get(&local) answers (upstream.rs:541, :548,
// :521).
struct DetourLess {
    [[nodiscard]] bool operator()(const SocketAddr& a, const SocketAddr& b) const {
        if (a.ip.v4 != b.ip.v4) return !a.ip.v4 && b.ip.v4;
        if (a.ip.bytes != b.ip.bytes) return a.ip.bytes < b.ip.bytes;
        return a.port < b.port;
    }
};

// The table and its lock, as one process-wide static — which is upstream.rs:532-537's OnceLock over
// a Mutex, and the same shape configured() above uses for the parsed-proxy memo.
//
// Deviation: std::mutex has no poisoned state, so Rust's `Err(_) => intended` answers
// (upstream.rs:542, :553) and the `if let Ok(mut map)` skips (:520, :584) have nothing to fail on
// here; a lock either works or the thread waits. Every other arm is kept as written.
struct Detours {
    std::mutex guard;
    std::map<SocketAddr, Detour, DetourLess> table;
};

Detours& detours() {
    static Detours all;
    return all;
}

} // namespace

std::uint64_t next_detour_id() {
    // upstream.rs:527-530: one static counter, starting at 1, relaxed, so two detours opened on the
    // same client address still get ids that tell them apart.
    static std::atomic<std::uint64_t> next{1};
    return next.fetch_add(1, std::memory_order_relaxed);
}

void remember_detour(const SocketAddr& client, const Detour& detour) {
    // upstream.rs:584-593, attach_detour_via's insert once its relay is up: the client address is
    // the key, so a re-attach replaces the detour that was there — map.insert does the same.
    Detours& all = detours();
    const std::lock_guard<std::mutex> held(all.guard);
    all.table[client] = detour;
}

void forget_detour(const SocketAddr& client, std::uint64_t id) {
    // upstream.rs:519-525. The id test first: DetourGuard's Drop and the pump task's end both call
    // this, and by then a newer detour may own the same client address — removing that one would
    // silently send a live socket's traffic straight to the peer instead of through the relay.
    Detours& all = detours();
    const std::lock_guard<std::mutex> held(all.guard);
    const auto found = all.table.find(client);
    if (found != all.table.end() && found->second.id == id) all.table.erase(found);
}

SocketAddr relay_target(const SocketAddr& local, const SocketAddr& intended) {
    // upstream.rs:539-544: the shim this socket's traffic was handed to, or the intended peer when
    // nothing is detouring it. An empty table is the no-proxy answer, and it is also the answer for
    // a socket the engine never registered — which is every socket of a direct run.
    Detours& all = detours();
    const std::lock_guard<std::mutex> held(all.guard);
    const auto found = all.table.find(local);
    return found == all.table.end() ? intended : found->second.shim;
}

std::string connect_request(const Upstream& proxy, std::string_view authority) {
    // The CONNECT a http proxy is fed: authority twice (request line and Host), keep-alive,
    // then the basic-auth line when a user is configured, then the empty line. A socks5 proxy
    // gets none of this — its framing is encode_request — so the two tunnels part here.
    std::string request = "CONNECT " + std::string(authority) + " HTTP/1.1\r\nHost: " +
                          std::string(authority) + "\r\nProxy-Connection: Keep-Alive\r\n";
    if (const auto auth = proxy.proxy_authorization()) request += *auth;
    request += "\r\n";
    return request;
}

std::optional<std::uint16_t> http_status(std::span<const std::uint8_t> head) {
    const std::string text = utf8_lossy(head);
    std::string_view line = text;
    if (const auto nl = text.find('\n'); nl != std::string::npos) line = std::string_view(text).substr(0, nl);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1); // Rust's lines(): one \r off

    std::size_t at = 0;
    const auto token = [&] {
        while (at < line.size() && is_space(line[at])) ++at;
        const std::size_t start = at;
        while (at < line.size() && !is_space(line[at])) ++at;
        return line.substr(start, at - start);
    };

    const std::string_view version = token();
    if (version.empty() || !version.starts_with("HTTP/")) return std::nullopt;
    const std::string_view status = token();
    if (status.empty()) return std::nullopt;
    return parse_u16(status); // parts.next()?.parse::<u16>().ok()
}

std::expected<std::uint16_t, std::string> connect_answer(std::span<const std::uint8_t> head) {
    const auto status = http_status(head);
    if (!status) return std::unexpected("the upstream proxy answer was not http");
    if (*status < 200 || *status >= 300) {
        // The status number is all the answer says back: nothing the proxy sent past the
        // status line — which could echo a request header and its credentials — is repeated.
        return std::unexpected("the upstream proxy answered " + std::to_string(*status) +
                               " to the connect");
    }
    return *status;
}

// ---------------------------------------------------------------------------
// The UDP relay: upstream.rs:440-498, 556-608.
// ---------------------------------------------------------------------------

namespace {

// A connected TCP socket with a timeout on every operation: non-blocking connect + select,
// then blocking reads with a select-guarded deadline. The relay is a long-lived control
// channel, so the timeout is the handshake one.
[[nodiscard]] std::expected<SOCKET, std::string> dial_proxy(const Upstream& proxy,
                                                           std::chrono::milliseconds timeout) {
    const auto target = parse_address(proxy.host);
    if (!target) {
        // A name is resolved here, not by the proxy: the relay is a socks5 control connection,
        // and the proxy's own address is the only thing the engine can dial.
        return std::unexpected("the upstream proxy host " + proxy.host +
                               " is not an IP address");
    }
    const SocketAddr peer{*target, proxy.port};
    const SOCKET sock = ::socket(target->v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return std::unexpected(std::string("socket failed"));

    u_long nonblock = 1;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    sockaddr_storage storage{};
    int length = 0;
    if (target->v4) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(storage);
        v4.sin_family = AF_INET;
        v4.sin_port = htons(proxy.port);
        std::memcpy(&v4.sin_addr.s_addr, target->bytes.data() + 12, 4);
        length = sizeof sockaddr_in;
    } else {
        auto& v6 = reinterpret_cast<sockaddr_in6&>(storage);
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(proxy.port);
        std::memcpy(&v6.sin6_addr, target->bytes.data(), 16);
        length = sizeof sockaddr_in6;
    }
    const int started = ::connect(sock, reinterpret_cast<sockaddr*>(&storage), length);
    if (started != 0) {
        const int code = WSAGetLastError();
        if (code != WSAEWOULDBLOCK && code != WSAEINPROGRESS) {
            closesocket(sock);
            return std::unexpected("connect failed (" + std::to_string(code) + ")");
        }
        fd_set write;
        FD_ZERO(&write);
        FD_SET(sock, &write);
        timeval budget{};
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
        budget.tv_sec = static_cast<long>(ms.count() / 1000);
        budget.tv_usec = static_cast<long>((ms.count() % 1000) * 1000);
        if (::select(0, nullptr, &write, nullptr, &budget) <= 0) {
            closesocket(sock);
            return std::unexpected(std::string("connect timed out"));
        }
        int failed = 0;
        int size = sizeof failed;
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&failed), &size);
        if (failed != 0) {
            closesocket(sock);
            return std::unexpected("connect failed (" + std::to_string(failed) + ")");
        }
    }
    nonblock = 0;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    return sock;
}

[[nodiscard]] bool wait_readable(SOCKET sock, std::chrono::milliseconds budget) {
    fd_set read;
    FD_ZERO(&read);
    FD_SET(sock, &read);
    timeval slice{};
    const auto ms = std::min<std::chrono::milliseconds>(budget, std::chrono::milliseconds(50));
    slice.tv_sec = static_cast<long>(ms.count() / 1000);
    slice.tv_usec = static_cast<long>((ms.count() % 1000) * 1000);
    return ::select(0, &read, nullptr, nullptr, &slice) > 0;
}

[[nodiscard]] bool send_all(SOCKET sock, std::span<const std::uint8_t> bytes,
                            const std::chrono::steady_clock::time_point& finish) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        if (std::chrono::steady_clock::now() >= finish) return false;
        const int wrote = ::send(sock, reinterpret_cast<const char*>(bytes.data() + sent),
                                 static_cast<int>(bytes.size() - sent), 0);
        if (wrote <= 0) return false;
        sent += static_cast<std::size_t>(wrote);
    }
    return true;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> recv_exact(
    SOCKET sock, std::size_t want, const std::chrono::steady_clock::time_point& finish) {
    std::vector<std::uint8_t> out;
    out.reserve(want);
    std::vector<std::uint8_t> chunk(2048);
    while (out.size() < want) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            finish - std::chrono::steady_clock::now());
        if (left.count() <= 0 || !wait_readable(sock, left)) return std::nullopt;
        const int got = ::recv(sock, reinterpret_cast<char*>(chunk.data()),
                               static_cast<int>(std::min<std::size_t>(chunk.size(),
                                                                     want - out.size())),
                               0);
        if (got <= 0) return std::nullopt;
        out.insert(out.end(), chunk.begin(), chunk.begin() + got);
    }
    return out;
}

// The greeting + optional login + ASSOCIATE, the way every other socks5 path does the first
// two and then asks for the relay. The reply's address is where the relay lives.
[[nodiscard]] std::expected<std::variant<SocketTarget, HostLookup>, std::string>
associate_handshake(const Upstream& proxy, std::chrono::milliseconds timeout) {
    auto dialed = dial_proxy(proxy, timeout);
    if (!dialed) return std::unexpected(dialed.error());
    const SOCKET sock = *dialed;
    const auto finish = std::chrono::steady_clock::now() + timeout;

    const std::vector<std::uint8_t> greeting = greet_request(proxy.wants_auth());
    if (!send_all(sock, greeting, finish)) {
        closesocket(sock);
        return std::unexpected(std::string("greeting send failed"));
    }
    auto answer = recv_exact(sock, 2, finish);
    if (!answer) {
        closesocket(sock);
        return std::unexpected(std::unexpected("no greeting answer"));
    }
    if (auto checked = check_greeting(proxy.wants_auth(), *answer); !checked) {
        closesocket(sock);
        return std::unexpected(checked.error());
    }
    if (answer->at(1) == AUTH_USERPASS) {
        auto login = authenticate_request(proxy.user, proxy.password);
        if (!login) {
            closesocket(sock);
            return std::unexpected(login.error());
        }
        if (!send_all(sock, *login, finish)) {
            closesocket(sock);
            return std::unexpected(std::unexpected("login send failed"));
        }
        auto auth_answer = recv_exact(sock, 2, finish);
        if (!auth_answer) {
            closesocket(sock);
            return std::unexpected(std::unexpected("no login answer"));
        }
        if (auto checked = check_auth_answer(*auth_answer); !checked) {
            closesocket(sock);
            return std::unexpected(checked.error());
        }
    }

    // CMD_ASSOCIATE with a wildcard target: the relay's address comes back in the reply.
    const SocketTarget wildcard{};
    const std::vector<std::uint8_t> request = encode_request(CMD_ASSOCIATE, wildcard);
    if (!send_all(sock, request, finish)) {
        closesocket(sock);
        return std::unexpected(std::unexpected("associate send failed"));
    }
    auto head = recv_exact(sock, 4, finish);
    if (!head) {
        closesocket(sock);
        return std::unexpected(std::unexpected("no associate answer"));
    }
    const auto atyp = check_reply_head(*head);
    if (!atyp) {
        closesocket(sock);
        return std::unexpected(atyp.error());
    }
    // The bound address follows the head: 4 bytes for v4, 1+len for a name, 16 for v6.
    std::size_t extra = 0;
    switch (*atyp) {
        case ATYP_V4: extra = 4; break;
        case ATYP_V6: extra = 16; break;
        case ATYP_NAME: {
            auto len = recv_exact(sock, 1, finish);
            if (!len) {
                closesocket(sock);
                return std::unexpected(std::unexpected("no name length"));
            }
            extra = 1 + (*len)[0];
            break;
        }
        default: break;
    }
    auto rest = recv_exact(sock, extra + 2, finish);
    if (!rest) {
        closesocket(sock);
        return std::unexpected(std::unexpected("no relay address"));
    }
    std::vector<std::uint8_t> addr_bytes(head->begin() + 4, head->end());
    addr_bytes.insert(addr_bytes.end(), rest->begin(), rest->end());
    const std::span<const std::uint8_t> addr_span(addr_bytes.data(), addr_bytes.size());
    auto decoded = decode_udp_header(addr_span);
    if (!decoded) {
        closesocket(sock);
        return std::unexpected(std::unexpected("the relay address is not a socks5 address"));
    }
    closesocket(sock);
    return relay_address(decoded->first, proxy.host, proxy.port);
}

} // namespace

std::expected<std::variant<SocketTarget, HostLookup>, std::string>
associate(const Upstream& proxy, std::chrono::milliseconds timeout) {
    return associate_handshake(proxy, timeout);
}

RelayDatagram relay_send(const SocketTarget& target,
                         std::span<const std::uint8_t> payload) {
    RelayDatagram out;
    out.target = target;
    const auto header = encode_udp_header(target);
    out.framed.reserve(header.size() + payload.size());
    out.framed.insert(out.framed.end(), header.begin(), header.end());
    out.framed.insert(out.framed.end(), payload.begin(), payload.end());
    return out;
}

std::optional<std::pair<SocketTarget, std::size_t>>
relay_receive(std::span<const std::uint8_t> buf) {
    return decode_udp_header(buf);
}

// ---------------------------------------------------------------------------
// DetourGuard + attach_detour + bind_via_upstream: upstream.rs:506-625.
// ---------------------------------------------------------------------------

namespace {

// The pump: shim → relay and relay → shim, until the guard's stop flag is set. The shim is
// non-blocking; the relay is a UDP socket the proxy owns. The pump is the only reader of the
// shim, so the last-sender state is thread-local. The stop flag is shared_ptr so it outlives
// the pump thread.
void detour_pump(SOCKET shim, const SocketTarget& relay, const SocketAddr& peer,
                 const SocketAddr& client, std::shared_ptr<std::atomic<bool>> stop) {
    const SOCKET relay_sock =
        ::socket(relay.ip && relay.ip->v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (relay_sock == INVALID_SOCKET) return;
    u_long nonblock = 1;
    ::ioctlsocket(relay_sock, FIONBIO, &nonblock);

    sockaddr_storage relay_addr{};
    int relay_len = 0;
    if (relay.ip && relay.ip->v4) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(relay_addr);
        v4.sin_family = AF_INET;
        v4.sin_port = htons(relay.port);
        std::memcpy(&v4.sin_addr.s_addr, relay.ip->bytes.data() + 12, 4);
        relay_len = sizeof sockaddr_in;
    } else if (relay.ip) {
        auto& v6 = reinterpret_cast<sockaddr_in6&>(relay_addr);
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(relay.port);
        std::memcpy(&v6.sin6_addr, relay.ip->bytes.data(), 16);
        relay_len = sizeof sockaddr_in6;
    } else {
        closesocket(relay_sock);
        return;
    }

    std::vector<std::uint8_t> from_client(DETOUR_PUMP_BUFFER_LEN);
    std::vector<std::uint8_t> from_relay(DETOUR_PUMP_BUFFER_LEN);
    std::optional<SocketAddr> reply_to;

    while (!stop->load()) {
        // Shim → relay: one datagram, framed and sent.
        fd_set read;
        FD_ZERO(&read);
        FD_SET(shim, &read);
        timeval slice{};
        slice.tv_usec = 50'000;
        if (::select(0, &read, nullptr, nullptr, &slice) > 0) {
            sockaddr_storage sender{};
            int sender_len = sizeof sender;
            const int got = ::recvfrom(shim, reinterpret_cast<char*>(from_client.data()),
                                       static_cast<int>(from_client.size()), 0,
                                       reinterpret_cast<sockaddr*>(&sender), &sender_len);
            if (got > 0) {
                SocketTarget origin{};
                origin.ip = sockaddr_to_ip(sender);
                origin.port = sender_len >= sizeof sockaddr_in
                    ? ntohs(reinterpret_cast<sockaddr_in*>(&sender)->sin_port)
                    : 0;
                SocketTarget client_target{};
                client_target.ip = client.ip;
                client_target.port = client.port;
                if (from_detoured_socket(client_target, origin)) {
                    reply_to = SocketAddr{origin.ip.value_or(IpAddress{}), origin.port};
                    SocketTarget peer_target{};
                    peer_target.ip = peer.ip;
                    peer_target.port = peer.port;
                    auto framed = relay_send(peer_target,
                                             std::span<const std::uint8_t>(
                                                 from_client.data(), static_cast<std::size_t>(got)));
                    (void)::sendto(relay_sock, reinterpret_cast<const char*>(framed.framed.data()),
                                   static_cast<int>(framed.framed.size()), 0,
                                   reinterpret_cast<sockaddr*>(&relay_addr), relay_len);
                }
            }
        }
        // Relay → shim: one datagram, unframed and sent to the last sender.
        FD_ZERO(&read);
        FD_SET(relay_sock, &read);
        slice.tv_usec = 50'000;
        if (::select(0, &read, nullptr, nullptr, &slice) > 0) {
            const int got = ::recvfrom(relay_sock, reinterpret_cast<char*>(from_relay.data()),
                                       static_cast<int>(from_relay.size()), 0, nullptr, nullptr);
            if (got > 0 && reply_to.has_value()) {
                auto decoded = relay_receive(std::span<const std::uint8_t>(
                    from_relay.data(), static_cast<std::size_t>(got)));
                if (decoded.has_value()) {
                    const auto& [origin, offset] = *decoded;
                    (void)origin;
                    sockaddr_storage target{};
                    int target_len = 0;
                    if (reply_to->ip.v4) {
                        auto& v4 = reinterpret_cast<sockaddr_in&>(target);
                        v4.sin_family = AF_INET;
                        v4.sin_port = htons(reply_to->port);
                        std::memcpy(&v4.sin_addr.s_addr, reply_to->ip.bytes.data() + 12, 4);
                        target_len = sizeof sockaddr_in;
                    } else {
                        auto& v6 = reinterpret_cast<sockaddr_in6&>(target);
                        v6.sin6_family = AF_INET6;
                        v6.sin6_port = htons(reply_to->port);
                        std::memcpy(&v6.sin6_addr, reply_to->ip.bytes.data(), 16);
                        target_len = sizeof sockaddr_in6;
                    }
                    (void)::sendto(shim,
                                   reinterpret_cast<const char*>(from_relay.data() + offset),
                                   static_cast<int>(got - static_cast<int>(offset)), 0,
                                   reinterpret_cast<sockaddr*>(&target), target_len);
                }
            }
        }
    }
    closesocket(relay_sock);
}

} // namespace

DetourGuard::DetourGuard(SocketAddr client, std::uint64_t id, SocketAddr shim, SocketAddr relay,
                         SocketTarget relay_target, std::thread pump,
                         std::shared_ptr<std::atomic<bool>> stop)
    : client_(client), id_(id), shim_(shim), relay_(relay), relay_target_(relay_target),
      stop_(std::move(stop)) {
    pump_ = std::move(pump);
}

DetourGuard::~DetourGuard() { stop(); }

DetourGuard::DetourGuard(DetourGuard&& other) noexcept { *this = std::move(other); }

DetourGuard& DetourGuard::operator=(DetourGuard&& other) noexcept {
    if (this != &other) {
        stop();
        client_ = other.client_;
        id_ = other.id_;
        shim_ = other.shim_;
        relay_ = other.relay_;
        relay_target_ = other.relay_target_;
        pump_ = std::move(other.pump_);
        stop_ = std::move(other.stop_);
    }
    return *this;
}

void DetourGuard::stop() {
    if (stop_) stop_->store(true);
    if (pump_.joinable()) pump_.join();
    if (id_ != 0) {
        forget_detour(client_, id_);
        id_ = 0;
    }
}

std::expected<DetourGuard, std::string> attach_detour(const Upstream& proxy,
                                                      const SocketAddr& client,
                                                      const SocketAddr& peer,
                                                      bool client_is_v4) {
    if (bypasses_upstream(peer.ip)) {
        // A local peer is reached without the upstream proxy.
        return DetourGuard{};
    }

    auto relay = associate(proxy, std::chrono::milliseconds(HANDSHAKE_TIMEOUT_MS));
    if (!relay) return std::unexpected(relay.error());

    // A proxy that answered a name is a HostLookup for the engine to resolve.
    if (auto* lookup = std::get_if<HostLookup>(&*relay)) {
        return std::unexpected("the upstream proxy relay is named " + lookup->host +
                               ", which the engine cannot resolve here");
    }
    const SocketTarget& relay_target = std::get<SocketTarget>(*relay);

    // Bind a loopback shim.
    const SOCKET shim = ::socket(client_is_v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (shim == INVALID_SOCKET) return std::unexpected(std::string("shim socket failed"));
    sockaddr_in loop{};
    loop.sin_family = client_is_v4 ? AF_INET : AF_INET6;
    loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    loop.sin_port = 0;
    if (::bind(shim, reinterpret_cast<sockaddr*>(&loop), sizeof loop) != 0) {
        const int code = WSAGetLastError();
        closesocket(shim);
        return std::unexpected("shim bind failed (" + std::to_string(code) + ")");
    }
    sockaddr_in bound{};
    int len = sizeof bound;
    if (getsockname(shim, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
        const int code = WSAGetLastError();
        closesocket(shim);
        return std::unexpected("shim getsockname failed (" + std::to_string(code) + ")");
    }
    SocketAddr shim_addr;
    shim_addr.ip.v4 = client_is_v4;
    if (client_is_v4) {
        std::memcpy(shim_addr.ip.bytes.data() + 12, &bound.sin_addr.s_addr, 4);
        shim_addr.port = ntohs(bound.sin_port);
    } else {
        std::memcpy(shim_addr.ip.bytes.data(), &bound.sin_addr.s_addr, 16);
        shim_addr.port = ntohs(bound.sin_port);
    }
    u_long nonblock = 1;
    ::ioctlsocket(shim, FIONBIO, &nonblock);

    const std::uint64_t id = next_detour_id();
    remember_detour(client, Detour{id, shim_addr, peer});

    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread pump(detour_pump, shim, relay_target, peer, client, stop);
    SocketAddr relay_addr;
    relay_addr.ip = relay_target.ip.value_or(IpAddress{});
    relay_addr.port = relay_target.port;
    return DetourGuard{client, id, shim_addr, relay_addr,
                       relay_target, std::move(pump), std::move(stop)};
}

std::expected<BoundSocket, std::string> bind_via_upstream(const Upstream& proxy,
                                                           const SocketAddr& peer) {
    // upstream.rs:610-625: bind a wildcard socket, attach the detour, connect to relay_target.
    // The socket is returned to the caller. In this port the caller (WinUdp::open_for_peer)
    // already binds the socket; this is the convenience that does all three steps.
    auto attached = attach_detour(proxy, SocketAddr{}, peer, peer.ip.v4);
    if (!attached) return std::unexpected(attached.error());
    BoundSocket out;
    out.local = attached->shim();
    out.target = relay_target(SocketAddr{}, peer);
    out.guard = std::move(*attached);
    return out;
}

} // namespace hemera::core::upstream
