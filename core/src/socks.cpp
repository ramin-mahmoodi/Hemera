#include "socks.hpp"

#include "consts.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX // std::min and std::max are used below
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>
#include <random>
#include <utility>

namespace aether::core::socks {
namespace {

void push16(std::vector<std::uint8_t>& into, std::uint16_t value) {
    into.push_back(static_cast<std::uint8_t>(value >> 8));
    into.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint16_t read16(std::span<const std::uint8_t> data, std::size_t at) {
    return static_cast<std::uint16_t>((static_cast<std::uint32_t>(data[at]) << 8) |
                                      static_cast<std::uint32_t>(data[at + 1]));
}

// A u16 the way Rust's str::parse::<u16> reads one: plain digits only. A leading '+` parses in
// Rust and is dropped here, the way routing.cpp drops it; no configuration value uses one.
std::optional<std::uint16_t> port_of(std::string_view text) {
    std::uint32_t value = 0;
    if (text.empty()) return std::nullopt;
    for (const char c : text) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
        value = value * 10 + static_cast<std::uint32_t>(c - '0');
        if (value > 65535) return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

// Rust's str::parse::<u64>: digits only, and a number too big for 64 bits is no number.
std::optional<std::uint64_t> parse_u64(std::string_view text) {
    if (text.empty()) return std::nullopt;
    std::uint64_t value = 0;
    for (const char c : text) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
        const auto digit = static_cast<std::uint64_t>(c - '0');
        if (value > (0xffffffffffffffffull - digit) / 10) return std::nullopt;
        value = value * 10 + digit;
    }
    return value;
}

bool whitespace(char c) {
    return c == ' ' || (c >= '\t' && c <= '\r'); // the ASCII part of Rust's split_whitespace
}

// The second whitespace-free run of `text[..line_end]`, as proxy_connect_succeeded takes it.
std::optional<std::string_view> second_token(std::string_view text) {
    std::optional<std::string_view> first;
    std::size_t at = 0;
    while (at < text.size()) {
        if (whitespace(text[at])) {
            ++at;
            continue;
        }
        const std::size_t begin = at;
        while (at < text.size() && !whitespace(text[at])) ++at;
        const std::string_view token = text.substr(begin, at - begin);
        if (!first) {
            first = token;
            continue;
        }
        return token;
    }
    return std::nullopt;
}

// socks.rs's skip_name: a label run, or the two bytes of a compression pointer; it does not
// follow the pointer, and a length past the end only shows up when the next read runs off.
std::optional<std::size_t> skip_name(std::span<const std::uint8_t> buffer, std::size_t pos) {
    for (;;) {
        if (pos >= buffer.size()) return std::nullopt;
        const std::uint8_t len = buffer[pos];
        if ((len & 0xc0) == 0xc0) return pos + 2;
        if (len == 0) return pos + 1;
        pos += 1 + len;
    }
}

std::uint8_t octet(std::span<const std::uint8_t> data, std::size_t at) { return data[at]; }

// The gateway half of the Rust core's process-wide state: the OnceLock for the address and the
// health flag that turns the gateway off for the rest of the run once it fails.
std::mutex gateway_gate;
bool gateway_installed = false;
std::optional<Endpoint> gateway_address;
std::atomic<bool> gateway_healthy{true};

} // namespace

Target Target::from_ip(const IpAddress& address) {
    Target target;
    target.value_ = address;
    return target;
}

Target Target::from_domain(std::string name) {
    Target target;
    target.value_ = std::move(name);
    return target;
}

bool Target::is_ip() const {
    return std::holds_alternative<IpAddress>(value_);
}

const IpAddress& Target::ip() const {
    return std::get<IpAddress>(value_);
}

const std::string& Target::domain() const {
    return std::get<std::string>(value_);
}

std::string Target::text() const {
    if (is_ip()) return address_text(ip());
    return domain();
}

std::string address_text(const IpAddress& address) {
    if (address.v4) {
        return std::to_string(address.bytes[12]) + '.' + std::to_string(address.bytes[13]) + '.' +
               std::to_string(address.bytes[14]) + '.' + std::to_string(address.bytes[15]);
    }

    // inet_ntop and inet_pton are Winsock calls, so winsock has to be started even though no
    // socket is opened here; dns.cpp keeps the same guard for its own use.
    static const struct Starter {
        Starter() {
            WSADATA ignored;
            WSAStartup(MAKEWORD(2, 2), &ignored);
        }
    } started;

    char buffer[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET6, address.bytes.data(), buffer, INET6_ADDRSTRLEN) != nullptr) {
        return buffer;
    }
    return "::"; // no 16 valid bytes ever make inet_ntop fail
}

std::string Endpoint::text() const {
    if (address.v4) return address_text(address) + ":" + std::to_string(port);
    return "[" + address_text(address) + "]:" + std::to_string(port);
}

std::optional<Endpoint> parse_socket_address(std::string_view text) {
    if (text.starts_with('[')) {
        // Bracketed form: Rust's SocketAddrV6 wants a closing bracket and a port after it, and
        // the brackets only ever wrap an IPv6; "[1.2.3.4]:80" is no address to Rust either.
        const std::size_t close = text.find(']');
        if (close == std::string_view::npos || close < 2) return std::nullopt;
        if (close + 2 >= text.size() + 1 || text[close + 1] != ':') return std::nullopt;
        const std::string_view host = text.substr(1, close - 1);
        if (host.find(':') == std::string_view::npos) return std::nullopt;
        const auto address = parse_address(host);
        if (!address || address->v4) return std::nullopt;
        const auto port = port_of(text.substr(close + 2));
        if (!port) return std::nullopt;
        return Endpoint{*address, *port};
    }

    // Unbracketed: the part before the last colon is the address, after it the port, exactly
    // the way Rust splits `::1:80` into address `::1` and port 80 while "2606:4700::1111" holds
    // no usable split and never reaches this code as a SocketAddr at all.
    const std::size_t colon = text.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;
    const auto port = port_of(text.substr(colon + 1));
    if (!port) return std::nullopt;
    const auto address = parse_address(text.substr(0, colon));
    if (!address) return std::nullopt;
    return Endpoint{*address, *port};
}

std::string utf8_lossy(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size());
    std::size_t at = 0;
    while (at < bytes.size()) {
        const std::uint8_t lead = bytes[at];
        std::size_t width = 0;
        std::uint8_t second_low = 0x80;
        std::uint8_t second_high = 0xbf;
        if (lead <= 0x7f) {
            width = 1;
        } else if (lead >= 0xc2 && lead <= 0xdf) {
            width = 2;
        } else if (lead == 0xe0) {
            width = 3;
            second_low = 0xa0; // over-long three-byte sequences are not well-formed
        } else if (lead >= 0xe1 && lead <= 0xec) {
            width = 3;
        } else if (lead == 0xed) {
            width = 3;
            second_high = 0x9f; // surrogates are not UTF-8
        } else if (lead >= 0xee && lead <= 0xef) {
            width = 3;
        } else if (lead == 0xf0) {
            width = 4;
            second_low = 0x90;
        } else if (lead >= 0xf1 && lead <= 0xf3) {
            width = 4;
        } else if (lead == 0xf4) {
            width = 4;
            second_high = 0x8f; // past U+10FFFF is not UTF-8
        } else {
            out += "\uFFFD"; // 0xEF 0xBF 0xBD; this file is compiled with /utf-8
            ++at;
            continue;
        }

        // Walk the sequence and stop at the first byte that is not a valid continuation. The
        // maximal subpart is everything valid up to it -- or up to the end when the input simply
        // runs out -- and it becomes one U+FFFD, as Rust's from_utf8_lossy substitutes.
        std::size_t consumed = 1;
        for (std::size_t k = 1; k < width; ++k) {
            const std::uint8_t low = k == 1 ? second_low : 0x80;
            const std::uint8_t high = k == 1 ? second_high : 0xbf;
            if (at + k >= bytes.size()) break;
            const std::uint8_t byte = bytes[at + k];
            if (byte < low || byte > high) break;
            ++consumed;
        }
        if (consumed == width) {
            out.append(reinterpret_cast<const char*>(bytes.data() + at), width);
        } else {
            out += "\uFFFD";
        }
        at += consumed;
    }
    return out;
}

std::expected<Greeting, std::string> parse_greeting(std::span<const std::uint8_t> buffer) {
    if (buffer.size() < 2) return std::unexpected("not enough input to read");
    if (buffer[0] != VER) return std::unexpected("bad greeting version");
    const std::size_t nmethods = buffer[1];
    if (buffer.size() < 2 + nmethods) return std::unexpected("not enough input to read");
    Greeting greeting;
    greeting.methods = buffer.subspan(2, nmethods);
    greeting.length = 2 + nmethods;
    return greeting;
}

std::vector<std::uint8_t> build_method_selection() {
    return {VER, 0x00};
}

std::expected<std::size_t, std::string> request_tail_bytes(std::uint8_t atyp,
                                                             std::uint8_t fifth) {
    switch (atyp) {
        case ATYP_V4: return 5;   // 3 address bytes + port
        case ATYP_V6: return 17;  // 15 address bytes + port
        case ATYP_DOMAIN: return static_cast<std::size_t>(fifth) + 2;  // name + port
        default: return std::unexpected("bad atyp");
    }
}

std::expected<Request, std::string> parse_request(std::span<const std::uint8_t> buffer) {
    if (buffer.size() < 4) return std::unexpected("not enough input to read");
    if (buffer[0] != VER) return std::unexpected("bad socks version");

    Request request;
    request.command = buffer[1]; // read_request hands the command on unchecked; handle_client
                                  // rejects everything that is not CONNECT or ASSOCIATE
    std::size_t pos = 4;
    switch (buffer[3]) {
        case ATYP_V4: {
            if (buffer.size() < pos + 4 + 2) return std::unexpected("not enough input to read");
            IpAddress address;
            address.v4 = true;
            for (std::size_t i = 0; i < 4; ++i) address.bytes[12 + i] = octet(buffer, pos + i);
            request.target = Target::from_ip(address);
            pos += 4;
            break;
        }
        case ATYP_V6: {
            if (buffer.size() < pos + 16 + 2) return std::unexpected("not enough input to read");
            IpAddress address;
            for (std::size_t i = 0; i < 16; ++i) address.bytes[i] = octet(buffer, pos + i);
            request.target = Target::from_ip(address);
            pos += 16;
            break;
        }
        case ATYP_DOMAIN: {
            if (buffer.size() < pos + 1) return std::unexpected("not enough input to read");
            const std::size_t len = buffer[pos];
            ++pos;
            if (buffer.size() < pos + len + 2) return std::unexpected("not enough input to read");
            request.target = Target::from_domain(utf8_lossy(buffer.subspan(pos, len)));
            pos += len;
            break;
        }
        default:
            return std::unexpected("bad atyp");
    }

    request.port = read16(buffer, pos);
    request.length = pos + 2;
    return request;
}

std::vector<std::uint8_t> build_reply(std::uint8_t code) {
    // reply(): the 10-byte answer with the all-zero IPv4 bearer address.
    return {VER, code, 0x00, ATYP_V4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

std::vector<std::uint8_t> build_bound_reply(const Endpoint& bound) {
    std::vector<std::uint8_t> reply{VER, REP_OK, 0x00};
    if (bound.address.v4) {
        reply.push_back(ATYP_V4);
        reply.insert(reply.end(), bound.address.bytes.begin() + 12,
                     bound.address.bytes.end());
    } else {
        reply.push_back(ATYP_V6);
        reply.insert(reply.end(), bound.address.bytes.begin(), bound.address.bytes.end());
    }
    push16(reply, bound.port);
    return reply;
}

std::optional<UdpRequest> parse_udp_request(std::span<const std::uint8_t> buffer) {
    if (buffer.size() < 4 || buffer[2] != 0) return std::nullopt;

    const std::uint8_t atyp = buffer[3];
    std::size_t pos = 4;
    Target target;
    switch (atyp) {
        case ATYP_V4: {
            if (buffer.size() < pos + 4) return std::nullopt;
            IpAddress address;
            address.v4 = true;
            for (std::size_t i = 0; i < 4; ++i) address.bytes[12 + i] = octet(buffer, pos + i);
            target = Target::from_ip(address);
            pos += 4;
            break;
        }
        case ATYP_V6: {
            if (buffer.size() < pos + 16) return std::nullopt;
            IpAddress address;
            for (std::size_t i = 0; i < 16; ++i) address.bytes[i] = octet(buffer, pos + i);
            target = Target::from_ip(address);
            pos += 16;
            break;
        }
        case ATYP_DOMAIN: {
            if (buffer.size() < pos + 1) return std::nullopt;
            const std::size_t len = buffer[pos];
            ++pos;
            if (buffer.size() < pos + len) return std::nullopt;
            target = Target::from_domain(utf8_lossy(buffer.subspan(pos, len)));
            pos += len;
            break;
        }
        default:
            return std::nullopt;
    }

    if (buffer.size() < pos + 2) return std::nullopt;
    UdpRequest request;
    request.target = std::move(target);
    request.port = read16(buffer, pos);
    request.payload = buffer.subspan(pos + 2);
    return request;
}

std::vector<std::uint8_t> build_udp_reply(const Endpoint& source,
                                          std::span<const std::uint8_t> data) {
    std::vector<std::uint8_t> packet{0x00, 0x00, 0x00};
    if (source.address.v4) {
        packet.push_back(ATYP_V4);
        packet.insert(packet.end(), source.address.bytes.begin() + 12,
                      source.address.bytes.end());
    } else {
        packet.push_back(ATYP_V6);
        packet.insert(packet.end(), source.address.bytes.begin(), source.address.bytes.end());
    }
    push16(packet, source.port);
    packet.insert(packet.end(), data.begin(), data.end());
    return packet;
}

IpAddress normalize_ip(const IpAddress& address) {
    if (address.v4) return address;
    // to_ipv4_mapped: the ::ffff/96 shape and nothing else; :: and ::1 stay IPv6.
    for (std::size_t i = 0; i < 10; ++i) {
        if (address.bytes[i] != 0) return address;
    }
    if (address.bytes[10] != 0xff || address.bytes[11] != 0xff) return address;
    IpAddress v4;
    v4.v4 = true;
    for (std::size_t i = 0; i < 4; ++i) v4.bytes[12 + i] = address.bytes[12 + i];
    return v4;
}

bool is_loopback(const IpAddress& address) {
    if (address.v4) return address.bytes[12] == 127;
    // Rust's `addr == Ipv6Addr::LOCALHOST`, which is all sixteen octets.
    static constexpr std::array<std::uint8_t, 16> one{0, 0, 0, 0, 0, 0, 0, 0,
                                                      0, 0, 0, 0, 0, 0, 0, 1};
    return address.bytes == one;
}

bool is_unspecified(const IpAddress& address) {
    return std::all_of(address.bytes.begin(), address.bytes.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

IpAddress expected_udp_source(const Endpoint& control_peer, const Target& requested) {
    if (requested.is_ip() && !is_unspecified(requested.ip())) return normalize_ip(requested.ip());
    return normalize_ip(control_peer.address);
}

bool udp_source_allowed(const IpAddress& expected, std::optional<Endpoint> latched,
                        const Endpoint& from) {
    if (latched) return *latched == from; // the exact address and port that opened the channel
    return normalize_ip(from.address) == normalize_ip(expected);
}

bool direct_target_allowed(const IpAddress& client, const IpAddress& address) {
    const IpAddress target = normalize_ip(address);
    if (is_loopback(target) || is_unspecified(target)) {
        return is_loopback(normalize_ip(client));
    }
    return true;
}

bool should_use_gateway(std::uint16_t port) {
    return port == 80 || port == 443;
}

std::optional<Endpoint> parse_gateway_proxy(std::string_view address) {
    const std::string_view trimmed = trim(address);
    if (trimmed.empty()) return std::nullopt;
    return parse_socket_address(trimmed);
}

std::optional<std::string> set_gateway_proxy(std::string_view address) {
    const std::string_view trimmed = trim(address);
    if (trimmed.empty()) return std::nullopt; // the Rust core returns before even parsing

    const auto parsed = parse_socket_address(trimmed);
    if (!parsed) {
        return "[-] ignoring malformed gateway proxy address " + std::string(trimmed);
    }

    std::lock_guard lock(gateway_gate);
    if (gateway_installed) return std::nullopt; // OnceLock::set() failing logs nothing
    gateway_installed = true;
    gateway_address = *parsed;
    gateway_healthy.store(true, std::memory_order_relaxed);
    return "[+] gateway filtering active: http and https will traverse " + parsed->text() +
           " inside the tunnel";
}

std::optional<Endpoint> gateway_proxy() {
    if (!gateway_healthy.load(std::memory_order_relaxed)) return std::nullopt;
    std::lock_guard lock(gateway_gate);
    return gateway_address;
}

std::optional<std::string> retire_gateway(std::string_view reason) {
    if (gateway_healthy.exchange(false, std::memory_order_relaxed)) {
        return "[-] the gateway proxy is not reachable (" + std::string(reason) +
               "); sending traffic straight through the tunnel instead. organization http "
               "filtering will not apply";
    }
    return std::nullopt; // the swap already said it, once
}

std::vector<std::uint8_t> build_proxy_connect(std::string_view target, std::uint16_t port) {
    std::string authority;
    if (target.find(':') != std::string_view::npos && !target.starts_with('[')) {
        authority = "[" + std::string(target) + "]:" + std::to_string(port);
    } else {
        authority = std::string(target) + ":" + std::to_string(port);
    }
    const std::string text = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                             "\r\nUser-Agent: " + std::string(UA_REGISTER) + "\r\n\r\n";
    return {text.begin(), text.end()};
}

std::optional<bool> proxy_connect_succeeded(std::span<const std::uint8_t> head) {
    const std::string text = utf8_lossy(head);
    const std::size_t line_end = text.find("\r\n");
    if (line_end == std::string::npos) return std::nullopt;
    const std::optional<std::string_view> status =
        second_token(std::string_view{text.data(), line_end});
    if (!status) return std::nullopt;
    const auto code = port_of(*status);
    if (!code) return std::nullopt;
    return *code >= 200 && *code < 300;
}

std::optional<std::size_t> find_head_end(std::span<const std::uint8_t> buffer) {
    static constexpr std::uint8_t marker[] = {0x0d, 0x0a, 0x0d, 0x0a};
    const auto at = std::search(buffer.begin(), buffer.end(), std::begin(marker), std::end(marker));
    if (at == buffer.end()) return std::nullopt;
    return static_cast<std::size_t>(at - buffer.begin()) + 4;
}

std::optional<std::string> world_reachable_warning(std::string_view kind, const Endpoint& listen) {
    if (is_loopback(listen.address)) return std::nullopt;
    return "[!] the " + std::string(kind) + " listener is bound to " + listen.text() +
           ", which is reachable from outside this machine. It accepts every client without "
           "authentication, so anyone who can reach " +
           listen.text() +
           " can send traffic through your tunnel. Bind it to 127.0.0.1 unless you intend to "
           "share it.";
}

std::optional<std::pair<std::string, std::uint16_t>> parse_authority(std::string_view raw,
                                                                     std::uint16_t default_port) {
    raw = trim(raw);
    if (raw.empty()) return std::nullopt;

    if (raw.starts_with('[')) {
        const std::size_t close = raw.find(']'); // Rust's split_once(']') takes the first one
        if (close == std::string_view::npos) return std::nullopt;
        const std::string_view host = raw.substr(1, close - 1);
        if (host.empty()) return std::nullopt;
        std::uint16_t port = default_port;
        const std::string_view tail = raw.substr(close + 1);
        // Anything after the bracket counts as a port only behind a colon; tail "junk" leaves
        // the default standing, which is exactly what Rust's strip_prefix(':') is_true_of for "".
        if (tail.starts_with(':')) {
            const auto parsed = port_of(tail.substr(1));
            if (!parsed) return std::nullopt;
            port = *parsed;
        }
        return std::pair{std::string(host), port};
    }

    const std::size_t colon = raw.rfind(':'); // rsplit_once(':')
    if (colon != std::string_view::npos) {
        const std::string_view host = raw.substr(0, colon);
        if (host.find(':') == std::string_view::npos) {
            if (host.empty()) return std::nullopt;
            const auto port = port_of(raw.substr(colon + 1));
            if (!port) return std::nullopt; // a non-numeric port is refused, not defaulted
            return std::pair{std::string(host), *port};
        }
    }
    // No colon, or a host that still holds one: the whole text is the host.
    return std::pair{std::string(raw), default_port};
}

std::optional<HttpRequestLine> parse_request_line(std::string_view line) {
    // parts = line.split_whitespace(); method and target are needed, the version is not.
    std::optional<std::string_view> method;
    std::optional<std::string_view> target;
    std::string_view version = "HTTP/1.1";
    std::size_t at = 0;
    std::size_t seen = 0;
    while (at < line.size()) {
        if (whitespace(line[at])) {
            ++at;
            continue;
        }
        const std::size_t begin = at;
        while (at < line.size() && !whitespace(line[at])) ++at;
        const std::string_view token = line.substr(begin, at - begin);
        ++seen;
        if (seen == 1) method = token;
        else if (seen == 2) target = token;
        else if (seen == 3) {
            version = token;
            break; // the rest of the line is not looked at
        }
    }
    if (!method || !target) return std::nullopt;

    HttpRequestLine request;
    request.method = std::string(*method);

    const bool connect = request.method.size() == 7 &&
                         std::equal(request.method.begin(), request.method.end(), "connect",
                                    [](char left, char right) {
                                        return std::tolower(static_cast<unsigned char>(left)) ==
                                               right;
                                    });
    if (connect) {
        const auto authority = parse_authority(*target, 443);
        if (!authority) return std::nullopt;
        request.authority = authority->first;
        request.port = authority->second;
        return request; // rewritten stays empty: CONNECT is relayed as it stands
    }

    // Rust strips "http://" or "HTTP://" and nothing else, so "Http://" is refused.
    std::string_view without_scheme;
    if (target->starts_with("http://")) without_scheme = target->substr(7);
    else if (target->starts_with("HTTP://")) without_scheme = target->substr(7);
    else return std::nullopt;

    std::string_view authority_part = without_scheme;
    std::string_view path = "/";
    if (const std::size_t slash = without_scheme.find('/'); slash != std::string_view::npos) {
        authority_part = without_scheme.substr(0, slash);
        path = without_scheme.substr(slash); // the leading '/' stays on the origin-form path
    }
    const auto authority = parse_authority(authority_part, 80);
    if (!authority) return std::nullopt;
    request.authority = authority->first;
    request.port = authority->second;
    request.rewritten = request.method + " " + std::string(path) + " " + std::string(version) +
                        "\r\n";
    return request;
}

std::vector<Endpoint> parse_resolvers(std::string_view raw) {
    std::vector<Endpoint> servers;
    std::size_t at = 0;
    for (;;) {
        const std::size_t cut = raw.find_first_of(", ;", at);
        const std::string_view entry = trim(raw.substr(at, cut == std::string_view::npos
                                                               ? std::string_view::npos
                                                               : cut - at));
        if (!entry.empty()) {
            std::optional<Endpoint> server = parse_socket_address(entry);
            if (!server) {
                if (const auto ip = parse_address(entry)) server = Endpoint{*ip, DNS_PORT};
            }
            if (server && std::find(servers.begin(), servers.end(), *server) == servers.end()) {
                servers.push_back(*server);
            }
        }
        if (cut == std::string_view::npos) break;
        at = cut + 1;
    }
    return servers;
}

std::vector<Endpoint> resolver_addresses(const Settings& settings) {
    std::vector<Endpoint> servers =
        parse_resolvers(settings.get("AETHER_DNS").value_or(std::string_view{}));
    if (servers.empty()) {
        for (const std::string_view seed : {"1.1.1.1", "1.0.0.1"}) {
            if (const auto ip = parse_address(seed)) servers.push_back(Endpoint{*ip, DNS_PORT});
        }
    }
    return servers;
}

std::vector<std::uint8_t> build_dns_query(std::string_view name, std::uint16_t qtype,
                                          std::uint16_t id) {
    std::vector<std::uint8_t> query;
    query.reserve(32 + name.size());
    push16(query, id);
    query.insert(query.end(), {0x01, 0x00}); // recursion desired
    query.insert(query.end(), {0x00, 0x01}); // one question
    query.insert(query.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    // Rust's split('.') keeps the empty label a trailing dot leaves behind and pushes its zero
    // length too, so this loop must not skip empty labels the way dns.cpp's build_query does.
    std::size_t at = 0;
    for (;;) {
        const std::size_t dot = name.find('.', at);
        const std::string_view label =
            name.substr(at, dot == std::string_view::npos ? std::string_view::npos : dot - at);
        query.push_back(static_cast<std::uint8_t>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
        if (dot == std::string_view::npos) break;
        at = dot + 1;
    }
    query.push_back(0x00);
    push16(query, qtype);
    query.insert(query.end(), {0x00, 0x01}); // the Internet class
    return query;
}

std::pair<std::vector<std::uint8_t>, std::uint16_t> new_dns_query(std::string_view name,
                                                                  std::uint16_t qtype) {
    static thread_local std::mt19937 generator{std::random_device{}()};
    const std::uint16_t id = static_cast<std::uint16_t>(generator() & 0xffff);
    return {build_dns_query(name, qtype, id), id};
}

std::expected<std::vector<std::uint8_t>, std::string> frame_dns_query(
    std::span<const std::uint8_t> query) {
    if (query.size() > 0xffff) return std::unexpected("dns query is too long to frame");
    std::vector<std::uint8_t> framed;
    framed.reserve(query.size() + 2);
    push16(framed, static_cast<std::uint16_t>(query.size()));
    framed.insert(framed.end(), query.begin(), query.end());
    return framed;
}

std::optional<std::size_t> dns_frame_length(std::span<const std::uint8_t> header) {
    if (header.size() < 2) return std::nullopt;
    return static_cast<std::size_t>(read16(header, 0));
}

std::optional<std::uint8_t> dns_rcode(std::span<const std::uint8_t> response) {
    if (response.size() < 4) return std::nullopt;
    return static_cast<std::uint8_t>(response[3] & 0x0f);
}

std::optional<IpAddress> parse_dns_answer(std::span<const std::uint8_t> response,
                                          std::uint16_t qtype) {
    if (response.size() < 12) return std::nullopt;
    const auto qd = read16(response, 4);
    const auto an = read16(response, 6);
    std::size_t pos = 12;

    for (std::uint16_t i = 0; i < qd; ++i) {
        const auto past = skip_name(response, pos);
        if (!past) return std::nullopt;
        pos = *past + 4; // the question's type and class
    }

    for (std::uint16_t i = 0; i < an; ++i) {
        const auto past = skip_name(response, pos);
        if (!past) return std::nullopt;
        pos = *past;
        if (pos + 10 > response.size()) return std::nullopt;
        const auto rtype = read16(response, pos);
        const auto rdlen = read16(response, pos + 8);
        pos += 10;
        if (pos + rdlen > response.size()) return std::nullopt;
        if (rtype == qtype && qtype == QTYPE_A && rdlen == 4) {
            IpAddress address;
            address.v4 = true;
            for (std::size_t k = 0; k < 4; ++k) address.bytes[12 + k] = response[pos + k];
            return address;
        }
        if (rtype == qtype && qtype == QTYPE_AAAA && rdlen == 16) {
            IpAddress address;
            for (std::size_t k = 0; k < 16; ++k) address.bytes[k] = response[pos + k];
            return address;
        }
        pos += rdlen;
    }
    return std::nullopt;
}

routing::Host host_of(const Target& target) {
    if (target.is_ip()) return routing::Host{target.ip()};
    return routing::Host{std::string_view{target.domain()}};
}

routing::Action decide_route(const routing::RuleSet& set, const Target& target,
                             std::optional<std::string_view> sniffed, std::uint16_t port) {
    if (sniffed) {
        const auto decided = set.decide(routing::Host{*sniffed}, port);
        if (decided != routing::Action::Proxy) return decided;
    }
    return set.decide(host_of(target), port);
}

bool sniff_enabled(const Settings& settings) {
    const auto value = settings.get("AETHER_ROUTE_SNIFF");
    if (!value) return true;
    return !(*value == "0" || *value == "off" || *value == "false");
}

std::uint64_t sniff_window_ms(const Settings& settings) {
    const auto value = settings.get("AETHER_ROUTE_SNIFF_MS");
    if (!value) return DEFAULT_SNIFF_WINDOW_MS;
    const auto ms = parse_u64(trim(*value));
    if (!ms || *ms == 0) return DEFAULT_SNIFF_WINDOW_MS;
    return *ms;
}

std::uint64_t half_close_linger_secs(const Settings& settings) {
    const auto value = settings.get("AETHER_HALF_CLOSE_SECS");
    if (!value) return DEFAULT_HALF_CLOSE_LINGER_SECS;
    const auto secs = parse_u64(*value); // Rust parses this value without trimming it first
    if (!secs || *secs == 0) return DEFAULT_HALF_CLOSE_LINGER_SECS;
    return std::min(*secs, MAX_HALF_CLOSE_LINGER_SECS);
}

std::size_t client_limit(std::size_t by_tier, std::optional<std::size_t> open_files) {
    if (!open_files) return by_tier;
    const std::size_t headroom =
        open_files > 64 ? (*open_files - 64) / 2 : 0; // saturating_sub(64)
    return std::min(by_tier, std::max(headroom, std::size_t{32}));
}

std::size_t client_limit_for(const Settings& settings, sysprofile::Tier tier) {
    if (const auto value = settings.get("AETHER_MAX_CLIENTS")) {
        const auto limit = parse_u64(trim(*value));
        if (limit && *limit > 0 && *limit <= static_cast<std::uint64_t>(SIZE_MAX)) {
            return static_cast<std::size_t>(*limit);
        }
    }

    std::size_t by_tier = 8192;
    switch (tier) {
        case sysprofile::Tier::Low: by_tier = 512; break;
        case sysprofile::Tier::Medium: by_tier = 2048; break;
        case sysprofile::Tier::High: break;
    }
    // open_file_limit() answers nothing on Windows, so the file-descriptor half of the Rust
    // calculation never caps the tier number here; client_limit() keeps the formula for a port
    // that can read one.
    return client_limit(by_tier, std::nullopt);
}

} // namespace aether::core::socks
