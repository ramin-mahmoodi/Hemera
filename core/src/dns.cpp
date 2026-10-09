#include "dns.hpp"

#include "settings.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <random>

namespace hemera::core {
namespace {

// inet_pton and inet_ntop are Winsock calls, so winsock has to be started even where no socket is
// opened. The static is created when the translation unit is loaded and lives to its end, which is
// how the Rust supervisor keeps it.
const struct Winsock {
    Winsock() {
        WSADATA ignored;
        WSAStartup(MAKEWORD(2, 2), &ignored);
    }
} winsock;

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool starts_with_scheme(std::string_view value, std::string_view scheme) {
    return value.size() >= scheme.size() &&
           lowered(value.substr(0, scheme.size())) == scheme;
}

// Rust's Ipv4Addr reads up to three digits per octet, leading zeros included, and prints them
// without them; inet_pton refuses "01.2.3.4", so the four octets are read here.
std::optional<std::string> v4_literal(std::string_view text) {
    std::string out;
    std::size_t at = 0;
    for (int octet = 0; octet < 4; ++octet) {
        const std::size_t dot = text.find('.', at);
        const std::size_t end = dot == std::string_view::npos ? text.size() : dot;
        const std::string_view part = text.substr(at, end - at);
        if (part.empty() || part.size() > 3) return std::nullopt;
        std::uint32_t value = 0;
        for (const char c : part) {
            if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
            value = value * 10 + static_cast<std::uint32_t>(c - '0');
        }
        if (value > 255) return std::nullopt;
        out += std::to_string(value);
        if (octet == 3) {
            if (end != text.size()) return std::nullopt;
            return out;
        }
        if (dot == std::string_view::npos) return std::nullopt;
        out += '.';
        at = dot + 1;
    }
    return std::nullopt;
}

bool label_ok(std::string_view label) {
    if (label.empty() || label.size() > 63) return false;
    return std::all_of(label.begin(), label.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '-' || c == '_';
    });
}

std::optional<std::uint16_t> port_of(std::string_view text) {
    std::uint32_t value = 0;
    if (text.empty() || text.size() > 5) return std::nullopt;
    for (char c : text) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
        value = value * 10 + static_cast<std::uint32_t>(c - '0');
    }
    if (value > 65535) return std::nullopt;
    return static_cast<std::uint16_t>(value);
}

std::string_view unbracket(std::string_view text) {
    if (text.size() >= 2 && text.front() == '[' && text.back() == ']') {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

// `text` as `ip:port`, `[ipv6]:port`, or an IP address alone, on `default_port`.
std::optional<std::pair<std::string, std::uint16_t>> socket_address(std::string_view text,
                                                                    std::uint16_t default_port) {
    if (const auto bare = ip_literal(text)) return std::pair{*bare, default_port};

    if (text.starts_with('[')) {
        const std::size_t close = text.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        const std::optional<std::string> ip = ip_literal(text.substr(1, close - 1));
        if (!ip) return std::nullopt;
        const std::string_view tail = text.substr(close + 1);
        if (tail.empty()) return std::pair{*ip, default_port};
        if (tail.front() != ':') return std::nullopt;
        const std::optional<std::uint16_t> port = port_of(tail.substr(1));
        if (!port) return std::nullopt;
        return std::pair{*ip, *port};
    }

    const std::size_t colon = text.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;
    const std::optional<std::uint16_t> port = port_of(text.substr(colon + 1));
    if (!port) return std::nullopt;
    if (const auto ip = ip_literal(text.substr(0, colon))) return std::pair{*ip, *port};
    return std::nullopt;
}

std::uint16_t random_id() {
    thread_local std::mt19937 generator{std::random_device{}()};
    return static_cast<std::uint16_t>(generator() & 0xffff);
}

void push16(std::vector<std::uint8_t>& into, std::uint16_t value) {
    into.push_back(static_cast<std::uint8_t>(value >> 8));
    into.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint16_t read16(std::span<const std::uint8_t> msg, std::size_t at) {
    return static_cast<std::uint16_t>((msg[at] << 8) | msg[at + 1]);
}

std::optional<std::size_t> skip_name(std::span<const std::uint8_t> msg, std::size_t at) {
    for (;;) {
        if (at >= msg.size()) return std::nullopt;
        const std::uint8_t len = msg[at];
        if ((len & 0xc0) == 0xc0) return at + 2; // a compressed name: two bytes and it is over
        if (len == 0) return at + 1;
        at += 1 + len;
    }
}

std::optional<std::vector<std::uint8_t>> parse_https_ech(std::span<const std::uint8_t> msg) {
    if (msg.size() < 12) return std::nullopt;
    const std::size_t questions = read16(msg, 4);
    const std::size_t answers = read16(msg, 6);
    std::size_t at = 12;

    for (std::size_t i = 0; i < questions; ++i) {
        const auto next = skip_name(msg, at);
        if (!next) return std::nullopt;
        at = *next + 4;
        if (at > msg.size()) return std::nullopt;
    }

    for (std::size_t i = 0; i < answers; ++i) {
        const auto next = skip_name(msg, at);
        if (!next) return std::nullopt;
        at = *next;
        if (at + 10 > msg.size()) return std::nullopt;
        const std::uint16_t type = read16(msg, at);
        const std::size_t length = read16(msg, at + 8);
        at += 10;
        if (at + length > msg.size()) return std::nullopt;
        if (type == RR_HTTPS) {
            // The SVCB rdata: the target name, then parameters of key, length and value.
            const std::size_t end = at + length;
            const auto after_target = skip_name(msg, at + 2);
            if (after_target) {
                std::size_t p = *after_target;
                while (p + 4 <= end) {
                    const std::uint16_t key = read16(msg, p);
                    const std::size_t value_len = read16(msg, p + 2);
                    p += 4;
                    if (p + value_len > end) break;
                    if (key == SVCPARAM_ECH) {
                        return std::vector<std::uint8_t>(msg.begin() + static_cast<std::ptrdiff_t>(p),
                                                         msg.begin() +
                                                             static_cast<std::ptrdiff_t>(p + value_len));
                    }
                    p += value_len;
                }
            }
        }
        at += length;
    }
    return std::nullopt;
}

} // namespace

// The text an address, in the form the log shows it: compressed and lower case for IPv6.
std::optional<std::string> ip_literal(std::string_view text) {
    if (const auto four = v4_literal(text)) return four;

    std::array<std::uint8_t, 16> bytes{};
    char buffer[INET6_ADDRSTRLEN] = {};
    if (inet_pton(AF_INET6, std::string(text).c_str(), bytes.data()) == 1) {
        inet_ntop(AF_INET6, bytes.data(), buffer, sizeof(buffer));
        return std::string(buffer);
    }
    return std::nullopt;
}

std::optional<IpAddress> parse_address(std::string_view text) {
    const auto normalized = ip_literal(text);
    if (!normalized) return std::nullopt;

    IpAddress address;
    // An IPv4-mapped IPv6 address carries dots too, so the colon is what tells them apart.
    if (normalized->find(':') == std::string::npos) {
        if (inet_pton(AF_INET, normalized->c_str(), address.bytes.data() + 12) != 1) {
            return std::nullopt;
        }
        address.v4 = true;
        return address;
    }
    if (inet_pton(AF_INET6, normalized->c_str(), address.bytes.data()) != 1) {
        return std::nullopt;
    }
    return address;
}

std::string SocketAddr::to_string() const {
    char buffer[INET6_ADDRSTRLEN] = {};
    const void* source = ip.v4 ? static_cast<const void*>(ip.bytes.data() + 12)
                               : static_cast<const void*>(ip.bytes.data());
    const int family = ip.v4 ? AF_INET : AF_INET6;
    if (inet_ntop(family, source, buffer, static_cast<ULONG>(sizeof(buffer))) == nullptr) {
        return "unknown:" + std::to_string(port);
    }
    if (ip.v4) return std::string(buffer) + ":" + std::to_string(port);
    return std::string("[") + buffer + "]:" + std::to_string(port);
}

std::optional<SocketAddr> parse_socket_addr(std::string_view text) {
    // Rust's SocketAddr parse reads a bare IPv6 address only as a host, never with a port; more
    // than one colon outside brackets is a malformed string rather than an address and a port.
    if (std::ranges::count(text, ':') > 1 && !text.starts_with('[')) return std::nullopt;

    const auto parsed = socket_address(text, 0);
    // A port of zero is no port to reach anything on.
    if (!parsed || parsed->second == 0) return std::nullopt;
    const auto ip = parse_address(parsed->first);
    if (!ip) return std::nullopt;
    return SocketAddr{*ip, parsed->second};
}

bool valid_domain(std::string_view name) {
    if (name.ends_with('.')) name = name.substr(0, name.size() - 1);
    if (name.empty() || name.size() > 253) return false;
    std::size_t at = 0;
    while (at <= name.size()) {
        const std::size_t dot = name.find('.', at);
        const std::string_view label =
            name.substr(at, dot == std::string_view::npos ? std::string_view::npos : dot - at);
        if (!label_ok(label)) return false;
        if (dot == std::string_view::npos) break;
        at = dot + 1;
    }
    return true;
}

std::optional<std::string> host_address(std::string_view value) {
    if (const auto ip = ip_literal(unbracket(value))) return ip;
    if (valid_domain(value)) return std::string(value);
    return std::nullopt;
}

std::optional<std::pair<std::string, std::uint16_t>> host_and_port(std::string_view value,
                                                                   std::uint16_t default_port) {
    if (const auto host = host_address(value)) return std::pair{*host, default_port};

    const std::size_t colon = value.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;
    const std::string_view host = value.substr(0, colon);
    // An IPv6 address takes brackets before a port.
    if (host.contains(':') && !host.starts_with('[')) return std::nullopt;
    const std::optional<std::uint16_t> port = port_of(value.substr(colon + 1));
    // A port of zero is no port to reach anything on.
    if (!port || *port == 0) return std::nullopt;
    if (const auto named = host_address(host)) return std::pair{*named, *port};
    return std::nullopt;
}

std::expected<EchDns, std::string> EchDns::parse(std::string_view value) {
    const std::string_view whole = trim(value);
    if (starts_with_scheme(whole, "https://")) {
        std::vector<std::string_view> pieces;
        std::size_t at = 0;
        for (;;) {
            const std::size_t next = whole.find('@', at);
            pieces.push_back(whole.substr(at, next == std::string_view::npos
                                                       ? std::string_view::npos
                                                       : next - at));
            if (next == std::string_view::npos) break;
            at = next + 1;
        }

        const std::string_view url = trim(pieces.front());
        // The authority of the URL: up to the first '/', '?' or '#', with an optional port, an
        // IPv6 host being bracketed.
        const std::string_view authority_part = url.substr(8);
        const std::string_view authority =
            authority_part.substr(0, authority_part.find_first_of("/?#"));
        std::string_view host = authority;
        std::uint16_t port = 443;
        if (authority.starts_with('[')) {
            const std::size_t close = authority.find(']');
            if (close == std::string_view::npos) {
                host = std::string_view{};
            } else {
                host = authority.substr(1, close - 1);
                if (authority.size() > close + 1 && authority[close + 1] == ':') {
                    if (const auto number = port_of(authority.substr(close + 2))) port = *number;
                }
            }
        } else {
            const std::size_t colon = authority.rfind(':');
            if (colon != std::string_view::npos) {
                if (const auto number = port_of(authority.substr(colon + 1))) {
                    host = authority.substr(0, colon);
                    port = *number;
                }
            }
        }
        if (host.empty()) return std::unexpected(std::string(whole) + " names no host");

        EchDns dns;
        dns.kind = EchDns::Kind::Https;
        dns.host = std::string(host);
        dns.port = port;
        dns.endpoint.url = std::string(url);

        for (std::size_t i = 1; i < pieces.size(); ++i) {
            const std::string_view piece = pieces[i];
            const std::string neither = "@" + std::string(piece) + " in " + std::string(whole) +
                                        " is neither @address= nor @sni=";
            const std::size_t equals = piece.find('=');
            if (equals == std::string_view::npos) return std::unexpected(neither);
            const std::string_view name = trim(piece.substr(0, equals));
            const std::string_view setting = trim(piece.substr(equals + 1));
            const std::string kind_name = lowered(name);

            // A name used twice is refused before its value is judged, as the Rust core does.
            std::optional<std::string>* slot = nullptr;
            std::string taken;
            std::string failure;
            if (kind_name == "address") {
                slot = &dns.endpoint.address;
                if (const auto named = host_address(setting)) {
                    taken = *named; // an IPv6 host loses its brackets here
                } else {
                    failure = "@address=" + std::string(setting) +
                              " is no IP address or domain name; the port is the URL's";
                }
            } else if (kind_name == "sni") {
                slot = &dns.endpoint.sni;
                if (ip_literal(unbracket(setting)) || !valid_domain(setting)) {
                    failure = "@sni=" + std::string(setting) + " is no domain name";
                } else {
                    taken = std::string(setting);
                }
            } else {
                return std::unexpected(neither);
            }
            if (slot->has_value()) {
                return std::unexpected(std::string(whole) + " names @" + std::string(name) +
                                       " twice");
            }
            if (!failure.empty()) return std::unexpected(failure);
            *slot = std::move(taken);
        }
        return dns;
    }

    bool tcp = false;
    std::string_view rest;
    if (starts_with_scheme(whole, "udp://")) {
        rest = whole.substr(6);
    } else if (starts_with_scheme(whole, "tcp://")) {
        rest = whole.substr(6);
        tcp = true;
    } else {
        return std::unexpected(std::string(whole) +
                               " is no udp://, tcp:// or https:// address");
    }
    while (rest.ends_with('/')) rest = rest.substr(0, rest.size() - 1);
    const auto address = socket_address(rest, 53);
    if (!address) return std::unexpected(std::string(whole) + " names no IP address");

    EchDns dns;
    dns.kind = tcp ? EchDns::Kind::Tcp : EchDns::Kind::Udp;
    dns.host = address->first;
    dns.port = address->second;
    return dns;
}

std::string EchDns::text() const {
    if (kind == Kind::Https) {
        std::string out = endpoint.url;
        if (endpoint.address) out += "@address=" + *endpoint.address;
        if (endpoint.sni) out += "@sni=" + *endpoint.sni;
        return out;
    }
    std::string out = kind == Kind::Tcp ? "tcp://" : "udp://";
    if (host.contains(':')) {
        out += "[" + host + "]";
    } else {
        out += host;
    }
    out += ":" + std::to_string(port);
    return out;
}

std::vector<std::uint8_t> tcp_message(std::span<const std::uint8_t> message) {
    std::vector<std::uint8_t> framed;
    framed.reserve(message.size() + 2);
    push16(framed, static_cast<std::uint16_t>(message.size()));
    framed.insert(framed.end(), message.begin(), message.end());
    return framed;
}

std::vector<std::uint8_t> build_query(std::string_view name, std::uint16_t qtype,
                                     std::uint16_t id) {
    std::vector<std::uint8_t> query;
    push16(query, id);
    query.insert(query.end(), {0x01, 0x00});             // a recursion-desired question
    query.insert(query.end(), {0x00, 0x01});             // one question
    query.insert(query.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    std::size_t at = 0;
    while (at < name.size()) {
        const std::size_t dot = name.find('.', at);
        const std::string_view label = name.substr(
            at, dot == std::string_view::npos ? std::string_view::npos : dot - at);
        if (!label.empty()) {
            query.push_back(static_cast<std::uint8_t>(label.size()));
            query.insert(query.end(), label.begin(), label.end());
        }
        if (dot == std::string_view::npos) break;
        at = dot + 1;
    }
    query.push_back(0x00);
    push16(query, qtype);
    query.insert(query.end(), {0x00, 0x01}); // the Internet class
    return query;
}

std::pair<std::vector<std::uint8_t>, std::uint16_t> new_query(std::string_view name,
                                                              std::uint16_t qtype) {
    const std::uint16_t id = random_id();
    return {build_query(name, qtype, id), id};
}

bool response_matches(std::span<const std::uint8_t> msg, std::uint16_t id, std::string_view name,
                      std::uint16_t qtype) {
    if (msg.size() < 12) return false;
    if (read16(msg, 0) != id) return false;
    if ((msg[2] & 0x80) == 0) return false; // not an answer
    if (read16(msg, 4) != 1) return false;  // not exactly one question

    std::size_t pos = 12;
    std::size_t at = 0;
    while (at <= name.size()) {
        const std::size_t dot = name.find('.', at);
        const std::string_view label =
            name.substr(at, dot == std::string_view::npos ? std::string_view::npos : dot - at);
        at = dot == std::string_view::npos ? name.size() + 1 : dot + 1;
        if (label.empty()) continue;
        if (pos >= msg.size()) return false;
        const std::size_t len = msg[pos];
        if (len != label.size()) return false;
        ++pos;
        if (pos + len > msg.size()) return false;
        if (!std::equal(msg.begin() + static_cast<std::ptrdiff_t>(pos),
                        msg.begin() + static_cast<std::ptrdiff_t>(pos + len), label.begin(),
                        label.end(), [](std::uint8_t c, char d) {
                            return std::tolower(c) ==
                                   std::tolower(static_cast<unsigned char>(d));
                        })) {
            return false;
        }
        pos += len;
    }

    if (pos >= msg.size() || msg[pos] != 0) return false;
    ++pos;
    if (pos + 4 > msg.size()) return false;
    return read16(msg, pos) == qtype;
}

std::expected<std::vector<std::uint8_t>, std::string> answer_ech(
    std::span<const std::uint8_t> msg, std::string_view name) {
    const auto ech = parse_https_ech(msg);
    if (ech && !ech->empty()) return *ech;
    return std::unexpected(std::string(name) + " has no HTTPS record with an ech parameter");
}

std::expected<std::vector<std::uint8_t>, std::string> fetch_ech_config(const Settings& settings,
                                                                       const EchTransport& transport) {
    const std::string_view dns_value = trim(settings.get("HEMERA_ECH_DNS").value_or(""));
    const auto dns = EchDns::parse(dns_value.empty() ? DEFAULT_ECH_DNS : dns_value);
    if (!dns) return std::unexpected("--ech-dns: " + dns.error());

    const std::string_view domain_value = trim(settings.get("HEMERA_ECH_DOMAIN").value_or(""));
    const std::string_view domain =
        domain_value.empty() ? std::string_view{DEFAULT_ECH_DOMAIN} : domain_value;
    if (!valid_domain(domain)) {
        return std::unexpected("--ech-domain: " + std::string(domain) + " is no domain name");
    }
    std::string bare(domain);
    while (bare.ends_with('.')) bare.pop_back();

    const auto answer = transport(*dns, bare);
    if (!answer) {
        if (answer.error().empty()) {
            return std::unexpected(dns->text() + " did not answer for " + bare);
        }
        return std::unexpected(bare + " via " + dns->text() + " failed: " + answer.error());
    }
    return *answer;
}

} // namespace hemera::core
