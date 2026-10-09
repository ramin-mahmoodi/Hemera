#pragma once

#include "settings.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hemera::core {

// Port of dns.rs: where an ECHConfigList is looked up and how its wire messages look. The
// resolvers themselves -- UDP, TCP and DNS-over-HTTPS -- belong to the egress layer that is not
// ported yet, so fetch_ech_config() takes the lookup as a callback.

inline constexpr const char* DEFAULT_ECH_DNS = "udp://1.1.1.1";
inline constexpr const char* DEFAULT_ECH_DOMAIN = "cloudflare-ech.com";

inline constexpr std::uint16_t RR_HTTPS = 65;
inline constexpr std::uint16_t SVCPARAM_ECH = 5;

// How long the lookup of the ECHConfigList may take, over any transport.
inline constexpr int ECH_LOOKUP_TIMEOUT_MS = 12000;
// Over UDP the question goes out again after this long without an answer, until the lookup gives
// up.
inline constexpr int UDP_RESEND_AFTER_MS = 2000;

// The text an IP literal, in the form the log shows it: compressed and lower case for IPv6, and
// without a leading zero for IPv4. Nothing when `text` is no address.
[[nodiscard]] std::optional<std::string> ip_literal(std::string_view text);

// An address as bytes: sixteen of them, an IPv4 one held in the last four.
struct IpAddress {
    std::array<std::uint8_t, 16> bytes{};
    bool v4 = false;

    [[nodiscard]] bool operator==(const IpAddress&) const = default;

    // The four octets of an IPv4 address, and the first two bytes of an IPv6 one, which is where
    // the ranges that matter to a routing rule live.
    [[nodiscard]] std::uint32_t head() const {
        if (v4) {
            return (static_cast<std::uint32_t>(bytes[12]) << 24) |
                   (static_cast<std::uint32_t>(bytes[13]) << 16) |
                   (static_cast<std::uint32_t>(bytes[14]) << 8) |
                   static_cast<std::uint32_t>(bytes[15]);
        }
        return (static_cast<std::uint32_t>(bytes[0]) << 8) | static_cast<std::uint32_t>(bytes[1]);
    }
};

// `text` as an address, in the same way ip_literal reads it; nothing when it is no address.
[[nodiscard]] std::optional<IpAddress> parse_address(std::string_view text);

// An address and a port, which is what a tunnel and a resolver are reached on.
struct SocketAddr {
    IpAddress ip;
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const SocketAddr&) const = default;
    [[nodiscard]] bool is_ipv4() const { return ip.v4; }
    // The form both Rust and the logs use: `[v6]` in brackets before the port, v4 plain.
    [[nodiscard]] std::string to_string() const;
};

// `text` as `ip:port` or `[ipv6]:port`. An IPv6 address only takes brackets before a port, exactly
// as Rust's `SocketAddr` parse insists; a bare address, which has no port to reach, is nothing.
[[nodiscard]] std::optional<SocketAddr> parse_socket_addr(std::string_view text);

// Whether `name` is a domain whose HTTPS record can be asked for: labels of letters, digits,
// '-' and '_', of 1 to 63 bytes each and 253 in all, a trailing dot allowed.
[[nodiscard]] bool valid_domain(std::string_view name);

// `value` as the address a connection goes to: an IP address, an IPv6 one with or without
// brackets, or a domain name; nothing when it is neither.
[[nodiscard]] std::optional<std::string> host_address(std::string_view value);

// `value` as the address and port a connection goes to: host_address, on `default_port`, or
// followed by ':port', an IPv6 address then in brackets; nothing when it is neither.
[[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>> host_and_port(
    std::string_view value, std::uint16_t default_port);

// A DNS-over-HTTPS endpoint. The host of its URL is the HTTP host, of Host or :authority, and
// also where the connection goes and the server name of the ClientHello, unless `address` and
// `sni` name others.
struct DohEndpoint {
    std::string url;
    std::optional<std::string> address;
    std::optional<std::string> sni;
};

// The resolver the ECHConfigList is asked for: a DNS server over UDP or TCP, or a
// DNS-over-HTTPS endpoint (RFC 8484).
struct EchDns {
    enum class Kind { Udp, Tcp, Https };

    Kind kind = Kind::Udp;
    // A literal address for Udp and Tcp; the URL's host for Https.
    std::string host;
    std::uint16_t port = 0;
    // Https only.
    DohEndpoint endpoint;

    // `value`: `udp://ip[:port]` or `tcp://ip[:port]`, on port 53 unless one is given and with an
    // IPv6 address in brackets, or an `https://` URL, on port 443 unless it names one, with
    // `@address=` and `@sni=` after it if need be.
    [[nodiscard]] static std::expected<EchDns, std::string> parse(std::string_view value);
    // How the log shows it.
    [[nodiscard]] std::string text() const;
};

// `message` as it goes over TCP: behind its length, in two bytes in network order.
[[nodiscard]] std::vector<std::uint8_t> tcp_message(std::span<const std::uint8_t> message);

// A question for `qtype` of `name`, with `id` in front of it.
[[nodiscard]] std::vector<std::uint8_t> build_query(std::string_view name, std::uint16_t qtype,
                                                   std::uint16_t id);
// The same with a fresh transaction id, which is what the answer has to carry.
[[nodiscard]] std::pair<std::vector<std::uint8_t>, std::uint16_t> new_query(std::string_view name,
                                                                           std::uint16_t qtype);

// Whether `message` is the answer to exactly that question: a reply, with one question, whose
// name and record type match. Anything else is discarded, so a spoofed answer cannot slip in.
[[nodiscard]] bool response_matches(std::span<const std::uint8_t> message, std::uint16_t id,
                                    std::string_view name, std::uint16_t qtype);

// The ech parameter of the HTTPS record in `message`, a reply about `name`.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> answer_ech(
    std::span<const std::uint8_t> message, std::string_view name);

// Asks `dns` for the HTTPS record of `domain`. An empty error reason means it never answered;
// anything else says how it failed.
using EchTransport =
    std::function<std::expected<std::vector<std::uint8_t>, std::string>(const EchDns& dns,
                                                                        std::string_view domain)>;

// The lookup --ech auto performs: the resolver and the domain the settings name, asked through
// `transport`. The returned bytes are an ECHConfigList, ready for ech_key()'s fetch callback.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> fetch_ech_config(
    const Settings& settings, const EchTransport& transport);

} // namespace hemera::core
