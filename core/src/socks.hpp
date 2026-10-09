#pragma once

#include "dns.hpp"
#include "routing.hpp"
#include "settings.hpp"
#include "sysprofile.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hemera::core::socks {

// Port of socks.rs: the proxy protocol codec. Everything here is bytes in, decision out; the
// listeners, the relay loops, the timeouts that fire and the netstack round trips that
// handle_client, handle_connect, handle_udp_associate, accept_clients and serve_* perform stay
// with the engine.

// The greeting accepts the methods the client offers and answers 0x00, the way the Rust
// handshake does: this server has no username/password stage, no method the client offers
// selects one, and a greeting that names none still gets 0x00. There is no SOCKS4, SOCKS4a or
// BIND path in socks.rs either; every command that is not CONNECT or UDP ASSOCIATE is refused
// with REP_NOT_SUPPORTED.

inline constexpr std::uint8_t VER = 0x05;
inline constexpr std::uint8_t CMD_CONNECT = 0x01;
inline constexpr std::uint8_t CMD_UDP_ASSOCIATE = 0x03;
inline constexpr std::uint8_t ATYP_V4 = 0x01;
inline constexpr std::uint8_t ATYP_DOMAIN = 0x03;
inline constexpr std::uint8_t ATYP_V6 = 0x04;
inline constexpr std::uint8_t REP_OK = 0x00;
inline constexpr std::uint8_t REP_GENERAL = 0x01;
inline constexpr std::uint8_t REP_NOT_ALLOWED = 0x02;
inline constexpr std::uint8_t REP_NOT_SUPPORTED = 0x07;

inline constexpr std::uint16_t QTYPE_A = 1;
inline constexpr std::uint16_t QTYPE_AAAA = 28;
inline constexpr std::uint8_t RCODE_NXDOMAIN = 3;
inline constexpr std::uint16_t DNS_PORT = 53;

// The waits the engine arms when it drives these codecs over a socket.
inline constexpr std::uint64_t HANDSHAKE_TIMEOUT_MS = 10000;
inline constexpr std::uint64_t DIRECT_CONNECT_TIMEOUT_MS = 10000;
inline constexpr std::uint64_t GATEWAY_PROBE_TIMEOUT_MS = 5000;
inline constexpr std::uint64_t DNS_OVER_TCP_TIMEOUT_MS = 20000;
inline constexpr std::uint64_t ACCEPT_WARN_EVERY_MS = 10000;
// A sniff window of 0 would block forever, so it reads as the default, as the Rust filter does.
inline constexpr std::uint64_t DEFAULT_SNIFF_WINDOW_MS = 400;
inline constexpr std::uint64_t DEFAULT_HALF_CLOSE_LINGER_SECS = 30;
inline constexpr std::uint64_t MAX_HALF_CLOSE_LINGER_SECS = 86400;

inline constexpr std::size_t DNS_MAX_IN_FLIGHT = 32;
inline constexpr std::size_t RELAY_CHUNK = 16384;
inline constexpr std::size_t GATEWAY_HEAD_LIMIT = 8192;
inline constexpr std::size_t HTTP_HEAD_LIMIT = 16 * 1024;

// The two shapes a socks target takes: an address, or the name the client asked for.
class Target {
public:
    [[nodiscard]] static Target from_ip(const IpAddress& address);
    [[nodiscard]] static Target from_domain(std::string name);

    [[nodiscard]] bool is_ip() const;
    // Undefined unless is_ip().
    [[nodiscard]] const IpAddress& ip() const;
    // Empty unless the target is a name.
    [[nodiscard]] const std::string& domain() const;

    // The Display impl: the address as the log shows it, or the name as it arrived.
    [[nodiscard]] std::string text() const;

    [[nodiscard]] bool operator==(const Target&) const = default;

private:
    std::variant<IpAddress, std::string> value_;
};

// An address and a port, the way the relay latches a client or reports the bound relay address.
struct Endpoint {
    IpAddress address;
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const Endpoint&) const = default;
    // SocketAddr's Display: an IPv6 in brackets.
    [[nodiscard]] std::string text() const;
};

// The address of an Endpoint as text, IPv6 compressed and lower case the way Rust prints it.
[[nodiscard]] std::string address_text(const IpAddress& address);

// `text` as `ip:port` or `[ipv6]:port` with the port mandatory, as Rust's SocketAddr parse does;
// nothing when it is anything else. Unlike dns.hpp's host_and_port a name or a portless address
// is refused here, because set_gateway_proxy and the resolver list read them as failures too.
[[nodiscard]] std::optional<Endpoint> parse_socket_address(std::string_view text);

// socks.rs's from_utf8_lossy use on wire bytes: every maximal ill-formed subsequence of the
// input becomes one U+FFFD, valid sequences keep their bytes.
[[nodiscard]] std::string utf8_lossy(std::span<const std::uint8_t> bytes);

// --- SOCKS5 greeting -------------------------------------------------------------

struct Greeting {
    std::span<const std::uint8_t> methods;
    std::size_t length = 0;  // bytes the greeting occupies in the buffer
};

// [VER][NMETHODS][methods...] as the async handshake reads it. "bad greeting version" when the
// first byte is not 0x05; a buffer that does not hold the whole greeting is what read_exact
// would still be waiting for, and the error says so.
[[nodiscard]] std::expected<Greeting, std::string> parse_greeting(
    std::span<const std::uint8_t> buffer);

// The reply the handshake writes whatever the client offered: [VER, 0x00], no authentication.
[[nodiscard]] std::vector<std::uint8_t> build_method_selection();

// --- SOCKS5 request and replies ----------------------------------------------------

struct Request {
    std::uint8_t command = 0;
    Target target;
    std::uint16_t port = 0;
    std::size_t length = 0;
};

// [VER][CMD][RSV][ATYP][address][port:2] as read_request does once the greeting is done. The
// reserved byte is read and ignored; "bad socks version" and "bad atyp" carry over verbatim.
[[nodiscard]] std::expected<Request, std::string> parse_request(std::span<const std::uint8_t> buffer);

// What is still on the wire after the five head bytes [VER][CMD][RSV][ATYP][first]: the head
// already holds the first address byte (or the length byte, for a name), so the tail is what
// is left of the address plus the two port bytes. Getting this wrong by one hangs every
// client at the handshake timeout, which is why the arithmetic lives here under test rather
// than inline at the call site.
[[nodiscard]] std::expected<std::size_t, std::string> request_tail_bytes(std::uint8_t atyp,
                                                                         std::uint8_t fifth);

// The fixed 10-byte reply of reply(): version, code, zero, IPv4-atyp, all-zero address and port.
[[nodiscard]] std::vector<std::uint8_t> build_reply(std::uint8_t code);

// reply_bound(): the address the relay bound, so the client knows where to send datagrams.
[[nodiscard]] std::vector<std::uint8_t> build_bound_reply(const Endpoint& bound);

// --- UDP associate framing -----------------------------------------------------------

struct UdpRequest {
    Target target;
    std::uint16_t port = 0;
    std::span<const std::uint8_t> payload;  // everything after the address and port
};

// The SOCKS5 UDP header: two reserved bytes, the fragment byte, ATYP, address, port. The
// reserved bytes are never looked at; a nonzero fragment byte means a split datagram, which
// this relay does not reassemble, so it is dropped, and a bad ATYP drops it too. That is the
// whole of FTYPE/RSV/FRAG handling in socks.rs; there is no RUDP path.
[[nodiscard]] std::optional<UdpRequest> parse_udp_request(std::span<const std::uint8_t> buffer);

// build_udp_reply(): the header back out of the far end's address, then the datagram.
[[nodiscard]] std::vector<std::uint8_t> build_udp_reply(const Endpoint& source,
                                                        std::span<const std::uint8_t> data);

// --- address predicates --------------------------------------------------------------

// An IPv4-mapped IPv6 as the IPv4 it maps; anything else unchanged.
[[nodiscard]] IpAddress normalize_ip(const IpAddress& address);
[[nodiscard]] bool is_loopback(const IpAddress& address);
[[nodiscard]] bool is_unspecified(const IpAddress& address);

// expected_udp_source(): the address a UDP associate's first datagram must come from; the
// control peer when the request declared the wildcard or named no address at all.
[[nodiscard]] IpAddress expected_udp_source(const Endpoint& control_peer, const Target& requested);

// udp_source_allowed(): before the latch the source address must be the expected one; after it,
// the exact source address and port that latched, so a second client cannot take the channel.
[[nodiscard]] bool udp_source_allowed(const IpAddress& expected, std::optional<Endpoint> latched,
                                      const Endpoint& from);

// direct_target_allowed(): this machine's loopback and the wildcard only answer a direct
// connection made from this machine's loopback.
[[nodiscard]] bool direct_target_allowed(const IpAddress& client, const IpAddress& address);

// --- gateway proxy (http/https through an upstream CONNECT) ---------------------------

[[nodiscard]] bool should_use_gateway(std::uint16_t port);

// The parsing half of set_gateway_proxy: trimmed, a blank or malformed address names nothing;
// the caller keeps the log lines Rust prints for each outcome.
[[nodiscard]] std::optional<Endpoint> parse_gateway_proxy(std::string_view address);

// The gateway the Rust core keeps in its process-wide OnceLock and health flag, kept the same
// way here: the first accepted address wins, and the whole process later sees the fallback. The
// return value is the line the Rust core logs, when it logs one; the engine prints it.
[[nodiscard]] std::optional<std::string> set_gateway_proxy(std::string_view address);
[[nodiscard]] std::optional<Endpoint> gateway_proxy();
// retire_gateway(): the switch to no gateway, told once.
[[nodiscard]] std::optional<std::string> retire_gateway(std::string_view reason);

// build_proxy_connect(): the CONNECT request that goes to the gateway, authority bracketed
// when a bare IPv6 needs it.
[[nodiscard]] std::vector<std::uint8_t> build_proxy_connect(std::string_view target,
                                                            std::uint16_t port);

// proxy_connect_succeeded(): the verdict off the status line; nothing when there is no status
// line or the code is no number.
[[nodiscard]] std::optional<bool> proxy_connect_succeeded(std::span<const std::uint8_t> head);

// find_head_end(): the length of the head up to and including the blank line, or nothing until
// it is all in.
[[nodiscard]] std::optional<std::size_t> find_head_end(std::span<const std::uint8_t> buffer);

// warn_if_world_reachable(): the line the Rust core logs when a listener sits on an address
// outside this machine and lets anyone through with no authentication.
[[nodiscard]] std::optional<std::string> world_reachable_warning(std::string_view kind,
                                                                 const Endpoint& listen);

// --- http proxy request line -----------------------------------------------------------

struct HttpRequestLine {
    std::string method;
    std::string authority;
    std::uint16_t port = 0;
    // For a plain GET/POST the origin-form first line that replaces the absolute-form one
    // before the request is relayed; CONNECT has none.
    std::optional<std::string> rewritten;

    [[nodiscard]] bool operator==(const HttpRequestLine&) const = default;
};

// parse_authority(): host[:port], an IPv6 under brackets; bare colons in an unbracketed value
// keep the whole text as the host on the default port, as Rust's rsplit_once guard does.
[[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>> parse_authority(
    std::string_view raw, std::uint16_t default_port);

// parse_request_line(): CONNECT in any case, or an absolute http:// URL rewritten to origin
// form. Anything else -- origin form, https://, a line with too few parts -- is refused, and
// the caller answers 400.
[[nodiscard]] std::optional<HttpRequestLine> parse_request_line(std::string_view line);

// --- the DNS the tunnel does itself ------------------------------------------------------

// A resolver list the way resolver_addresses/parse_resolvers read HEMERA_DNS: tokens on ',', ' '
// and ';', each `ip:port` or a bare address on port 53, duplicates and junk dropped.
[[nodiscard]] std::vector<Endpoint> parse_resolvers(std::string_view raw);
// The same over the settings, falling back to Cloudflare when nothing usable is configured.
[[nodiscard]] std::vector<Endpoint> resolver_addresses(const Settings& settings);

// build_dns_query(): the question socks.rs writes. Unlike dns.cpp's build_query every label from
// Rust's split('.') is pushed, an empty one included, so a trailing dot adds its own zero; the
// answer check skips empty labels either way.
[[nodiscard]] std::vector<std::uint8_t> build_dns_query(std::string_view name, std::uint16_t qtype,
                                                        std::uint16_t id);
// The same with a fresh transaction id, as dns.hpp's new_query does for ECH lookups.
[[nodiscard]] std::pair<std::vector<std::uint8_t>, std::uint16_t> new_dns_query(
    std::string_view name, std::uint16_t qtype);

// dns_over_stream's framing: the query behind its two-byte length. A query too long to frame is
// the Rust "dns query is too long to frame"; dns.hpp's tcp_message truncates instead, so this
// codec cannot reuse it.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> frame_dns_query(
    std::span<const std::uint8_t> query);
// The length prefix of a framed answer, when the header arrived.
[[nodiscard]] std::optional<std::size_t> dns_frame_length(std::span<const std::uint8_t> header);

// Whether a message is the answer to exactly that question is dns.hpp's response_matches;
// socks.rs's dns_response_matches is the same check, byte for byte, and reuses it.

// The response code, the low nibble of the fourth byte.
[[nodiscard]] std::optional<std::uint8_t> dns_rcode(std::span<const std::uint8_t> response);

// parse_dns_answer(): the first record of `qtype` that is an A or AAAA address, reading through
// compressed names; nothing when the message holds no such record.
[[nodiscard]] std::optional<IpAddress> parse_dns_answer(std::span<const std::uint8_t> response,
                                                        std::uint16_t qtype);

// --- routing decisions over a socks target ------------------------------------------------

// host_of(): what a rule looks at for this target. The string_view for a domain lives inside
// the target, which has to outlive the Host.
[[nodiscard]] routing::Host host_of(const Target& target);

// decide_route(): the name a sniffed ClientHello or Host header revealed leads, and the target
// itself decides only when the name did not say proxy.
[[nodiscard]] routing::Action decide_route(const routing::RuleSet& set, const Target& target,
                                           std::optional<std::string_view> sniffed,
                                           std::uint16_t port);

// The HEMERA_ROUTE_SNIFF switch: on unless the value is exactly "0", "off" or "false".
[[nodiscard]] bool sniff_enabled(const Settings& settings);
// HEMERA_ROUTE_SNIFF_MS in milliseconds; a non-number or 0 is the default.
[[nodiscard]] std::uint64_t sniff_window_ms(const Settings& settings);
// HEMERA_HALF_CLOSE_SECS: a plain u64, trimmed by nobody, at most 86400 seconds.
[[nodiscard]] std::uint64_t half_close_linger_secs(const Settings& settings);

// client_limit()'s arithmetic: an HEMERA_MAX_CLIENTS value wins when it parses above 0; the
// tier's number stands unless a file-descriptor limit caps it, and that limit is one only
// Unix answers (see sysprofile.hpp), so on Windows open_files is empty.
[[nodiscard]] std::size_t client_limit(std::size_t by_tier, std::optional<std::size_t> open_files);
[[nodiscard]] std::size_t client_limit_for(const Settings& settings, sysprofile::Tier tier);

} // namespace hemera::core::socks
