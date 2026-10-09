#pragma once

// Port of netstack.rs: the packet / address / accounting surface of the tunnel's network stack.
// Everything here is pure -- no device, no task, no smoltcp state machine. Those parts stay in
// the engine and are reported separately.

#include "dns.hpp"      // IpAddress, parse_address, ip_literal
#include "sysprofile.hpp" // Tuning, Tier, tuning(), the buffer accessors

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace aether::core::netpacket {

// ---------------------------------------------------------------------------
// Constants a caller reads. Every one of these names a number the Rust uses.

// The tunnel's working MTU: the IPv6 minimum the Rust pins for both the live tunnel (lib.rs
// TUNNEL_MTU) and the ironclad probe (tunnelping.rs PING_MTU). They are the same 1280.
inline constexpr std::size_t PING_MTU = 1280;
inline constexpr std::size_t TUNNEL_MTU = 1280;
// RFC 8200's minimum IPv6 link MTU, which is exactly why the two above are 1280.
inline constexpr std::size_t IPV6_MIN_MTU = 1280;

// Header sizes the codecs key off.
inline constexpr std::size_t IPV4_MIN_HEADER = 20;   // IHL 5
inline constexpr std::size_t IPV4_MAX_HEADER = 60;   // IHL 15
inline constexpr std::size_t IPV4_MIN_IHL = 5;
inline constexpr std::size_t IPV6_HEADER = 40;
inline constexpr std::size_t TCP_MIN_HEADER = 20;    // data offset 5
inline constexpr std::size_t UDP_HEADER = 8;
inline constexpr std::size_t ICMPV6_HEADER = 8;      // type, code, checksum (echo: id, seq)

// Default hop counts the Rust builds with (netstack build_tcp ip[8]=64, masque probe 64,
// socks.rs IPv4Repr hop_limit 64, IPv6 emitted with 64). smoltcp's IPv6 default is 64 too.
inline constexpr std::uint8_t DEFAULT_TTL_V4 = 64;
inline constexpr std::uint8_t DEFAULT_HOP_LIMIT_V6 = 64;

// IP protocol / next-header numbers referenced by the stack.
inline constexpr std::uint8_t IPPROTO_ICMP = 1;
inline constexpr std::uint8_t IPPROTO_TCP = 6;
inline constexpr std::uint8_t IPPROTO_UDP = 17;
inline constexpr std::uint8_t IPPROTO_ICMPV6 = 58;

// ICMPv6 echo message types (RFC 4443).
inline constexpr std::uint8_t ICMPV6_ECHO_REQUEST = 128;
inline constexpr std::uint8_t ICMPV6_ECHO_REPLY = 0;

// IPv4 flags byte bits.
inline constexpr std::uint8_t IPV4_FLAG_DF = 0x40;
inline constexpr std::uint8_t IPV4_FLAG_MF = 0x20;

// TCP control bits, as netstack.rs's tests read them (SYN 0x02, ACK 0x10, SYN-ACK 0x12, FIN 0x01,
// RST 0x04, PSH 0x08).
inline constexpr std::uint8_t TCP_FIN = 0x01;
inline constexpr std::uint8_t TCP_SYN = 0x02;
inline constexpr std::uint8_t TCP_RST = 0x04;
inline constexpr std::uint8_t TCP_PSH = 0x08;
inline constexpr std::uint8_t TCP_ACK = 0x10;

// The window netstack.rs's build_tcp advertises. It is a test value, not a runtime constant: the
// live window comes from smoltcp's receive buffer. Kept so the golden packet reproduces byte-exact.
inline constexpr std::uint16_t DEFAULT_TCP_WINDOW = 64240;

// Port allocation, straight from netstack.rs: alloc_port starts at 49152 and wraps to it once the
// running value reaches 65000.
inline constexpr std::uint16_t PORT_FIRST = 49152;
inline constexpr std::uint16_t PORT_WRAP_AT = 65000;

// The lower bound on max_tcp_pending: rx*2, never below 64 KiB (netstack.rs's max(64 * 1024)).
inline constexpr std::size_t MIN_TCP_PENDING = 64 * 1024;

// Scheduling and accounting limits the run loop reads.
inline constexpr std::size_t MAX_INGEST_PER_TICK = 512;
inline constexpr std::size_t MAX_RECV_CHUNKS = 128;
inline constexpr std::size_t DROP_REPORT_STEP = 512;
inline constexpr std::uint64_t BACKPRESSURE_RETRY_MS = 2;
inline constexpr std::uint64_t MAX_IDLE_TICK_MS = 250;
inline constexpr std::uint64_t ORPHAN_LINGER_MS = 10 * 1000; // ORPHAN_LINGER = 10 s

// The connect/keepalive ceiling both timeouts clamp to (v.min(86_400) seconds).
inline constexpr std::uint64_t MAX_TIMEOUT_SECS = 86'400;
inline constexpr std::uint64_t DEFAULT_KEEPALIVE_SECS = 60;
inline constexpr std::uint64_t DEFAULT_CONNECT_SECS = 30;

// ---------------------------------------------------------------------------
// RFC 1071 Internet checksum.

// The ones-complement sum exactly as netstack.rs's checksum16 and masque.rs's
// ipv4_header_checksum compute it: pairs big-endian, an odd trailing byte shifted left 8, carries
// folded, then complemented. `initial` seeds the accumulator (netstack always passes 0).
// Accumulates in uint32_t, matching Rust; packet-sized inputs cannot overflow it (see .cpp).
[[nodiscard]] std::uint16_t inet_checksum(std::span<const std::uint8_t> data,
                                          std::uint32_t initial = 0);

// The checksum an L4 header carries: like inet_checksum, but a computed 0 becomes 0xFFFF, the rule
// smoltcp's checksum() applies for TCP/UDP/ICMPv6 (a zero L4 checksum means "not computed" and is
// illegal on the paths that require it). netstack.rs's own test helper stores the raw value, but
// its packets never landed on 0, so the two agree; this is the strict version.
[[nodiscard]] std::uint16_t inet_checksum_l4(std::span<const std::uint8_t> data);

// IPv4 pseudo-header contribution: src, dst, zero, protocol, then the L4 length in two bytes. The
// caller checksums pseudo + segment together, exactly as netstack.rs's build_tcp lays it down.
[[nodiscard]] std::vector<std::uint8_t> ipv4_pseudo(const IpAddress& src, const IpAddress& dst,
                                                    std::uint8_t protocol,
                                                    std::size_t l4_len);

// IPv6 pseudo-header contribution: src(16), dst(16), the upper-layer length as four bytes, three
// zero bytes, and the next-header byte (RFC 2460, the only thing that differs from IPv4 here).
[[nodiscard]] std::vector<std::uint8_t> ipv6_pseudo(const IpAddress& src, const IpAddress& dst,
                                                    std::uint8_t next_header,
                                                    std::size_t l4_len);

// ---------------------------------------------------------------------------
// IPv4.

struct Ipv4Header {
    IpAddress src;               // v4 form: octets in bytes[12..16]
    IpAddress dst;
    std::uint8_t ttl = DEFAULT_TTL_V4;
    std::uint8_t protocol = 0;   // next-header / protocol field
    std::uint8_t tos = 0;        // DSCP + ECN, byte 1
    std::uint16_t identification = 0;
    std::uint8_t flags = 0;      // the top 3 bits of bytes 6, DF/MF
    std::uint16_t fragment_offset = 0; // raw 13-bit field, in 8-byte units
    std::vector<std::uint8_t> options; // IHL options; length must keep the header a multiple of 4
};

struct Ipv4Packet {
    Ipv4Header header;
    std::size_t header_len = 0;       // IHL * 4
    std::uint16_t total_length = 0;   // declared, from bytes 2-3
    std::span<const std::uint8_t> payload{}; // bytes behind the header
};

// The IHL implied by an option list, or nothing when the options push the header past 60 bytes or
// off a 4-byte boundary.
[[nodiscard]] std::expected<std::uint8_t, std::string> ipv4_ihl(std::size_t options_len);

// Emits the IPv4 header for a payload of `payload_len` into `out`, filling the header checksum.
// Returns the header length written. `out` must be at least that big; a total length that would
// overflow the 16-bit field is refused.
[[nodiscard]] std::expected<std::size_t, std::string> build_ipv4_header(
    const Ipv4Header& header, std::size_t payload_len, std::span<std::uint8_t> out);

// Parses and validates an IPv4 header. Mirrors smoltcp's Ipv4Packet::new_checked and
// Ipv4Repr::parse: version 4, IHL of at least 5 that fits the buffer, a total length that neither
// exceeds the buffer nor underflows the header, and a fragment offset that -- with the payload --
// cannot overflow the 16-bit reassembly window. The malformed shapes the Rust drops are dropped.
[[nodiscard]] std::expected<Ipv4Packet, std::string> parse_ipv4(std::span<const std::uint8_t> buf);

// ---------------------------------------------------------------------------
// IPv6.

struct Ipv6Header {
    IpAddress src;               // full 16 bytes
    IpAddress dst;
    std::uint8_t hop_limit = DEFAULT_HOP_LIMIT_V6;
    std::uint8_t next_header = 0;
    std::uint8_t traffic_class = 0;
    std::uint32_t flow_label = 0; // 20 bits
};

struct Ipv6Packet {
    Ipv6Header header;
    std::uint16_t payload_length = 0;
    std::span<const std::uint8_t> payload{};
};

[[nodiscard]] std::expected<std::size_t, std::string> build_ipv6_header(
    const Ipv6Header& header, std::size_t payload_len, std::span<std::uint8_t> out);

// Version 6, a full 40 bytes, and a payload length that does not exceed the buffer. Anything
// shorter than 40 bytes, or claiming a payload the buffer cannot hold, is refused.
[[nodiscard]] std::expected<Ipv6Packet, std::string> parse_ipv6(std::span<const std::uint8_t> buf);

// ---------------------------------------------------------------------------
// TCP.

struct TcpSegment {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = DEFAULT_TCP_WINDOW;
    std::uint16_t urgent_pointer = 0;
    std::vector<std::uint8_t> options; // option bytes; header stays a multiple of 4, 20..60
};

struct TcpParsed {
    TcpSegment segment;
    std::size_t header_len = 0; // data offset * 4
    std::span<const std::uint8_t> payload{};
};

// Writes a TCP header plus its options into `out` (at least 20 + options bytes). The checksum
// field is left zero; tcp_checksum fills it once the segment sits in the packet. Returns the header
// length. A bad option length (not a multiple of 4, or past 60 bytes) is refused.
[[nodiscard]] std::expected<std::size_t, std::string> build_tcp_header(
    const TcpSegment& seg, std::span<std::uint8_t> out);

// The TCP checksum over `pseudo` + `header` (checksum field already zero) + `payload`, written
// into the header at bytes 16-18. Returns the value written.
[[nodiscard]] std::uint16_t tcp_checksum(std::span<const std::uint8_t> pseudo,
                                        std::span<std::uint8_t> header,
                                        std::span<const std::uint8_t> payload);

[[nodiscard]] std::expected<TcpParsed, std::string> parse_tcp(std::span<const std::uint8_t> buf);

// ---------------------------------------------------------------------------
// UDP.

struct UdpDatagram {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    // The length field is 8 + payload; a datagram with no payload is refused (a zero/undersized
    // UDP length is malformed and the Rust stack drops it).
};

struct UdpParsed {
    UdpDatagram datagram;
    std::uint16_t length = 0; // the field as it arrived
    std::span<const std::uint8_t> payload{};
};

[[nodiscard]] std::expected<std::size_t, std::string> build_udp_header(
    const UdpDatagram& dg, std::size_t payload_len, std::span<std::uint8_t> out);

[[nodiscard]] std::uint16_t udp_checksum(std::span<const std::uint8_t> pseudo,
                                         std::span<std::uint8_t> header,
                                         std::span<const std::uint8_t> payload);

[[nodiscard]] std::expected<UdpParsed, std::string> parse_udp(std::span<const std::uint8_t> buf);

// ---------------------------------------------------------------------------
// ICMPv6 echo.

struct Icmpv6Echo {
    std::uint8_t type = ICMPV6_ECHO_REQUEST;
    std::uint8_t code = 0;      // always 0 for echo request/reply
    std::uint16_t identifier = 0;
    std::uint16_t sequence = 0;
    std::vector<std::uint8_t> payload;
};

// Builds an echo request/reply message (type/code/checksum/id/seq/payload), computing the checksum
// over the IPv6 pseudo-header (next-header 58) plus the message.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> build_icmpv6_echo(
    const Icmpv6Echo& echo, const IpAddress& src, const IpAddress& dst);

[[nodiscard]] std::expected<Icmpv6Echo, std::string> parse_icmpv6(std::span<const std::uint8_t> buf,
                                                                  const IpAddress& src,
                                                                  const IpAddress& dst);

// ---------------------------------------------------------------------------
// Whole-packet builders, used by the golden vectors. Each returns the full octets.

[[nodiscard]] std::vector<std::uint8_t> build_ipv4_tcp(const Ipv4Header& ip, const TcpSegment& tcp,
                                                       std::span<const std::uint8_t> payload);
[[nodiscard]] std::vector<std::uint8_t> build_ipv6_udp(const Ipv6Header& ip, const UdpDatagram& udp,
                                                        std::span<const std::uint8_t> payload);

// ---------------------------------------------------------------------------
// Tunnel address assignment / parsing. The literal parsing itself is delegated to dns.hpp's
// parse_address (which normalises the leading zeros inet_pton would refuse, as Rust's IpAddr does),
// so no address parser is duplicated here.

struct TunnelAddr {
    IpAddress ip;
    std::uint8_t prefix = 0;
    [[nodiscard]] bool operator==(const TunnelAddr&) const = default;
};

// netstack.rs's parse_v4 / parse_v6: empty text is no address (Ok(None)); otherwise the CIDR is
// stripped and parsed strictly as that family, with a prefix from the /bits or the family default
// (32 for v4, 128 for v6). A bad literal is an error carrying the original text.
[[nodiscard]] std::expected<std::optional<TunnelAddr>, std::string> parse_v4(std::string_view text);
[[nodiscard]] std::expected<std::optional<TunnelAddr>, std::string> parse_v6(std::string_view text);

// routable_prefix_v4/v6: a /31 or /32 host route is widened to /24 for v4, a /127 or /128 to /64
// for v6, so the assignment is routable on the link.
[[nodiscard]] std::uint8_t routable_prefix_v4(std::uint8_t prefix);
[[nodiscard]] std::uint8_t routable_prefix_v6(std::uint8_t prefix);

// The default gateway the Rust derives from a local address: for v4 the host octet is bumped (last
// octet == 1 -> 2, else 1) and the first three octets kept; for v6 only the final octet is bumped
// the same way. These are the routes apply_addrs installs.
[[nodiscard]] IpAddress gateway_v4(const TunnelAddr& local);
[[nodiscard]] IpAddress gateway_v6(const TunnelAddr& local);

// Cmd::SetAddrs semantics as a pure merge: `v4.or(current_v4)`, `v6.or(current_v6)` -- assigning
// one family keeps the other.
struct AddrPair {
    std::optional<TunnelAddr> v4;
    std::optional<TunnelAddr> v6;
};
[[nodiscard]] AddrPair merge_addrs(const AddrPair& current, const AddrPair& update);

// ---------------------------------------------------------------------------
// MTU and fragmentation decisions.

// Whether a whole IP packet of `packet_len` fits the interface MTU.
[[nodiscard]] bool fits_mtu(std::size_t packet_len, std::size_t mtu);

// The IPv4 fragmenter's plan (netstack.rs hands fragmentation to smoltcp; this models smoltcp's
// and RFC 791's rules): every non-final fragment carries a payload that is a multiple of 8, each
// fragment's total length stays within the 16-bit field, and the whole datagram stays within the
// reassembly window. When DF is set and the packet does not fit, fragmentation is refused.
struct FragmentPlan {
    bool needs = false;
    std::size_t mtu = 0;
    std::size_t fragment_data = 0;  // payload bytes each leading fragment carries (multiple of 8)
    std::size_t fragment_count = 0; // 1 when nothing to split
};
[[nodiscard]] std::expected<FragmentPlan, std::string> plan_ipv4_fragments(
    const Ipv4Header& header, std::size_t l4_len, std::size_t mtu, bool dont_fragment);

// ---------------------------------------------------------------------------
// Socket-table accounting. These are the backlog, buffer and read/close rules netstack.rs enforces,
// expressed as pure functions over the state smoltcp exposes to the loop. The state machine itself
// (what a SYN-ACK does to a socket) is the engine's; only the loop's decisions are ported here.

// alloc_port: hands out the current port and advances the counter, wrapping to PORT_FIRST once it
// reaches PORT_WRAP_AT.
[[nodiscard]] std::uint16_t alloc_port(std::uint16_t& next_port);

// max_tcp_pending: rx*2 saturating, never below MIN_TCP_PENDING.
[[nodiscard]] std::size_t max_tcp_pending(std::size_t tcp_rx_buf);

// udp_meta: the metadata-slot count the tier picks (Low 32, Medium 64, High 128).
[[nodiscard]] std::size_t udp_meta(sysprofile::Tier tier);

// DataIn::Tcp's backlog rule. Given how much is already pending, the cap, and a fresh write, it
// says how many bytes are taken now and whether the write must be deferred (and how much of it).
struct PendingAdmit {
    std::size_t accepted = 0;    // bytes appended to pending this call
    std::size_t deferred = 0;    // bytes left over, to be pushed back (0 when fully taken)
    bool defers() const { return deferred > 0; }
};
[[nodiscard]] PendingAdmit tcp_pending_admit(std::size_t pending_len, std::size_t max,
                                             std::size_t data_len);

// smoltcp's TCP states, as inputs to the loop's decisions (transitions are the engine's).
enum class TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

// connected = Established | CloseWait. terminal = Closed | TimeWait (netstack.rs's matches!).
[[nodiscard]] bool tcp_connected(TcpState state);
[[nodiscard]] bool tcp_terminal(TcpState state);

// One pass of service_tcp, reduced to the decisions it makes. The engine calls smoltcp for the
// booleans (can_send, can_recv) and the current state, then acts on the result.
struct TcpInput {
    TcpState state = TcpState::SynSent;
    bool established = false;     // the conn has already reported success
    bool half_closed = false;     // a close was requested downstream
    bool pending_empty = true;
    bool can_send = false;
    bool can_recv = false;
    bool app_gone = false;        // the to_app channel is closed
    bool connect_cancelled = false; // the caller dropped the connect future
    bool connect_deadline = false;  // now >= connect_deadline
    bool linger_elapsed = false;    // now - orphaned_at >= orphan_linger
    std::size_t pending_len = 0;
    std::size_t max_pending = 0;
};

struct TcpActions {
    bool report_established = false;
    bool report_refused = false;   // "connection refused"
    bool report_timeout = false;   // "connection timed out"
    bool send_pending = false;     // socket.can_send() and pending is not empty
    bool close_for_half = false;   // half_closed && pending_empty -> socket.close()
    bool abort = false;            // orphan lingers past the deadline, or still has data
    bool close_orphan = false;     // orphan, but keep lingering
    bool clear_pending = false;    // TimeWait -> drop the pending buffer
    bool close_closewait = false;  // CloseWait -> socket.close()
    bool remove = false;           // drop the socket from the table
    bool backpressured = false;    // a to_app reserve would block
};

[[nodiscard]] TcpActions decide_tcp(const TcpInput& in);

// service_udp's decision: the app channel is gone -> drop the conn; otherwise drain up to
// MAX_RECV_CHUNKS, and flag backpressure when a reserve would block.
struct UdpInput {
    bool app_gone = false;
    bool backpressured = false;
};
struct UdpActions {
    bool remove = false;
};
[[nodiscard]] UdpActions decide_udp(const UdpInput& in);

// ---------------------------------------------------------------------------
// Timeout rules (tcp_keepalive / tcp_connect_timeout), as pure parsers of the env value. The Rust
// reads std::env::var directly; here the caller passes the Settings lookup, matching the codebase.

// A u64 seconds value with an optional leading '+', no spaces, > 0, clamped to 86400; anything
// else (empty, junk, 0, overflow) falls back to `fallback_secs`.
[[nodiscard]] std::uint64_t parse_timeout_secs(std::optional<std::string_view> env,
                                               std::uint64_t fallback_secs);
[[nodiscard]] std::uint64_t keepalive_secs(std::optional<std::string_view> env);
[[nodiscard]] std::uint64_t connect_secs(std::optional<std::string_view> env);

} // namespace aether::core::netpacket
