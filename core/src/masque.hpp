#pragma once

// Port of hemera/src/masque.rs, plus the protocol-codec surface of hemera/src/masque_h2.rs: the
// CONNECT-IP request either carrier puts on the wire, the capsule and datagram framings, and every
// limit, flag and timeout a caller of the HTTP/2 carrier reads.
//
// What stays with the libraries and the engine, because the Rust core never wrote those bytes
// itself: HPACK (h2 crate -> nghttp2), QPACK and the h3 request/response framing (quiche::h3 ->
// nghttp3), the QUIC DATAGRAM frame around an h3 ip-datagram (quiche -> ngtcp2), TLS/ECH (BoringSSL,
// see tls.hpp) and the tokio tasks, channels and socket dialing around run() and verify_h2().
// Everything below is the hemera-specific half: which fields go, in what order, with what values,
// and how the payloads in front of them are framed.

#include "consts.hpp"
#include "dns.hpp"
#include "settings.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hemera::core::masque {

// ---- errors ------------------------------------------------------------------

// HemeraError::Capsule / HemeraError::Masque keep their prefixes, so a log line out of this port
// reads exactly like one out of the Rust core: "capsule: bad ip version 5".
[[nodiscard]] std::string capsule_error(std::string_view reason);
[[nodiscard]] std::string masque_error(std::string_view reason);

// octets::BufferTooShortError's own Display text, which is what every short-buffer failure the
// Rust codecs hit turns into.
inline constexpr std::string_view k_buffer_too_short = "BufferTooShortError";
// octets' panic text for a value that will not fit a variable-length integer. This port refuses
// such a value instead of aborting the process, which is the one deliberate divergence from
// masque.rs, noted again where each of those functions lives.
inline constexpr std::string_view k_varint_too_wide = "value is too large for varint";

// ---- the variable-length integer both framings are built from ----------------

// octets' MAX_VAR_INT: the largest value a 62-bit QUIC varint carries.
inline constexpr std::uint64_t MAX_VAR_INT = 0x3fffffffffffffffULL;

// How wide `value` goes out: masque.rs::varint_len, which is octets' varint_len with its
// unreachable arm left reachable -- it answers 8 for anything at or above 2^30.
[[nodiscard]] std::size_t varint_len(std::uint64_t value);

// How long the varint whose first byte is `first` is (octets' varint_parse_len).
[[nodiscard]] std::size_t varint_parse_len(std::uint8_t first);

// The value at the front of `at`, advanced past it; the capsule_error of a buffer that does not
// hold all of it. Like octets' get_varint, an encoding wider than the value needs is read rather
// than refused -- the drafts both framings follow say so, and a stricter reader here would
// disagree with the Rust core about a live edge.
[[nodiscard]] std::expected<std::uint64_t, std::string> read_varint(
    std::span<const std::uint8_t>& at);

// The value at the end of `out`, prefixed with its own length. False, writing nothing, when
// `value` is over MAX_VAR_INT.
[[nodiscard]] bool append_varint(std::vector<std::uint8_t>& out, std::uint64_t value);

// ---- the CONNECT request, on either carrier ----------------------------------

// One header field, as the Rust hands it to the codec: raw bytes, the names already lower case
// the way HTTP requires and the values exactly as the core writes them.
struct HeaderField {
    std::string name;
    std::string value;

    [[nodiscard]] bool operator==(const HeaderField&) const = default;
};

// The authority and path every hemera MASQUE tunnel asks for -- quic.rs:784-790, which the tunnel
// and the prober both feed into masque.
inline constexpr std::string_view DEFAULT_AUTHORITY = "cloudflareaccess.com";
inline constexpr std::string_view DEFAULT_PATH = "/";

// masque.rs::connect_ip_request, field for field and in order, for the HTTP/3 carrier. The value
// of :protocol is consts::CF_CONNECT_PROTOCOL ("cf-connect-ip"), and `user-agent` goes out empty.
[[nodiscard]] std::vector<HeaderField> connect_ip_request(std::string_view authority,
                                                         std::string_view path);

// The HTTP/2 carrier's request. Rust builds an http::Request with method CONNECT and the URI
// "https://{authority}:443" plus three fields; h2's own encoder then emits :method, :authority
// from the URI and -- because a plain CONNECT takes neither, which its headers.rs asserts -- no
// :scheme and no :path, before the fields in the order the builder gave them. That ordered field
// set is what the C++ stack has to hand nghttp2, so it is spelled out here.
[[nodiscard]] std::string h2_connect_authority(std::string_view authority);
[[nodiscard]] std::string h2_connect_uri(std::string_view authority);
[[nodiscard]] std::vector<HeaderField> h2_connect_request_fields(std::string_view authority);

// Whether the edge's response says the stream is open: `status.is_success()` of the http crate, a
// 2xx, which is the gate both verify_h2() and run() put on the tunnel before any packet moves.
[[nodiscard]] bool connect_succeeded(std::uint16_t status);

// The error text the Rust builds for a response that is not: "masque: h2 connect-ip status 403".
[[nodiscard]] std::string h2_connect_status_error(std::uint16_t status);

// ---- CONNECT-IP over HTTP/3: the QUIC datagram body --------------------------

// RFC 9484's quarter-stream id: the stream id divided by four, which is what travels in front of
// the packet so the edge can send its reply back on the same request stream.
[[nodiscard]] std::uint64_t quarter_stream_id(std::uint64_t stream_id);

// masque.rs::encode_ip_datagram: varint(quarter stream id) then varint(CONNECT_IP_CONTEXT_ID)
// then the IP packet, which is the whole payload of the DATAGRAM frame (frame type
// consts::H3_DATAGRAM_00 is ngtcp2's to write).
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> encode_ip_datagram(
    std::uint64_t stream_id, std::span<const std::uint8_t> ip_packet);

// masque.rs::decode_ip_datagram: nothing when the leading integers name a different stream or a
// non-zero context id, an error when the frame is too short to hold either, and the packet behind
// them otherwise -- which may be empty, as it is on the Rust side.
[[nodiscard]] std::expected<std::optional<std::vector<std::uint8_t>>, std::string>
decode_ip_datagram(std::span<const std::uint8_t> datagram, std::uint64_t expect_stream_id);

// ---- CONNECT-IP over HTTP/2: the capsules on the request stream -------------

// The four capsule types the core knows, by their wire numbers.
inline constexpr std::uint64_t CAPSULE_DATAGRAM = 0x00;
inline constexpr std::uint64_t CAPSULE_ADDRESS_ASSIGN = 0x01;
inline constexpr std::uint64_t CAPSULE_ADDRESS_REQUEST = 0x02;
inline constexpr std::uint64_t CAPSULE_ROUTE_ADVERTISEMENT = 0x03;

// An address the edge handed out, as the Address Assign capsule carries it: `address` is four
// bytes for version 4 and sixteen for version 6.
struct AssignedAddress {
    std::uint64_t request_id = 0;
    std::uint8_t ip_version = 0;
    std::vector<std::uint8_t> address;
    std::uint8_t prefix_len = 0;

    [[nodiscard]] bool operator==(const AssignedAddress&) const = default;
};

// One range of the Route Advertisement capsule. `protocol` is the IP protocol number it covers.
struct RouteAdvertisement {
    std::uint8_t ip_version = 0;
    std::vector<std::uint8_t> start;
    std::vector<std::uint8_t> end;
    std::uint8_t protocol = 0;

    [[nodiscard]] bool operator==(const RouteAdvertisement&) const = default;
};

// masque.rs's Capsule enum, as a tagged struct so a caller can read every arm without a variant.
// `value` carries a Datagram packet or an Unknown capsule's bytes; `assigned` and `routes` carry
// the two list forms; `type_id` is the wire type of an Unknown capsule.
struct Capsule {
    enum class Kind { AddressAssign, AddressRequest, Datagram, RouteAdvertisement, Unknown };

    Kind kind = Kind::AddressRequest;
    std::uint64_t type_id = 0;
    std::vector<AssignedAddress> assigned;
    std::vector<RouteAdvertisement> routes;
    std::vector<std::uint8_t> value;

    [[nodiscard]] bool operator==(const Capsule&) const = default;
};

// How long one capsule is, header included: the two varints and the value behind them.
[[nodiscard]] std::size_t capsule_len(std::uint64_t kind, std::size_t value_len);

// encode_capsule, on a buffer of its own.
[[nodiscard]] std::vector<std::uint8_t> encode_capsule(std::uint64_t kind,
                                                      std::span<const std::uint8_t> value);

// append_capsule: onto the end of `out`, so several packets can share one DATA frame. False and
// nothing written when `kind` is over MAX_VAR_INT (Rust sizes its buffer blindly there).
[[nodiscard]] bool append_capsule(std::vector<std::uint8_t>& out, std::uint64_t kind,
                                 std::span<const std::uint8_t> value);

// The Address Request capsule, draft-ietf-masque-connect-ip's request_id/version/prefix triple.
// An error only when `request_id` will not fit a varint.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> encode_address_request(
    std::uint64_t request_id, std::uint8_t ip_version, std::uint8_t prefix_len);

// encode_datagram_capsule / append_datagram_capsule: the bare IP packet behind a type-0 capsule,
// which is exactly what the Cloudflare edge expects on the HTTP/2 carrier (the h3 carrier, by
// contrast, keeps the context id in front of it).
[[nodiscard]] std::vector<std::uint8_t> encode_datagram_capsule(
    std::span<const std::uint8_t> ip_packet);
void append_datagram_capsule(std::vector<std::uint8_t>& out,
                             std::span<const std::uint8_t> ip_packet);

// strip_datagram_context: a packet either with or without its leading context id, which is what
// the edge may answer with on either carrier. Nothing when neither reading is an IP packet at all.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> strip_datagram_context(
    std::span<const std::uint8_t> payload);

// The check behind it, and the only shape test either carrier makes: version 4 or 6 in the high
// nibble, and twenty bytes or more to read a header from.
[[nodiscard]] bool looks_like_ip_packet(std::span<const std::uint8_t> data);

// How much a CapsuleParser holds before it throws its buffer away, as masque.rs caps it.
inline constexpr std::size_t MAX_CAPSULE_BUF = 256 * 1024;

// The streaming capsule reader of the request stream body. It keeps whatever it has not framed
// yet, so a capsule split across DATA frames is reassembled.
class CapsuleParser {
  public:
    // Rust warns and drops both what it held and what arrived once the buffer would pass
    // MAX_CAPSULE_BUF; false is that same event, for the caller to log.
    [[nodiscard]] bool push(std::span<const std::uint8_t> data);

    // The next whole capsule, nothing when the bytes so far do not make one, and an error -- after
    // the capsule's own bytes have already been consumed, exactly as Rust drains first -- when the
    // value behind a known type does not parse.
    [[nodiscard]] std::expected<std::optional<Capsule>, std::string> next();

    [[nodiscard]] std::size_t buffered() const { return buf_.size(); }
    void reset() { buf_.clear(); }

  private:
    std::vector<std::uint8_t> buf_;
};

// bytes_to_ip, shared by both carriers' address-assignment paths: version 4 reads four bytes and
// version 6 sixteen, in dns.hpp's IpAddress form; anything else is no address.
[[nodiscard]] std::optional<IpAddress> to_ip_address(std::uint8_t version,
                                                    std::span<const std::uint8_t> bytes);

// An address the edge assigned, and the line the Rust logs for it: "edge assigned 172.16.0.2/24".
struct EdgeAssignment {
    IpAddress ip;
    std::uint8_t prefix = 0;

    [[nodiscard]] bool operator==(const EdgeAssignment&) const = default;
    [[nodiscard]] std::string text() const;
};

// What one chunk of the request stream yields. drain_capsules() of both carriers, with its
// channels turned into return values: the packets for the netstack, the addresses the edge
// assigned, how many route advertisements arrived, how many datagrams were thrown out for being
// no IP packet, and the parse error that stopped the drain, if any.
struct Drained {
    std::vector<std::vector<std::uint8_t>> packets;
    std::vector<EdgeAssignment> assigned;
    std::size_t routes = 0;
    std::size_t discarded = 0;
    std::optional<std::string> parse_error;

    // Rust's `got_data`, which is what gates the data-plane validation: a datagram that is an IP
    // packet was seen, whether or not the queue below had room for it. Rust sets it before the
    // send, so a discarded-for-no-room packet still counts; `discarded` counts only the ones that
    // were no IP packet at all.
    //
    // The inbound queue itself is the engine's: where Rust drops a packet on TrySendError::Full and
    // stops the drain on Closed, this returns every packet that framed, and a caller with a bounded
    // queue applies its own limit and its own stop.
    bool delivered = false;
};

[[nodiscard]] Drained drain_capsules(CapsuleParser& parser);

// ---- the HTTP/2 carrier: limits, flags and the shape a caller fills in -------

// ALPN: HTTP/2, then HTTP/1.1, as Chrome offers them; the edge picks HTTP/2, which the tunnel
// speaks. Wire format already: each protocol preceded by its own length byte, which is what
// tls::Fingerprint::apply and BoringSSL's set_alpn_protos take.
inline constexpr std::array<std::uint8_t, 12> H2_ALPN{
    0x02, 'h',  '2',  0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

// The largest DATA frame the edge may send: the h2 default is the RFC minimum of 16 KiB, and a
// fast stream would pay four times the frame headers and wakeups for it.
inline constexpr std::uint32_t H2_MAX_FRAME_SIZE = 64 * 1024;

// How much a single write to the edge may carry: packets queued behind one another are gathered up
// to this much, because a capsule on its own costs a DATA frame, a TLS record and a TCP segment.
inline constexpr std::size_t H2_SEND_BATCH_BYTES = 32 * 1024;

// The depth of the queue in front of the send task, and how long a clean shutdown waits for it to
// put the closing frame on the wire.
inline constexpr std::size_t H2_SENDER_QUEUE = 16;
inline constexpr std::chrono::milliseconds SENDER_CLOSE_GRACE{250};

// Round trips the probe has to see come back before socks5 is exposed, and how often it goes out
// while the tunnel is still being validated.
inline constexpr std::uint32_t DATA_PROBE_REQUIRED_SUCCESSES = 2;
inline constexpr std::chrono::milliseconds DATA_PROBE_RESEND{700};

// The defaults of the three second-valued switches, and the ceiling of a day on each.
inline constexpr std::chrono::seconds VALIDATE_SECS_DEFAULT{10};
inline constexpr std::chrono::seconds KEEPALIVE_INTERVAL_DEFAULT{15};
inline constexpr std::chrono::seconds KEEPALIVE_TIMEOUT_DEFAULT{20};
inline constexpr std::uint64_t MAX_ENV_SECS = 86'400;

// The h2::client::Builder parameters, which nghttp2's option setters take one for one: the two
// windows the machine's profile picks (64 KiB on both is the h2 default, and 64 KiB over a 130 ms
// round trip is about 500 KB/s however fast the line underneath is) and the frame ceiling.
struct H2Flow {
    std::uint32_t initial_stream_window = 0;
    std::uint32_t initial_connection_window = 0;
    std::uint32_t max_frame_size = H2_MAX_FRAME_SIZE;

    [[nodiscard]] bool operator==(const H2Flow&) const = default;
};

[[nodiscard]] H2Flow h2_flow(const Settings& settings);

// HEMERA_MASQUE_HTTP2 (--h2 / --http2): HTTP/2 instead of HTTP/3, on the words Rust accepts --
// 1, true, h2, yes, on, trimmed and lower cased. Note "h2" is accepted here and by nothing else:
// settings.hpp's is_truthy does not know that word, so enabled() has its own reading.
[[nodiscard]] bool enabled(const Settings& settings);

// HEMERA_MASQUE_H2_PEER (--h2-peer): the address the HTTP/2 carrier connects to instead of the
// QUIC one. A value that is no `ip:port` is ignored, as Rust ignores a failed parse, and the
// quic_peer stands.
[[nodiscard]] SocketAddr h2_peer(const Settings& settings, const SocketAddr& quic_peer);

// HEMERA_MASQUE_NO_DATA_CHECK (--no-data-check): the check runs unless the variable is there at
// all, whatever it says.
[[nodiscard]] bool data_check_enabled(const Settings& settings);

// HEMERA_MASQUE_VALIDATE_SECS, HEMERA_MASQUE_H2_KEEPALIVE_SECS and
// HEMERA_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS: a positive whole number of seconds, at most a day, or
// the default. A leading '+' parses in Rust, so it parses here.
[[nodiscard]] std::chrono::seconds validation_timeout(const Settings& settings);
[[nodiscard]] std::chrono::seconds h2_keepalive_interval(const Settings& settings);
[[nodiscard]] std::chrono::seconds h2_keepalive_timeout(const Settings& settings);

// Everything the HTTP/2 tunnel needs that is not a socket. Same fields, same meaning, as
// masque_h2::H2TunnelConfig; the pin expectations are the ones every Rust call site passes --
// pin_endpoint on, and the consts::MASQUE_PINS set -- because the edges serve a different
// certificate per SNI and some are self-signed, so chain verification is off and the pin is the
// only check (see tls::install_verification).
struct H2TunnelConfig {
    SocketAddr peer;
    std::string sni{CONNECT_SNI};
    std::string authority{DEFAULT_AUTHORITY};
    std::string path{DEFAULT_PATH};
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    // The tunnel's own IPv4: the source address of the data-plane probe. Rust's field is an
    // Ipv4Addr, which dns.hpp's IpAddress carries in its last four octets; a value with v4 unset
    // reads as 0.0.0.0, which is the Ipv4Addr::UNSPECIFIED a caller has to pass for that anyway.
    IpAddress local_ipv4;
    bool quiet = false;
    bool pin_endpoint = true;
    std::vector<std::vector<std::uint8_t>> expected_pins;
    // The ECHConfigList the handshake offers: the session's (tls::session_ech), or none, as on the
    // inner hop of masque-in-masque.
    std::optional<std::vector<std::uint8_t>> ech_config_list;

    H2TunnelConfig();

    // Whether a handshake that failed with `message` was turned down for its ECHConfigList, which
    // is the only failure BoringSSL reports as ECH_REJECTED and the only one a retry config is
    // handed out for.
    [[nodiscard]] bool offers_ech() const { return ech_config_list.has_value(); }

    // A line for the log that names the peer and the sizes of the key material, never the
    // material itself.
    [[nodiscard]] std::string describe() const;
};

// consts::MASQUE_PINS as the Vec<Vec<u8>> Rust's call sites build, so a caller that only needs the
// default can fill the config in one line.
[[nodiscard]] std::vector<std::vector<std::uint8_t>> default_expected_pins();

// pump_outbound's gathering, as a pure function over what the outbound queue holds: the first
// packet always goes, then whatever is already behind it while the frame is under
// H2_SEND_BATCH_BYTES -- so a frame may end up over the limit by the one capsule that crossed it,
// which is what the Rust loop does. `taken` says how many of `queued` the frame carries.
struct SendBatch {
    std::vector<std::uint8_t> frame;
    std::size_t taken = 0;
};

[[nodiscard]] SendBatch batch_datagram_capsules(std::span<const std::vector<std::uint8_t>> queued);

// ---- the data-plane probe ----------------------------------------------------

// The packet the probe sends: a DNS query for cloudflare.com A/IN, inside UDP/53, inside IPv4 to
// 8.8.8.8, exactly as masque.rs::build_dns_probe_packet writes it (an empty UDP checksum, TTL 64,
// a random IP id and a random source port from 20000..60000). Pass `dns_id` and `sport` to get the
// same bytes twice; left out, they are drawn fresh, as Rust's rand calls do. `dns_id` doubles as
// the IP id, where Rust draws a second, unrelated random -- the two differ only when no id is
// passed, which is the only difference between this and the Rust.
[[nodiscard]] std::vector<std::uint8_t> build_dns_probe_packet(
    const IpAddress& src, std::optional<std::uint16_t> dns_id = {},
    std::optional<std::uint16_t> sport = {});

// The DNS message on its own, for a caller that wants the query without the IP/UDP wrapping. Rust
// keeps this private and draws a random id inside it; `id` is a parameter here so the same bytes
// can be produced twice, which is how the golden test below checks the whole probe packet.
[[nodiscard]] std::vector<std::uint8_t> probe_dns_query(std::uint16_t id);

// The IPv4 header checksum, one's complement of the sum of the big-endian 16-bit words, carries
// folded. The same computation netpacket::inet_checksum documents.
[[nodiscard]] std::uint16_t ipv4_header_checksum(std::span<const std::uint8_t> header);

// Whether `message` says the handshake was rejected for its ECH config: masque_h2::rejected_ech.
[[nodiscard]] bool rejected_ech(std::string_view message);

} // namespace hemera::core::masque
