#pragma once

// Port of hemera/src/masque_h2.rs: the HTTP/2 MASQUE carrier -- CONNECT-IP carried over HTTP/2
// datagram capsules on a request stream instead of HTTP/3, with the same certificate / pinning /
// ECH surface as the QUIC carrier. Everything this file decides is kept here: the tunnel config,
// the on/off switch and its exact env reading, the h2 peer and connect target, the connect-ip
// request's field set and order, the flow-control window sizes it asks sysprofile for, the
// capsule/datagram framing it puts on the stream (built on masque.hpp's codecs, which is what
// masque_h2.rs's `use crate::masque` reaches), the response-status rules, and every constant.
//
// What is NOT here, on purpose, is the socket half: the dial, the BoringSSL handshake with its ECH
// retry loop and the nghttp2 drive are masque_h2_runtime.cpp, which acts on every decision below and
// takes its stream from a seam -- the way dns.hpp hands fetch_ech_config()'s resolver to a caller and
// https.hpp leaves the handshake to the engine.

#include "dns.hpp"
#include "masque.hpp"
#include "settings.hpp"
#include "sysprofile.hpp"
#include "transport.hpp"
#include "upstream.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hemera::core::masque_h2 {

// ---- the constants of masque_h2.rs, with their Rust lines -----------------------------------

// ALPN: HTTP/2, then HTTP/1.1, as Chrome offers them; the edge picks HTTP/2, which the tunnel
// speaks (masque_h2.rs:23). Wire format already: each protocol preceded by its own length byte.
inline constexpr std::array<std::uint8_t, 12> H2_ALPN{
    0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

// The largest DATA frame the edge may send us; the h2 default is the RFC minimum of 16 KiB
// (masque_h2.rs:28).
inline constexpr std::uint32_t H2_MAX_FRAME_SIZE = 64 * 1024;

// How much a single write to the edge may carry; queued packets are gathered up to this much so a
// burst costs one frame rather than one frame per packet (masque_h2.rs:34).
inline constexpr std::size_t H2_SEND_BATCH_BYTES = 32 * 1024;

// How long a clean shutdown waits for the send task to put its closing frame on the wire
// (masque_h2.rs:38).
inline constexpr std::chrono::milliseconds SENDER_CLOSE_GRACE{250};

// Round trips the probe has to see come back before socks5 is exposed, and how often it goes out
// while the tunnel is still being validated (masque_h2.rs:118-119).
inline constexpr std::uint32_t DATA_PROBE_REQUIRED_SUCCESSES = 2;
inline constexpr std::chrono::milliseconds DATA_PROBE_RESEND{700};

// The depth of the queue in front of the send task (masque_h2.rs:487).
inline constexpr std::size_t H2_SENDER_QUEUE = 16;

// The defaults of the three second-valued switches and the ceiling of a day on each
// (masque_h2.rs:114-115, 127, 137-138, 126/136).
inline constexpr std::uint64_t VALIDATE_SECS_DEFAULT = 10;
inline constexpr std::uint64_t KEEPALIVE_INTERVAL_DEFAULT = 15;
inline constexpr std::uint64_t KEEPALIVE_TIMEOUT_DEFAULT = 20;
inline constexpr std::uint64_t MAX_ENV_SECS = 86'400;

// The port the H2 edge is reached on: build_connect_request writes `format!("{}:443", authority)`
// (masque_h2.rs:197), and -- unlike https.hpp's authority(), which drops 443 -- it is kept in full.
inline constexpr std::uint16_t CONNECT_PORT = 443;

// ---- the tunnel configuration (masque_h2.rs:80-94) -------------------------------------------

struct H2TunnelConfig {
    SocketAddr peer;
    std::string sni{std::string(CONNECT_SNI)};
    std::string authority{std::string(masque::DEFAULT_AUTHORITY)};
    std::string path{std::string(masque::DEFAULT_PATH)};
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    // The tunnel's own IPv4: the source address of the data-plane probe (masque_h2.rs:320,395).
    IpAddress local_ipv4;
    bool quiet = false;
    bool pin_endpoint = true;
    // The pin expectations every Rust call site passes -- consts::MASQUE_PINS -- as Vec<Vec<u8>>,
    // the type masque_h2.rs uses (a spoofed SNI still connects, a man in the middle does not).
    std::vector<std::vector<std::uint8_t>> expected_pins;
    // The ECHConfigList the handshake offers: the session's, or none as on the inner hop of
    // masque-in-masque (masque_h2.rs:91-93).
    std::optional<std::vector<std::uint8_t>> ech_config_list;

    H2TunnelConfig();

    // Whether the handshake offers an ECH key at all; a session that started without one never
    // takes a retry key (masque_h2.rs:230,242).
    [[nodiscard]] bool offers_ech() const { return ech_config_list.has_value(); }
};

// consts::MASQUE_PINS as the Vec<Vec<u8>> the Rust call sites build for expected_pins.
[[nodiscard]] std::vector<std::vector<std::uint8_t>> default_expected_pins();

// ---- the switches and their exact env reading -------------------------------------------------

// HEMERA_MASQUE_HTTP2 (--h2 / --http2): HTTP/2 instead of HTTP/3, on the words Rust accepts --
// 1, true, h2, yes, on, trimmed and lower cased (masque_h2.rs:141-149). "h2" is this switch's own
// word; settings.hpp's is_truthy does not know it, so enabled() has its own reading.
[[nodiscard]] bool enabled(const Settings& settings);

// HEMERA_MASQUE_H2_PEER (--h2-peer): the address the HTTP/2 carrier connects to instead of the QUIC
// one (masque_h2.rs:151-158). A value that is no `ip:port` (an IPv6 host without brackets and a
// port, or a bare address) is ignored as Rust's failed parse is, and quic_peer stands.
[[nodiscard]] SocketAddr h2_peer(const Settings& settings, const SocketAddr& quic_peer);

// HEMERA_MASQUE_NO_DATA_CHECK (--no-data-check): the check runs unless the variable is there at all,
// whatever it says -- mere presence turns it off, its value says nothing (masque_h2.rs:104-106).
[[nodiscard]] bool data_check_enabled(const Settings& settings);

// HEMERA_MASQUE_VALIDATE_SECS / _H2_KEEPALIVE_SECS / _H2_KEEPALIVE_TIMEOUT_SECS: a positive whole
// number of seconds, at most a day, else the default (masque_h2.rs:108-139). Rust parses the value
// without trimming it, so a leading '+' parses and a surrounding space does not.
[[nodiscard]] std::chrono::seconds validation_timeout(const Settings& settings);
[[nodiscard]] std::chrono::seconds h2_keepalive_interval(const Settings& settings);
[[nodiscard]] std::chrono::seconds h2_keepalive_timeout(const Settings& settings);

// Whether a handshake that failed with `message` was turned down for its ECHConfigList, which
// BoringSSL reports as ECH_REJECTED -- the only failure a retry config is handed out for
// (masque_h2.rs:44-46).
[[nodiscard]] bool rejected_ech(std::string_view message);

// ---- the builder h2::client runs on (masque_h2.rs:71-78) --------------------------------------

// h2 flow control, as nghttp2's option setters take it: the two windows the machine's profile picks
// (64 KiB on both is the h2 default, and caps a 130 ms link near 500 KB/s) and the frame ceiling.
struct FlowControl {
    std::uint32_t initial_stream_window = 0;
    std::uint32_t initial_connection_window = 0;
    std::uint32_t max_frame_size = H2_MAX_FRAME_SIZE;

    [[nodiscard]] bool operator==(const FlowControl&) const = default;
};

// h2_builder(): initial_window_size(sysprofile::h2_stream_window_bytes),
// initial_connection_window_size(sysprofile::h2_connection_window_bytes), max_frame_size(64 KiB).
[[nodiscard]] FlowControl h2_flow(const Settings& settings);

// ---- the connect-ip request (masque_h2.rs:196-207) --------------------------------------------

// What http::Request::builder() is handed: method CONNECT, the URI https://{authority}:443, and
// three fields in the order the builder gave them.
struct ConnectRequest {
    std::string method = "CONNECT";
    std::string uri;
    std::vector<std::pair<std::string, std::string>> headers;

    [[nodiscard]] bool operator==(const ConnectRequest&) const = default;
};

// The authority the CONNECT goes to: `{cfg.authority}:443`, the literal the Rust formats.
[[nodiscard]] std::string connect_authority(const H2TunnelConfig& cfg);
// The URI: `https://{authority}:443`.
[[nodiscard]] std::string connect_uri(const H2TunnelConfig& cfg);
// build_connect_request(): CONNECT, the URI, cf-connect-proto / pq-enabled / user-agent in order.
[[nodiscard]] ConnectRequest build_connect_request(const H2TunnelConfig& cfg);

// The header block h2 emits for that request. A plain CONNECT (no :protocol, which CF's CONNECT-IP
// replaces with the cf-connect-proto field) carries :method and :authority from the URI -- no
// :scheme and no :path -- then the builder's fields in order. That ordered set is what the engine
// hands nghttp2.
[[nodiscard]] std::vector<std::pair<std::string, std::string>> connect_request_fields(
    const H2TunnelConfig& cfg);

// ---- the response-status acceptance rules (masque_h2.rs:307-312, 474-479) ----------------------

// Whether `status` is a success: http's StatusCode::is_success(), 200 through 299.
[[nodiscard]] bool status_is_success(std::uint16_t status);
// The error the Rust returns for anything else: "h2 connect-ip status {code}".
[[nodiscard]] std::string status_error(std::uint16_t status);
// Ok for a 2xx, otherwise the verbatim status error.
[[nodiscard]] std::expected<void, std::string> check_status(std::uint16_t status);

// ---- the datagram capsules on the request stream (pump_outbound / drain_capsules) -------------

// pump_outbound's gathering: the first packet always goes in, then whatever is already behind it
// while the frame is under H2_SEND_BATCH_BYTES -- so a frame may end up over the limit by the one
// capsule that crossed it. `taken` says how many of `queued` the frame carries.
struct SendFrame {
    std::vector<std::uint8_t> data;
    std::size_t taken = 0;
};
[[nodiscard]] SendFrame outbound_frame(std::span<const std::vector<std::uint8_t>> queued);

// drain_capsules' result: the IP packets for the netstack, the addresses the edge assigned, the
// route-advertisement count, the datagrams thrown out for being no IP packet, the parse error that
// stopped the drain, and Rust's `got_data` (a datagram that is an IP packet was seen).
struct Received {
    std::vector<std::vector<std::uint8_t>> packets;
    std::vector<masque::EdgeAssignment> assigned;
    std::size_t routes = 0;
    std::size_t discarded = 0;
    std::optional<std::string> parse_error;
    bool delivered = false;
};

// Reads a run of DATA chunks as the request stream body, framing the capsules inside them and
// handing back whatever datagram carries an IP packet. The h2 carrier answers with the bare packet
// (no context id), so a value with or without one both come back out.
[[nodiscard]] Received receive_stream(std::span<const std::uint8_t> data);

// bytes_to_ip (masque_h2.rs:790-800): version 4 reads four bytes and version 6 sixteen, in dns.hpp's
// IpAddress form; anything else is no address.
[[nodiscard]] std::optional<IpAddress> bytes_to_ip(std::uint8_t version,
                                                   std::span<const std::uint8_t> bytes);

// ---- the data-plane probe ---------------------------------------------------------------------

// masque::build_dns_probe_packet(cfg.local_ipv4): a DNS query for cloudflare.com inside UDP/53
// inside IPv4 to 8.8.8.8 (an empty UDP checksum, TTL 64, a random id and source port). Pass the two
// ids for the same bytes twice; left out, they are drawn fresh.
[[nodiscard]] std::vector<std::uint8_t> probe_packet(const H2TunnelConfig& cfg,
                                                     std::optional<std::uint16_t> dns_id = {},
                                                     std::optional<std::uint16_t> sport = {});
// The probe as it goes on the stream: encode_datagram_capsule(probe) (masque_h2.rs:320-322).
[[nodiscard]] std::vector<std::uint8_t> probe_capsule(const H2TunnelConfig& cfg,
                                                      std::optional<std::uint16_t> dns_id = {},
                                                      std::optional<std::uint16_t> sport = {});

// ---- the carrier runtime (masque_h2.rs:209-277, 279-377, 386-657) -----------------------------
//
// The socket half is masque_h2_runtime.cpp: it dials, shakes hands over what it dialled, drives
// nghttp2 and pumps the capsules. Every decision it acts on is one of the declarations above.
//
// What `Dial` above cannot do is hand back the stream it dialled -- its result is a verdict, not a
// connection -- and both a handshake and a request stream need the bytes they were made on. So the
// runtime's seam is DialSocket, and verify_h2()/run() are its two adapters.

// The byte stream the TLS handshake runs over: dial()'s TcpStream, minus tokio (masque_h2.rs:209-216).
// Every call is non-blocking; the loop that owns the stream does the waiting, the way transport.cpp's
// pump waits on its own socket.
struct TcpIo {
    virtual ~TcpIo() = default;

    // The bytes the peer sent, 0 when it closed the connection. An empty result means nothing is
    // there yet, which is what makes the wait the caller's.
    [[nodiscard]] virtual std::expected<std::size_t, std::string> read(std::span<std::uint8_t> out) = 0;
    // The bytes the kernel took, which may be fewer than asked for; a short write is not an error.
    [[nodiscard]] virtual std::expected<std::size_t, std::string> write(
        std::span<const std::uint8_t> bytes) = 0;
    // True when the stream is ready inside `wait`, false when the wait ran out.
    [[nodiscard]] virtual bool wait(std::chrono::milliseconds limit, bool for_write) = 0;
};

// dial(): the peer in, the connected stream out. A proxy detour, when one is on, answers this and
// the carrier never learns whether the bytes went direct or through it (masque_h2.rs:209-216).
using DialSocket =
    std::function<std::expected<std::unique_ptr<TcpIo>, std::string>(const SocketAddr& peer)>;

// egress::tcp_connect(peer) with set_nodelay, which is what dial() falls back to when no detour is
// configured (masque_h2.rs:212, 238). `budget` bounds the connect itself; left out, the operating
// system's own timeout is the only bound, which is all the Rust's un-timed dial has either.
[[nodiscard]] std::expected<std::unique_ptr<TcpIo>, std::string>
connect_tcp(const SocketAddr& peer, std::optional<std::chrono::milliseconds> budget = {});

// proxy.connect(peer): the same stream through the proxy -- socks5 greeting/login/CONNECT or one
// http CONNECT -- for dial()'s proxy arm (masque_h2.rs:211).
[[nodiscard]] std::expected<std::unique_ptr<TcpIo>, std::string>
connect_via_proxy(const upstream::Upstream& proxy, const SocketAddr& peer,
                  std::optional<std::chrono::milliseconds> budget = {});

// dial() (masque_h2.rs:209-216): the proxy's stream when HEMERA_UPSTREAM names one, the direct
// connect when not. The announce lines ride the observer, so the carrier never learns which arm
// answered -- the two arms of Rust's match.
[[nodiscard]] std::expected<std::unique_ptr<TcpIo>, std::string>
dial(const SocketAddr& peer, const Settings& settings,
     std::optional<std::chrono::milliseconds> budget = {},
     transport::Observer* observer = nullptr);

// pump_outbound's outbound_rx (masque_h2.rs:392 through Internals): the netstack's tunnel packets.
struct OutboundSource {
    virtual ~OutboundSource() = default;
    // try_recv: nothing when the queue is empty. `gone` is recv()'s None -- the netstack dropped its
    // sender -- which is the arm that ends the request stream (masque_h2.rs:693-697).
    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> try_recv() = 0;
    [[nodiscard]] virtual bool gone() const { return false; }
};

// The control queue, quic.rs's `ctrl_rx`, which run() reads beside the sockets
// (masque_h2.rs:590-599). Nothing when nothing is waiting; `gone` is the same answer as Close.
struct ControlQueue {
    virtual ~ControlQueue() = default;
    [[nodiscard]] virtual std::optional<quic::Control> try_recv() = 0;
    [[nodiscard]] virtual bool gone() const { return false; }
};

// What run() carries besides its config: the three seams transport.hpp already names, so one host
// drives both carriers, and the two queues and the ready signal the H3 session holds inside itself.
struct TunnelSeams {
    // quic.rs's inbound_tx: the datagrams that came off the stream, for the netstack. Null is the
    // answer a check gives -- the packets are counted, and only counted.
    transport::InboundSink* inbound = nullptr;
    // masque_h2.rs:389's addr_tx, the assignments out of the Address Assign capsules. Optional, as
    // the Rust's is.
    transport::AddressSink* assigned = nullptr;
    // log_or_debug's channel: the [h2] lines, as the Rust writes them. `quiet` picks the level, and
    // the level is the host's to read off the line transport.hpp's Observer carries.
    transport::Observer* observer = nullptr;
    // outbound_rx. Required for a tunnel: nothing else puts packets on the stream.
    OutboundSource* outbound = nullptr;
    // ctrl_rx. Null means nothing ever closes the tunnel from the outside; the edge still can.
    ControlQueue* control = nullptr;
    // ready_tx, fired exactly once, when the data plane has proved itself
    // (masque_h2.rs:390, 509-514, 627-633).
    std::function<void()> ready;
};

// verify_h2 (masque_h2.rs:279-377): dial through `dial`, shake hands, put the connect-ip request on
// the stream, and prove the data plane answers DATA_PROBE_REQUIRED_SUCCESSES probes inside `timeout`.
// The round trip the edge answered with, or the classified text the Rust's HemeraError carries.
[[nodiscard]] std::expected<std::chrono::milliseconds, std::string> verify_h2_with(
    const H2TunnelConfig& cfg, std::chrono::milliseconds timeout, const Settings& settings,
    const DialSocket& dial, transport::Observer* observer = nullptr);

// run (masque_h2.rs:386-657): the tunnel loop -- the request, the capsules out, the capsules in, the
// keepalive ping, the validation and pong deadlines -- until the control queue closes it or the edge
// ends the stream. It blocks, which is the shape the engine's tunnel thread has.
[[nodiscard]] std::expected<void, std::string> run_with(const H2TunnelConfig& cfg,
                                                        const Settings& settings,
                                                        const DialSocket& dial,
                                                        const TunnelSeams& seams);

// ---- the socket/async half, left as a declared boundary for the engine ------------------------

// The engine dials the peer and hands back an established TLS + HTTP/2 request stream it then
// drives; the pure port opens no socket. This is masque_h2.rs's dial() / connect_tls() / h2 handshake
// collapsed into the one callback a caller supplies.
using Dial = std::function<std::expected<void, std::string>(const SocketAddr& peer)>;

// masque_h2.rs::verify_h2 -- dial, shake hands, send the connect-ip request, run the end-to-end
// data-plane probe and report the latency it took. Declared only; the BoringSSL/nghttp2 loop that
// implements it is the engine's, exactly as the resolvers live outside dns.hpp and the handshake
// outside https.hpp.
[[nodiscard]] std::expected<std::chrono::milliseconds, std::string> verify_h2(
    const H2TunnelConfig& cfg, std::chrono::milliseconds timeout, const Settings& settings,
    const Dial& dial);

// masque_h2.rs::run -- the long-lived tunnel loop: connect-ip request, the send task pumping
// outbound datagram capsules, the keepalive ping, the validation deadline and the control channel.
// Declared only for the same reason.
[[nodiscard]] std::expected<void, std::string> run(const H2TunnelConfig& cfg,
                                                   const Settings& settings, const Dial& dial);

} // namespace hemera::core::masque_h2
