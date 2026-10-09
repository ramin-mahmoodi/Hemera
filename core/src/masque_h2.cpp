// Port of hemera/src/masque_h2.rs's decidable half; see masque_h2.hpp for what is left to the
// engine's nghttp2/BoringSSL drive loop. The capsule and datagram framings come from masque.hpp,
// which is the C++ stand-in for masque_h2.rs's `use crate::masque`.
#include "masque_h2.hpp"

#include <algorithm>
#include <cctype>
#include <limits>

namespace hemera::core::masque_h2 {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Rust's `parse::<u64>()`: whole ASCII digits, an optional leading '+' that from_chars refuses, no
// surrounding space, and nothing that will not fit -- which is what makes a huge value fall to the
// default rather than clamp.
std::optional<std::uint64_t> parse_u64_rust(std::string_view text) {
    if (text.starts_with('+')) text.remove_prefix(1);
    if (text.empty()) return std::nullopt;

    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        constexpr std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
        if (value > (max - digit) / 10) return std::nullopt;
        value = value * 10 + digit;
    }
    return value;
}

// The `.filter(|&v| v > 0).map(|v| v.min(86_400)).unwrap_or(default)` the three second-valued
// switches share. `raw` is the value as it stands: Rust parses the environment without trimming, so
// " 30" is no number and falls to the default.
std::chrono::seconds env_secs(std::optional<std::string_view> raw, std::uint64_t fallback) {
    if (!raw) return std::chrono::seconds(fallback);
    const std::optional<std::uint64_t> value = parse_u64_rust(*raw);
    if (!value || *value == 0) return std::chrono::seconds(fallback);
    return std::chrono::seconds(std::min<std::uint64_t>(*value, MAX_ENV_SECS));
}

} // namespace

std::vector<std::vector<std::uint8_t>> default_expected_pins() {
    return masque::default_expected_pins();
}

H2TunnelConfig::H2TunnelConfig() : expected_pins(default_expected_pins()) {}

bool enabled(const Settings& settings) {
    const std::optional<std::string_view> raw = settings.get("HEMERA_MASQUE_HTTP2");
    if (!raw) return false;
    const std::string value = lowered(trim(*raw));
    // "h2" is this switch's own word; is_truthy() does not know it.
    return value == "1" || value == "true" || value == "h2" || value == "yes" || value == "on";
}

SocketAddr h2_peer(const Settings& settings, const SocketAddr& quic_peer) {
    if (const std::optional<std::string_view> raw = settings.get("HEMERA_MASQUE_H2_PEER")) {
        // A value that is no `ip:port` is ignored rather than fatal, as Rust's failed parse is.
        if (const auto addr = parse_socket_addr(trim(*raw))) return *addr;
    }
    return quic_peer;
}

bool data_check_enabled(const Settings& settings) {
    // The presence of the key is the whole switch: a value of "0" or an empty one still turns the
    // check off, because Rust only asks whether the variable is there at all.
    return settings.find("HEMERA_MASQUE_NO_DATA_CHECK") == nullptr;
}

std::chrono::seconds validation_timeout(const Settings& settings) {
    return env_secs(settings.get("HEMERA_MASQUE_VALIDATE_SECS"), VALIDATE_SECS_DEFAULT);
}

std::chrono::seconds h2_keepalive_interval(const Settings& settings) {
    return env_secs(settings.get("HEMERA_MASQUE_H2_KEEPALIVE_SECS"), KEEPALIVE_INTERVAL_DEFAULT);
}

std::chrono::seconds h2_keepalive_timeout(const Settings& settings) {
    return env_secs(settings.get("HEMERA_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS"),
                    KEEPALIVE_TIMEOUT_DEFAULT);
}

bool rejected_ech(std::string_view message) {
    return message.find("ECH_REJECTED") != std::string_view::npos;
}

FlowControl h2_flow(const Settings& settings) {
    return FlowControl{sysprofile::h2_stream_window_bytes(settings),
                       sysprofile::h2_connection_window_bytes(settings), H2_MAX_FRAME_SIZE};
}

std::string connect_authority(const H2TunnelConfig& cfg) {
    // `format!("{}:443", cfg.authority)` -- the port is kept even though it is 443, which is the
    // one place this differs from https.hpp's authority().
    return cfg.authority + ":" + std::to_string(CONNECT_PORT);
}

std::string connect_uri(const H2TunnelConfig& cfg) { return "https://" + connect_authority(cfg); }

ConnectRequest build_connect_request(const H2TunnelConfig& cfg) {
    ConnectRequest req;
    req.method = "CONNECT";
    req.uri = connect_uri(cfg);
    // The three fields in the order http::Request::builder() gives them; user-agent is empty on
    // purpose, as the edge reads an absent one differently.
    req.headers = {
        {"cf-connect-proto", std::string(CF_CONNECT_PROTOCOL)},
        {"pq-enabled", "false"},
        {"user-agent", ""},
    };
    return req;
}

std::vector<std::pair<std::string, std::string>> connect_request_fields(const H2TunnelConfig& cfg) {
    // The H3 field set carried onto H2, minus :scheme/:path (extended CONNECT omits them):
    // without :protocol the edge reads a plain CONNECT and answers 400, and without
    // capsule-protocol it will not carry capsules. The Rust H2 extras (cf-connect-proto,
    // pq-enabled) are out: the edge answers 400 with them beside :protocol.
    return {
        {":method", "CONNECT"},
        {":protocol", std::string(CF_CONNECT_PROTOCOL)},
        {":authority", connect_authority(cfg)},
        {"user-agent", ""},
        {"capsule-protocol", "?1"},
    };
}

bool status_is_success(std::uint16_t status) { return status >= 200 && status < 300; }

std::string status_error(std::uint16_t status) {
    return "h2 connect-ip status " + std::to_string(status);
}

std::expected<void, std::string> check_status(std::uint16_t status) {
    if (status_is_success(status)) return {};
    return std::unexpected(status_error(status));
}

SendFrame outbound_frame(std::span<const std::vector<std::uint8_t>> queued) {
    SendFrame frame;
    if (queued.empty()) return frame;

    // The first packet always goes in; one more is added while the frame is still under the limit,
    // which is how a frame can end up over it by the capsule that crossed.
    masque::append_datagram_capsule(frame.data, queued[0]);
    frame.taken = 1;
    while (frame.data.size() < H2_SEND_BATCH_BYTES && frame.taken < queued.size()) {
        masque::append_datagram_capsule(frame.data, queued[frame.taken]);
        ++frame.taken;
    }
    return frame;
}

Received receive_stream(std::span<const std::uint8_t> data) {
    Received out;
    masque::CapsuleParser parser;
    static_cast<void>(parser.push(data));
    masque::Drained drained = masque::drain_capsules(parser);

    out.packets = std::move(drained.packets);
    out.assigned = std::move(drained.assigned);
    out.routes = drained.routes;
    out.discarded = drained.discarded;
    out.parse_error = drained.parse_error;
    out.delivered = drained.delivered;
    return out;
}

std::optional<IpAddress> bytes_to_ip(std::uint8_t version, std::span<const std::uint8_t> bytes) {
    return masque::to_ip_address(version, bytes);
}

std::vector<std::uint8_t> probe_packet(const H2TunnelConfig& cfg, std::optional<std::uint16_t> dns_id,
                                       std::optional<std::uint16_t> sport) {
    return masque::build_dns_probe_packet(cfg.local_ipv4, dns_id, sport);
}

std::vector<std::uint8_t> probe_capsule(const H2TunnelConfig& cfg, std::optional<std::uint16_t> dns_id,
                                        std::optional<std::uint16_t> sport) {
    return masque::encode_datagram_capsule(probe_packet(cfg, dns_id, sport));
}

// verify_h2() and run() are declared in masque_h2.hpp and deliberately not defined here: dialing
// the peer, the BoringSSL handshake with the ECH retry loop, the nghttp2 connection driver, the send
// task pumping outbound capsules and the keepalive select are the engine's, and they take the Dial
// callback above rather than open a socket from this module.

} // namespace hemera::core::masque_h2
