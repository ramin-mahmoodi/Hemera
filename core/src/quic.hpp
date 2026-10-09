#pragma once

#include "dns.hpp"
#include "noize.hpp"
#include "settings.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aether::core::quic {

// Port of everything aether/src/quic.rs decides before it touches a socket: the sizes, the flags,
// the timeouts, the environment knobs, the version-negotiation bait packet, and the QUIC transport
// parameters the TLS config of tls.rs carries. The event loop, the h3 connection and the sockets
// are the engine's; the numbers it must run on are all here, so a handshake cannot quietly drift
// from what the Rust core does.

using NoizeConfig = ::aether::core::noize::NoizeConfig;

inline constexpr std::size_t MAX_DATAGRAM_SIZE = 1350;
inline constexpr std::size_t MIN_DATAGRAM_SIZE = 1200;
// How wide a destination connection id a received header is read with (quiche::MAX_CONN_ID_LEN).
inline constexpr std::size_t MAX_CONN_ID_LEN = 20;
// The buffer a socket read is taken into.
inline constexpr std::size_t SOCKET_BUFFER = 65535;
// A fresh source connection id, in bytes.
inline constexpr std::size_t SCID_LEN = 16;

// The control queue: migration and close requests, few and never dropped for a busy data plane.
inline constexpr std::size_t CONTROL_QUEUE = 16;

// The net and datagram queues, which follow the machine's profile as the Rust core's do.
[[nodiscard]] std::size_t net_queue(const Settings& settings);

enum class Control {
    Migrate,
    Close,
};

// The address the tunnel is handed once the edge assigns it.
struct AssignedAddr {
    IpAddress ip;
    std::uint8_t prefix = 0;

    [[nodiscard]] bool operator==(const AssignedAddr&) const = default;
};

struct TunnelConfig {
    SocketAddr peer;
    std::string sni;
    std::string authority;
    std::string path;
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    NoizeConfig noize;
    // The tunnel's own IPv4: the source address of the data-plane probe.
    IpAddress local_ipv4;
    bool quiet = false;
    std::size_t max_datagram = MAX_DATAGRAM_SIZE;
    bool version_bait = true;

    // Never below what a QUIC implementation must accept, never above what a tunnel asks for.
    [[nodiscard]] std::size_t datagram_budget() const;
};

// How long the data plane has to prove itself before the edge is called broken.
[[nodiscard]] std::chrono::seconds validation_timeout(const Settings& settings);

// Whether the data-plane check runs at all: the mere presence of the key turns it off, its
// value says nothing.
[[nodiscard]] bool data_check_enabled(const Settings& settings);

// Round trips the probe has to see come back before socks5 is exposed.
inline constexpr std::uint32_t DATA_PROBE_REQUIRED_SUCCESSES = 2;

// A ping keeps an idle connection and its NAT mapping alive.
inline constexpr std::chrono::seconds KEEPALIVE_INTERVAL{20};
// How often the data-plane probe goes out while the tunnel is being validated.
inline constexpr std::chrono::milliseconds PROBE_INTERVAL{700};

// QUIC v2 (RFC 9369): a draft-version probe makes a filter that only knows v1 answer with a
// Version Negotiation packet, which proves the path is open before the real handshake starts.
inline constexpr std::uint32_t QUIC_V2_VERSION = 0x6b33'43cf;
inline constexpr std::chrono::milliseconds QUIC_V2_BAIT_WAIT{600};
// A single, quick probe during a scan, where the wait is the cost.
inline constexpr std::chrono::milliseconds QUIC_V2_VERIFY_BAIT_WAIT{500};
inline constexpr int QUIC_V2_BAIT_TRIES = 2;
inline constexpr int QUIC_V2_VERIFY_BAIT_TRIES = 1;
inline constexpr std::size_t QUIC_V2_BAIT_LEN = 1200;

// On unless the value is one of the four words that mean off; anything else, including a stray
// string, leaves it on.
[[nodiscard]] bool quic_v2_bait_enabled(const Settings& settings);

// A QUIC variable-length integer narrowed to two bytes: the 14 value bits with the 0x40 00 prefix
// that says "two bytes follow".
[[nodiscard]] std::array<std::uint8_t, 2> quic_varint2(std::uint64_t value);

// The bait itself: a v2 Initial-shaped long header of the minimum QUIC size, unpadded payload zero.
[[nodiscard]] std::vector<std::uint8_t> build_version_bait();

// The wildcard address of the peer's family, with a port for the system to pick.
[[nodiscard]] SocketAddr bind_addr_for(const SocketAddr& peer);

[[nodiscard]] std::array<std::uint8_t, SCID_LEN> random_scid();

[[nodiscard]] std::string_view default_authority();
[[nodiscard]] std::string_view default_path();
[[nodiscard]] std::string_view default_sni();

// The QUIC transport parameters tls.rs::build_config installs (tls.rs:347-361), as data for the
// ngtcp2 layer. A tunnel that knows its own budget overrides the two payload sizes with
// TunnelConfig::datagram_budget().
struct TransportParams {
    std::uint64_t max_idle_timeout_ms = 120'000;
    std::size_t max_recv_udp_payload_size = MAX_DATAGRAM_SIZE;
    std::size_t max_send_udp_payload_size = MAX_DATAGRAM_SIZE;
    std::uint64_t initial_max_data = 10'000'000;
    std::uint64_t initial_max_stream_data_bidi_local = 2'000'000;
    std::uint64_t initial_max_stream_data_bidi_remote = 2'000'000;
    std::uint64_t initial_max_stream_data_uni = 2'000'000;
    std::uint64_t initial_max_streams_bidi = 100;
    std::uint64_t initial_max_streams_uni = 100;
    bool disable_active_migration = true;
    // enable_dgram(true, 65536, 65536): the MASQUE carrier is datagrams, and a datagram is as
    // large as the whole tunnel's budget allows.
    bool datagram_enabled = true;
    std::size_t datagram_recv_max_size = 65'536;
    std::size_t datagram_send_max_size = 65'536;
    // set_application_protos(&[consts::ALPN_H3]).
    std::string_view alpn = "h3";

    [[nodiscard]] bool operator==(const TransportParams&) const = default;
};

[[nodiscard]] const TransportParams& transport_params();

// What one edge is checked against, from quic.rs::VerifyParams. `timeout` is the caller's whole
// budget for the handshake plus the probe; a tunnel's own default is validation_timeout().
struct VerifyParams {
    SocketAddr peer;
    std::string sni;
    std::string authority;
    std::string path;
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    NoizeConfig noize;
    std::chrono::milliseconds timeout{0};
    IpAddress local_ipv4;
};

} // namespace aether::core::quic
