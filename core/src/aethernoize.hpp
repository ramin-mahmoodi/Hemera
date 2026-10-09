#pragma once

#include "dns.hpp" // SocketAddr, the peer the Rust carries but never aims at

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// transport.hpp: the socket the junk goes out through. Forward-declared rather than included, the
// way noize.hpp does it, because this header is reached through coreflow.hpp and prober.hpp while
// transport.hpp sits on the other side of quic.hpp; the definition is only needed where the sends
// happen, in aethernoize.cpp.
namespace aether::core::transport {
struct UdpIo;
}

namespace aether::core::aethernoize {

// Port of aethernoize.rs: the heavier noise dialect, where a signature can carry a counter, a
// run of letters or digits, and a range of sizes, and the first one is wrapped to look like an
// IKE v2 security-association request. Sending it needs the socket, so that is the egress
// layer's; the packets themselves and the language they are written in are here.

struct AetherNoizeConfig {
    std::optional<std::string> i1;
    std::optional<std::string> i2;
    std::optional<std::string> i3;
    std::optional<std::string> i4;
    std::optional<std::string> i5;
    std::size_t jc = 0;
    std::size_t jc_before_hs = 0;
    std::size_t jc_after_i1 = 0;
    std::size_t jc_after_hs = 0;
    std::size_t jmin = 0;
    std::size_t jmax = 0;
    std::chrono::milliseconds junk_interval{0};
    std::chrono::milliseconds handshake_delay{0};
    bool allow_zero_size = false;

    [[nodiscard]] static AetherNoizeConfig off();
    [[nodiscard]] static AetherNoizeConfig light();
    [[nodiscard]] static AetherNoizeConfig balanced();
    [[nodiscard]] static AetherNoizeConfig aggressive();
    [[nodiscard]] static AetherNoizeConfig firewall();
    [[nodiscard]] static AetherNoizeConfig gfw();

    [[nodiscard]] bool is_enabled() const;
};

// The profile a name asks for, whatever its case or padding; anything unknown is balanced.
[[nodiscard]] AetherNoizeConfig from_profile(std::string_view name);

// A signature as its bytes: <b hex> literal, <t> the clock, <c> a counter that never repeats,
// <r len> random bytes, <rc len> random letters, <rd len> random digits, each of which may be
// written as a `min-max` range.
[[nodiscard]] std::vector<std::uint8_t> parse_cps(std::string_view spec);

// `payload` behind an IKE v2 request header, which is how the first packet of a session looks
// to anything reading the wire.
[[nodiscard]] std::vector<std::uint8_t> wrap_ikev2(std::span<const std::uint8_t> payload);

// One junk packet, of a size the profile allows.
[[nodiscard]] std::vector<std::uint8_t> generate_junk(const AetherNoizeConfig& cfg);

// ---------------------------------------------------------------------------
// The three senders: aethernoize.rs:313-400.
//
// All three write through transport.hpp's UdpIo, which is the port's stand-in for the
// tokio::net::UdpSocket the Rust takes, and they sleep on the calling thread with
// std::this_thread::sleep_for where the Rust awaits tokio::time::sleep. That is why the WireGuard
// loop that calls them runs on a blocking thread (wireguard.rs:232 and :271 spawn two of them).
//
// `peer` is carried because the Rust signatures carry it (aethernoize.rs:317-318, 362-366), and it
// is named `_peer`: every send below goes through send_connected (aethernoize.rs:313-315), which
// calls sock.send() -- the connected-socket write -- and never sock.send_to(). So the address
// chooses nothing here; it is part of the shape of the API, not of the packet. The port keeps the
// parameter for exactly that reason and uses it for nothing, and `peer` stays unused-but-named for
// the same reason noize.cpp's send_junk takes it.
//
// Nothing in these three functions logs. The Rust writes no log:: line between aethernoize.rs:313
// and :400, so the port is silent too and takes no Note sink; the contrast with noize.rs, whose
// pre_handshake writes trace!/debug! for every send, is deliberate and not an omission. The result
// of each send is dropped the way `let _ =` drops it, so a socket error is a missing packet and
// nothing more -- junk never decides whether the tunnel comes up.

// aethernoize.rs:317-360: the whole pre-handshake curtain, in the order the Rust writes it -- the
// i1 signature IKE v2-wrapped (when the profile has one and it parses to bytes) and 2 ms behind it,
// then jc_after_i1 junk packets, then jc_before_hs junk packets, each paused by junk_interval when
// the profile set one, then the i2/i3/i4/i5 signatures in that order with 1 ms after each, then a
// handshake_delay pause before the return, which is the caller's cue to start the real handshake.
// A profile that is_enabled() is false for returns before it sends anything (aethernoize.rs:318-
// 320).
void apply_obfuscation(transport::UdpIo& sock, const SocketAddr& peer,
                       const AetherNoizeConfig& cfg);

// aethernoize.rs:362-374: jc_after_hs junk packets, each followed by junk_interval when the profile
// set one. There is deliberately no is_enabled() guard on this one -- aethernoize.rs:362-367 has
// none -- because the caller only reaches it when the count itself is non-zero (wireguard.rs:259),
// and a profile with jc_after_hs set but is_enabled() false still gets its packets, as in Rust.
void send_post_handshake_junk(transport::UdpIo& sock, const SocketAddr& peer,
                              const AetherNoizeConfig& cfg);

// aethernoize.rs:376-400: the keepalive tick's cover traffic. jc_before_hs, floored at 1, is the
// base; a random 0..=base is added to it; each packet then has its first byte bumped by 0x40 when
// that byte is a WireGuard message type (1..=4), so the run still reads as WG to nothing in
// particular, and the gap after each packet is junk_interval plus a random 0..=8 ms. No `peer`:
// aethernoize.rs:376 takes only the socket and the config.
void send_keepalive_junk(transport::UdpIo& sock, const AetherNoizeConfig& cfg);

} // namespace aether::core::aethernoize
