#pragma once

#include "dns.hpp" // SocketAddr, the address a junk packet is aimed at

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// transport.hpp: the socket the junk goes out through. Forward-declared rather than included,
// because transport.hpp reaches this header through quic.hpp and a cycle would decide which of the
// two gets to name the other; the definition is only needed where the sends happen, in noize.cpp.
namespace aether::core::transport {
struct UdpIo;
}

namespace aether::core::noize {

// Port of aether/src/noize.rs: the junk a handshake is wrapped in, so the first packets of a
// session look like nothing in particular. What is here is the whole of the Rust module: the
// profile, the packets themselves and the <b>/<t>/<n>/<r> signature language they are written in
// (noize.rs:8-145), and the sender that puts them on the wire before the ClientHello
// (noize.rs:147-209).
//
// The sender is deliberately not a socket of its own. Rust handed pre_handshake a
// tokio::net::UdpSocket and awaited through it; the port has no reactor, so it takes the same
// seam every other pre-handshake write goes through -- transport.hpp's UdpIo, whose real
// implementation is WinUdp -- and sleeps on the calling thread with std::this_thread instead of
// tokio::time. quic.rs:341 calls this from the tunnel's own task, immediately before the first
// flush(), which is the one moment nothing else is writing to that socket and so the only moment
// the junk can be sure of going first.

struct NoizeConfig {
    std::size_t jc_before_hs = 0;
    std::size_t jc_after_i1 = 0;
    std::size_t jmin = 0;
    std::size_t jmax = 0;
    std::optional<std::string> i1;
    std::optional<std::string> i2;
    std::chrono::milliseconds junk_interval{0};

    [[nodiscard]] static NoizeConfig off();
    [[nodiscard]] static NoizeConfig firewall();
    [[nodiscard]] static NoizeConfig light();
    [[nodiscard]] static NoizeConfig gfw();

    // Whether there is anything to send at all.
    [[nodiscard]] bool is_enabled() const;
};

// The noise profile a name asks for: off/none, light, gfw/aggressive/heavy, and anything else
// the balanced firewall profile.
[[nodiscard]] NoizeConfig from_profile(std::string_view name);

// One junk packet, of a random size between jmin and jmax and random bytes.
[[nodiscard]] std::vector<std::uint8_t> junk_packet(const NoizeConfig& cfg);

// A signature as its bytes: <b hex> literal, <t> the clock as four bytes, <n> a random eight,
// <r len> random bytes, and everything outside a tag left out.
[[nodiscard]] std::vector<std::uint8_t> parse_cps(std::string_view spec);

// ---------------------------------------------------------------------------
// The sender.

// The level the Rust log macro used, carried with the text so a host cannot quietly promote junk
// noise into its info log: pre_handshake writes trace! everywhere and debug! for the four send
// failures (noize.rs:163, 168-169, 180-181, 190-191, 202-203, 208). Same reason coreflow.hpp's
// Note carries one.
enum class Level { Trace, Debug };

// Where those lines go. This library owns no logger and prints nothing by itself: transport.cpp
// routes through Observer::on_note, coreflow.cpp collects into Notes, and a host that wants no
// noise from the handshake hands pre_handshake no sink at all. Passing it in is what keeps the
// choice with the caller, which is the port's convention everywhere else.
using Note = std::function<void(Level level, std::string_view line)>;

// crate::upstream::relay_target(local, intended) as the port reaches it (noize.rs:152). In Rust
// that is a free function over a process-wide detour table; here the table is behind the
// Session::Seams::relay seam (transport.hpp:341-344), which has exactly this shape and is what a
// caller should hand in. Empty is the answer for a socket with no upstream on it, which is Rust's
// map(...).unwrap_or(intended): the peer itself.
using RelayTarget = std::function<SocketAddr(const SocketAddr& local, const SocketAddr& intended)>;

// noize.rs:147-156 send_junk: one packet, at the address the socket is really aimed at. Rust
// picks `sock.send()` when the socket has a peer set and `sock.send_to(relay_target(local, peer))`
// otherwise; WinUdp::send already makes that same choice internally (transport.cpp:249-259 -- a
// connected socket takes ::send and ignores the destination), so passing the target it computes is
// faithful to both arms rather than a second way of saying the same thing. The fallback of
// noize.rs:153, when even local_addr() failed, is the peer: here that is a socket whose bound
// address is unset.
[[nodiscard]] std::expected<std::size_t, std::string>
send_junk(transport::UdpIo& io, const SocketAddr& peer, std::span<const std::uint8_t> packet,
          const RelayTarget& relay = {});

// noize.rs:158-209 pre_handshake: wrap the handshake in the profile's noise, in the order the
// Rust writes and with nothing else in between -- jc_before_hs junk packets, then the i1
// signature when it has one and it parses to bytes, then jc_after_i1 junk packets, then the i2
// signature. It sleeps junk_interval after every junk packet (the last one included, as the Rust
// loop does) whenever the profile set an interval, and 2 ms after a signature i1 that went out;
// i2 gets no pause, because noize.rs:198-206 gives it none.
//
// A profile whose is_enabled() answers false sends nothing and logs nothing, so `--noize off`
// costs no packets and no sleeping (noize.rs:159-161). Every failure is a debug! line and a
// moved-on: Rust cannot let junk decide whether the tunnel comes up, so neither can this, and a
// caller that hands no sink simply does not hear about it.
//
// Blocking: this is the port's stand-in for the awaited sleeps, and quic.rs calls it from the same
// single task the pump runs in, so the caller is the thread that would otherwise be sleeping.
void pre_handshake(transport::UdpIo& io, const SocketAddr& peer, const NoizeConfig& cfg,
                   const RelayTarget& relay = {}, const Note& note = {});

} // namespace aether::core::noize
