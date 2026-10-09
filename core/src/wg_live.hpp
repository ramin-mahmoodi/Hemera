#pragma once

// Port of the LIVE half of hemera/src/wireguard.rs (pinned commit 6175b67): the socket that
// bind_via_upstream produces, the synchronous verify_endpoint / verify_endpoint_keep_session
// handshake drive (:526-721), the dataplane confirmation it runs inside them (:431-524), and the
// four-task run loop of WgTunnel::run (:154-349).
//
// wireguard.hpp holds the protocol -- the Noise_IK state machine, the wire layout, Tunn's timers --
// and already holds the three hemeranoize call sites the loop reaches (wireguard.hpp:589-606,
// implemented at wireguard.cpp:2191-2241). Nothing is re-decided here: this module supplies the
// bytes, the waiting, the socket and the order, and calls those helpers where wireguard.rs writes
// the bare send.
//
// The engine, not this module, owns the threads of the Rust's tokio runtime. Rust drives this path
// with four tasks sharing Arc<Mutex<Box<Tunn>>>; WgTunnel::run is ported with std::thread over a
// std::mutex around the same Tunn, because the port's rule is threads and blocking Winsock. The
// select! arms become the waits the seams below hand back, so every deadline in here is one the
// Rust also has and a test can drive without a network.
//
// WHAT IS NOT HERE, and why:
//   * Control. wireguard.rs's run() takes only `outbound_rx: mpsc::Receiver<Vec<u8>>`; unlike
//     quic.rs it has no control channel, so none is invented here.

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "coreflow.hpp"    // Cancel, Error, the HemeraError Display every {e} in a Rust line needs
#include "dns.hpp"         // SocketAddr, IpAddress
#include "prober.hpp"      // format_duration_debug -- Rust's {:?} on a Duration
#include "settings.hpp"    // Settings, for HEMERA_WG_NO_DATA_CHECK and HEMERA_WG_STALE_SECS
#include "transport.hpp"   // UdpIo, WinUdp, Arrived, InboundSink
#include "upstream.hpp"    // relay_target
#include "wireguard.hpp"   // Key, ClientId, Tunn, TunnResult, the three call sites

namespace hemera::core::wg_live {

// Cancel is coreflow's shared cancel flag (coreflow.hpp:262, itself an alias for localapi::Cancel);
// this path names it bare in every signature, so pull it in rather than re-qualify ten times.
using coreflow::Cancel;

// ---------------------------------------------------------------------------
// The log seam.
//
// Rust's log level for this crate defaults to info (lib.rs:82-88: "info,hemera={HEMERA_LOG_LEVEL}"),
// so the lines this path prints by default are the warn!, error! and info! ones; the trace! and
// debug! lines are carried at their own level rather than dropped, so a host running with
// --log-level debug sees exactly what the Rust would and a host at info sees exactly what it
// would not. coreflow.hpp's Level has no Trace arm and noize.hpp's has only Trace and Debug, so
// this path needs its own five; the ported text is identical either way.
enum class Level { Trace, Debug, Info, Warn, Error };

using Note = std::function<void(Level level, std::string_view line)>;

// ---------------------------------------------------------------------------
// The clock, the wait and the randomness.
//
// Rust uses Instant::now() everywhere on this path and tokio::time for the waiting. Here both are
// seams: a test hands a clock it advances itself and a wait that never blocks, so the 750 ms and
// 2000 ms retransmits and the 10 s verify timeout are exercised without a second of real wall time
// -- and without a socket that is not a fake.
using Clock = std::function<std::chrono::milliseconds()>;
// The host's tokio::time::sleep: block this thread for `d`, or until the wait's own condition.
using Sleep = std::function<void(std::chrono::milliseconds d)>;
// The readiness half of the select: wait up to `d` for a datagram. True when one is waiting, false
// when the time ran out -- which is Rust's sleep arm firing.
using Wait = std::function<bool(std::chrono::milliseconds d)>;
// rand::random::<u16>() / random_range(20000..60000) / the health jitter draw, in the three places
// the Rust asks for a random number on this path. Supplied so a probe packet is reproducible.
struct Random {
    std::function<std::uint16_t()> u16;
    std::function<std::uint16_t(std::uint16_t lo, std::uint16_t hi_exclusive)> u16_in;
    // 0..=n, the way Rust's random_range(0..=x) reads.
    std::function<std::uint64_t(std::uint64_t n)> up_to;
};

// The default clock: steady_clock since an arbitrary epoch, which is what Instant::now() is.
[[nodiscard]] Clock monotonic_clock();
// std::this_thread::sleep_for, the port's stand-in for tokio::time::sleep.
[[nodiscard]] Sleep thread_sleep();
// The randomness a live run uses: RAND_bytes through BoringSSL, never a hand-rolled generator.
[[nodiscard]] Random boringssl_random();

// ---------------------------------------------------------------------------
// The socket. Port of upstream.rs::bind_via_upstream (:610-625).
//
// bind the wildcard of the peer's family -> attach_detour -> relay_target(local, peer) -> connect.
// The two addresses are kept apart on purpose, because they are not the same thing and a caller
// must be able to tell which one a packet went to: `peer` is the WireGuard endpoint the account
// names, which the Rust carries (:89, :126) and only ever logs; `target` is where the socket is
// aimed, and it is relay_target's answer that --upstream changes.
struct WgSocket {
    transport::UdpIo* io = nullptr;
    SocketAddr peer{};
    SocketAddr target{};

    // sock.send(): the connected write. The destination carried is `target`, which is what the
    // connect aimed the socket at; UdpIo::send takes an address for the unconnected case and
    // WinUdp ignores it once connected (transport.cpp:249-259), so both arms of the Rust's choice
    // end up naming the same socket and the same destination.
    [[nodiscard]] std::expected<std::size_t, std::string> send(
        std::span<const std::uint8_t> packet) const;

    // sock.recv(): one datagram, nothing when the socket has none yet.
    [[nodiscard]] std::expected<std::optional<transport::Arrived>, std::string> recv() const;

    [[nodiscard]] SocketAddr local() const;
};

// bind_via_upstream's three steps, as far as this tree can take them. `make_io` is the socket
// factory -- WinUdp::open_for_peer in a real run, which is egress::udp_bind("0.0.0.0:0")/
// ("[::]:0") plus the non-blocking and buffer work (upstream.rs:616, transport.hpp:144-147), and a
// recording fake in a test -- and `relay` is upstream::relay_target, defaulted, so a caller that
// says nothing still gets the detour table. `connect` is upstream.rs:622's socket.connect(target);
// a WinUdp is connected, a fake may ignore it, which is why the resolved target also travels as the
// destination of every send this module makes.
struct OpenSeams {
    // The Settings the socket is opened with (SO_RCVBUF/SO_SNDBUF); a default one when unset.
    const Settings* settings = nullptr;
    std::function<std::expected<std::unique_ptr<transport::UdpIo>, std::string>(
        const SocketAddr& peer, const Settings& settings)>
        make_io;
    noize::RelayTarget relay;
    std::function<std::expected<void, std::string>(transport::UdpIo& io, const SocketAddr& target)>
        connect;
    // Where the "[+] {peer} is reached through the upstream relay" line goes, when a detour is
    // raised. Null stays silent, which is what a check wants (verify's own lines are all
    // trace!/debug!).
    Note note = nullptr;
};

// The socket and the ownership of it: Rust's `(UdpSocket, SocketAddr, DetourGuard)` tuple. The
// guard rides along because the detour only lives while it does: dropping it calls forget_detour
// and the socket's sends would go direct from then on.
struct OpenedSocket {
    WgSocket sock{};
    std::unique_ptr<transport::UdpIo> io;
    std::optional<upstream::DetourGuard> detour;
};

[[nodiscard]] std::expected<OpenedSocket, coreflow::Error> open_socket(const SocketAddr& peer,
                                                                       OpenSeams& seams);

// ---------------------------------------------------------------------------
// verify_endpoint / verify_endpoint_keep_session: wireguard.rs:526-721.
//
// The whole of it, in the Rust's order: bind_via_upstream (:568), the pre-handshake curtain when
// the profile is on (:573-575), Tunn::new with keepalive.unwrap_or(25) (:580-587), the initiation
// out of encapsulate(&[]) with the client id injected and the raw send at :606, then the loop
// (:614-720) racing the socket, the 250 ms timer and the deadline.
//
// The timer arm carries the retransmits -- the same init bytes again once 750 ms has gone and again
// once 2000 ms has (VERIFY_RETRY_DELAYS, :17-18, :688-699), which is what the Rust's own test
// (:899-934) asserts -- and update_timers' own handshake packet (:702-713).
//
// The cookie case is not a special branch here: a CookieReply makes decapsulate answer
// WriteToNetwork with the mac2 initiation, and the Rust's :654-678 arm sends exactly that one packet
// and then calls the handshake done. One reply, one re-initiation, no loop of its own -- the port
// keeps that, because keeping it is the difference between a retry and a stall.
struct VerifyParams {
    SocketAddr peer{};
    wireguard::Key private_key{};   // key material: never logged, never echoed
    wireguard::Key peer_public{};   // key material: never logged, never echoed
    wireguard::ClientId client_id{};
    IpAddress local_ipv4{};
    hemeranoize::HemeraNoizeConfig noise{};
    std::chrono::milliseconds timeout{10000};
    // Rust's Option<u16>: verify_endpoint_keep_session turns None into Some(25) at :584.
    std::optional<std::uint16_t> keepalive{};
    // HEMERA_WG_NO_DATA_CHECK, read the way :560 reads it: present disables, absent enables.
    const Settings* settings = nullptr;
};

struct VerifyEnv {
    Clock now;
    Sleep sleep;
    Wait wait;
    Random random;
    Note note;
};

// The port of Rust's EstablishedSession (:97-103): the tunnel and the socket that just completed a
// handshake, plus the peer and client id the loop needs. `obfuscation_sent` is true on the way out,
// because this socket has already been behind the noise -- which is exactly why
// WgTunnel::from_established starts obf_sent at true (wireguard.rs:147) and WgTunnel::new at false
// (:128).
struct LiveSession {
    WgSocket sock{};
    std::unique_ptr<wireguard::Tunn> tunn;
    SocketAddr peer{};
    wireguard::ClientId client_id{};
    bool obfuscation_sent = true;
    // The Duration verify_endpoint answers with (:646 the handshake's own, :638/:663 the
    // dataplane's). Kept on the session so the keep-session form and the plain form cannot disagree
    // about what was measured.
    std::chrono::milliseconds elapsed{0};
    // The socket this session owns, when open_socket made it. Moved into run_tunnel.
    std::unique_ptr<transport::UdpIo> owned;
    // The detour the socket is behind, when open_socket raised one. Moved into run_tunnel
    // beside the socket, because the detour only lives while the guard does.
    std::optional<upstream::DetourGuard> detour;
};

// wireguard.rs:550-721. Returns the elapsed time the Rust returns -- the handshake's own when
// HEMERA_WG_NO_DATA_CHECK is set (:646) and the dataplane round trip when it is not (:638, :663),
// which is the default -- and the session the tunnel runs on.
[[nodiscard]] std::expected<LiveSession, coreflow::Error>
verify_endpoint_keep_session(const VerifyParams& params, WgSocket& sock, const VerifyEnv& env,
                             const Cancel& cancel);

// wireguard.rs:526-548, which is that call with the session dropped on the floor.
[[nodiscard]] std::expected<std::chrono::milliseconds, coreflow::Error>
verify_endpoint(const VerifyParams& params, WgSocket& sock, const VerifyEnv& env,
                const Cancel& cancel);

// The one-call form the engine wants: it opens the socket through the seams, drives the handshake,
// and hands back the session or the failure. When `session` is requested the socket stays open in
// it; otherwise the socket closes here, as Rust's does when verify_endpoint drops the tuple.
struct VerifyJob {
    VerifyParams params;
    VerifyEnv env;
    OpenSeams open;
};

[[nodiscard]] std::expected<std::chrono::milliseconds, coreflow::Error>
verify_endpoint(VerifyJob job, const Cancel& cancel);
[[nodiscard]] std::expected<LiveSession, coreflow::Error>
verify_endpoint_keep_session(VerifyJob job, const Cancel& cancel);

// ---------------------------------------------------------------------------
// The dataplane confirmation: wireguard.rs:431-524.
//
// send_dataplane_probe encapsulates a synthetic cloudflare.com A query (:404-429, built by
// wireguard.hpp's build_dataplane_probe) and puts it on the wire; verify_dataplane wants
// DATAPLANE_REQUIRED_SUCCESSES (2) round trips, resending the probe every 700 ms (:471) and
// immediately after each confirmation after a DATAPLANE_PROBE_GAP (600 ms) floor (:508-511), and
// gives up at the deadline that the handshake's own timeout set.
//
// It is exposed because it is a loop with its own timing rules and because the two log lines the
// Rust writes inside it (:476-481, :499-506) are part of this path's output.
struct DataplaneEnv {
    Clock now;
    Sleep sleep;
    Wait wait;
    Random random;
    Note note;
};

[[nodiscard]] std::expected<void, coreflow::Error> send_dataplane_probe(
    WgSocket& sock, wireguard::Tunn& tunn, const wireguard::ClientId& client_id,
    std::span<const std::uint8_t> probe);

[[nodiscard]] std::expected<std::chrono::milliseconds, coreflow::Error> verify_dataplane(
    WgSocket& sock, wireguard::Tunn& tunn, const wireguard::ClientId& client_id,
    const IpAddress& local_ipv4, std::chrono::milliseconds start, std::chrono::milliseconds deadline,
    const DataplaneEnv& env);

// ---------------------------------------------------------------------------
// WgConfig and the run loop: wireguard.rs:72-95, :105-133, :154-349.
//
// Four tasks over one Arc<Mutex<Box<Tunn>>>, and the loop returns whichever of them finishes first
// (:326-346) with the other three aborted by the TaskGuard (:319-324, :42-50). Ported as four
// std::thread over a std::mutex around the same Tunn, and the first to stop wins: the rest are
// released through their stop flag and joined on the way out, which is the TaskGuard's Drop.
//
// The sends are the three wireguard.hpp call sites, and only those:
//   send_task's WriteToNetwork arm -> wireguard::send_data_packet  (wireguard.rs:243-265)
//   timer_task's update_timers arm -> wireguard::send_timer_packet (wireguard.rs:277-286)
//   health_task's probe send       -> plain inject + send, as wireguard.rs:438-443 writes it
// recv_task's reply send (:194-200) has no junk in front of it in Rust, so it has none here either.
struct TunnelConfig {
    wireguard::Key local_private_key{};  // key material: never logged, never echoed
    wireguard::Key peer_public_key{};    // key material: never logged, never echoed
    SocketAddr peer{};
    IpAddress local_ipv4{};
    IpAddress local_ipv6{};
    wireguard::ClientId client_id{};
    std::optional<wireguard::Key> preshared_key;
    std::optional<std::uint16_t> persistent_keepalive;
    hemeranoize::HemeraNoizeConfig noise{};

    // WgTunnel::new starts this false (:128); from_established starts it true (:147), because that
    // socket already ran the curtain during the verify. It is per-tunnel state, shared by the four
    // tasks in Rust through Arc<Mutex<bool>> and here through the loop's own mutex.
    bool obfuscation_sent = false;
};

// quic.rs's `outbound_rx` for this carrier: the netstack's produced IP packets. `try_recv` stands in
// for `recv()` -- it returns nothing when the queue is empty within `budget` -- and `closed()` is
// the channel being dropped, which is what ends the Rust's `while let Some(p) = ...` at :235 and
// makes the task print "wireguard send task ended" (:331-334).
struct OutboundSource {
    virtual ~OutboundSource() = default;
    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> try_recv(
        std::chrono::milliseconds budget) = 0;
    [[nodiscard]] virtual bool closed() const { return false; }
};

struct DataPlane {
    // inbound_tx: the packets the tunnel unsealed, as the stack sees them (transport::InboundSink).
    transport::InboundSink* inbound = nullptr;
    // outbound_rx: the packets the stack wants sealed.
    OutboundSource* outbound = nullptr;
};

struct RunEnv {
    Clock now;
    Sleep sleep;
    // The socket's readiness wait, which recv_task blocks in (:181).
    Wait wait;
    Random random;
    Note note;
    // HEMERA_WG_STALE_SECS through wireguard.hpp's wg_stale_timeout_ms (:556-558).
    const Settings* settings = nullptr;
    // The tick the timer task runs on; wireguard.hpp's timer_tick_ms (250 ms) when unset.
    std::chrono::milliseconds tick{static_cast<long long>(wireguard::timer_tick_ms)};
};

// WgTunnel::new's product plus the loop's channel ends. `sock` owns nothing when `owned` is empty,
// which is the case for a session handed over by verify_endpoint_keep_session.
struct Tunnel {
    TunnelConfig cfg;
    WgSocket sock{};
    DataPlane plane{};
    RunEnv env{};
    std::unique_ptr<wireguard::Tunn> tunn;
    std::unique_ptr<transport::UdpIo> owned;
    std::optional<upstream::DetourGuard> detour;
};

// The run, exactly as Rust's `WgTunnel::run(self, outbound_rx) -> Result<()>` reads (:154): it does
// not return until one of the four tasks ends, and the answer is that task's. "other: wireguard
// tunnel stale: no valid data from peer" is the health task's (:303-305); a cancelled run returns
// the Cancelled variant, which is the port's only addition and is documented at coreflow.hpp:960-964.
[[nodiscard]] std::expected<void, coreflow::Error> run_tunnel(Tunnel& tunnel,
                                                               const Cancel& cancel);

// The two constructors of Rust's WgTunnel, kept apart the way the Rust keeps them apart, because the
// difference between them is a security property: a tunnel built from a verified session must not
// run the curtain a second time, and one built fresh must.
[[nodiscard]] Tunnel tunnel_from_config(TunnelConfig cfg, WgSocket&& sock,
                                        std::unique_ptr<transport::UdpIo> owned, DataPlane plane,
                                        RunEnv env);
[[nodiscard]] Tunnel tunnel_from_session(LiveSession&& session,
                                         const hemeranoize::HemeraNoizeConfig& noise,
                                         DataPlane plane, RunEnv env,
                                         const IpAddress& local_ipv4);

} // namespace hemera::core::wg_live
