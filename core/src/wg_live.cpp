#include "wg_live.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <stdexcept>
#include <thread>
#include <utility>

#include <openssl/rand.h>

#include <condition_variable>

namespace hemera::core::wg_live {

namespace {

// The lines this path writes are Rust's, word for word, with Rust's own levels. wireguard.rs has no
// info! inside verify_endpoint and no trace! inside the hemeranoize calls, so nothing here invents
// one; a missing sink means the caller does not want to hear about it, which is what the port does
// everywhere else (noize.hpp:77-81).
void emit(const Note& note, Level level, const std::string& line) {
    if (note) note(level, std::string_view(line));
}

// Instant::now() on the steady clock, which is what Rust's monotonic instant is: it never goes
// backwards and has no relation to the wall clock.
std::chrono::milliseconds steady_now() {
    using namespace std::chrono;
    static const steady_clock::time_point epoch = steady_clock::now();
    return duration_cast<milliseconds>(steady_clock::now() - epoch);
}

// prober.hpp's Rust `{:?}` for a Duration, so "[wg] handshake done in 1.234s" reads the way the
// Rust prints it rather than the way a std::chrono::duration would.
std::string dur(std::chrono::milliseconds d) { return prober::format_duration_debug(d); }

// boringtun's NoiseError derives Debug, so Rust's `{e:?}` is the variant name. wireguard.hpp's
// message() gives the human text, which is a different string and belongs to the error paths that
// actually carry one; these two lines are trace!/warn! diagnostics and use the name.
std::string debug_noise_error(wireguard::WgError e) {
    using wireguard::WgError;
    switch (e) {
        case WgError::DestinationBufferTooSmall: return "DestinationBufferTooSmall";
        case WgError::IncorrectPacketLength: return "IncorrectPacketLength";
        case WgError::UnexpectedPacket: return "UnexpectedPacket";
        case WgError::WrongPacketType: return "WrongPacketType";
        case WgError::WrongIndex: return "WrongIndex";
        case WgError::WrongKey: return "WrongKey";
        case WgError::InvalidTai64nTimestamp: return "InvalidTai64nTimestamp";
        case WgError::WrongTai64nTimestamp: return "WrongTai64nTimestamp";
        case WgError::InvalidMac: return "InvalidMac";
        case WgError::InvalidAeadTag: return "InvalidAeadTag";
        case WgError::InvalidCounter: return "InvalidCounter";
        case WgError::DuplicateCounter: return "DuplicateCounter";
        case WgError::InvalidPacket: return "InvalidPacket";
        case WgError::NoCurrentSession: return "NoCurrentSession";
        case WgError::LockFailed: return "LockFailed";
        case WgError::ConnectionExpired: return "ConnectionExpired";
        case WgError::UnderLoad: return "UnderLoad";
    }
    return "InvalidPacket";
}

// Rust's `{:?}` on a &[u8] is `[1, 2, 3]`; on an empty slice, `[]`.
std::string debug_slice(std::span<const std::uint8_t> bytes) {
    std::string out = "[";
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) out += ", ";
        out += std::to_string(bytes[i]);
    }
    out += "]";
    return out;
}

std::string debug_addr(const IpAddress& addr) {
    if (addr.v4) {
        return std::to_string(addr.bytes[12]) + "." + std::to_string(addr.bytes[13]) + "." +
               std::to_string(addr.bytes[14]) + "." + std::to_string(addr.bytes[15]);
    }
    // Ipv6Addr's Debug is the condensed lowercase form; dns.hpp owns the address text, so the two
    // renderings cannot drift apart.
    SocketAddr full{addr, 0};
    std::string text = full.to_string();
    if (!text.empty() && text.front() == '[') text.erase(0, 1);
    if (!text.empty() && text.back() == ']') text.pop_back();
    const std::size_t colon = text.rfind(':');
    if (colon != std::string::npos) text.erase(colon);
    return text;
}

// TunnResult derives Debug in boringtun, so Rust's `{:?}` on it is the variant with its payload.
// wireguard.hpp's TunnResult owns its bytes rather than borrowing them, which is the one shape
// change the protocol port documented (wireguard.hpp:488-489); the rendering follows that shape.
std::string debug_tunn_result(const wireguard::TunnResult& res) {
    switch (res.kind) {
        case wireguard::TunnResult::Kind::Done: return "Done";
        case wireguard::TunnResult::Kind::Err: return "Err(" + debug_noise_error(res.error) + ")";
        case wireguard::TunnResult::Kind::WriteToNetwork:
            return "WriteToNetwork(" + debug_slice(res.bytes) + ")";
        case wireguard::TunnResult::Kind::WriteToTunnelV4: {
            IpAddress v4;
            v4.v4 = true;
            v4.bytes = {};
            for (std::size_t i = 0; i < 4; ++i) v4.bytes[12 + i] = res.v4[i];
            return "WriteToTunnelV4(" + debug_slice(res.bytes) + ", " + debug_addr(v4) + ")";
        }
        case wireguard::TunnResult::Kind::WriteToTunnelV6: {
            IpAddress v6;
            v6.v4 = false;
            v6.bytes = res.v6;
            return "WriteToTunnelV6(" + debug_slice(res.bytes) + ", " + debug_addr(v6) + ")";
        }
    }
    return "Done";
}

// The io::Error half of Rust's `?` on a socket call: HemeraError::Io renders as "io: {e}", and the
// text {e} carries is the one UdpIo already produced ("recv: socket error 10054" and friends --
// transport.cpp:164-167). Nothing is re-worded here, so a line that interpolates {e} on this path
// prints the same bytes the port prints everywhere else for the same failure.
coreflow::Error io_error(const std::string& text) {
    return coreflow::Error{coreflow::ErrorKind::Io, text};
}

std::expected<std::size_t, coreflow::Error> send_checked(WgSocket& sock,
                                                         std::span<const std::uint8_t> packet) {
    auto sent = sock.send(packet);
    if (!sent) return std::unexpected(io_error(sent.error()));
    return *sent;
}

// The WSAGetLastError codes behind the transient/fatal split of wireguard.rs:26-40, which Rust
// spells as std::io::ErrorKind. Windows has no NotConnected/HostUnreachable of its own, so the
// codes are the only thing to go on, and the text UdpIo hands back is "recv: socket error 10054".
// Anything the mapping does not know is Other, which wireguard::is_transient_socket_error treats as
// fatal -- the conservative side of the Rust's rule, and the side that cannot mask a dead socket.
wireguard::SocketErrorKind socket_kind(std::string_view text) {
    const std::size_t at = text.find("socket error ");
    if (at == std::string_view::npos) {
        if (text.find("would block") != std::string_view::npos) return wireguard::SocketErrorKind::WouldBlock;
        if (text.find("timed out") != std::string_view::npos) return wireguard::SocketErrorKind::TimedOut;
        return wireguard::SocketErrorKind::Other;
    }
    const long code = std::strtol(std::string(text.substr(at + 13)).c_str(), nullptr, 10);
    switch (code) {
        case 10061: return wireguard::SocketErrorKind::ConnectionRefused;
        case 10054: return wireguard::SocketErrorKind::ConnectionReset;
        case 10053: case 10056: case 10057: return wireguard::SocketErrorKind::ConnectionAborted;
        case 10065: case 11003: return wireguard::SocketErrorKind::HostUnreachable;
        case 10051: case 11010: return wireguard::SocketErrorKind::NetworkUnreachable;
        case 10004: return wireguard::SocketErrorKind::Interrupted;
        case 10035: return wireguard::SocketErrorKind::WouldBlock;
        case 10060: return wireguard::SocketErrorKind::TimedOut;
        case 10059: return wireguard::SocketErrorKind::NotConnected;
        case 10049: case 10048: return wireguard::SocketErrorKind::AddrNotAvailable;
        case 10013: return wireguard::SocketErrorKind::PermissionDenied;
        case 10022: return wireguard::SocketErrorKind::InvalidInput;
        default: return wireguard::SocketErrorKind::Other;
    }
}

// A std::function seam that was not handed one must never be the reason a run dies silently: the
// waits and the clock are required arguments of every entry point, and these refuse to guess.
[[noreturn]] void missing_seam(std::string_view name) {
    throw std::invalid_argument(std::string("wg_live: the ") + std::string(name) +
                                " seam is not wired");
}

std::chrono::milliseconds now_ms(const Clock& now) {
    if (!now) missing_seam("clock");
    return now();
}

void sleep_for(const Sleep& sleep, std::chrono::milliseconds d) {
    if (d.count() <= 0) return;
    if (!sleep) missing_seam("sleep");
    sleep(d);
}

bool wait_for(const Wait& wait, std::chrono::milliseconds d) {
    if (!wait) return true; // a caller with no readiness seam drives the socket itself
    if (d.count() < 0) d = std::chrono::milliseconds{0};
    return wait(d);
}

std::uint16_t draw_u16(const Random& random) {
    if (!random.u16) missing_seam("random");
    return random.u16();
}

} // namespace

// ---------------------------------------------------------------------------
// The default seams.

Clock monotonic_clock() {
    return [] { return steady_now(); };
}

Sleep thread_sleep() {
    return [](std::chrono::milliseconds d) {
        if (d.count() > 0) std::this_thread::sleep_for(d);
    };
}

Random boringssl_random() {
    Random out;
    out.u16 = [] {
        std::uint16_t value = 0;
        // rand::random::<u16>() in Rust; RAND_bytes here, because the port's rule is that all
        // randomness comes from BoringSSL (no hand-rolled generator, no std::mt19937 on a wire).
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof value) != 1) return std::uint16_t{0};
        return value;
    };
    out.u16_in = [](std::uint16_t lo, std::uint16_t hi_exclusive) {
        if (hi_exclusive <= lo) return lo;
        const std::uint32_t span = static_cast<std::uint32_t>(hi_exclusive) - lo;
        std::uint32_t raw = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&raw), sizeof raw) != 1) return lo;
        return static_cast<std::uint16_t>(lo + raw % span);
    };
    out.up_to = [](std::uint64_t n) {
        std::uint32_t raw = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&raw), sizeof raw) != 1) return std::uint64_t{0};
        return static_cast<std::uint64_t>(raw) % (n + 1);
    };
    return out;
}

// ---------------------------------------------------------------------------
// WgSocket.

std::expected<std::size_t, std::string> WgSocket::send(std::span<const std::uint8_t> packet) const {
    if (!io) return std::unexpected("send: the wireguard socket is not wired");
    return io->send(target, packet);
}

std::expected<std::optional<transport::Arrived>, std::string> WgSocket::recv() const {
    if (!io) return std::unexpected("recv: the wireguard socket is not wired");
    return io->receive();
}

SocketAddr WgSocket::local() const { return io ? io->local() : SocketAddr{}; }

std::expected<OpenedSocket, coreflow::Error> open_socket(const SocketAddr& peer, OpenSeams& seams) {
    // upstream.rs:611-616: the wildcard of the peer's family, port 0. WinUdp::open_for_peer is that
    // bind plus the non-blocking and buffer work, and it is the factory's default below.
    if (!seams.make_io) {
        return std::unexpected(coreflow::Error::other(
            "wireguard socket factory is not wired: no live socket can be opened"));
    }
    static const Settings k_default_settings{};
    const Settings& settings = seams.settings ? *seams.settings : k_default_settings;

    auto io = seams.make_io(peer, settings);
    if (!io) {
        // udp_bind's failure is an io error all the way up in Rust (`?` at upstream.rs:616).
        return std::unexpected(io_error(io.error()));
    }

    OpenedSocket opened;
    opened.io = std::move(*io);
    opened.sock.peer = peer;

    // upstream.rs:618-621: attach_detour, then local_addr(), then relay_target(local, peer). The
    // parse is the silent one: the "[+] dialling out through ..." announce belongs to the
    // memoized configured() read (https_runtime already made it), so a second announce here
    // would print the line twice per run.
    const SocketAddr local = opened.sock.local();
    if (const auto raw = settings.get("HEMERA_UPSTREAM")) {
        if (auto proxy = upstream::Upstream::parse(*raw)) {
            auto attached =
                upstream::attach_detour(*proxy, local, peer, local.ip.v4);
            if (!attached) return std::unexpected(io_error(attached.error()));
            opened.detour = std::move(*attached);
            // A local peer bypasses the proxy (attach_detour_via's early return): the guard is
            // empty and there is no relay to name.
            if (opened.detour->id() != 0) {
                emit(seams.note, Level::Info,
                     "[+] " + peer.to_string() +
                         " is reached through the upstream relay at " +
                         opened.detour->relay().to_string());
            }
        }
    }
    opened.sock.target = seams.relay ? seams.relay(local, peer) : upstream::relay_target(local, peer);

    // upstream.rs:622 socket.connect(target). The connect is what makes the Rust's sock.send() and
    // sock.recv() the peer-only calls they are; a socket that cannot connect still gets every send
    // aimed at `target` explicitly, so nothing silently travels somewhere else.
    if (seams.connect) {
        auto linked = seams.connect(*opened.io, opened.sock.target);
        if (!linked) return std::unexpected(io_error(linked.error()));
    }

    opened.sock.io = opened.io.get();
    return opened;
}

// ---------------------------------------------------------------------------
// The dataplane probe: wireguard.rs:404-524.

std::expected<void, coreflow::Error> send_dataplane_probe(
    WgSocket& sock, wireguard::Tunn& tunn, const wireguard::ClientId& client_id,
    std::span<const std::uint8_t> probe) {
    // wireguard.rs:438-449.
    auto result = tunn.encapsulate(probe);
    switch (result.kind) {
        case wireguard::TunnResult::Kind::WriteToNetwork: {
            auto bytes = std::move(result.bytes);
            wireguard::inject_client_id(std::span<std::uint8_t>{bytes}, client_id);
            auto sent = send_checked(sock, bytes);
            if (!sent) return std::unexpected(sent.error());
            return {};
        }
        case wireguard::TunnResult::Kind::Err:
            // :444-446, HemeraError::Other(format!("dataplane encap: {e:?}")).
            return std::unexpected(coreflow::Error::other("dataplane encap: " +
                                                          debug_noise_error(result.error)));
        default:
            // The Rust's `_ => {}`: Done and the two tunnel arms send nothing and fail nothing.
            return {};
    }
}

std::expected<std::chrono::milliseconds, coreflow::Error> verify_dataplane(
    WgSocket& sock, wireguard::Tunn& tunn, const wireguard::ClientId& client_id,
    const IpAddress& local_ipv4, std::chrono::milliseconds start,
    std::chrono::milliseconds deadline, const DataplaneEnv& env) {
    // wireguard.rs:463-471: one probe for the whole verify, built fresh (:404-429 with its three
    // random draws), sent once before the loop, and re-sent on the 700 ms resend clock from :471.
    std::array<std::uint8_t, 4> src{};
    for (std::size_t i = 0; i < 4; ++i) src[i] = local_ipv4.bytes[12 + i];
    const std::vector<std::uint8_t> probe = wireguard::build_dataplane_probe(
        src, draw_u16(env.random), draw_u16(env.random),
        env.random.u16_in ? env.random.u16_in(20000, 60000)
                          : static_cast<std::uint16_t>(20000));

    std::uint32_t successes = 0;
    auto last_probe_at = now_ms(env.now);
    auto first = send_dataplane_probe(sock, tunn, client_id, probe);
    if (!first) return std::unexpected(first.error()); // :470 is a `?`
    auto resend_at = last_probe_at + std::chrono::milliseconds(wireguard::dataplane_resend_ms);

    for (;;) {
        const auto now = now_ms(env.now);
        if (now >= deadline) {
            // :475-482.
            emit(env.note, Level::Debug,
                 "[wg] dataplane verify timed out (" + std::to_string(successes) + "/" +
                     std::to_string(wireguard::dataplane_required_successes) + " confirmations)");
            return std::unexpected(coreflow::Error::other("dataplane timeout"));
        }
        if (now >= resend_at) {
            // :484 `let _ =`, so a failed resend only means the next tick resends again.
            (void)send_dataplane_probe(sock, tunn, client_id, probe);
            last_probe_at = now;
            resend_at = now + std::chrono::milliseconds(wireguard::dataplane_resend_ms);
        }

        const auto to_deadline = deadline - now;
        const auto to_resend = resend_at - now;
        const auto slice = std::min(to_deadline, to_resend);
        const auto slice_ms = std::chrono::duration_cast<std::chrono::milliseconds>(slice);
        if (sock.wait_readable(slice_ms)) {
            // Socket has data ready
        } else if (!wait_for(env.wait, std::min(slice_ms, std::chrono::milliseconds(20)))) {
            continue;
        }

        // :492-520, the recv arm. A failure here is `r?`, an io error all the way up.
        auto arrived = sock.recv();
        if (!arrived) return std::unexpected(io_error(arrived.error()));
        if (!arrived->has_value()) continue;
        auto packet = std::move(arrived->value().packet);
        if (packet.empty()) continue;
        wireguard::strip_client_id(std::span<std::uint8_t>{packet});

        auto result = tunn.decapsulate(std::nullopt, std::span<const std::uint8_t>{packet});
        switch (result.kind) {
            case wireguard::TunnResult::Kind::WriteToTunnelV4:
            case wireguard::TunnResult::Kind::WriteToTunnelV6: {
                successes += 1;
                // :499-502. The elapsed is measured from the verify_endpoint start, not the
                // dataplane's own beginning, exactly as Rust passes `start` in at :637/:662, and
                // both lines take start.elapsed() at their own moment (:499 and :504).
                const auto confirmed = now_ms(env.now) - start;
                emit(env.note, Level::Debug,
                     "[wg] dataplane round-trip " + std::to_string(successes) + "/" +
                         std::to_string(wireguard::dataplane_required_successes) +
                         " confirmed in " + dur(confirmed));
                if (successes >= wireguard::dataplane_required_successes) {
                    const auto elapsed = now_ms(env.now) - start;
                    emit(env.note, Level::Debug, "[wg] dataplane ok in " + dur(elapsed));
                    return elapsed;
                }
                // :508-511: the next send is at least a probe gap away, but never in the past.
                const auto next_at =
                    std::max(now, last_probe_at +
                                      std::chrono::milliseconds(wireguard::dataplane_probe_gap_ms));
                (void)send_dataplane_probe(sock, tunn, client_id, probe);
                last_probe_at = next_at;
                resend_at = next_at + std::chrono::milliseconds(wireguard::dataplane_resend_ms);
                break;
            }
            case wireguard::TunnResult::Kind::WriteToNetwork: {
                // :513-517, the cookie/retransmit reply the state machine wants out. `let _ =`.
                auto bytes = std::move(result.bytes);
                wireguard::inject_client_id(std::span<std::uint8_t>{bytes}, client_id);
                (void)sock.send(bytes);
                break;
            }
            default:
                break; // :518 `_ => {}`
        }
    }
}

// ---------------------------------------------------------------------------
// verify_endpoint_keep_session: wireguard.rs:550-721.

namespace {

// The loop body shared by the two entry points, spelled out once because the Rust writes it once.
// Every arm, every log line and every `?` is where wireguard.rs puts it.
std::expected<LiveSession, coreflow::Error> drive_verify(const VerifyParams& params,
                                                        WgSocket& sock, const VerifyEnv& env,
                                                        const Cancel& cancel,
                                                        std::unique_ptr<transport::UdpIo> owned_io,
                                                        std::optional<upstream::DetourGuard> detour = {}) {
    // :560. std::env::var(..).is_err(): the mere presence of the name, even empty, disables it.
    const bool data_check =
        params.settings == nullptr || params.settings->find("HEMERA_WG_NO_DATA_CHECK") == nullptr;
    // :561-566.
    emit(env.note, Level::Trace,
         "[wg] verify " + params.peer.to_string() + " obf=" +
             (params.noise.is_enabled() ? "true" : "false") +
             " data_check=" + (data_check ? "true" : "false"));

    // :568 already happened -- the socket is the caller's, opened through open_socket, which is
    // bind_via_upstream. Nothing here re-derives the destination.
    const auto start = now_ms(env.now);
    const auto deadline = start + params.timeout;

    // :573-575, the curtain before Tunn::new at :580, so the initiation is the first thing that
    // arrives behind the noise. This is wireguard.cpp:2231's pre_handshake_obfuscation, which is
    // the :573 call site and carries the is_enabled() guard the Rust writes.
    // The socket this hands is aimed at `target`, which is what the connect did; `peer` travels as
    // the Rust's `_peer` does (hemeranoize.hpp:77-86).
    wireguard::pre_handshake_obfuscation(*sock.io, sock.target, params.noise);

    // :577-587. keepalive.unwrap_or(25), the same default wireguard.hpp:176 publishes.
    wireguard::Tunn::Config config;
    config.static_private = params.private_key;
    config.peer_static_public = params.peer_public;
    config.preshared_key = std::nullopt; // Tunn::new's third argument is None at :583
    config.persistent_keepalive = params.keepalive.value_or(wireguard::default_persistent_keepalive);
    config.index = 0; // :586, the global index Rust passes as 0
    // The clock travels by value, not as a reference into `env`: the session this function returns
    // outlives the call, and the Tunn it hands back keeps calling this clock for the rest of its
    // life. std::function copies are cheap and the seam is copyable by design.
    const Clock tunnel_clock = env.now;
    config.clock = [tunnel_clock] {
        return static_cast<std::uint64_t>(now_ms(tunnel_clock).count());
    };
    auto tunn = std::make_unique<wireguard::Tunn>(std::move(config));

    // :593-603. encapsulate(&[]) is the handshake kick-off; anything but WriteToNetwork is the
    // warn! at :600 and the Other("handshake init failed") at :601.
    auto first = tunn->encapsulate(std::span<const std::uint8_t>{});
    if (first.kind != wireguard::TunnResult::Kind::WriteToNetwork) {
        emit(env.note, Level::Warn, "[wg] unexpected encap result: " + debug_tunn_result(first));
        return std::unexpected(coreflow::Error::other("handshake init failed"));
    }
    std::vector<std::uint8_t> init_packet = std::move(first.bytes);
    wireguard::inject_client_id(std::span<std::uint8_t>{init_packet}, params.client_id);

    // :605-606.
    emit(env.note, Level::Trace, "[wg] sending init " + std::to_string(init_packet.size()) +
                                     " bytes to " + params.peer.to_string());
    {
        auto sent = send_checked(sock, init_packet);
        if (!sent) return std::unexpected(sent.error());
    }

    std::size_t retry_index = 0;
    std::uint32_t attempts = 0;
    // :609-611: the interval's immediate first tick is consumed before the loop, so the timer arm
    // first runs one TICK later.
    auto timer_due = start + std::chrono::milliseconds(wireguard::timer_tick_ms);

    for (;;) {
        // The port's addition, documented at coreflow.hpp:960-964: a synchronous run checks the flag
        // before it does any work, so a cancelled verify never reports a timeout it did not wait for.
        if (cancel.is_cancelled()) {
            return std::unexpected(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
        }

        const auto now = now_ms(env.now);
        if (now >= deadline) {
            // :615-618.
            emit(env.note, Level::Trace,
                 "[wg] timeout after " + std::to_string(attempts) + " recv attempts");
            return std::unexpected(coreflow::Error::other("verify timeout"));
        }

        const auto remaining = deadline - now;
        const auto slice = std::min(remaining, timer_due - now);
        const auto slice_ms = std::chrono::duration_cast<std::chrono::milliseconds>(slice);
        bool ready = false;
        if (sock.wait_readable(slice_ms)) {
            ready = true;
        } else {
            ready = wait_for(env.wait, std::min(slice_ms, std::chrono::milliseconds(20)));
        }

        if (ready) {
            auto arrived = sock.recv();
            if (!arrived) return std::unexpected(io_error(arrived.error())); // :625 `let n = r?`
            if (arrived->has_value()) {
                attempts += 1; // :624, counted before the zero-length skip, as Rust does
                auto packet = std::move(arrived->value().packet);
                if (packet.empty()) continue; // :626-628
                emit(env.note, Level::Trace, "[wg] recv " + std::to_string(packet.size()) +
                                                 " bytes (attempt " + std::to_string(attempts) + ")");
                wireguard::strip_client_id(std::span<std::uint8_t>{packet});

                auto result =
                    tunn->decapsulate(std::nullopt, std::span<const std::uint8_t>{packet});

                // :632-685. The two success arms differ only in whether a packet has to go out
                // first, so the finish is one block.
                bool established_now = false;
                std::chrono::milliseconds handshake_elapsed{0};
                switch (result.kind) {
                    case wireguard::TunnResult::Kind::Done:
                        handshake_elapsed = now_ms(env.now) - start;
                        emit(env.note, Level::Trace,
                             "[wg] handshake done in " + dur(handshake_elapsed));
                        established_now = true;
                        break;
                    case wireguard::TunnResult::Kind::WriteToNetwork: {
                        // This is the cookie path as surely as it is the response path: a
                        // CookieReply makes decapsulate answer with the mac2 initiation, and the
                        // Rust sends that one packet and calls the handshake good (:654-678).
                        auto bytes = std::move(result.bytes);
                        wireguard::inject_client_id(std::span<std::uint8_t>{bytes},
                                                    params.client_id);
                        emit(env.note, Level::Trace, "[wg] sending response " +
                                                         std::to_string(bytes.size()) + " bytes");
                        auto sent = send_checked(sock, bytes);
                        if (!sent) return std::unexpected(sent.error()); // :658 `?`
                        handshake_elapsed = now_ms(env.now) - start;
                        emit(env.note, Level::Trace,
                             "[wg] handshake success in " + dur(handshake_elapsed));
                        established_now = true;
                        break;
                    }
                    case wireguard::TunnResult::Kind::Err:
                        emit(env.note, Level::Trace,
                             "[wg] decap error: " + debug_noise_error(result.error));
                        break;
                    default:
                        emit(env.note, Level::Trace,
                             "[wg] unexpected decap: " + debug_tunn_result(result));
                        break;
                }

                if (established_now) {
                    std::chrono::milliseconds elapsed = handshake_elapsed;
                    if (data_check) {
                        // :637/:662, and the returned Duration is the dataplane's, not the
                        // handshake's (:638/:663).
                        DataplaneEnv dp_env{env.now, env.sleep, env.wait, env.random, env.note};
                        auto dp = verify_dataplane(sock, *tunn, params.client_id,
                                                   params.local_ipv4, start, deadline, dp_env);
                        if (!dp) return std::unexpected(dp.error());
                        elapsed = *dp;
                    }
                    LiveSession session;
                    session.sock = sock;
                    session.tunn = std::move(tunn);
                    session.peer = params.peer;
                    session.client_id = params.client_id;
                    session.elapsed = elapsed;
                    // wireguard.rs:147: this socket has been behind the noise, so WgTunnel::new
                    // would be starting the curtain a second time.
                    session.obfuscation_sent = true;
                    session.owned = std::move(owned_io);
                    session.detour = std::move(detour);
                    return session;
                }
            }
        }

        const auto after = now_ms(env.now);
        if (after < timer_due) continue; // the deadline check waits for the next turn, as Rust's does

        // :687-714, the timer arm.
        timer_due = after + std::chrono::milliseconds(wireguard::timer_tick_ms);

        // :688-699. VERIFY_RETRY_DELAYS is [750ms, 2000ms]: the identical init packet goes out again
        // once each of those has been passed, and never a third time.
        if (retry_index < std::size(wireguard::verify_retry_delays_ms)) {
            const auto delay = std::chrono::milliseconds(
                wireguard::verify_retry_delays_ms[retry_index]);
            if (after - start >= delay) {
                retry_index += 1;
                emit(env.note, Level::Trace,
                     "[wg] retransmitting init to " + params.peer.to_string() + " after " +
                         dur(delay) + " (" + std::to_string(retry_index) + "/" +
                         std::to_string(std::size(wireguard::verify_retry_delays_ms)) + ")");
                auto sent = send_checked(sock, init_packet);
                if (!sent) return std::unexpected(sent.error()); // :698 `?`
            }
        }

        auto timed = tunn->update_timers();
        switch (timed.kind) {
            case wireguard::TunnResult::Kind::WriteToNetwork: {
                auto bytes = std::move(timed.bytes);
                wireguard::inject_client_id(std::span<std::uint8_t>{bytes}, params.client_id);
                emit(env.note, Level::Trace, "[wg] timer generated " +
                                                 std::to_string(bytes.size()) +
                                                 " byte handshake packet");
                auto sent = send_checked(sock, bytes);
                if (!sent) return std::unexpected(sent.error()); // :707 `?`
                break;
            }
            case wireguard::TunnResult::Kind::Err:
                // :709-711, the only error the timer arm can raise.
                return std::unexpected(coreflow::Error::other("wireguard timer failed: " +
                                                              debug_noise_error(timed.error)));
            default:
                break; // :712 `_ => {}`
        }
    }
}

} // namespace

std::expected<LiveSession, coreflow::Error>
verify_endpoint_keep_session(const VerifyParams& params, WgSocket& sock, const VerifyEnv& env,
                             const Cancel& cancel) {
    return drive_verify(params, sock, env, cancel, nullptr);
}

std::expected<std::chrono::milliseconds, coreflow::Error>
verify_endpoint(const VerifyParams& params, WgSocket& sock, const VerifyEnv& env,
                const Cancel& cancel) {
    // :526-548: the elapsed time, and the session dropped on the floor -- which closes the socket
    // with it in Rust, because the tuple is the only owner. A caller that wants the tunnel to carry
    // on from this handshake calls the keep-session form instead.
    auto session = drive_verify(params, sock, env, cancel, nullptr);
    if (!session) return std::unexpected(session.error());
    return session->elapsed;
}

std::expected<std::chrono::milliseconds, coreflow::Error> verify_endpoint(VerifyJob job,
                                                                         const Cancel& cancel) {
    OpenSeams& seams = job.open;
    auto opened = open_socket(job.params.peer, seams);
    if (!opened) return std::unexpected(opened.error());
    auto session = drive_verify(job.params, opened->sock, job.env, cancel, std::move(opened->io),
                                std::move(opened->detour));
    if (!session) return std::unexpected(session.error());
    const auto elapsed = session->elapsed;
    return elapsed;
}

std::expected<LiveSession, coreflow::Error> verify_endpoint_keep_session(VerifyJob job,
                                                                        const Cancel& cancel) {
    OpenSeams& seams = job.open;
    auto opened = open_socket(job.params.peer, seams);
    if (!opened) return std::unexpected(opened.error());
    return drive_verify(job.params, opened->sock, job.env, cancel, std::move(opened->io),
                        std::move(opened->detour));
}

// ---------------------------------------------------------------------------
// WgTunnel::run: wireguard.rs:154-349.
//
// Four threads over one Tunn under one mutex, and the first to stop wins: the rest are
// released through the shared stop flag and joined on the way out, which is the TaskGuard's
// Drop. The sends are the three wireguard.hpp call sites, and only those.

namespace {

struct RunShared {
    std::mutex mutex;
    std::condition_variable done_cv;
    bool done = false;
    // Nothing is Ok(()), an error the tunnel's own answer -- Rust's select, first-past-the-post.
    std::optional<coreflow::Error> error;
    std::atomic<bool> stop{false};

    void finish(std::optional<coreflow::Error> err) {
        {
            const std::lock_guard<std::mutex> lock(mutex);
            if (done) return;
            done = true;
            error = std::move(err);
        }
        stop.store(true);
        done_cv.notify_all();
    }
};

// The port's addition (coreflow.hpp:960-964) aside, every sleep down here is a Rust sleep sliced
// against the stop flag, so a finished run joins in ~50 ms no matter which wait a thread is in.
void sleep_sliced(const Sleep& sleep, std::chrono::milliseconds total, const RunShared& shared,
                  const Cancel& cancel) {
    auto left = total;
    while (left.count() > 0 && !shared.stop.load() && !cancel.is_cancelled()) {
        const auto chunk = std::min(left, std::chrono::milliseconds(50));
        sleep_for(sleep, chunk);
        left -= chunk;
    }
}

} // namespace

Tunnel tunnel_from_config(TunnelConfig cfg, WgSocket&& sock, std::unique_ptr<transport::UdpIo> owned,
                           DataPlane plane, RunEnv env) {
    // WgTunnel::new (:106-133): the socket is the caller's (bound through bind_via_upstream),
    // Tunn::new takes the keys with keepalive and index 0, and the curtain latch starts false.
    wireguard::Tunn::Config tunn_config;
    tunn_config.static_private = cfg.local_private_key;
    tunn_config.peer_static_public = cfg.peer_public_key;
    tunn_config.preshared_key = cfg.preshared_key;
    tunn_config.persistent_keepalive = cfg.persistent_keepalive.value_or(0);
    tunn_config.index = 0;
    const Clock tunnel_clock = env.now;
    tunn_config.clock = [tunnel_clock] {
        return static_cast<std::uint64_t>(now_ms(tunnel_clock).count());
    };
    Tunnel tunnel;
    tunnel.cfg = std::move(cfg);
    tunnel.sock = std::move(sock);
    tunnel.tunn = std::make_unique<wireguard::Tunn>(std::move(tunn_config));
    tunnel.owned = std::move(owned);
    tunnel.plane = plane;
    tunnel.env = std::move(env);
    return tunnel;
}

Tunnel tunnel_from_session(LiveSession&& session, const hemeranoize::HemeraNoizeConfig& noise,
                           DataPlane plane, RunEnv env, const IpAddress& local_ipv4) {
    // WgTunnel::from_established (:135-152): the session's Tunn and socket carry on, and the
    // curtain latch starts true because that socket has already been behind the noise.
    Tunnel tunnel;
    tunnel.cfg.peer = session.peer;
    tunnel.cfg.local_ipv4 = local_ipv4;
    tunnel.cfg.client_id = session.client_id;
    tunnel.cfg.noise = noise;
    tunnel.cfg.obfuscation_sent = true;
    tunnel.sock = session.sock;
    tunnel.tunn = std::move(session.tunn);
    tunnel.owned = std::move(session.owned);
    tunnel.detour = std::move(session.detour);
    tunnel.plane = plane;
    tunnel.env = std::move(env);
    return tunnel;
}

std::expected<void, coreflow::Error> run_tunnel(Tunnel& tunnel, const Cancel& cancel) {
    wireguard::Tunn& tunn = *tunnel.tunn;
    WgSocket& sock = tunnel.sock;
    const RunEnv& env = tunnel.env;
    const SocketAddr peer = tunnel.cfg.peer;
    const wireguard::ClientId client_id = tunnel.cfg.client_id;
    const hemeranoize::HemeraNoizeConfig noise = tunnel.cfg.noise;

    RunShared shared;
    std::mutex tunn_mutex;
    std::mutex rx_mutex;
    auto last_valid_rx = now_ms(env.now);
    bool obfuscation_sent = tunnel.cfg.obfuscation_sent;
    bool post_hs_junk_sent = false;

    auto note = [&](Level level, const std::string& line) { emit(env.note, level, line); };
    const std::chrono::milliseconds tick =
        env.tick.count() > 0 ? env.tick : std::chrono::milliseconds(wireguard::timer_tick_ms);

    // The recv task (:176-230).
    std::thread recv([&] {
        std::uint32_t transient_errors = 0;
        while (!shared.stop.load() && !cancel.is_cancelled()) {
            auto arrived = sock.recv();
            if (!arrived) {
                const auto kind = socket_kind(arrived.error());
                if (wireguard::is_transient_socket_error(kind)) {
                    transient_errors += 1;
                    if (transient_errors > wireguard::max_transient_recv_errors) {
                        note(Level::Error, "recv error: " + arrived.error() + "; giving up after " +
                                               std::to_string(transient_errors) +
                                               " consecutive transient failures");
                        shared.finish(io_error(arrived.error()));
                        return;
                    }
                    note(Level::Debug, "transient recv error: " + arrived.error() +
                                           "; keeping the tunnel and retrying");
                    sleep_sliced(env.sleep,
                                 std::chrono::milliseconds(wireguard::transient_recv_backoff_ms),
                                 shared, cancel);
                    continue;
                }
                note(Level::Error, "recv error: " + arrived.error());
                shared.finish(io_error(arrived.error()));
                return;
            }
            if (!arrived->has_value()) {
                if (sock.wait_readable(std::chrono::milliseconds(20))) {
                    continue;
                }
                if (shared.stop.load() || cancel.is_cancelled()) break;
                continue;
            }
            auto packet = std::move(arrived->value().packet);
            if (packet.empty()) continue; // :182, Ok(0)
            transient_errors = 0;
            wireguard::strip_client_id(std::span<std::uint8_t>{packet});
            wireguard::TunnResult result;
            {
                const std::lock_guard<std::mutex> lock(tunn_mutex);
                result = tunn.decapsulate(std::nullopt, std::span<const std::uint8_t>{packet});
            }
            switch (result.kind) {
                case wireguard::TunnResult::Kind::Done: {
                    const std::lock_guard<std::mutex> lock(rx_mutex);
                    last_valid_rx = now_ms(env.now);
                    break;
                }
                case wireguard::TunnResult::Kind::Err:
                    note(Level::Trace, "decapsulate error: " + debug_noise_error(result.error));
                    break;
                case wireguard::TunnResult::Kind::WriteToNetwork: {
                    {
                        const std::lock_guard<std::mutex> lock(rx_mutex);
                        last_valid_rx = now_ms(env.now);
                    }
                    wireguard::inject_client_id(std::span<std::uint8_t>{result.bytes}, client_id);
                    (void)sock.send(result.bytes); // :199 `let _ =`
                    break;
                }
                case wireguard::TunnResult::Kind::WriteToTunnelV4:
                case wireguard::TunnResult::Kind::WriteToTunnelV6: {
                    {
                        const std::lock_guard<std::mutex> lock(rx_mutex);
                        last_valid_rx = now_ms(env.now);
                    }
                    if (tunnel.plane.inbound != nullptr) {
                        (void)tunnel.plane.inbound->try_send(
                            std::span<const std::uint8_t>{result.bytes});
                    }
                    break;
                }
            }
        }
        if (cancel.is_cancelled()) {
            shared.finish(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
        }
    });

    // The send task (:232-269).
    std::thread send([&] {
        if (tunnel.plane.outbound == nullptr) return; // nothing will ever arrive; not the run's end
        while (!shared.stop.load() && !cancel.is_cancelled()) {
            auto next = tunnel.plane.outbound->try_recv(std::chrono::milliseconds(100));
            if (!next.has_value()) {
                if (tunnel.plane.outbound->closed()) {
                    note(Level::Info, "wireguard send task ended");
                    shared.finish(std::nullopt);
                    return;
                }
                continue;
            }
            wireguard::TunnResult result;
            {
                const std::lock_guard<std::mutex> lock(tunn_mutex);
                result = tunn.encapsulate(std::span<const std::uint8_t>{*next});
            }
            switch (result.kind) {
                case wireguard::TunnResult::Kind::Done:
                    break;
                case wireguard::TunnResult::Kind::Err:
                    note(Level::Trace, "encapsulate error: " + debug_noise_error(result.error));
                    break;
                case wireguard::TunnResult::Kind::WriteToNetwork: {
                    wireguard::inject_client_id(std::span<std::uint8_t>{result.bytes}, client_id);
                    // wireguard.rs:246: drop(tunn) before anything that can sleep or fail -- the
                    // curtain and the send run without the Tunn lock, so the recv, timer and
                    // health arms never wait behind them.
                    if (sock.io != nullptr) {
                        wireguard::send_data_packet(*sock.io, sock.target, noise, result.bytes,
                                                   obfuscation_sent, post_hs_junk_sent);
                    }
                    break;
                }
                default:
                    break; // :266, the tunnel arms never come out of encapsulate
            }
        }
        if (cancel.is_cancelled()) {
            shared.finish(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
        }
    });

    // The timer task (:271-288).
    std::thread timer([&] {
        while (!shared.stop.load() && !cancel.is_cancelled()) {
            sleep_sliced(env.sleep, tick, shared, cancel);
            if (shared.stop.load() || cancel.is_cancelled()) break;
            wireguard::TunnResult timed;
            {
                const std::lock_guard<std::mutex> lock(tunn_mutex);
                timed = tunn.update_timers();
            }
            if (timed.kind == wireguard::TunnResult::Kind::WriteToNetwork) {
                wireguard::inject_client_id(std::span<std::uint8_t>{timed.bytes}, client_id);
                if (sock.io != nullptr) wireguard::send_timer_packet(*sock.io, noise, timed.bytes);
            }
        }
        if (cancel.is_cancelled()) {
            shared.finish(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
        }
    });

    // The health task (:291-317).
    std::thread health([&] {
        const std::uint64_t stale_ms =
            env.settings != nullptr ? wireguard::wg_stale_timeout_ms(*env.settings)
                                    : wireguard::wg_stale_default_secs * 1000;
        std::array<std::uint8_t, 4> src{};
        for (std::size_t i = 0; i < 4; ++i) src[i] = tunnel.cfg.local_ipv4.bytes[12 + i];
        while (!shared.stop.load() && !cancel.is_cancelled()) {
            const std::uint64_t offset =
                env.random.up_to ? env.random.up_to(2 * wireguard::wg_healthcheck_jitter_ms) : 0;
            sleep_sliced(env.sleep,
                         std::chrono::milliseconds(wireguard::health_check_pause_ms(offset)), shared,
                         cancel);
            if (shared.stop.load() || cancel.is_cancelled()) break;
            std::chrono::milliseconds idle_for;
            {
                const std::lock_guard<std::mutex> lock(rx_mutex);
                idle_for = now_ms(env.now) - last_valid_rx;
            }
            if (idle_for.count() >= static_cast<long long>(stale_ms)) {
                note(Level::Warn, "[wg] no valid data from peer " + peer.to_string() + " in " +
                                      dur(idle_for) + "; tunnel considered dead");
                shared.finish(
                    coreflow::Error::other("wireguard tunnel stale: no valid data from peer"));
                return;
            }
            const std::vector<std::uint8_t> probe = wireguard::build_dataplane_probe(
                src, draw_u16(env.random), draw_u16(env.random),
                env.random.u16_in ? env.random.u16_in(20000, 60000)
                                  : static_cast<std::uint16_t>(20000));
            {
                const std::lock_guard<std::mutex> lock(tunn_mutex);
                if (auto probe_sent = send_dataplane_probe(sock, tunn, client_id, probe);
                    !probe_sent) {
                    note(Level::Trace,
                         "[wg] health probe send failed: " + probe_sent.error().display());
                }
            }
        }
        if (cancel.is_cancelled()) {
            shared.finish(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
        }
    });

    {
        std::unique_lock<std::mutex> lock(shared.mutex);
        while (!shared.done && !cancel.is_cancelled()) {
            shared.done_cv.wait_for(lock, std::chrono::milliseconds(50));
        }
    }
    // The select's other arm: a cancelled run reads as Cancelled, whatever won the race -- the
    // port's only addition, documented at coreflow.hpp:960-964.
    if (cancel.is_cancelled() && !shared.done) {
        shared.finish(coreflow::Error{coreflow::ErrorKind::Cancelled, {}});
    }
    shared.stop.store(true);
    if (recv.joinable()) recv.join();
    if (send.joinable()) send.join();
    if (timer.joinable()) timer.join();
    if (health.joinable()) health.join();

    if (!shared.error.has_value()) return {};
    return std::unexpected(*shared.error);
}

} // namespace hemera::core::wg_live
