#pragma once

// The live transport: the socket, the QUIC connection and the MASQUE request the tunnel runs on.
//
// Every other module of this port decides something and then hands the bytes to somebody else. This
// is that somebody else. It is the port of the socket half of quic.rs -- bind_udp_fast, the version
// bait, tls::build_config, quiche::connect, the h3 connection and its connect-ip request, the
// datagram pump in both directions, the 20 second keepalive, the data-plane validation and the
// closes -- rebuilt on ngtcp2 + BoringSSL + nghttp3 instead of quiche, which is the pairing the
// spike at core/spike/quic_ngtcp2.c proved against a live WARP edge.
//
// What is NOT here, on purpose: the decisions. Sizes, timeouts, transport parameters, the shaping
// switches, the ECH key, the pins, the capsule and ip-datagram framings and every limit come from
// quic.hpp, tls.hpp, masque.hpp and Settings, which are already ported and tested; this module
// reads them and acts. Where the Rust put a tokio task, a channel and an Instant between those
// decisions and the socket, this module puts the seams below: an injected clock (`now` on every
// call, the way netstack.hpp does it), an injected socket (UdpIo, of which WinUdp is the real WS2
// one), bounded queues for what comes off the tunnel, and a random source, so the whole bring-up
// can be driven without a network.
//
// The pump is synchronous. open() brings the context, the socket and the connection into being and
// sends nothing yet; tick(now) does one turn of quic.rs's run loop -- drain the socket, arm the
// timers, handle expiry, poll h3, drain datagrams, flush, notice a close -- and reports the delay
// the Rust select loop would have slept for. A host with a real socket calls tick from its own
// readiness loop; a test calls it with a fake socket and a clock it controls.

#include "masque.hpp" // the ip-datagram codec the pump frames through
#include "quic.hpp"   // TunnelConfig, TransportParams, the sizes and the timeouts
#include "settings.hpp"

#include <openssl/ssl.h>

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
#include <vector>

namespace hemera::core::transport {

// The engine's clock, the same convention netstack.hpp uses: every deadline is one of these and
// every one is handed in by the caller.
using TimePoint = std::chrono::steady_clock::time_point;
using Millis = std::chrono::milliseconds;

// ---------------------------------------------------------------------------
// The close, and what it means. Declared ahead of the seams because an observer reads one.

// One CONNECTION_CLOSE, from either side, in the shape quic.rs logs it:
// "peer closed: code=0x174 app=false reason=".
struct CloseInfo {
    bool from_peer = false;
    // quiche's `is_app`: an application error code rather than a transport (or crypto) one. The
    // distinction is what makes tls::ech_rejected refuse to read a 0x179 that only looks like one.
    bool application_error = false;
    std::uint64_t code = 0;
    std::string reason;

    [[nodiscard]] bool operator==(const CloseInfo&) const = default;

    // "peer closed: ..." / "local closed: ...", with the code in hex and the reason after it, as
    // quic.rs:551-571 formats both.
    [[nodiscard]] std::string text() const;
};

// What a close of that shape means, so a caller can tell the one that needs a device certificate
// from the one that needs an ECH retry.
enum class CloseCause {
    None,
    // Application close 0x00: the tunnel's own "bye", "eof" or a plain peer goodbye.
    Normal,
    // No answer inside the idle timeout the transport parameters named.
    Idle,
    // Crypto alert 116 (transport 0x174): the edge asked for a certificate and got no Certificate
    // message. The WARP MASQUE edge does this to a handshake without the device certificate, which
    // is why bring-up installs it.
    CertificateRequired,
    // Crypto alert 121 (transport 0x179): our own ech_required, the one case a retry config exists
    // for. tls::ech_rejected is the authority on this; it is what CloseCause::EchRejected mirrors.
    EchRejected,
    // The data-plane validation deadline, which quic.rs closes with before it returns.
    ValidationTimeout,
    // A reset of the connection id or a stateless reset: nothing the reason field explains.
    Reset,
    // Anything else the peer or we decided.
    Other,
};

[[nodiscard]] CloseCause classify_close(const CloseInfo& close);

// ---------------------------------------------------------------------------
// The seams.

// The room a bounded queue answers, in the words quic.rs's mpsc channels give: Accepted is
// try_send's Ok, Full and Closed are its two TrySendError arms.
enum class Room {
    Accepted,
    Full,
    Closed,
};

// One datagram off the socket: quic.rs's `Ok((n, observed))` from recv_from.
struct Arrived {
    SocketAddr from;
    std::vector<std::uint8_t> packet;

    [[nodiscard]] bool from_peer(const SocketAddr& peer) const;
};

// The UDP socket the session speaks through -- bind_udp_fast's product, minus tokio. Both calls are
// non-blocking, because the pump that owns this session owns the sleeping.
struct UdpIo {
    virtual ~UdpIo() = default;

    // sock.local_addr(), the address the session was bound to.
    [[nodiscard]] virtual SocketAddr local() const = 0;

    // send_to: the bytes the kernel took, or the error text. quic.rs's flush writes every packet the
    // connection produces; a short write is an error, as Rust's `?` makes it.
    [[nodiscard]] virtual std::expected<std::size_t, std::string> send(
        const SocketAddr& to, std::span<const std::uint8_t> packet) = 0;

    // recv_from: the datagram, nothing when the socket would block, the error text when it is gone.
    [[nodiscard]] virtual std::expected<std::optional<Arrived>, std::string> receive() = 0;

    // wait_readable: waits up to timeout for datagram arrival using kernel select.
    [[nodiscard]] virtual bool wait_readable(std::chrono::milliseconds /*timeout*/) { return false; }
};

// The real UdpIo: a non-blocking WS2 datagram socket, bound, buffered and marked the way
// bind_udp_fast leaves it.
class WinUdp : public UdpIo {
public:
    // socket + FIONBIO + the profile's SO_RCVBUF/SO_SNDBUF + bind. `bind` names the family and may
    // carry port 0, which lets the system pick; quic.rs reaches for that through bind_addr_for().
    // egress::apply's firewall mark is a Unix socket option, so on Windows there is nothing to
    // apply and the mark stays where egress.hpp left it.
    [[nodiscard]] static std::expected<std::unique_ptr<WinUdp>, std::string>
    open(const SocketAddr& bind, const Settings& settings);

    // The same, bound to the wildcard of the peer's family: quic.rs's
    // bind_udp_fast(bind_addr_for(&peer)).
    [[nodiscard]] static std::expected<std::unique_ptr<WinUdp>, std::string>
    open_for_peer(const SocketAddr& peer, const Settings& settings);

    ~WinUdp() override;
    WinUdp(const WinUdp&) = delete;
    WinUdp& operator=(const WinUdp&) = delete;

    // verify_masque's sock.connect(relay_target(local, peer)): after it, an unset destination means
    // the connected peer, which is what makes the bait's `sock.send` and the flush's `sock.send` the
    // same call as it is in Rust.
    [[nodiscard]] std::expected<void, std::string> connect_to(const SocketAddr& peer);
    [[nodiscard]] bool connected() const;
    [[nodiscard]] bool wait_readable(std::chrono::milliseconds timeout) override;

    [[nodiscard]] SocketAddr local() const override;
    [[nodiscard]] std::expected<std::size_t, std::string> send(
        const SocketAddr& to, std::span<const std::uint8_t> packet) override;
    [[nodiscard]] std::expected<std::optional<Arrived>, std::string> receive() override;

private:
    WinUdp() = default;

    struct Impl;
    std::shared_ptr<Impl> impl_;
};

// The inbound data plane: quic.rs's `inbound_tx`, the channel the netstack reads its tunnel traffic
// off. A Full answer drops the packet and counts it (Rust's trace! line); a Closed one stops the
// drain, which is how Rust learns the stack went away.
struct InboundSink {
    virtual ~InboundSink() = default;
    [[nodiscard]] virtual Room try_send(std::span<const std::uint8_t> ip_packet) = 0;
};

// The address the edge assigns: quic.rs's `addr_tx`, a try_send that ignores a full queue.
struct AddressSink {
    virtual ~AddressSink() = default;
    [[nodiscard]] virtual Room try_send(const quic::AssignedAddr& assigned) = 0;
};

// The lines quic.rs writes to log::, at one seam. Everything the Rust prints is here, and nothing
// that would name a credential: the certificate, the key and the ECH key are always lengths.
struct Observer {
    virtual ~Observer() = default;

    // log::info!/debug!/trace!, already formatted the way the Rust writes them: the alpn line,
    // "connect-ip request sent on stream 0", "[*] validating masque data-plane before exposing
    // socks5", the probe round trips, "edge assigned 172.16.0.2/24", the close lines.
    virtual void on_note(std::string_view line) { (void)line; }
    // The once-per-process notice tls::install_verification hands back.
    virtual void on_verification(std::string_view line) { (void)line; }
    // The close, whichever side asked for it.
    virtual void on_close(const CloseInfo& close) { (void)close; }
    // The capsule's assignment, as well as the note about it.
    virtual void on_assigned(const quic::AssignedAddr& assigned) { (void)assigned; }
    // The connect-ip answer, as well as the note about it.
    virtual void on_status(std::uint16_t status) { (void)status; }
};

// ---------------------------------------------------------------------------
// The numbers bring-up runs on.

// Whether this session is the tunnel (quic.rs::run) or the throwaway edge check (quic.rs::
// verify_masque): same socket, same handshake, same request; different bait timing, different
// answer rules, no capsules and no keepalive interval on the check.
enum class Purpose {
    Tunnel,
    Verify,
};

// Every duration a pump decision needs, read from Settings once so no branch of the pump reads an
// environment variable itself.
struct Timers {
    // quic.rs:347, the 20 second interval that pings an established connection: ngtcp2's keep-alive
    // timeout, which sends the ack-eliciting packet the moment the connection is that long idle.
    Millis keepalive{std::chrono::duration_cast<Millis>(quic::KEEPALIVE_INTERVAL)};
    // quic.rs:350, how often the data-plane probe goes out while the tunnel is being validated.
    Millis probe{std::chrono::duration_cast<Millis>(quic::PROBE_INTERVAL)};
    // The bait's wait and try count: QUIC_V2_BAIT_WAIT/QUIC_V2_BAIT_TRIES for a tunnel,
    // QUIC_V2_VERIFY_BAIT_WAIT/QUIC_V2_VERIFY_BAIT_TRIES for a check.
    Millis bait_wait{quic::QUIC_V2_BAIT_WAIT};
    std::uint32_t bait_tries = quic::QUIC_V2_BAIT_TRIES;
    // quic::validation_timeout(settings): how long the data plane has to prove itself.
    Millis validation{std::chrono::duration_cast<Millis>(quic::validation_timeout({}))};
    // The idle timeout the transport parameters advertise.
    Millis idle{120000};
    // The two keepalive switches with no flag in cli.rs: a Settings value is the only way to move
    // them, so the transport reads them through masque::h2_keepalive_* rather than hardcoding.
    Millis h2_keepalive_interval{std::chrono::duration_cast<Millis>(
        masque::KEEPALIVE_INTERVAL_DEFAULT)};
    Millis h2_keepalive_timeout{
        std::chrono::duration_cast<Millis>(masque::KEEPALIVE_TIMEOUT_DEFAULT)};
    // The whole budget of a check: quic::VerifyParams::timeout, unused for a tunnel.
    Millis verify_deadline{0};

    // The settings' answer for one purpose.
    [[nodiscard]] static Timers from_settings(const Settings& settings, Purpose purpose);
};

// quic.rs:317-319 on top of tls.rs:347-361: the transport parameters the context was built with,
// with the tunnel's own datagram budget over the two payload sizes.
struct ConnectionSetup {
    quic::TransportParams params;
    // The budget every write, read and datagram is sized against.
    std::size_t datagram_budget = quic::MAX_DATAGRAM_SIZE;
    // settings.max_tx_udp_payload_size, and no_pmtud: quiche sizes the path from
    // max_send_udp_payload_size alone.
    std::size_t max_tx_udp_payload = quic::MAX_DATAGRAM_SIZE;
    bool no_pmtud = true;
    // The depth of the queue in front of the datagram pump: sysprofile's channel capacity, which is
    // what quic.rs's outbound channel is bounded by.
    std::size_t outbound_queue = 0;
    // The round trips the probe has to see before the tunnel says it is ready.
    std::uint32_t probe_successes_needed = quic::DATA_PROBE_REQUIRED_SUCCESSES;

    [[nodiscard]] static ConnectionSetup for_tunnel(const quic::TunnelConfig& tunnel,
                                                    const Settings& settings);
    [[nodiscard]] bool operator==(const ConnectionSetup&) const = default;
};

// ---------------------------------------------------------------------------
// The TLS context, and the ECH key on one connection.

// tls.rs::build_config, on BoringSSL instead of the quiche wrapper that held it: the shaping of
// Fingerprint::apply, TLS 1.3 alone over a QUIC connection, the device certificate, and the
// verification the caller's pins ask for -- in that order, because the order is what the Rust
// writes. The certificate is not optional: without it the edge finishes the handshake and closes
// with crypto alert 116, so a build without one fails here rather than on the wire.
//
// `verification` takes the once-per-process notice install_verification returns, which the caller
// logs. The context is the caller's to free.
[[nodiscard]] std::expected<SSL_CTX*, std::string> build_client_context(
    const quic::TunnelConfig& tunnel, const Settings& settings, std::string& verification);

// The ALPN list BoringSSL takes: each protocol preceded by its own length byte, out of
// quic::TransportParams::alpn.
[[nodiscard]] std::vector<std::uint8_t> alpn_wire(std::string_view alpn);

// tls.rs::inject_ech on a BoringSSL handle: refuse a list BoringSSL cannot offer, rather than run
// the handshake with the server name in the clear.
[[nodiscard]] std::expected<void, std::string> offer_ech(SSL* ssl,
                                                         std::span<const std::uint8_t> config_list);

// ---------------------------------------------------------------------------
// The framing, which the pump uses and a caller may want on its own.

// masque.rs::encode_ip_datagram on the request stream the tunnel answers back on.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> frame_ip_datagram(
    std::uint64_t stream_id, std::span<const std::uint8_t> ip_packet);

// masque.rs::decode_ip_datagram: the IP packet behind the two varints, nothing when they name
// another stream or a context we did not ask for.
[[nodiscard]] std::expected<std::optional<std::vector<std::uint8_t>>, std::string>
unframe_ip_datagram(std::span<const std::uint8_t> datagram, std::uint64_t stream_id);

// masque.rs::connect_ip_request for this tunnel -- the field set quic.rs:466 hands the h3 codec,
// which is what the pump then submits.
[[nodiscard]] std::vector<masque::HeaderField> connect_request(const quic::TunnelConfig& tunnel);

// ---------------------------------------------------------------------------
// The session.

// Everything the pump holds: the connection, the context, the queues, the timers, the counters.
// Opaque here and defined in transport.cpp, where the ngtcp2 and nghttp3 callbacks -- which are C
// function pointers, so they cannot be members -- can name it and take it as their user_data.
struct SessionState;

class Session {
public:
    // The phases of quic.rs's run loop, which is what a host's readiness callback drives on.
    enum class Phase {
        // The version-bait probes, if the tunnel wants them and the setting leaves them on.
        Baiting,
        // QUIC and TLS, up to the handshake completing.
        Handshake,
        // The connect-ip request is out; waiting for :status.
        Request,
        // The edge answered 2xx; the data-plane probe has to come back
        // DATA_PROBE_REQUIRED_SUCCESSES times inside validation_timeout.
        Validating,
        // The tunnel is carrying traffic.
        Ready,
        // A CONNECTION_CLOSE is waiting to go out.
        Closing,
        // Done; error() says what the Rust would have returned.
        Closed,
    };

    struct Seams {
        // The socket. Required: nothing can be sent without it.
        UdpIo* io = nullptr;
        // The data plane's two ends. Both optional: quic.rs's run() runs with addr_tx none, and a
        // caller that only wants the handshake (verify_masque) needs neither.
        InboundSink* inbound = nullptr;
        AddressSink* assigned = nullptr;
        Observer* observer = nullptr;
        // What quic.rs's flush writes to: upstream::relay_target(local, peer), the proxy's shim
        // when a detour is on the socket and the peer itself when it is not. The default is the
        // direct answer, which is what a session with no upstream setting gets.
        std::function<SocketAddr(const SocketAddr& local, const SocketAddr& peer)> relay;
        // A second socket for Control::Migrate (quic.rs's do_migrate binds one). Nothing can
        // migrate without it.
        std::function<std::expected<std::unique_ptr<UdpIo>, std::string>(const SocketAddr& bind)>
            make_io;
        // The source for connection ids and packet numbers: RAND_bytes unless a test wants the same
        // bytes twice.
        std::function<void(std::uint8_t* out, std::size_t len)> make_random;
    };

    struct Setup {
        quic::TunnelConfig tunnel;
        Purpose purpose = Purpose::Tunnel;
        // quic::VerifyParams::timeout for a check; ignored for a tunnel.
        Millis verify_timeout{0};

        // quic.rs::run's argument.
        [[nodiscard]] static Setup for_tunnel(const quic::TunnelConfig& tunnel);
        // quic.rs::verify_masque's, which carries no quiet flag, no budget and no bait switch: the
        // check baits whenever HEMERA_QUIC_V2 leaves it on.
        [[nodiscard]] static Setup for_verify(const quic::VerifyParams& params);
    };

    struct Tick {
        // How long the Rust select loop would have slept before this turn: the connection's own
        // expiry, the phase's deadline, or the socket's readiness wait once everything is quiet.
        std::optional<Millis> delay;
        Phase phase = Phase::Handshake;
        bool closed = false;
        // The Err quic.rs would have returned, in HemeraError's words: "masque: ...", "ech: ...".
        // Nothing while the run is still going, and nothing when it ended on a close, which is an
        // Ok(()) with close() set.
        std::optional<std::string> error;
    };

    // Everything before the first byte: check_tls_options, the context, the socket's identity, the
    // connection with quic.hpp's parameters, the SNI, the ALPN and the ECH key. Opens nothing and
    // sends nothing -- that is the first tick's job.
    [[nodiscard]] static std::expected<std::unique_ptr<Session>, std::string>
    open(const Setup& setup, const Settings& settings, Seams seams, TimePoint now);

    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // One turn of the run loop, in quic.rs's order: the validation deadline, the socket, the
    // control queue, the timers, the expiry, the h3 poll, the datagram drain, the flush, the ECH
    // retry, the close.
    Tick tick(TimePoint now);

    // For a host that reads the socket itself: hand the session a datagram, exactly as if tick had
    // taken it off the wire.
    void deliver(std::span<const std::uint8_t> packet, const SocketAddr& from, TimePoint now);

    // The data plane, outbound. quic.rs frames an ip-datagram on the request stream the moment a
    // packet arrives and drops it when the stream is not there yet -- so until the edge answers the
    // connect-ip request this says Closed and counts the drop. Full is the outbound queue being at
    // sysprofile's channel capacity, which is where Rust's mpsc::send would have waited.
    [[nodiscard]] Room send_ip_packet(std::span<const std::uint8_t> ip_packet);

    // quic.rs's control channel: Migrate binds a second socket and probes it, Close sends the
    // "bye" application close.
    void control(quic::Control control);

    // The rest of the surface a host needs: state, and what it means.
    [[nodiscard]] Phase phase() const;
    [[nodiscard]] bool ready() const;
    [[nodiscard]] const std::optional<std::string>& error() const;
    [[nodiscard]] const CloseInfo& close() const;
    [[nodiscard]] std::optional<std::uint16_t> status() const;
    // The connect-ip stream, -1 until the request is out. The datagram framing names it, so a host
    // that carries packets itself needs it.
    [[nodiscard]] std::int64_t request_stream() const;
    // The address the edge last assigned, if any capsule carried one.
    [[nodiscard]] std::optional<quic::AssignedAddr> assigned() const;

    [[nodiscard]] const Timers& timers() const;
    [[nodiscard]] const ConnectionSetup& setup() const;
    [[nodiscard]] const quic::TunnelConfig& tunnel() const;
    [[nodiscard]] SocketAddr peer() const;
    [[nodiscard]] SocketAddr local() const;

    // Framed datagrams waiting for room on the connection, oldest first -- the bytes between
    // send_ip_packet and the DATAGRAM frame, so a caller can see what is backlogged.
    [[nodiscard]] std::span<const std::vector<std::uint8_t>> pending_datagrams() const;

    // Counters, for the host's stats line.
    [[nodiscard]] std::size_t tx_packets() const;
    [[nodiscard]] std::size_t rx_packets() const;
    [[nodiscard]] std::size_t datagrams_sent() const;
    [[nodiscard]] std::size_t datagrams_received() const;
    [[nodiscard]] std::size_t datagrams_dropped() const;
    // The keep-alive timeout actually armed on the connection, which is what quic.hpp's knob asked
    // for. ngtcp2 sends the ack-eliciting packet itself once the connection has been idle this long,
    // so there is no counter to read -- the armed value is the honest answer.
    [[nodiscard]] Millis keepalive_timeout() const;
    [[nodiscard]] std::uint32_t probe_successes() const;
    // Whether the handshake went with the ECH key it was given -- SSL_ech_accepted, the check
    // quic.rs:454 puts on the connection before anything moves.
    [[nodiscard]] bool ech_accepted() const;
    [[nodiscard]] std::string_view negotiated_alpn() const;

    // ---- The ECH retry (quic.rs:513 tunnel / quic.rs:978 verify) ------------------------------
    // When a server turns down the ECHConfigList we offered, BoringSSL closes with the client's own
    // ech_required alert (crypto 0x179) and hands back the server's retry_configs. The Rust does not
    // fail there: it makes the handshake again, at once, offering that retry key, and remembers it
    // for the session's later handshakes. That loop lives here.
    //
    // How it is driven: Session::tick performs the retry itself on the turn it observes the
    // ech_required close, because that is the shape quic.rs uses -- inline in its own select loop --
    // and because a fresh connection is neither draining nor closed, so the pump simply carries on
    // with it (Rust's `continue`). The accessors below are the same decision opened to a host that
    // drives the socket itself and to the suite: candidate() says a retry is due, apply_ech_retry()
    // is the body once the server's list is in hand (a host that sourced the bytes elsewhere, or a
    // test -- the real pump reads them off the failed SSL), and the two readers observe the result.
    // Purpose::Tunnel and Purpose::Verify have DIFFERENT guards; see ech_retry_candidate().

    // Whether a refused ECH handshake is due its single retry now. quic.rs:517-522 asks, for the
    // tunnel, that the close is our ech_required alert AND !established_ever AND a key is in play;
    // quic.rs:982, for a verify, asks only for the alert and !ech_retried -- the missing guards are
    // the Rust's own difference, copied exactly.
    [[nodiscard]] bool ech_retry_candidate() const;

    // The retry body once the server's retry_configs are in hand (quic.rs:523-544 / 983-998): a list
    // BoringSSL cannot offer is refused -- usable_retry's gate, tls.rs:492 -- and nothing changes
    // (false); a usable one is adopted for the rest of the session, offered on a brand-new connection
    // with a fresh SCID, and flushed (true). Never silently degrades: the retried handshake is still
    // held to SSL_ech_accepted by the same rule establish() already applies.
    [[nodiscard]] bool apply_ech_retry(std::vector<std::uint8_t> server_retry, TimePoint now);

    // Whether the session has already taken its one retry, and the key it is now offering.
    [[nodiscard]] bool ech_retried() const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> offered_ech_key() const;

private:
    Session();

    std::unique_ptr<SessionState> state_;
};

} // namespace hemera::core::transport
