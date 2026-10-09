#include "transport.hpp"

#include "masque.hpp"
#include "noize.hpp"
#include "quic.hpp"
#include "settings.hpp"
#include "sysprofile.hpp"
#include "tls.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace hemera::core::transport {

// tls.hpp declares its surface directly in hemera::core (no nested tls namespace); the alias lets
// this module read it as the header's prose calls it, and keeps quic:: / masque:: unambiguous.
namespace tls = ::hemera::core;

namespace {

// The room the connect-ip request carries the probe in: quic.rs's dgram_send target. The datagram
// frame itself is ngtcp2's to write (frame type consts::H3_DATAGRAM_00); this module only frames
// the ip-datagram body in front of it and hands it to the connection.

std::string_view to_view(const std::vector<std::uint8_t>& bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void clear_ssl_error() {
    while (ERR_get_error() != 0) {
    }
}

std::string ssl_error(std::string_view fallback) {
    const unsigned long code = ERR_get_error();
    if (code == 0) return std::string(fallback);
    // NOTE: fallback.data() is NOT null-terminated (string_view), so %s would read past the end
    // and smash the stack -- which is exactly what an earlier revision did here.
    std::string out(fallback);
    (void)code;
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// The close, and what it means.

std::string CloseInfo::text() const {
    // quic.rs:551-571 writes both halves the same way, and the code always in hex.
    std::string out = from_peer ? "peer closed: code=0x" : "local closed: code=0x";
    char hex[24];
    std::snprintf(hex, sizeof hex, "%llx", static_cast<unsigned long long>(code));
    out += hex;
    out += " app=";
    out += (application_error ? "true" : "false");
    out += " reason=";
    out += reason;
    return out;
}

CloseCause classify_close(const CloseInfo& close) {
    // An application close carrying NO_ERROR is the tunnel's own bye/eof or a plain peer goodbye.
    if (close.application_error) {
        if (close.code == 0x00) {
            if (close.reason == "validation-timeout") return CloseCause::ValidationTimeout;
            return CloseCause::Normal;
        }
        return CloseCause::Other;
    }

    // Transport / crypto codes. A 0x174 is crypto alert 116, certificate_required -- the one the
    // WARP edge sends when bring-up carried no device certificate.
    if (close.code == 0x174) return CloseCause::CertificateRequired;
    // tls::ech_rejected is the authority on the ECH alert, so a 0x179 that only looks like one (an
    // application code in disguise) never reads as EchRejected.
    if (tls::ech_rejected(close.application_error, static_cast<std::uint32_t>(close.code))) {
        return CloseCause::EchRejected;
    }
    if (close.reason == "validation-timeout") return CloseCause::ValidationTimeout;
    if (close.reason == "idle-timeout") return CloseCause::Idle;
    // A stateless reset or a lost connection id: NO_ERROR transport close with nothing to say.
    if (close.code == 0x00 && close.reason.empty()) return CloseCause::Reset;
    return CloseCause::Other;
}

// ---------------------------------------------------------------------------
// The seams: arrival filtering.

bool Arrived::from_peer(const SocketAddr& peer) const { return from == peer; }

// ---------------------------------------------------------------------------
// WinUdp -- the real socket. Never exercised offline (the suite injects a fake UdpIo), so this is
// bind_udp_fast's product translated onto WS2: a non-blocking datagram socket with the profile's
// buffers, bound to the family the peer lives in.

struct WinUdp::Impl {
    SOCKET fd = INVALID_SOCKET;
    SocketAddr local{};
    bool connected = false;
};

namespace {

std::once_flag k_wsa_once;
bool k_wsa_ready = false;

bool ensure_wsa() {
    std::call_once(k_wsa_once, [] {
        WSADATA data{};
        k_wsa_ready = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
    });
    return k_wsa_ready;
}

void to_sockaddr(const SocketAddr& addr, sockaddr_storage& storage, int& len) {
    std::memset(&storage, 0, sizeof storage);
    if (addr.is_ipv4()) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(addr.port);
        std::memcpy(&v4->sin_addr.s_addr, addr.ip.bytes.data() + 12, 4);
        len = static_cast<int>(sizeof sockaddr_in);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(addr.port);
        std::memcpy(&v6->sin6_addr, addr.ip.bytes.data(), 16);
        len = static_cast<int>(sizeof sockaddr_in6);
    }
}

SocketAddr from_sockaddr(const sockaddr_storage& storage, int len) {
    SocketAddr addr{};
    if (storage.ss_family == AF_INET && len >= static_cast<int>(sizeof sockaddr_in)) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&storage);
        addr.ip.v4 = true;
        std::memcpy(addr.ip.bytes.data() + 12, &v4->sin_addr.s_addr, 4);
        addr.port = ntohs(v4->sin_port);
    } else if (storage.ss_family == AF_INET6 && len >= static_cast<int>(sizeof sockaddr_in6)) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&storage);
        addr.ip.v4 = false;
        std::memcpy(addr.ip.bytes.data(), &v6->sin6_addr, 16);
        addr.port = ntohs(v6->sin6_port);
    }
    return addr;
}

std::string last_socket_error() {
    char buf[64];
    std::snprintf(buf, sizeof buf, "socket error %d", WSAGetLastError());
    return std::string(buf);
}

} // namespace

std::expected<std::unique_ptr<WinUdp>, std::string> WinUdp::open(const SocketAddr& bind,
                                                                 const Settings& settings) {
    if (!ensure_wsa()) return std::unexpected("WSAStartup failed");

    const int family = bind.is_ipv4() ? AF_INET : AF_INET6;
    const SOCKET fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCKET) return std::unexpected("socket: " + last_socket_error());

    auto impl = std::make_shared<WinUdp::Impl>();
    impl->fd = fd;

    u_long nonblocking = 1;
    if (::ioctlsocket(fd, FIONBIO, &nonblocking) != 0) {
        closesocket(fd);
        return std::unexpected("FIONBIO: " + last_socket_error());
    }

    const int buffer =
        static_cast<int>(std::min<std::size_t>(sysprofile::udp_socket_buf_bytes(settings), 1u << 22));
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buffer), sizeof buffer);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buffer), sizeof buffer);

    // egress::apply's firewall mark is a Unix-only socket option; Windows has no equivalent here,
    // so the mark stays where egress.hpp left it and nothing further is applied.

    sockaddr_storage storage{};
    int len = 0;
    to_sockaddr(bind, storage, len);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&storage), len) != 0) {
        closesocket(fd);
        return std::unexpected("bind: " + last_socket_error());
    }

    sockaddr_storage name{};
    int namelen = static_cast<int>(sizeof name);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&name), &namelen) != 0) {
        closesocket(fd);
        return std::unexpected("getsockname: " + last_socket_error());
    }
    impl->local = from_sockaddr(name, namelen);

    std::unique_ptr<WinUdp> out(new WinUdp());
    out->impl_ = std::move(impl);
    return out;
}

std::expected<std::unique_ptr<WinUdp>, std::string> WinUdp::open_for_peer(const SocketAddr& peer,
                                                                         const Settings& settings) {
    return open(quic::bind_addr_for(peer), settings);
}

WinUdp::~WinUdp() {
    if (impl_ && impl_->fd != INVALID_SOCKET) {
        closesocket(impl_->fd);
        impl_->fd = INVALID_SOCKET;
    }
}

std::expected<void, std::string> WinUdp::connect_to(const SocketAddr& peer) {
    sockaddr_storage storage{};
    int len = 0;
    to_sockaddr(peer, storage, len);
    if (::connect(impl_->fd, reinterpret_cast<sockaddr*>(&storage), len) != 0) {
        return std::unexpected("connect: " + last_socket_error());
    }
    impl_->connected = true;
    return {};
}

bool WinUdp::connected() const { return impl_ && impl_->connected; }

SocketAddr WinUdp::local() const { return impl_ ? impl_->local : SocketAddr{}; }

std::expected<std::size_t, std::string> WinUdp::send(const SocketAddr& to,
                                                    std::span<const std::uint8_t> packet) {
    if (packet.empty()) return std::size_t{0};

    int wrote = 0;
    if (impl_->connected) {
        wrote = ::send(impl_->fd, reinterpret_cast<const char*>(packet.data()),
                       static_cast<int>(packet.size()), 0);
    } else {
        sockaddr_storage storage{};
        int len = 0;
        to_sockaddr(to, storage, len);
        wrote = ::sendto(impl_->fd, reinterpret_cast<const char*>(packet.data()),
                         static_cast<int>(packet.size()), 0, reinterpret_cast<sockaddr*>(&storage),
                         len);
    }
    if (wrote < 0) return std::unexpected("send: " + last_socket_error());
    // A short write is an error, as Rust's `?` makes it: the kernel took the whole datagram or
    // something is wrong with the socket.
    if (static_cast<std::size_t>(wrote) != packet.size()) return std::unexpected("send: short write");
    return static_cast<std::size_t>(wrote);
}

std::expected<std::optional<Arrived>, std::string> WinUdp::receive() {
    std::vector<std::uint8_t> buf(quic::SOCKET_BUFFER);
    sockaddr_storage storage{};
    int len = static_cast<int>(sizeof storage);
    const int got = ::recvfrom(impl_->fd, reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&storage),
                               &len);
    if (got == SOCKET_ERROR) {
        const int code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) return std::optional<Arrived>{};
        return std::unexpected("recv: socket error " + std::to_string(code));
    }
    buf.resize(static_cast<std::size_t>(got));
    Arrived arrived{from_sockaddr(storage, len), std::move(buf)};
    return std::optional<Arrived>{std::move(arrived)};
}

// ---------------------------------------------------------------------------
// The numbers bring-up runs on.

Timers Timers::from_settings(const Settings& settings, Purpose purpose) {
    Timers timers;
    timers.keepalive = std::chrono::duration_cast<Millis>(quic::KEEPALIVE_INTERVAL);
    timers.probe = std::chrono::duration_cast<Millis>(quic::PROBE_INTERVAL);
    timers.bait_wait =
        purpose == Purpose::Verify ? quic::QUIC_V2_VERIFY_BAIT_WAIT : quic::QUIC_V2_BAIT_WAIT;
    timers.bait_tries =
        purpose == Purpose::Verify ? static_cast<std::uint32_t>(quic::QUIC_V2_VERIFY_BAIT_TRIES)
                                     : static_cast<std::uint32_t>(quic::QUIC_V2_BAIT_TRIES);
    timers.validation = std::chrono::duration_cast<Millis>(quic::validation_timeout(settings));
    timers.idle = Millis(quic::transport_params().max_idle_timeout_ms);
    timers.h2_keepalive_interval =
        std::chrono::duration_cast<Millis>(masque::h2_keepalive_interval(settings));
    timers.h2_keepalive_timeout =
        std::chrono::duration_cast<Millis>(masque::h2_keepalive_timeout(settings));
    return timers;
}

ConnectionSetup ConnectionSetup::for_tunnel(const quic::TunnelConfig& tunnel,
                                           const Settings& settings) {
    ConnectionSetup setup;
    setup.params = quic::transport_params();
    setup.datagram_budget = tunnel.datagram_budget();
    setup.max_tx_udp_payload =
        std::max<std::size_t>(setup.datagram_budget, quic::MIN_DATAGRAM_SIZE);
    setup.no_pmtud = true;
    setup.outbound_queue = quic::net_queue(settings);
    setup.probe_successes_needed = quic::DATA_PROBE_REQUIRED_SUCCESSES;
    return setup;
}

// ---------------------------------------------------------------------------
// The TLS context and the ECH key.

std::vector<std::uint8_t> alpn_wire(std::string_view alpn) {
    // Each protocol preceded by its own length byte; this core speaks exactly one (h3).
    std::vector<std::uint8_t> out;
    out.push_back(static_cast<std::uint8_t>(alpn.size()));
    out.insert(out.end(), alpn.begin(), alpn.end());
    return out;
}

std::expected<SSL_CTX*, std::string> build_client_context(const quic::TunnelConfig& tunnel,
                                                         const Settings& settings,
                                                         std::string& verification) {
    // The order tls.rs::build_config writes: shaping, TLS 1.3 alone, the device certificate, then
    // verification. It is not cosmetic -- verification must be installed after the certificate is
    // on the context, and the certificate must be there at all or the edge closes with 0x174.
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return std::unexpected("SSL_CTX_new failed");

    // Free the context on any failure below; a caller owns it only once this returns a context.
    struct Fail {
        SSL_CTX** ctx;
        bool ok = false;
        ~Fail() {
            if (!ok && *ctx != nullptr) {
                SSL_CTX_free(*ctx);
                *ctx = nullptr;
            }
        }
    } fail{&ctx};

    if (ngtcp2_crypto_boringssl_configure_client_context(ctx) != 0) {
        return std::unexpected(
            ssl_error("ngtcp2_crypto_boringssl_configure_client_context failed"));
    }

    // Shaping: Fingerprint::apply installs GREASE, extension permutation, the curves, the cipher
    // rule and the ALPN list on the context.
    const std::vector<std::uint8_t> alpn = alpn_wire(quic::transport_params().alpn);
    if (const auto shaped = tls::Fingerprint::configured(settings).apply(ctx, alpn); !shaped) {
        return std::unexpected(shaped.error());
    }

    // QUIC carries TLS 1.3 alone, so the TLS 1.2 suites a --tls-ciphers might name never show.
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // The device certificate: bring-up installs it here, so mTLS device identity is part of the
    // transport, not a later feature. A context that cannot hold one fails now, not on the wire.
    if (const auto cert = tls::use_device_certificate(ctx, to_view(tunnel.cert_pem),
                                                     to_view(tunnel.key_pem));
        !cert) {
        return std::unexpected(cert.error());
    }

    // Pin-based verification, which hands back the once-per-process notice the caller logs.
    verification =
        tls::install_verification(ctx, /*pin_endpoint=*/true, tls::masque_pins(), settings);

    fail.ok = true;
    return ctx;
}

std::expected<void, std::string> offer_ech(SSL* ssl, std::span<const std::uint8_t> config_list) {
    // Refuse a list BoringSSL cannot offer rather than run the handshake with the server name in
    // the clear -- the same check tls::inject_ech makes, on an explicitly supplied key.
    if (const auto usable = tls::ensure_offerable(config_list); !usable) {
        return std::unexpected(usable.error());
    }
    if (SSL_set1_ech_config_list(ssl, config_list.data(), config_list.size()) != 1) {
        clear_ssl_error();
        return std::unexpected("SSL_set1_ech_config_list failed");
    }
    return {};
}

// ---------------------------------------------------------------------------
// The framing, through the already-ported masque codec.

std::expected<std::vector<std::uint8_t>, std::string> frame_ip_datagram(
    std::uint64_t stream_id, std::span<const std::uint8_t> ip_packet) {
    return masque::encode_ip_datagram(stream_id, ip_packet);
}

std::expected<std::optional<std::vector<std::uint8_t>>, std::string> unframe_ip_datagram(
    std::span<const std::uint8_t> datagram, std::uint64_t stream_id) {
    return masque::decode_ip_datagram(datagram, stream_id);
}

std::vector<masque::HeaderField> connect_request(const quic::TunnelConfig& tunnel) {
    return masque::connect_ip_request(tunnel.authority, tunnel.path);
}

Session::Setup Session::Setup::for_tunnel(const quic::TunnelConfig& tunnel) {
    Setup setup;
    setup.tunnel = tunnel;
    setup.purpose = Purpose::Tunnel;
    setup.verify_timeout = Millis{0};
    return setup;
}

Session::Setup Session::Setup::for_verify(const quic::VerifyParams& params) {
    quic::TunnelConfig tunnel;
    tunnel.peer = params.peer;
    tunnel.sni = params.sni;
    tunnel.authority = params.authority;
    tunnel.path = params.path;
    tunnel.cert_pem = params.cert_pem;
    tunnel.key_pem = params.key_pem;
    tunnel.ech_config_list = params.ech_config_list;
    tunnel.noize = params.noize;
    tunnel.local_ipv4 = params.local_ipv4;
    tunnel.quiet = false;
    tunnel.max_datagram = quic::MAX_DATAGRAM_SIZE;
    tunnel.version_bait = true;

    Setup setup;
    setup.tunnel = std::move(tunnel);
    setup.purpose = Purpose::Verify;
    setup.verify_timeout =
        std::chrono::duration_cast<Millis>(params.timeout);
    return setup;
}

// ---------------------------------------------------------------------------
// The session. SessionState is the type the header forward-declared here, so the ngtcp2 and nghttp3
// callbacks -- C function pointers, hence not members -- can name it and take it as their user_data.

struct SessionState {
    // Bring-up data.
    Session::Setup setup;
    Purpose purpose = Purpose::Tunnel;
    quic::TunnelConfig tunnel;
    Timers timers;
    ConnectionSetup conn_setup;

    // The seams (raw pointers borrow; relay / make_io / make_random are moved in and owned here).
    UdpIo* io = nullptr;
    InboundSink* inbound = nullptr;
    AddressSink* assigned_sink = nullptr;
    Observer* observer = nullptr;
    std::function<SocketAddr(const SocketAddr&, const SocketAddr&)> relay;
    std::function<void(std::uint8_t*, std::size_t)> make_random;

    // Addresses.
    SocketAddr peer{};
    SocketAddr local{};
    SocketAddr dest{}; // relay_target(local, peer), or the peer itself with no upstream

    // TLS / QUIC / H3 handles.
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    ngtcp2_conn* conn = nullptr;
    nghttp3_conn* h3 = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    ngtcp2_path_storage ps{};
    std::vector<std::uint8_t> txbuf;
    nghttp3_callbacks h3_cb{};
    nghttp3_settings h3_settings{};

    // Time base and the timestamp the last turn ran on (callbacks read it back).
    TimePoint base{};
    ngtcp2_tstamp cur_ts = 0;

    // Phase and result.
    Session::Phase phase = Session::Phase::Handshake;
    std::optional<std::string> error;
    CloseInfo close{};
    bool closed_recorded = false;
    bool local_close_initiated = false;

    // Handshake / request state.
    bool handshake_done = false;
    bool established_ever = false;
    bool ech_retried = false;
    std::optional<std::vector<std::uint8_t>> current_ech;
    std::int64_t req_stream = -1;
    std::optional<std::uint16_t> status;
    bool datagram_delivered = false;

    // Validation.
    std::vector<std::uint8_t> probe_packet;
    bool data_check = true;
    std::optional<TimePoint> validate_deadline;
    std::uint32_t validate_successes = 0;
    TimePoint last_probe{};

    // Verify budget.
    Millis verify_deadline_after{0};

    // Baiting.
    std::uint32_t bait_attempts = 0;
    bool bait_answered = false;

    // noize.rs's pre_handshake, once per run -- quic.rs calls it before the first flush, not before
    // every connection, so an ECH retry that rebuilds the connection does not send the junk again.
    bool noize_sent = false;

    // Accounting.
    std::size_t tx_packets = 0;
    std::size_t rx_packets = 0;
    std::size_t datagrams_sent = 0;
    std::size_t datagrams_received = 0;
    std::size_t datagrams_dropped = 0;
    std::uint64_t next_dgram_id = 1;
    std::vector<std::vector<std::uint8_t>> pending; // framed datagrams waiting for the connection

    std::optional<quic::AssignedAddr> assigned;
    masque::CapsuleParser capsules;
    std::vector<quic::Control> controls;

    std::string alpn_seen;
    bool ech_accepted_seen = false;

    ngtcp2_tstamp ts(TimePoint now) const {
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now - base).count();
        if (nanos < 0) nanos = 0;
        return static_cast<ngtcp2_tstamp>(nanos);
    }

    void note(std::string_view line) {
        if (observer) observer->on_note(line);
    }

    void send_out(const std::uint8_t* data, std::size_t len) {
        if (len == 0) return;
        // TEMP-DIAG (QUIC silence chase): every outbound datagram size post-handshake.
        if (established_ever) {
            note("outbound pkt: " + std::to_string(len) + " bytes");
        }
        auto r = io->send(dest, std::span<const std::uint8_t>(data, len));
        if (r) {
            ++tx_packets;
        } else {
            note("send: " + r.error());
            local_close(0x00, false, "socket-error", std::nullopt);
        }
    }

    void random_into(std::uint8_t* out, std::size_t len) {
        if (make_random) {
            make_random(out, len);
        } else {
            RAND_bytes(out, static_cast<int>(len));
        }
    }

    // Frames an ip-datagram onto the request stream and queues it for the next flush.
    void queue_datagram(std::span<const std::uint8_t> ip_packet) {
        if (req_stream < 0) {
            ++datagrams_dropped;
            return;
        }
        auto framed = masque::encode_ip_datagram(static_cast<std::uint64_t>(req_stream), ip_packet);
        if (!framed) {
            note("encap: " + framed.error());
            return;
        }
        if (conn_setup.outbound_queue != 0 && pending.size() >= conn_setup.outbound_queue) {
            return; // Room::Full is answered by send_ip_packet; the probe path just declines.
        }
        pending.push_back(std::move(*framed));
    }

    // quic.rs's flush: keep writing packets until the connection has nothing queued.
    void flush(ngtcp2_tstamp ts_now) {
        for (int guard = 0; guard < 4096; ++guard) {
            if (!pending.empty()) {
                std::vector<std::uint8_t>& d = pending.front();
                ngtcp2_vec dv;
                dv.base = d.data();
                dv.len = d.size();
                int accepted = 0;
                ngtcp2_pkt_info pi{};
                const ngtcp2_ssize nd = ngtcp2_conn_writev_datagram(
                    conn, &ps.path, &pi, txbuf.data(), txbuf.size(), &accepted,
                    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, next_dgram_id++, &dv, 1, ts_now);
                if (nd > 0) send_out(txbuf.data(), static_cast<std::size_t>(nd));
                if (nd >= 0) {
                    if (accepted) {
                        ++datagrams_sent;
                    } else {
                        ++datagrams_dropped; // a lost unreliable datagram
                    }
                } else {
                    // quic.rs logs a datagram dgram_send turns down and lets it go; a write error is
                    // the same loss seen from this side, so it is counted and named, not swallowed.
                    ++datagrams_dropped;
                    note("dgram_send: " + std::string(ngtcp2_strerror(static_cast<int>(nd))));
                }
                pending.erase(pending.begin());
                continue;
            }

            std::int64_t stream_id = -1;
            int fin = 0;
            nghttp3_vec vec[16];
            nghttp3_ssize sveccnt = 0;
            if (h3) {
                sveccnt = nghttp3_conn_writev_stream(h3, &stream_id, &fin, vec, 16);
                if (sveccnt < 0) {
                    note(std::string("writev_stream(h3): ") + nghttp3_strerror(static_cast<int>(sveccnt)));
                    break;
                }
            }
            std::uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
            if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

            ngtcp2_ssize ndatalen = -1;
            ngtcp2_pkt_info pi{};
            const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
                conn, &ps.path, &pi, txbuf.data(), txbuf.size(), &ndatalen, flags, stream_id,
                reinterpret_cast<const ngtcp2_vec*>(vec), sveccnt > 0 ? static_cast<std::size_t>(sveccnt) : 0,
                ts_now);
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                if (h3 && ndatalen >= 0) nghttp3_conn_add_write_offset(h3, stream_id, static_cast<size_t>(ndatalen));
                continue;
            }
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                if (h3) nghttp3_conn_block_stream(h3, stream_id);
                break;
            }
            if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
                if (h3) nghttp3_conn_shutdown_stream_write(h3, stream_id);
                continue;
            }
            if (nwrite < 0) break; // a benign stop; a real close surfaces via the ccerr
            if (nwrite == 0) break;
            send_out(txbuf.data(), static_cast<std::size_t>(nwrite));
            if (h3 && ndatalen >= 0) nghttp3_conn_add_write_offset(h3, stream_id, static_cast<size_t>(ndatalen));
        }
    }

    void feed(std::span<const std::uint8_t> data) {
        if (!conn || closed_recorded) return;
        cur_ts = ts(std::chrono::steady_clock::now());
        ngtcp2_pkt_info pi{};
        // Rust ignores a recv error with a trace!; a real terminal close surfaces through the ccerr.
        const int rv = ngtcp2_conn_read_pkt(conn, &ps.path, &pi, data.data(), data.size(), cur_ts);
        if (rv < 0) note("recv error: " + std::string(ngtcp2_strerror(rv)));
        // TEMP-DIAG (QUIC silence chase): every inbound datagram once the request is out.
        else if (phase == Session::Phase::Request || phase == Session::Phase::Ready) {
            note("inbound pkt: " + std::to_string(data.size()) + " bytes");
        }
    }

    void record_close(CloseInfo ci) {
        close = std::move(ci);
        closed_recorded = true;
        phase = Session::Phase::Closed;
        note(close.text());
        if (observer) observer->on_close(close);
    }

    // An application / transport close this side asks for, in quic.rs's shape.
    void local_close(std::uint64_t code, bool app, std::string reason,
                     std::optional<std::string> err) {
        if (err) error = std::move(err);
        if (closed_recorded) return;
        CloseInfo ci;
        ci.from_peer = false;
        ci.application_error = app;
        ci.code = code;
        ci.reason = reason;

        // A terminal packet, best-effort, if the connection ever spoke.
        if (conn && !local_close_initiated) {
            local_close_initiated = true;
            if (handshake_done) {
                ngtcp2_ccerr cc{};
                cc.type = app ? NGTCP2_CCERR_TYPE_APPLICATION : NGTCP2_CCERR_TYPE_TRANSPORT;
                cc.error_code = code;
                cc.frame_type = 0;
                cc.reason = reinterpret_cast<const std::uint8_t*>(reason.data());
                cc.reasonlen = reason.size();
                ngtcp2_pkt_info pi{};
                const ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
                    conn, &ps.path, &pi, txbuf.data(), txbuf.size(), &cc, ts(std::chrono::steady_clock::now()));
                if (nwrite > 0) send_out(txbuf.data(), static_cast<std::size_t>(nwrite));
            }
        }
        record_close(std::move(ci));
    }

    void handle_peer_close() {
        if (closed_recorded || !conn) return;
        const ngtcp2_ccerr* cc = ngtcp2_conn_get_ccerr2(conn);
        if (cc == nullptr) return;
        const bool real = cc->type != NGTCP2_CCERR_TYPE_TRANSPORT || cc->error_code != NGTCP2_NO_ERROR ||
                          cc->reason != nullptr;
        if (!real) return;
        CloseInfo ci;
        ci.from_peer = !local_close_initiated;
        ci.application_error = cc->type == NGTCP2_CCERR_TYPE_APPLICATION;
        ci.code = cc->error_code;
        ci.reason = cc->reason ? std::string(reinterpret_cast<const char*>(cc->reason), cc->reasonlen)
                                : std::string();
        record_close(std::move(ci));
    }

    // Handshake complete: build the h3 connection, open the streams, send the connect-ip request.
    bool establish(TimePoint now) {
        // Nothing goes over a handshake that went without the key it was given.
        if (current_ech && !SSL_ech_accepted(ssl)) {
            local_close(0x00, true, "ech", "ech: the handshake went without ECH");
            return false;
        }
        ech_accepted_seen = current_ech ? SSL_ech_accepted(ssl) == 1 : false;

        const unsigned char* alpn = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
        if (alpn && alpn_len > 0) alpn_seen.assign(reinterpret_cast<const char*>(alpn), alpn_len);

        note("quic handshake established; alpn=" + alpn_seen);
        established_ever = true;

        if (nghttp3_conn_client_new(&h3, &h3_cb, &h3_settings, nullptr, this) != 0) {
            local_close(0x00, true, "h3", "masque: h3 connection setup failed");
            return false;
        }

        std::int64_t ctrl = -1, qenc = -1, qdec = -1;
        if (ngtcp2_conn_open_uni_stream(conn, &ctrl, nullptr) != 0 ||
            nghttp3_conn_bind_control_stream(h3, ctrl) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &qenc, nullptr) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &qdec, nullptr) != 0 ||
            nghttp3_conn_bind_qpack_streams(h3, qenc, qdec) != 0) {
            local_close(0x00, true, "h3", "masque: h3 stream setup failed");
            return false;
        }

        std::int64_t connect_stream = -1;
        if (ngtcp2_conn_open_bidi_stream(conn, &connect_stream, nullptr) != 0) {
            local_close(0x00, true, "h3", "masque: cannot open the connect-ip stream");
            return false;
        }

        const std::vector<masque::HeaderField> fields = connect_request(tunnel);
        std::vector<nghttp3_nv> nva;
        nva.reserve(fields.size());
        for (const auto& f : fields) {
            nghttp3_nv nv;
            nv.name = reinterpret_cast<const std::uint8_t*>(f.name.data());
            nv.value = reinterpret_cast<const std::uint8_t*>(f.value.data());
            nv.namelen = f.name.size();
            nv.valuelen = f.value.size();
            nv.flags = NGHTTP3_NV_FLAG_NONE;
            nva.push_back(nv);
        }
        if (nghttp3_conn_submit_request(h3, connect_stream, nva.data(), nva.size(), nullptr,
                                        nullptr) != 0) {
            local_close(0x00, true, "h3", "masque: connect-ip request failed");
            return false;
        }
        req_stream = connect_stream;
        phase = Session::Phase::Request;
        note("connect-ip request sent on stream " + std::to_string(req_stream));

        if (!data_check) {
            phase = Session::Phase::Ready;
        } else {
            validate_deadline = now + timers.validation;
            note("[*] validating masque data-plane before exposing socks5");
        }
        return true;
    }

    // ---- The ECH retry, quic.rs:513 (tunnel) / quic.rs:978 (verify) ---------------------------
    // Declared here so Session's public methods can reach them; DEFINED after the ngtcp2/nghttp3
    // callbacks below, which build_connection installs. Kept as one code path shared with open():
    // the first handshake and every retry build the connection the same way, so they cannot drift.

    // The whole bring-up of one handshake on the session's existing context -- SSL object (app_data,
    // connect state, ALPN, SNI, the ECH key from current_ech), fresh connection ids, settings,
    // transport parameters, callbacks, path, txbuf, h3 tables -- up to ngtcp2_conn_client_new, its
    // tls native handle and its keep-alive timeout. Never touches ctx; frees only what it made on
    // failure. open() calls this first; apply_server_retry() calls it for every retry.
    [[nodiscard]] std::expected<void, std::string> build_connection(TimePoint now);

    // The quic.rs:517/982 guard, purpose by purpose. Reads the close and the session's flags only.
    [[nodiscard]] bool ech_retry_candidate() const;

    // quic.rs:523-544 / 983-998: the retry once the server's list is in hand. Usability-gated
    // (tls.rs:492), adopted, torn down and rebuilt with the new key, flushed. True when retried.
    bool apply_server_retry(std::vector<std::uint8_t> retry, TimePoint now);
};

namespace {

ngtcp2_conn* cb_get_conn(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<SessionState*>(ref->user_data)->conn;
}

void cb_rand(std::uint8_t* dest, std::size_t destlen, const ngtcp2_rand_ctx* rctx) {
    (void)rctx;
    RAND_bytes(dest, static_cast<int>(destlen));
}

int cb_get_new_cid2(ngtcp2_conn* conn, ngtcp2_cid* cid, ngtcp2_stateless_reset_token* token,
                    std::size_t cidlen, void* ud) {
    (void)conn;
    auto* s = static_cast<SessionState*>(ud);
    s->random_into(cid->data, cidlen);
    cid->datalen = cidlen;
    if (token != nullptr) s->random_into(token->data, sizeof token->data);
    return 0;
}

int cb_handshake_completed(ngtcp2_conn* conn, void* ud) {
    (void)conn;
    static_cast<SessionState*>(ud)->handshake_done = true;
    return 0;
}

int cb_recv_stream_data(ngtcp2_conn* conn, std::uint32_t flags, std::int64_t stream_id,
                        std::uint64_t offset, const std::uint8_t* data, std::size_t datalen, void* ud,
                        void* sud) {
    (void)offset;
    (void)sud;
    auto* s = static_cast<SessionState*>(ud);
    if (s->h3 == nullptr) return 0;
    const ngtcp2_ssize nconsumed = nghttp3_conn_read_stream2(
        s->h3, stream_id, data, datalen, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0, s->cur_ts);
    if (nconsumed < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, static_cast<uint64_t>(nconsumed));
    ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(nconsumed));
    return 0;
}

int cb_recv_datagram(ngtcp2_conn* conn, std::uint32_t flags, const std::uint8_t* data,
                     std::size_t datalen, void* ud) {
    (void)conn;
    (void)flags;
    auto* s = static_cast<SessionState*>(ud);
    if (s->req_stream < 0) return 0;
    const auto decoded = masque::decode_ip_datagram(std::span<const std::uint8_t>(data, datalen),
                                                    static_cast<std::uint64_t>(s->req_stream));
    if (!decoded) {
        s->note("decap: " + decoded.error());
        return 0;
    }
    if (!*decoded) return 0; // a different stream / context id: not ours to read
    ++s->datagrams_received;
    s->datagram_delivered = true;
    if (s->inbound != nullptr) {
        const std::vector<std::uint8_t>& ip = **decoded;
        switch (s->inbound->try_send(std::span<const std::uint8_t>(ip))) {
        case Room::Full:
            ++s->datagrams_dropped;
            s->note("inbound queue full, dropping datagram");
            break;
        case Room::Closed:
            break;
        case Room::Accepted:
            break;
        }
    }
    return 0;
}

int cb_h3_recv_header(nghttp3_conn* conn, std::int64_t stream_id, std::int32_t token,
                      nghttp3_rcbuf* name, nghttp3_rcbuf* value, std::uint8_t flags, void* cud,
                      void* sud) {
    (void)conn;
    (void)name;
    (void)flags;
    (void)sud;
    auto* s = static_cast<SessionState*>(cud);
    // TEMP-DIAG (QUIC silence chase): every response header as it arrives.
    {
        const nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
        const nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        std::string line = "[h3] hdr stream=" + std::to_string(stream_id) +
                           " token=" + std::to_string(token) + " name=" +
                           std::string(reinterpret_cast<const char*>(n.base), n.len) + " value=" +
                           std::string(reinterpret_cast<const char*>(v.base), v.len);
        s->note(line);
    }
    if (token == NGHTTP3_QPACK_TOKEN__STATUS && stream_id == s->req_stream) {
        const nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        std::uint16_t parsed = 0;
        for (size_t i = 0; i < v.len; ++i) {
            const char c = static_cast<char>(v.base[i]);
            if (c < '0' || c > '9') break;
            parsed = static_cast<std::uint16_t>(parsed * 10 + (c - '0'));
        }
        s->status = parsed;
    }
    return 0;
}

int cb_h3_recv_settings2(nghttp3_conn* conn, const nghttp3_proto_settings* settings, void* cud) {
    (void)conn;
    auto* s = static_cast<SessionState*>(cud);
    // TEMP-DIAG (QUIC silence chase): server SETTINGS receipt.
    s->note(std::string("[h3] server settings: h3_datagram=") +
            std::to_string(settings->h3_datagram) + " enable_connect_protocol=" +
            std::to_string(settings->enable_connect_protocol));
    (void)settings;
    return 0;
}

// Capsules (address-assign, route advertisement) ride as DATA on the connect-ip stream.
int cb_h3_recv_data(nghttp3_conn* conn, std::int64_t stream_id, const std::uint8_t* data,
                    std::size_t datalen, void* cud, void* sud) {
    (void)conn;
    (void)sud;
    auto* s = static_cast<SessionState*>(cud);
    if (stream_id != s->req_stream) return 0;
    (void)s->capsules.push(std::span<const std::uint8_t>(data, datalen));
    const masque::Drained drained = masque::drain_capsules(s->capsules);
    for (const masque::EdgeAssignment& a : drained.assigned) {
        quic::AssignedAddr addr;
        addr.ip = a.ip;
        addr.prefix = a.prefix;
        s->assigned = addr;
        s->note("edge assigned " + a.text());
        if (s->assigned_sink) (void)s->assigned_sink->try_send(addr);
        if (s->observer) s->observer->on_assigned(addr);
    }
    if (drained.parse_error) s->note("capsule parse: " + *drained.parse_error);
    return 0;
}

} // namespace

// ---------------------------------------------------------------------------
// The ECH retry, defined where the callbacks it installs already exist.

// build_connection is every handshake's bring-up on the session's existing context -- the whole of
// it, in one place, so open()'s first pass and quic.rs:535/993's retry can never drift. It reads
// current_ech (the key to offer), sets ssl and conn, and on any failure frees only the SSL object it
// made: the context is the caller's to keep (open) or reuse (retry).
std::expected<void, std::string> SessionState::build_connection(TimePoint now) {
    conn_ref.get_conn = cb_get_conn;
    conn_ref.user_data = this;

    ssl = SSL_new(ctx);
    if (ssl == nullptr) return std::unexpected("SSL_new failed");
    SSL_set_app_data(ssl, &conn_ref);
    SSL_set_connect_state(ssl);

    // The ALPN list, then SNI -- in that order, so a GREASE-able ClientHello still names the edge it
    // must reach. SSL_set_tlsext_host_name is the requirement the task pins.
    const std::vector<std::uint8_t> alpn = alpn_wire(quic::transport_params().alpn);
    if (SSL_set_alpn_protos(ssl, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0) {
        clear_ssl_error();
        SSL_free(ssl);
        ssl = nullptr;
        return std::unexpected("the ALPN protocol list was rejected");
    }
    SSL_set_tlsext_host_name(ssl, tunnel.sni.c_str());

    // ECH, before the connection is made: a key BoringSSL cannot offer is refused here rather than
    // sent in the clear later. current_ech carries the tunnel's key on the first pass and the
    // server's retry_configs on a retry (quic.rs:536/537, the connect-then-inject the port folds
    // into one because BoringSSL wants the list on the SSL before ngtcp2 wraps it).
    if (current_ech) {
        if (const auto offered = offer_ech(ssl, *current_ech); !offered) {
            SSL_free(ssl);
            ssl = nullptr;
            return std::unexpected("ech: " + offered.error());
        }
        note("ech config injected (" + std::to_string(current_ech->size()) + " bytes)");
    }

    // The connection ids, the settings and the transport parameters the quic.hpp numbers name.
    // A fresh SCID and DCID every time -- quic.rs:533's random_scid(), and the retry's new connection.
    std::array<std::uint8_t, NGTCP2_MIN_INITIAL_DCIDLEN> dcid_bytes{};
    std::array<std::uint8_t, quic::SCID_LEN> scid_bytes = quic::random_scid();
    random_into(dcid_bytes.data(), dcid_bytes.size());
    ngtcp2_cid dcid;
    ngtcp2_cid scid;
    ngtcp2_cid_init(&dcid, dcid_bytes.data(), dcid_bytes.size());
    ngtcp2_cid_init(&scid, scid_bytes.data(), scid_bytes.size());

    ngtcp2_settings qsettings;
    ngtcp2_transport_params qparams;
    ngtcp2_settings_default(&qsettings);
    // The base is the session's bring-up instant, stamped once by open and NOT re-stamped on a
    // retry, so the retried connection's timestamps keep counting from the same clock as every
    // counter and deadline the Session reports.
    qsettings.initial_ts = ts(now);
    qsettings.max_tx_udp_payload_size = conn_setup.max_tx_udp_payload;
    qsettings.no_pmtud = conn_setup.no_pmtud ? 1 : 0;

    ngtcp2_transport_params_default(&qparams);
    const quic::TransportParams& tp = conn_setup.params;
    qparams.max_idle_timeout = static_cast<ngtcp2_tstamp>(tp.max_idle_timeout_ms) * 1000000ull;
    qparams.initial_max_data = tp.initial_max_data;
    qparams.initial_max_stream_data_bidi_local = tp.initial_max_stream_data_bidi_local;
    qparams.initial_max_stream_data_bidi_remote = tp.initial_max_stream_data_bidi_remote;
    qparams.initial_max_stream_data_uni = tp.initial_max_stream_data_uni;
    qparams.initial_max_streams_bidi = tp.initial_max_streams_bidi;
    qparams.initial_max_streams_uni = tp.initial_max_streams_uni;
    qparams.disable_active_migration = tp.disable_active_migration ? 1 : 0;
    qparams.max_datagram_frame_size =
        tp.datagram_enabled ? static_cast<std::uint64_t>(tp.datagram_recv_max_size) : 0;
    // quic.rs caps what it will receive at the same budget it sends with
    // (set_max_recv_udp_payload_size, line 319); ngtcp2 advertises and enforces that as a transport
    // parameter, and its default is a far looser 65527.
    qparams.max_udp_payload_size = conn_setup.max_tx_udp_payload;

    ngtcp2_callbacks cb;
    std::memset(&cb, 0, sizeof cb);
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = ngtcp2_crypto_encrypt_cb;
    cb.decrypt = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cb.handshake_completed = cb_handshake_completed;
    cb.recv_stream_data = cb_recv_stream_data;
    cb.recv_datagram = cb_recv_datagram;
    cb.rand = cb_rand;
    cb.get_new_connection_id2 = cb_get_new_cid2;
    cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    cb.update_key = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

    sockaddr_storage local_storage{};
    sockaddr_storage remote_storage{};
    int local_len = 0;
    int remote_len = 0;
    to_sockaddr(local, local_storage, local_len);
    to_sockaddr(peer, remote_storage, remote_len);
    ngtcp2_path_storage_init(&ps, reinterpret_cast<const ngtcp2_sockaddr*>(&local_storage),
                             static_cast<ngtcp2_socklen>(local_len),
                             reinterpret_cast<const ngtcp2_sockaddr*>(&remote_storage),
                             static_cast<ngtcp2_socklen>(remote_len), nullptr);

    txbuf.resize(conn_setup.max_tx_udp_payload);
    if (txbuf.size() < quic::MIN_DATAGRAM_SIZE) txbuf.resize(quic::MIN_DATAGRAM_SIZE);

    std::memset(&h3_cb, 0, sizeof h3_cb);
    h3_cb.recv_header = cb_h3_recv_header;
    h3_cb.recv_settings2 = cb_h3_recv_settings2;
    h3_cb.recv_data = cb_h3_recv_data;
    nghttp3_settings_default(&h3_settings);
    h3_settings.enable_connect_protocol = 1; // SETTINGS_ENABLE_CONNECT_PROTOCOL (id 0x08)
    h3_settings.h3_datagram = 1;

    const int rv = ngtcp2_conn_client_new(&conn, &dcid, &scid, &ps.path, NGTCP2_PROTO_VER_V1, &cb,
                                          &qsettings, &qparams, nullptr, this);
    if (rv != 0) {
        conn = nullptr;
        SSL_free(ssl);
        ssl = nullptr;
        return std::unexpected(std::string("conn_client_new: ") + ngtcp2_strerror(rv));
    }
    ngtcp2_conn_set_tls_native_handle(conn, ssl);
    ngtcp2_conn_set_keep_alive_timeout(conn, static_cast<ngtcp2_tstamp>(timers.keepalive.count()) *
                                                  1000000ull);
    return {};
}

// The guard every retry decision opens with, purpose by purpose. quic.rs:517-522 (tunnel) asks for
// the ech_required close AND !established_ever AND current_ech.is_some() AND !ech_retried;
// quic.rs:982 (verify) asks only for the close AND !ech_retried -- the two extra guards missing from
// the verify path are the Rust's own difference and are not re-added here. tls::ech_rejected is the
// authority on the alert, so a 0x179 in disguise (an application code) never opens the retry.
bool SessionState::ech_retry_candidate() const {
    if (ech_retried) return false;
    if (!closed_recorded) return false; // the port's draining||closed
    if (!tls::ech_rejected(close.application_error, static_cast<std::uint32_t>(close.code))) {
        return false;
    }
    if (purpose == Purpose::Tunnel && (established_ever || !current_ech.has_value())) return false;
    return true;
}

// The retry body once the server's retry_configs are in hand. quic.rs:523-544 (tunnel) and
// 983-998 (verify) run the same steps, and this runs them in their order: log, adopt, set the key,
// rebuild the connection offering it, reset the state the dead connection owned, flush.
bool SessionState::apply_server_retry(std::vector<std::uint8_t> retry, TimePoint now) {
    // One retry per session, whichever carrier asked for it (the !ech_retried of quic.rs:519/982).
    if (ech_retried) return false;

    // usable_retry, tls.rs:492: refuse a list BoringSSL cannot offer, because a handshake given one
    // it cannot would go without ECH -- the silent degrade this port must never do. On the pump path
    // extract_ech_retry_configs already ran the same check and would have handed back nothing; a
    // host or the suite that brings the bytes itself still goes through this gate, so the two can
    // never disagree about what is offerable.
    if (const auto usable = tls::check_ech_config_list(retry); !usable) {
        note("the server handed back an ECH key that cannot be offered (" + usable.error() +
             "); not retrying with it");
        return false;
    }

    // Log, adopt, then set the current key -- quic.rs:524-531 / 984-990 in that order. The message
    // is the Rust's own; adopt records it for the session's later handshakes (tls.rs:442).
    if (purpose == Purpose::Tunnel) {
        note("ech_required: retrying handshake with server retry_configs (" +
             std::to_string(retry.size()) + " bytes)"); // quic.rs:524, a log::warn!
    } else {
        note("ech_required: verifying " + peer.to_string() +
             " again with the server's retry_configs (" + std::to_string(retry.size()) +
             " bytes)"); // quic.rs:984, a log::debug!
    }
    tls::adopt_ech_retry(retry);    // quic.rs:529/989 -- by value, a copy; the session keeps the slot
    ech_retried = true;             // quic.rs:530/990
    current_ech = std::move(retry); // quic.rs:531 (verify offers the same key inline, quic.rs:994)

    // Tear the refused connection down in dependency order, keeping the session's own context:
    // h3 rides on the QUIC connection, which rides on the SSL object.
    if (h3) { nghttp3_conn_del(h3); h3 = nullptr; }
    if (conn) { ngtcp2_conn_del(conn); conn = nullptr; }
    if (ssl) { SSL_free(ssl); ssl = nullptr; }

    // Reset the per-connection state the fresh connection must not inherit. quic.rs:540-542 names
    // h3_conn, req_stream and capsules; the rest are this port's own mirrors of the same turn:
    // handshake completion (so the pump re-runs establish on the new connection), the request
    // answer, the validation counters and deadline, and the datagram queue -- its frames name the
    // stream that just died. Deliberately NOT reset: established_ever, the tunnel's own retry guard,
    // already false when we arrive (quic.rs:518), and the process-wide ECH key adopt() just recorded.
    handshake_done = false;
    req_stream = -1;
    status = std::nullopt;
    datagram_delivered = false;
    validate_successes = 0;
    validate_deadline = std::nullopt;
    capsules.reset();
    pending.clear();
    next_dgram_id = 1;

    // Make the connection again offering the retry key (quic.rs:535-537's connect+inject_ech with a
    // fresh SCID at 533). If it cannot be built the session stays closed with the reason, rather
    // than reporting a live session whose connection was never made.
    if (const auto built = build_connection(now); !built) {
        error = "ech: the retried handshake could not be built (" + built.error() + ")";
        phase = Session::Phase::Closed;
        closed_recorded = true;
        return false;
    }

    // Past the close we are retrying: the fresh connection is neither draining nor closed, so the
    // loop carries on with it instead of reporting a closed one -- quic.rs's `continue`.
    closed_recorded = false;
    local_close_initiated = false;
    close = CloseInfo{};
    error = std::nullopt;
    phase = Session::Phase::Handshake;

    // The retried Initial goes out at once (quic.rs:543/997 -- flush before the continue).
    cur_ts = ts(now);
    flush(cur_ts);
    return true;
}

// ---------------------------------------------------------------------------
// Session.

Session::Session() = default;

Session::~Session() {
    if (!state_) return;
    SessionState* s = state_.get();
    if (s->h3) nghttp3_conn_del(s->h3);
    if (s->conn) ngtcp2_conn_del(s->conn);
    if (s->ssl) SSL_free(s->ssl);
    if (s->ctx) SSL_CTX_free(s->ctx);
}

std::expected<std::unique_ptr<Session>, std::string> Session::open(const Setup& setup,
                                                                   const Settings& settings,
                                                                   Seams seams, TimePoint now) {
    if (seams.io == nullptr) return std::unexpected("transport: no socket to speak through");

    auto state = std::make_unique<SessionState>();
    SessionState* s = state.get();
    s->setup = setup;
    s->purpose = setup.purpose;
    s->tunnel = setup.tunnel;
    s->timers = Timers::from_settings(settings, setup.purpose);
    s->conn_setup = ConnectionSetup::for_tunnel(setup.tunnel, settings);
    s->io = seams.io;
    s->inbound = seams.inbound;
    s->assigned_sink = seams.assigned;
    s->observer = seams.observer;
    s->relay = std::move(seams.relay);
    s->make_random = std::move(seams.make_random);
    if (setup.purpose == Purpose::Verify) s->verify_deadline_after = setup.verify_timeout;

    s->peer = setup.tunnel.peer;
    s->local = seams.io->local();
    s->dest = s->relay ? s->relay(s->local, s->peer) : s->peer;
    s->data_check = quic::data_check_enabled(settings);
    s->probe_packet = masque::build_dns_probe_packet(setup.tunnel.local_ipv4);

    // The context, in the documented order: shaping, TLS 1.3, the device certificate, verification.
    std::string verification;
    auto built = build_client_context(setup.tunnel, settings, verification);
    if (!built) return std::unexpected(built.error());
    s->ctx = *built;
    if (!verification.empty() && s->observer) s->observer->on_verification(verification);

    // The key this handshake offers, held before the connection is built so build_connection -- the
    // same path an ECH retry (quic.rs:513) walks -- reads it and refuses a list BoringSSL cannot
    // offer rather than send the server name in the clear.
    if (setup.tunnel.ech_config_list) s->current_ech = setup.tunnel.ech_config_list;

    // The SSL object, the connection ids, the settings and transport parameters the quic.hpp numbers
    // name, the callbacks and the QUIC connection: all of it build_connection's, and the one code
    // path every handshake of the session -- this first one and any retry -- shares. The base is
    // stamped here so build_connection's timestamps are relative to bring-up.
    s->base = now;
    if (const auto linked = s->build_connection(now); !linked) {
        // open() owns the context, so it is the one to free it when no connection can be made;
        // build_connection freed only the SSL object it had made.
        SSL_CTX_free(s->ctx);
        s->ctx = nullptr;
        return std::unexpected(linked.error());
    }

    // Bait first only if this is a tunnel that asked for it (or a check) and the setting is on.
    const bool want_bait = setup.tunnel.version_bait && quic::quic_v2_bait_enabled(settings);
    s->phase = want_bait ? Session::Phase::Baiting : Session::Phase::Handshake;

    auto session = std::unique_ptr<Session>(new Session());
    session->state_ = std::move(state);
    return session;
}

Session::Tick Session::tick(TimePoint now) {
    SessionState* s = state_.get();
    Tick out;

    // 0. The ECH retry, driven inline as the Rust drives it in its own select loop (quic.rs:513
    // tunnel / quic.rs:978 verify). On the turn a handshake is observed closed by our own
    // ech_required alert, the server's retry_configs are read off the failed SSL -- which stays live
    // until apply_server_retry frees it -- and the connection is made again at once. Running this
    // before the closed short-circuit is what lets the pump carry on with the fresh connection
    // rather than return Closed, which is exactly the effect of Rust's `continue`.
    if (s->ech_retry_candidate()) {
        if (const auto retry = tls::extract_ech_retry_configs(s->ssl); retry.has_value()) {
            (void)s->apply_server_retry(*retry, now);
        }
    }

    if (s->closed_recorded) {
        out.phase = Session::Phase::Closed;
        out.closed = true;
        out.error = s->error;
        out.delay = std::nullopt;
        return out;
    }

    s->cur_ts = s->ts(now);

    // 1. The data-plane validation deadline (quic.rs:357-369) and the whole-verify budget.
    if (s->purpose == Purpose::Tunnel && s->data_check && s->phase == Session::Phase::Validating &&
        s->validate_deadline && now >= *s->validate_deadline) {
        s->local_close(0x00, true, "validation-timeout",
                       "masque: data-plane validation timeout (handshake ok, no traffic)");
        out.phase = s->phase;
        out.closed = true;
        out.error = s->error;
        return out;
    }
    if (s->purpose == Purpose::Verify && s->verify_deadline_after.count() > 0 &&
        now >= s->base + s->verify_deadline_after) {
        s->local_close(0x00, true, "verify-timeout", "verify timeout");
        out.phase = s->phase;
        out.closed = true;
        out.error = s->error;
        return out;
    }

    // 2. The version bait (quic.rs's send_version_bait), driven one attempt per turn.
    if (s->phase == Session::Phase::Baiting) {
        while (auto arrived = s->io->receive()) {
            if (!*arrived) break;
            ++s->rx_packets;
            s->bait_answered = true;
            s->note("[quic] version-negotiation bait answered; the path is open for v1");
            break;
        }
        if (!s->bait_answered && s->bait_attempts < s->timers.bait_tries) {
            const std::vector<std::uint8_t> bait = quic::build_version_bait();
            (void)s->io->send(s->dest, std::span<const std::uint8_t>(bait));
            ++s->tx_packets;
            ++s->bait_attempts;
        }
        if (s->bait_answered || s->bait_attempts >= s->timers.bait_tries) {
            s->phase = Session::Phase::Handshake;
        }
        out.phase = s->phase;
        out.delay = s->bait_answered ? Millis{0} : s->timers.bait_wait;
        return out;
    }

    // 3. Drain the socket.
    while (auto arrived = s->io->receive()) {
        if (!*arrived) break;
        ++s->rx_packets;
        s->feed(std::span<const std::uint8_t>((*arrived)->packet));
        if (s->closed_recorded) break;
    }

    // 4. The control queue (quic.rs's ctrl_rx).
    for (quic::Control c : s->controls) {
        switch (c) {
        case quic::Control::Close:
            s->local_close(0x00, true, "bye", std::nullopt);
            break;
        case quic::Control::Migrate:
            // A second socket needs the make_io seam and a host-driven path change; nothing
            // migrates without it, so the pump only records the request.
            s->note("migration requested; the host owns the second socket");
            break;
        }
    }
    s->controls.clear();

    // 5. Timers / expiry.
    if (!s->closed_recorded && ngtcp2_conn_get_expiry2(s->conn) <= s->cur_ts) {
        const int rv = ngtcp2_conn_handle_expiry(s->conn, s->cur_ts);
        if (rv == NGTCP2_ERR_IDLE_CLOSE) {
            s->local_close(0x00, false, "idle-timeout", std::nullopt);
        } else if (rv < 0) {
            s->local_close(0x00, false, "expiry", std::nullopt);
        }
    }

    // 6. Handshake complete -> build h3 and send the connect-ip request.
    if (!s->closed_recorded && s->handshake_done && s->h3 == nullptr) {
        s->establish(now);
    }

    // 7. The connect-ip answer.
    if (!s->closed_recorded && s->status && s->phase == Session::Phase::Request) {
        if (masque::connect_succeeded(*s->status)) {
            if (s->observer) s->observer->on_status(*s->status);
            s->note("connect-ip status: " + std::to_string(*s->status));
            if (s->data_check) {
                s->phase = Session::Phase::Validating;
                s->last_probe = now;
            } else {
                s->phase = Session::Phase::Ready;
            }
        } else if (*s->status != 0) {
            s->local_close(0x00, true, "status",
                           "masque: the edge refused connect-ip with status " +
                               std::to_string(*s->status));
        }
    }

    // 8. The data-plane probe and its confirmations.
    if (!s->closed_recorded && s->phase == Session::Phase::Validating) {
        if (s->req_stream >= 0 && now - s->last_probe >= s->timers.probe) {
            s->queue_datagram(std::span<const std::uint8_t>(s->probe_packet));
            s->last_probe = now;
        }
        if (s->datagram_delivered) {
            ++s->validate_successes;
            s->note("[*] masque data-plane round-trip " + std::to_string(s->validate_successes) +
                    "/" + std::to_string(s->conn_setup.probe_successes_needed) + " confirmed");
            if (s->validate_successes >= s->conn_setup.probe_successes_needed) {
                s->phase = Session::Phase::Ready;
                s->validate_deadline = std::nullopt;
                s->note("[+] masque tunnel validated (end-to-end data confirmed); exposing socks5");
            }
        }
    }
    // One turn's datagram activity is accounted for; forget it before the next drain.
    s->datagram_delivered = false;

    // noize.rs's pre_handshake, once, ahead of the first packet the connection sends: quic.rs:341
    // (tunnel, after the bait at line 300) and quic.rs:857 (verify, after its own bait) both sit
    // between bring-up and flush. A disabled config returns without touching the socket.
    if (!s->noize_sent && !s->closed_recorded && s->phase == Session::Phase::Handshake) {
        s->noize_sent = true;
        noize::pre_handshake(
            *s->io, s->peer, s->tunnel.noize, s->relay,
            [s](noize::Level, std::string_view line) { s->note(line); });
    }

    // 9. The flush -- every packet the connection produced this turn.
    if (!s->closed_recorded) s->flush(s->cur_ts);

    // 10. A close either side asked for.
    s->handle_peer_close();

    // Delay: how long the Rust select loop would have slept.
    out.phase = s->phase;
    out.closed = s->closed_recorded;
    out.error = s->error;
    if (!s->closed_recorded) {
        ngtcp2_tstamp exp = ngtcp2_conn_get_expiry2(s->conn);
        Millis d{0};
        if (exp > s->cur_ts) d = Millis((exp - s->cur_ts) / 1000000ull);
        if (s->purpose == Purpose::Tunnel && s->phase == Session::Phase::Validating &&
            s->validate_deadline) {
            Millis left = std::chrono::duration_cast<Millis>(*s->validate_deadline - now);
            if (left < d) d = left;
        }
        out.delay = d;
        // TEMP-DIAG (QUIC 35s chase): suspiciously long sleeps.
        if (d > Millis(1000) && s->phase != Session::Phase::Handshake) {
            s->note("tick delay " + std::to_string(d.count()) + "ms in phase " +
                    std::to_string(static_cast<int>(s->phase)));
        }
    }
    return out;
}

void Session::deliver(std::span<const std::uint8_t> packet, const SocketAddr& /*from*/,
                      TimePoint now) {
    if (!state_ || state_->closed_recorded) return;
    state_->cur_ts = state_->ts(now);
    ++state_->rx_packets;
    state_->feed(packet);
}

Room Session::send_ip_packet(std::span<const std::uint8_t> ip_packet) {
    SessionState* s = state_.get();
    if (s->req_stream < 0) {
        ++s->datagrams_dropped; // no stream yet: quic.rs drops and counts, as Rust does
        return Room::Closed;
    }
    if (s->closed_recorded) {
        ++s->datagrams_dropped;
        return Room::Closed;
    }
    auto framed = masque::encode_ip_datagram(static_cast<std::uint64_t>(s->req_stream), ip_packet);
    if (!framed) return Room::Closed;
    if (s->conn_setup.outbound_queue != 0 && s->pending.size() >= s->conn_setup.outbound_queue) {
        return Room::Full;
    }
    s->pending.push_back(std::move(*framed));
    return Room::Accepted;
}

void Session::control(quic::Control control) {
    if (state_ && !state_->closed_recorded) state_->controls.push_back(control);
}

Session::Phase Session::phase() const { return state_->phase; }
bool Session::ready() const { return state_->phase == Session::Phase::Ready; }
const std::optional<std::string>& Session::error() const { return state_->error; }
const CloseInfo& Session::close() const { return state_->close; }
std::optional<std::uint16_t> Session::status() const { return state_->status; }
std::int64_t Session::request_stream() const { return state_->req_stream; }
std::optional<quic::AssignedAddr> Session::assigned() const { return state_->assigned; }
const Timers& Session::timers() const { return state_->timers; }
const ConnectionSetup& Session::setup() const { return state_->conn_setup; }
const quic::TunnelConfig& Session::tunnel() const { return state_->tunnel; }
SocketAddr Session::peer() const { return state_->peer; }
SocketAddr Session::local() const { return state_->local; }
std::span<const std::vector<std::uint8_t>> Session::pending_datagrams() const {
    return state_->pending;
}
std::size_t Session::tx_packets() const { return state_->tx_packets; }
std::size_t Session::rx_packets() const { return state_->rx_packets; }
std::size_t Session::datagrams_sent() const { return state_->datagrams_sent; }
std::size_t Session::datagrams_received() const { return state_->datagrams_received; }
std::size_t Session::datagrams_dropped() const { return state_->datagrams_dropped; }
Millis Session::keepalive_timeout() const { return state_->timers.keepalive; }
std::uint32_t Session::probe_successes() const { return state_->validate_successes; }
bool Session::ech_accepted() const { return state_->ech_accepted_seen; }
std::string_view Session::negotiated_alpn() const { return state_->alpn_seen; }

bool Session::ech_retry_candidate() const { return state_->ech_retry_candidate(); }
bool Session::apply_ech_retry(std::vector<std::uint8_t> server_retry, TimePoint now) {
    return state_->apply_server_retry(std::move(server_retry), now);
}
bool Session::ech_retried() const { return state_->ech_retried; }
std::optional<std::vector<std::uint8_t>> Session::offered_ech_key() const {
    return state_->current_ech;
}

} // namespace hemera::core::transport
