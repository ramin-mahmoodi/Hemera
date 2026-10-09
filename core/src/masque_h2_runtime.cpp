// The socket half of hemera/src/masque_h2.rs: the dial, the BoringSSL handshake over what it
// dialled with its one ECH retry (masque_h2.rs:209-277), the nghttp2 connection and the connect-ip
// request on stream 1, the data-plane probe verify_h2 runs on them (masque_h2.rs:279-377) and the
// tunnel loop that carries traffic on them (masque_h2.rs:386-657).
//
// Every decision here is masque_h2.hpp's: the constants with their Rust lines, the request field
// set (build_connect_request / connect_request_fields), the flow control h2_builder asks sysprofile
// for, the capsule framing from masque.hpp, the status rules and the probe counts. What this file
// adds is only the machinery that carries them: a non-blocking Winsock stream behind TcpIo, a
// BoringSSL memory BIO pair behind it, the ClientHello fragmentation of fragment.rs on the way out,
// and one nghttp2 client session whose body source is the request stream's capsule queue.
//
// It is blocking and thread-based, as the rest of this port is: no event loop, one absolute deadline
// covering the dial, the handshake, the request and the probe -- which is what
// `tokio::time::timeout(timeout, attempt)` at masque_h2.rs:372 is. The seam is DialSocket, so a test
// can drive the whole bring-up over a scripted byte pair and a proxy detour can answer it (the two
// arms of Rust's dial(), masque_h2.rs:209-216). A run carries no such deadline, because Rust's run
// sets none either (masque_h2.rs:413 is awaited bare); see Deadline::open_ended().
//
// run_with -- the long tunnel loop of masque_h2.rs:386-657 -- is here too: it drives the same
// bring-up, the same session and the same capsule queue, and takes the netstack's outbound queue,
// the control channel and the ready signal through masque_h2.hpp's TunnelSeams.

#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// NGHTTP2_NO_SSIZE_T comes from CMakeLists' target_compile_definitions, which is what lets
// nghttp2.h declare its own ssize_t; redefining it here only earns a C4005.

#include "masque_h2.hpp"

#include "fragment.hpp"
#include "settings.hpp"
#include "tls.hpp"
#include "upstream.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <string_view>
#include <utility>

namespace hemera::core::masque_h2 {

// tls.hpp declares its helpers directly in hemera::core; transport.cpp:33 gives them the same
// spelling, and it is what the Rust's `tls::` call sites (masque_h2.rs:226-258) read as.
namespace tls = ::hemera::core;

namespace {

// The winsock start-up guard, the refcounted one dns.cpp, socks.cpp and https_runtime.cpp keep:
// this file opens its own sockets, so it needs it whether or not egress did it first.
const struct Winsock {
    Winsock() {
        WSADATA ignored;
        ::WSAStartup(MAKEWORD(2, 2), &ignored);
    }
} winsock;

using Clock = std::chrono::steady_clock;
using Millis = std::chrono::milliseconds;

// HemeraError's kinds this half can produce, so a failure reads exactly like the Rust's Display:
// "io: ...", "tls: ...", "ech: ...", "masque: ...", "other: ..." (error.rs:3-38).
std::string prefixed(std::string_view kind, std::string_view text) {
    return std::string(kind) + ": " + std::string(text);
}

// Why a step stopped. A timeout is not a message: the Rust wraps the whole attempt in one timeout
// and writes a single sentence for it (masque_h2.rs:375), so everywhere the deadline runs out
// reports this and verify_h2_with renders that sentence, while a real failure already carries its
// own prefixed text.
struct Stop {
    std::string text;
    bool timed_out = false;

    [[nodiscard]] static Stop failed(std::string text) { return Stop{std::move(text), false}; }
    [[nodiscard]] static Stop timeout() { return Stop{{}, true}; }
};

// The one sentence `tokio::time::timeout` answers with, whatever step was in flight (masque_h2.rs:375).
std::string render(const Stop& stop) {
    return stop.timed_out ? prefixed("other", "h2 verify timeout") : stop.text;
}

// The same for a run, which has no `tokio::time::timeout` around it (masque_h2.rs:413 is awaited
// bare). The open-ended deadline only reaches this arm once its whole span has passed, so the
// sentence is the port's own; every real failure already carries the Rust's classified text.
std::string run_render(const Stop& stop) {
    if (!stop.timed_out) return stop.text;
    return prefixed("masque", "h2 bring-up did not complete");
}

std::string winsock_reason(int code) {
    char* raw = nullptr;
    const DWORD length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                            FORMAT_MESSAGE_IGNORE_INSERTS,
                                        nullptr, static_cast<UINT>(code), 0,
                                        reinterpret_cast<LPSTR>(&raw), 0, nullptr);
    std::string text;
    if (raw != nullptr) {
        text.assign(raw, length);
        LocalFree(raw);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
            text.pop_back();
        }
    }
    if (text.empty()) text = "socket error " + std::to_string(code);
    return text + " (" + std::to_string(code) + ")";
}

// The whole run's budget, absolute. Every wait below is bounded by what is left of it, which is how
// one timeout covers the dial, the handshake, the request and the probe as Rust's one does.
class Deadline {
public:
    explicit Deadline(Millis total) : end_(Clock::now() + total) {}

    // A tunnel's bring-up budget. masque_h2.rs::run bounds nothing: connect_tls is awaited bare
    // (masque_h2.rs:413) and send_capsule waits on the edge's window for as long as that takes
    // (masque_h2.rs:718-736), so the deadline a run passes is one no tunnel lives long enough to
    // reach and every wait is bounded by the peer's own answer instead. Ten years stays inside
    // steady_clock's range and inside the 32-bit seconds a select timeout takes.
    [[nodiscard]] static Deadline open_ended() { return Deadline(std::chrono::milliseconds{
                                                              315'360'000'000LL}); }

    [[nodiscard]] Millis left() const {
        const auto now = Clock::now();
        if (now >= end_) return Millis::zero();
        return std::chrono::duration_cast<Millis>(end_ - now);
    }
    [[nodiscard]] bool expired() const { return Clock::now() >= end_; }

private:
    Clock::time_point end_;
};

std::string_view as_view(const std::vector<std::uint8_t>& bytes) {
    return bytes.empty()
               ? std::string_view{}
               : std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// cfg.expected_pins is the Vec<Vec<u8>> of masque_h2.rs:90, the type the Rust call sites build from
// consts::MASQUE_PINS; tls.hpp's install_verification takes the fixed-width form. A pin of any other
// length matches nothing and is left out, which is what the Rust's slice compare does with it.
std::vector<tls::SpkiPin> pins_for(const std::vector<std::vector<std::uint8_t>>& expected) {
    std::vector<tls::SpkiPin> pins;
    for (const std::vector<std::uint8_t>& pin : expected) {
        if (pin.size() != sizeof(tls::SpkiPin)) continue;
        tls::SpkiPin copy{};
        std::memcpy(copy.data(), pin.data(), copy.size());
        pins.push_back(copy);
    }
    return pins;
}

void note(transport::Observer* observer, std::string_view line) {
    if (observer != nullptr) observer->on_note(line);
}

void clear_ssl_error() {
    while (ERR_get_error() != 0) {
    }
}

// Everything BoringSSL left on the error queue, in one line. ECH_REJECTED has to be readable here:
// it is the only thing the retry loop keys on (masque_h2.rs:44-46, 253), and BoringSSL's reason
// string for the rejection is that exact word.
std::string ssl_error_text(std::string_view fallback) {
    std::string text;
    for (;;) {
        const unsigned long code = ERR_get_error();
        if (code == 0) break;
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof buffer);
        if (!text.empty()) text += "; ";
        text += buffer;
    }
    if (text.empty()) {
        text = std::string(fallback);
        const int code = WSAGetLastError();
        if (code != 0) text += " (" + winsock_reason(code) + ")";
    }
    return text;
}

struct CtxFree {
    void operator()(SSL_CTX* ctx) const { SSL_CTX_free(ctx); }
};
struct SslFree {
    void operator()(SSL* ssl) const { SSL_free(ssl); }
};
using OwnedCtx = std::unique_ptr<SSL_CTX, CtxFree>;
using OwnedSsl = std::unique_ptr<SSL, SslFree>;

// proxy.connect(peer): the TCP stream through the proxy (masque_h2.rs:211, upstream.rs connect).
// socks5 runs the greeting, the login and CMD_CONNECT on a socket to the proxy; http runs one
// CONNECT and reads its answer to the empty line. Every step shares the one handshake budget,
// which is HANDSHAKE_TIMEOUT_MS capped by what the caller still has -- a run's open-ended
// deadline is not a license for a proxy handshake to take ten years.
namespace up = ::hemera::core::upstream;

namespace {

bool proxy_wait(SOCKET socket, bool for_write, Millis budget) {
    if (budget <= Millis::zero()) return false;
    fd_set watched;
    FD_ZERO(&watched);
    FD_SET(socket, &watched);
    timeval slice{};
    slice.tv_sec = static_cast<long>(budget.count() / 1000);
    slice.tv_usec = static_cast<long>((budget.count() % 1000) * 1000);
    const int ready =
        ::select(0, for_write ? nullptr : &watched, for_write ? &watched : nullptr, nullptr, &slice);
    return ready > 0;
}

[[nodiscard]] bool proxy_send_all(SOCKET socket, std::span<const std::uint8_t> bytes,
                                  const Clock::time_point& end) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        const Millis left =
            std::chrono::duration_cast<Millis>(end - Clock::now());
        if (left <= Millis::zero() || !proxy_wait(socket, true, left)) return false;
        const int wrote =
            ::send(socket, reinterpret_cast<const char*>(bytes.data() + sent),
                   static_cast<int>(bytes.size() - sent), 0);
        if (wrote <= 0) return false;
        sent += static_cast<std::size_t>(wrote);
    }
    return true;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> proxy_recv_exact(
    SOCKET socket, std::size_t want, const Clock::time_point& end) {
    std::vector<std::uint8_t> out;
    out.reserve(want);
    std::vector<std::uint8_t> chunk(2048);
    while (out.size() < want) {
        const Millis left = std::chrono::duration_cast<Millis>(end - Clock::now());
        if (left <= Millis::zero() || !proxy_wait(socket, false, left)) return std::nullopt;
        const int got = ::recv(socket, reinterpret_cast<char*>(chunk.data()),
                               static_cast<int>(std::min<std::size_t>(chunk.size(),
                                                                     want - out.size())),
                               0);
        if (got <= 0) return std::nullopt;
        out.insert(out.end(), chunk.begin(), chunk.begin() + got);
    }
    return out;
}

// The proxy's own address: a literal dialled as-is, a name resolved first. Addresses are tried
// in the order the system answers them, first one that connects wins.
[[nodiscard]] std::expected<SOCKET, std::string> dial_proxy_host(const up::Upstream& proxy,
                                                                 const Clock::time_point& end) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* list = nullptr;
    if (::getaddrinfo(proxy.host.c_str(), std::to_string(proxy.port).c_str(), &hints, &list) != 0 ||
        list == nullptr) {
        return std::unexpected(prefixed("io", "the upstream proxy host " + proxy.host +
                                                " did not resolve"));
    }
    struct Free {
        addrinfo* list;
        ~Free() { ::freeaddrinfo(list); }
    } free{list};
    std::string last;
    for (addrinfo* each = list; each != nullptr; each = each->ai_next) {
        const SOCKET socket =
            ::socket(each->ai_family, each->ai_socktype, each->ai_protocol);
        if (socket == INVALID_SOCKET) {
            last = winsock_reason(WSAGetLastError());
            continue;
        }
        u_long mode = 1;
        ::ioctlsocket(socket, FIONBIO, &mode);
        struct Guard {
            SOCKET socket;
            bool ok = false;
            ~Guard() {
                if (!ok) ::closesocket(socket);
            }
        } guard{socket};
        if (::connect(socket, each->ai_addr, static_cast<int>(each->ai_addrlen)) != 0 &&
            WSAGetLastError() != WSAEWOULDBLOCK) {
            last = winsock_reason(WSAGetLastError());
            continue;
        }
        const Millis left = std::chrono::duration_cast<Millis>(end - Clock::now());
        if (left <= Millis::zero() || !proxy_wait(socket, true, left)) {
            last = "the connect to the upstream proxy did not answer in time";
            continue;
        }
        int failed = 0;
        int size = sizeof failed;
        ::getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&failed), &size);
        if (failed != 0) {
            last = winsock_reason(failed);
            continue;
        }
        mode = 0;
        ::ioctlsocket(socket, FIONBIO, &mode);
        guard.ok = true;
        return socket;
    }
    return std::unexpected(prefixed("io", last.empty() ? up::connect_timed_out(proxy) : last));
}

[[nodiscard]] std::expected<SOCKET, std::string> connect_socket_via_proxy(
    const up::Upstream& proxy, const SocketAddr& peer, Millis budget) {
    const Clock::time_point end = Clock::now() + budget;
    auto dialed = dial_proxy_host(proxy, end);
    if (!dialed) return std::unexpected(dialed.error());
    const SOCKET socket = *dialed;
    struct Guard {
        SOCKET socket;
        bool ok = false;
        ~Guard() {
            if (!ok) ::closesocket(socket);
        }
    } guard{socket};

    if (proxy.kind == up::Kind::Socks5) {
        const std::vector<std::uint8_t> greeting = up::greet_request(proxy.wants_auth());
        if (!proxy_send_all(socket, greeting, end)) {
            return std::unexpected(prefixed("io", "the upstream proxy greeting did not send"));
        }
        auto answer = proxy_recv_exact(socket, 2, end);
        if (!answer) {
            return std::unexpected(prefixed("io", "the upstream proxy did not answer the greeting"));
        }
        if (auto checked = up::check_greeting(proxy.wants_auth(), *answer); !checked) {
            return std::unexpected(prefixed("other", checked.error()));
        }
        if (answer->at(1) == up::AUTH_USERPASS) {
            auto login = up::authenticate_request(proxy.user, proxy.password);
            if (!login) return std::unexpected(prefixed("other", login.error()));
            if (!proxy_send_all(socket, *login, end)) {
                return std::unexpected(prefixed("io", "the upstream proxy login did not send"));
            }
            auto auth_answer = proxy_recv_exact(socket, 2, end);
            if (!auth_answer) {
                return std::unexpected(
                    prefixed("io", "the upstream proxy did not answer the login"));
            }
            if (auto checked = up::check_auth_answer(*auth_answer); !checked) {
                return std::unexpected(prefixed("other", checked.error()));
            }
        }
        const up::SocketTarget target{{}, peer.ip, peer.port};
        const std::vector<std::uint8_t> request = up::encode_request(up::CMD_CONNECT, target);
        if (!proxy_send_all(socket, request, end)) {
            return std::unexpected(prefixed("io", "the upstream proxy connect did not send"));
        }
        auto head = proxy_recv_exact(socket, 4, end);
        if (!head) {
            return std::unexpected(prefixed("io", "the upstream proxy did not answer the connect"));
        }
        const auto atyp = up::check_reply_head(*head);
        if (!atyp) return std::unexpected(prefixed("other", atyp.error()));
        // The bound address rides behind the head and has to be read past for the stream to be
        // usable; a connect does not use it.
        std::size_t skip = 0;
        if (*atyp == up::ATYP_V4) skip = 4 + 2;
        else if (*atyp == up::ATYP_V6) skip = 16 + 2;
        else if (*atyp == up::ATYP_NAME) {
            auto length = proxy_recv_exact(socket, 1, end);
            if (!length) {
                return std::unexpected(
                    prefixed("io", "the upstream proxy did not answer the connect"));
            }
            skip = 1 + (*length)[0] + 2;
        }
        if (skip > 0 && !proxy_recv_exact(socket, skip, end)) {
            return std::unexpected(prefixed("io", "the upstream proxy did not answer the connect"));
        }
        guard.ok = true;
        return socket;
    }

    const std::string connect = up::connect_request(proxy, peer.to_string());
    if (!proxy_send_all(socket,
                        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(
                                                          connect.data()),
                                                      connect.size()),
                        end)) {
        return std::unexpected(prefixed("io", "the upstream proxy connect did not send"));
    }
    // The answer read a byte at a time to the empty line, as upstream.rs's http_connect does.
    std::string head;
    for (;;) {
        auto byte = proxy_recv_exact(socket, 1, end);
        if (!byte) {
            return std::unexpected(prefixed("io", std::string(up::HTTP_CLOSED_BEFORE_ANSWER)));
        }
        head += static_cast<char>((*byte)[0]);
        if (head.size() > up::MAX_HTTP_CONNECT_HEAD) {
            return std::unexpected(prefixed("other", std::string(up::HTTP_OVERSIZED_ANSWER)));
        }
        if (head.size() >= 4 && head.ends_with("\r\n\r\n")) break;
    }
    const std::span<const std::uint8_t> head_span(reinterpret_cast<const std::uint8_t*>(head.data()),
                                                 head.size());
    if (auto answered = up::connect_answer(head_span); !answered) {
        return std::unexpected(prefixed("other", answered.error()));
    }
    guard.ok = true;
    return socket;
}

} // namespace

sockaddr_storage to_storage(const SocketAddr& peer) {
    sockaddr_storage storage{};
    if (peer.ip.v4) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&storage);
        v4->sin_family = AF_INET;
        v4->sin_port = htons(peer.port);
        std::memcpy(&v4->sin_addr.s_addr, peer.ip.bytes.data() + 12, 4);
    } else {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(&storage);
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(peer.port);
        std::memcpy(&v6->sin6_addr, peer.ip.bytes.data(), 16);
    }
    return storage;
}

std::size_t storage_len(const sockaddr_storage& storage) {
    return storage.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

// A connected (or connecting) TCP socket, non-blocking, so every wait the runtime runs is a select
// with the caller's own budget in it. `wait` is the caller's sleep; `read` and `write` never sleep.
class WinTcpIo final : public TcpIo {
public:
    explicit WinTcpIo(SOCKET socket) : socket_(socket) {}
    WinTcpIo(const WinTcpIo&) = delete;
    WinTcpIo& operator=(const WinTcpIo&) = delete;
    ~WinTcpIo() override { close(); }

    void close() {
        if (socket_ != INVALID_SOCKET) {
            ::closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

    // The bytes the peer sent: 0 is its close. Nothing is ever there yet without a wait first --
    // which is the discipline the runtime keeps -- so a spurious would-block reads as 0 bytes here
    // exactly as an empty read does, and the caller's next wait is what tells the two apart.
    [[nodiscard]] std::expected<std::size_t, std::string> read(std::span<std::uint8_t> out) override {
        const int got = ::recv(socket_, reinterpret_cast<char*>(out.data()),
                               static_cast<int>(out.size()), 0);
        if (got >= 0) return static_cast<std::size_t>(got);
        const int code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) return std::size_t{0};
        return std::unexpected(prefixed("io", winsock_reason(code)));
    }

    [[nodiscard]] std::expected<std::size_t, std::string> write(
        std::span<const std::uint8_t> bytes) override {
        const int wrote = ::send(socket_, reinterpret_cast<const char*>(bytes.data()),
                                 static_cast<int>(bytes.size()), 0);
        if (wrote >= 0) return static_cast<std::size_t>(wrote);
        const int code = WSAGetLastError();
        if (code == WSAEWOULDBLOCK) return std::size_t{0};
        return std::unexpected(prefixed("io", winsock_reason(code)));
    }

    [[nodiscard]] bool wait(Millis limit, bool for_write) override {
        if (socket_ == INVALID_SOCKET) return false;
        fd_set watched;
        FD_ZERO(&watched);
        FD_SET(socket_, &watched);
        fd_set errors;
        FD_ZERO(&errors);
        FD_SET(socket_, &errors);
        TIMEVAL timer{};
        const Millis bounded = limit > Millis::zero() ? limit : Millis::zero();
        timer.tv_sec = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(bounded).count());
        timer.tv_usec = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(bounded % std::chrono::seconds(1))
                .count());
        const int ready = ::select(0, for_write ? nullptr : &watched, for_write ? &watched : nullptr,
                                   &errors, &timer);
        if (ready > 0) return true;
        // A socket that has an error pending is writable and readable in the sense the runtime
        // needs: it must go on to the read or write that reports it.
        return FD_ISSET(socket_, &errors) != FALSE;
    }

private:
    SOCKET socket_ = INVALID_SOCKET;
};

// ---------------------------------------------------------------------------
// The TLS over a TcpIo: BoringSSL on a memory BIO pair, with fragment.rs's ClientHello splitting on
// the way out (Rust's FragmentingStream, masque_h2.rs:239).

class Tls {
public:
    Tls(OwnedCtx ctx, std::unique_ptr<TcpIo> io, const FragmentConfig& fragment)
        : ctx_(std::move(ctx)), io_(std::move(io)), fragmenter_(fragment) {}
    Tls(const Tls&) = delete;
    Tls& operator=(const Tls&) = delete;
    ~Tls() {
        ssl_.reset();
        if (machine_ != nullptr) {
            BIO_free(machine_);
            machine_ = nullptr;
        }
    }

    // The BIO pair, the SSL on it and the server name. tokio_boring::connect(config, sni, stream)
    // is the SNI plus the hostname check; with verification off (masque_h2.rs:188-190) what is left
    // of it is the name.
    [[nodiscard]] static std::expected<std::unique_ptr<Tls>, Stop> open(OwnedCtx ctx,
                                                                        std::unique_ptr<TcpIo> io,
                                                                        std::string_view sni,
                                                                        const FragmentConfig& fragment) {
        auto link = std::make_unique<Tls>(std::move(ctx), std::move(io), fragment);
        BIO* side = nullptr;
        if (BIO_new_bio_pair(&side, 0, &link->machine_, 0) != 1) {
            return std::unexpected(
                Stop::failed(prefixed("tls", "no BIO pair for the handshake")));
        }
        link->ssl_.reset(SSL_new(link->ctx_.get()));
        if (link->ssl_ == nullptr) {
            return std::unexpected(Stop::failed(prefixed("tls", ssl_error_text("SSL_new failed"))));
        }
        // Both halves on one end, so the handshake never reads its own writes.
        SSL_set_bio(link->ssl_.get(), side, side);
        if (!sni.empty() && SSL_set_tlsext_host_name(link->ssl_.get(), std::string(sni).c_str()) != 1) {
            clear_ssl_error();
            return std::unexpected(
                Stop::failed(prefixed("tls", "the server name was refused")));
        }
        SSL_set_connect_state(link->ssl_.get());
        return link;
    }

    [[nodiscard]] SSL* ssl() const { return ssl_.get(); }

    // The full handshake, inside the run's deadline. The message it fails with is what
    // rejected_ech reads (masque_h2.rs:253).
    [[nodiscard]] std::expected<void, Stop> handshake(const Deadline& deadline) {
        for (;;) {
            const int done = SSL_connect(ssl_.get());
            // Whatever the ClientHello or the next flight produced goes out before anything waits.
            if (auto out = flush(deadline); !out) return std::unexpected(out.error());
            if (done == 1) return {};
            const int error = SSL_get_error(ssl_.get(), done);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                if (deadline.expired()) return std::unexpected(Stop::timeout());
                if (!io_->wait(deadline.left(), error == SSL_ERROR_WANT_WRITE)) {
                    return std::unexpected(Stop::timeout());
                }
                if (error == SSL_ERROR_WANT_WRITE) continue;
                const auto fed = pull(deadline.left());
                if (!fed) return std::unexpected(fed.error());
                if (!*fed) {
                    return std::unexpected(
                        Stop::failed(ssl_error_text("the connection ended in the middle of the handshake")));
                }
                continue;
            }
            return std::unexpected(
                Stop::failed(ssl_error_text("the handshake was refused")));
        }
    }

    // App bytes off the TLS connection, waiting at most `limit` for them. Stop::timeout is the
    // window running out with nothing in -- the caller's own timers decide what happens next -- and
    // 0 bytes is the connection ending.
    [[nodiscard]] std::expected<std::size_t, Stop> read(std::span<std::uint8_t> into, Millis limit) {
        const auto stop_at = Clock::now() + limit;
        for (;;) {
            const int got = SSL_read(ssl_.get(), into.data(), static_cast<int>(into.size()));
            if (got > 0) return static_cast<std::size_t>(got);
            const int error = SSL_get_error(ssl_.get(), got);
            if (error == SSL_ERROR_ZERO_RETURN) return std::size_t{0};
            if (error == SSL_ERROR_SYSCALL) {
                // The peer went away without a close_notify; whether the frame came whole is for
                // nghttp2 to say.
                clear_ssl_error();
                return std::size_t{0};
            }
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                return std::unexpected(
                    Stop::failed(prefixed("io", ssl_error_text("the read failed"))));
            }
            const Millis left =
                stop_at > Clock::now()
                    ? std::chrono::duration_cast<Millis>(stop_at - Clock::now())
                    : Millis::zero();
            if (left <= Millis::zero()) return std::unexpected(Stop::timeout());
            if (error == SSL_ERROR_WANT_WRITE) {
                if (!io_->wait(left, true)) return std::unexpected(Stop::timeout());
                continue;
            }
            const auto fed = pull(left);
            if (!fed) return std::unexpected(fed.error());
            if (!*fed) return std::unexpected(Stop::timeout());
        }
    }

    [[nodiscard]] std::expected<void, Stop> write(std::span<const std::uint8_t> bytes,
                                                  const Deadline& deadline) {
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            const int wrote = SSL_write(ssl_.get(), bytes.data() + sent,
                                        static_cast<int>(bytes.size() - sent));
            if (wrote > 0) {
                sent += static_cast<std::size_t>(wrote);
                if (auto out = flush(deadline); !out) return std::unexpected(out.error());
                continue;
            }
            const int error = SSL_get_error(ssl_.get(), wrote);
            if (error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_WANT_READ) {
                return std::unexpected(
                    Stop::failed(prefixed("io", ssl_error_text("the write failed"))));
            }
            if (deadline.expired()) return std::unexpected(Stop::timeout());
            if (auto out = flush(deadline); !out) return std::unexpected(out.error());
            if (error == SSL_ERROR_WANT_WRITE) {
                if (!io_->wait(deadline.left(), true)) return std::unexpected(Stop::timeout());
                continue;
            }
            const auto fed = pull(deadline.left());
            if (!fed) return std::unexpected(fed.error());
            if (!*fed) {
                return std::unexpected(
                    Stop::failed("the connection ended in the middle of the request"));
            }
        }
        return {};
    }

private:
    // What the wire has produced, into the handshake or the record layer. False is "nothing arrived
    // inside `limit`"; the connection ending is reported the same way and read off the next call.
    [[nodiscard]] std::expected<bool, Stop> pull(Millis limit) {
        if (limit > Millis::zero() && !io_->wait(limit, false)) return false;
        std::array<std::uint8_t, 16 * 1024> buffer{};
        const auto got = io_->read(std::span(buffer).first(4096));
        if (!got) return std::unexpected(Stop::failed(got.error()));
        if (*got == 0) {
            // The stream ended. The caller's next SSL call reports what that means where it stands.
            return false;
        }
        // Rust's FragmentingStream stops fragmenting at the first read (fragment.rs:170-193).
        fragmenter_.stop();
        std::span<const std::uint8_t> rest(buffer.data(), *got);
        while (!rest.empty()) {
            const size_t room = BIO_ctrl_get_write_guarantee(machine_);
            if (room == 0) {
                return std::unexpected(
                    Stop::failed("the handshake buffer would not take the record"));
            }
            const std::size_t piece = std::min(rest.size(), room);
            const int written = BIO_write(machine_, rest.data(), static_cast<int>(piece));
            if (written <= 0) {
                return std::unexpected(
                    Stop::failed(prefixed("tls", ssl_error_text("the record would not go in"))));
            }
            rest = rest.subspan(static_cast<std::size_t>(written));
        }
        return true;
    }

    // What SSL has produced, onto the wire -- in the ClientHello's case in the fragmenter's pieces,
    // each followed by its delay (fragment.rs's poll_write).
    [[nodiscard]] std::expected<void, Stop> flush(const Deadline& deadline) {
        std::array<std::uint8_t, 16 * 1024> buffer{};
        for (;;) {
            const int got = BIO_read(machine_, buffer.data(), static_cast<int>(buffer.size()));
            if (got <= 0) return {};
            std::span<const std::uint8_t> rest(buffer.data(), static_cast<std::size_t>(got));
            while (!rest.empty()) {
                std::size_t piece = rest.size();
                std::uint64_t delay_ms = 0;
                if (const auto plan = fragmenter_.plan(rest)) {
                    piece = std::min(plan->len, rest.size());
                    delay_ms = plan->delay_ms;
                }
                std::size_t sent = 0;
                while (sent < piece) {
                    if (deadline.expired()) return std::unexpected(Stop::timeout());
                    const auto wrote = io_->write(rest.subspan(sent, piece - sent));
                    if (!wrote) return std::unexpected(Stop::failed(wrote.error()));
                    if (*wrote > 0) {
                        sent += *wrote;
                        fragmenter_.advance(*wrote);
                        continue;
                    }
                    if (!io_->wait(deadline.left(), true)) return std::unexpected(Stop::timeout());
                }
                rest = rest.subspan(sent);
                if (delay_ms > 0) ::Sleep(static_cast<DWORD>(delay_ms));
            }
        }
    }

    OwnedCtx ctx_;
    std::unique_ptr<TcpIo> io_;
    BIO* machine_ = nullptr;
    OwnedSsl ssl_;
    FragmentWriter fragmenter_;
};

// ---------------------------------------------------------------------------
// build_tls (masque_h2.rs:160-194): the shaping, the device certificate, the verification.

std::expected<OwnedCtx, Stop> build_context(const H2TunnelConfig& cfg, const Settings& settings,
                                            std::string& verification) {
    OwnedCtx ctx(SSL_CTX_new(TLS_client_method()));
    if (ctx == nullptr) {
        return std::unexpected(
            Stop::failed(prefixed("tls", ssl_error_text("SSL_CTX_new failed"))));
    }
    // tls::Fingerprint::configured().apply(&mut builder, H2_ALPN) -- GREASE, the extension
    // permutation, the groups, the cipher rule and the ALPN list, in that order, because the order
    // is what the Rust writes.
    if (const auto shaped = tls::Fingerprint::configured(settings).apply(
            ctx.get(), std::span<const std::uint8_t>(H2_ALPN));
        !shaped) {
        return std::unexpected(Stop::failed(prefixed("tls", shaped.error())));
    }
    // The WARP device certificate: without it the edge finishes the handshake and closes 0x174.
    if (const auto cert = tls::use_device_certificate(ctx.get(), as_view(cfg.cert_pem),
                                                      as_view(cfg.key_pem));
        !cert) {
        return std::unexpected(Stop::failed(prefixed("tls", cert.error())));
    }
    // Pin-based verification, or none, exactly as cfg.pin_endpoint and cfg.expected_pins say; the
    // hostname check stays off, as config.set_verify_hostname(false) leaves it (masque_h2.rs:190).
    verification = tls::install_verification(ctx.get(), cfg.pin_endpoint,
                                             pins_for(cfg.expected_pins), settings);
    return ctx;
}

// connect_tls (masque_h2.rs:222-277): dial, shake hands over what was dialled, offer cfg's
// ECHConfigList when it has one, and -- the point of this loop, and one of the four sites in the
// Rust where a server-sent retry_configs list is adopted -- when the server turns that list down,
// take the list it hands back, adopt it for the session, and make the whole connection again with
// it: fresh socket, fresh context, fresh handshake. `retried` is the one-time guard; a second list
// is not taken, and an unusable one is refused rather than offered, because a handshake that went
// without the key it was given would put the server name in the clear.
std::expected<std::unique_ptr<Tls>, Stop> connect_tls(const H2TunnelConfig& cfg,
                                                      const Settings& settings,
                                                      const DialSocket& dial,
                                                      const Deadline& deadline,
                                                      transport::Observer* observer) {
    std::optional<std::vector<std::uint8_t>> ech = cfg.ech_config_list;
    bool retried = false;
    const FragmentConfig fragment = FragmentConfig::configured(settings);

    for (;;) {
        std::string verification;
        auto ctx = build_context(cfg, settings, verification);
        if (!ctx) return std::unexpected(ctx.error());
        if (observer != nullptr && !verification.empty()) {
            observer->on_verification(verification);
        }

        // dial() -- the detour's answer or egress::tcp_connect's -- with set_nodelay on the way
        // (masque_h2.rs:212, 238). A retry comes back through here, so the retried handshake is on
        // a fresh stream rather than on the one the server turned down.
        auto io = dial(cfg.peer);
        if (!io) {
            return std::unexpected(Stop::failed(io.error()));
        }

        auto link = Tls::open(std::move(*ctx), std::move(*io), cfg.sni, fragment);
        if (!link) return std::unexpected(link.error());

        if (ech) {
            // BoringSSL takes a key it offers nothing from, and the name would go in the clear
            // (masque_h2.rs:230-236).
            if (const auto usable = tls::ensure_offerable(*ech); !usable) {
                return std::unexpected(Stop::failed(prefixed("ech", usable.error())));
            }
            if (SSL_set1_ech_config_list((*link)->ssl(), ech->data(), ech->size()) != 1) {
                clear_ssl_error();
                return std::unexpected(Stop::failed(
                    prefixed("tls", "h2 ech config: " +
                                        ssl_error_text("SSL_set1_ech_config_list failed"))));
            }
        }

        if (auto went = (*link)->handshake(deadline); went) {
            if (ech) {
                // Nothing goes over a handshake that went without the key it was given
                // (masque_h2.rs:242-248) -- and that holds for the retried handshake as for the first.
                if (!tls::ech_accepted((*link)->ssl())) {
                    return std::unexpected(
                        Stop::failed(prefixed("ech", "the handshake went without ECH")));
                }
                note(observer, "[h2] ech accepted");
            }
            return std::move(link);
        } else if (went.error().timed_out) {
            return std::unexpected(went.error());
        } else {
            const std::string message = went.error().text;
            std::optional<std::vector<std::uint8_t>> retry;
            if (!retried && ech && rejected_ech(message)) {
                // extract_ech_retry_configs is the port's tls::usable_retry (masque_h2.rs:254-257):
                // nothing at all, or a list BoringSSL cannot offer, both answer nothing. The failed
                // SSL is read here, before it goes out of scope and takes the server's list with it.
                retry = tls::extract_ech_retry_configs((*link)->ssl());
            }
            if (!retry) {
                return std::unexpected(Stop::failed(
                    prefixed("tls", "h2 tls handshake: " + message)));
            }
            note(observer,
                 "[h2] ech_required: retrying the handshake with the server's retry_configs (" +
                     std::to_string(retry->size()) + " bytes)");
            tls::adopt_ech_retry(*retry);
            ech = std::move(retry);
            retried = true;
            // link and the socket it owns are dropped here; the loop dials again.
        }
    }
}

// ---------------------------------------------------------------------------
// The nghttp2 half: one client session, the connect-ip request on stream 1, and the request
// stream's body as a deferred source -- the capsule queue verify_h2 (and later run) feeds.
//
// nghttp2 takes C function pointers, so the callbacks below are free functions and the session's
// user_data is the drive; they are declared here because H2Drive::open hands them to
// nghttp2_session_callbacks_set_* before the class body is anywhere near them.
nghttp2_ssize h2_send(nghttp2_session*, const std::uint8_t*, std::size_t, int, void*);
int h2_header(nghttp2_session*, const nghttp2_frame*, const std::uint8_t*, std::size_t,
              const std::uint8_t*, std::size_t, std::uint8_t, void*);
int h2_frame_recv(nghttp2_session*, const nghttp2_frame*, void*);
int h2_data_chunk(nghttp2_session*, std::uint8_t, std::int32_t, const std::uint8_t*,
                  std::size_t, void*);
int h2_stream_close(nghttp2_session*, std::int32_t, std::uint32_t, void*);
int h2_error(nghttp2_session*, int, const char*, size_t, void*);
nghttp2_ssize h2_read_body(nghttp2_session*, std::int32_t, std::uint8_t*, std::size_t,
                           std::uint32_t* flags, nghttp2_data_source*, void*);

class H2Drive {
public:
    H2Drive() = default;
    H2Drive(const H2Drive&) = delete;
    H2Drive& operator=(const H2Drive&) = delete;
    ~H2Drive() {
        if (session_ != nullptr) nghttp2_session_del(session_);
    }

    // h2_builder().handshake(tls) + h2.ready() + send_request(req, false)
    // (masque_h2.rs:285-302), with the flow control of h2_flow and the field set of
    // connect_request_fields.
    [[nodiscard]] static std::expected<std::unique_ptr<H2Drive>, Stop>
    open(std::unique_ptr<Tls> tls, const H2TunnelConfig& cfg, const Settings& settings,
         const Deadline& deadline) {
        nghttp2_session_callbacks* callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0) {
            return std::unexpected(Stop::failed(prefixed("masque", "h2 handshake: out of memory")));
        }
        const struct Callbacks {
            nghttp2_session_callbacks* callbacks;
            ~Callbacks() { nghttp2_session_callbacks_del(callbacks); }
        } guard{callbacks};
        nghttp2_session_callbacks_set_send_callback2(callbacks, h2_send);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_data_chunk);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_stream_close);
        nghttp2_session_callbacks_set_error_callback2(callbacks, h2_error);

        auto drive = std::make_unique<H2Drive>();
        drive->tls_ = std::move(tls);
        drive->deadline_ = deadline;
        drive->fields_ = connect_request_fields(cfg);

        nghttp2_session* session = nullptr;
        if (nghttp2_session_client_new2(&session, callbacks, drive.get(), nullptr) != 0) {
            return std::unexpected(Stop::failed(prefixed("masque", "h2 handshake: no session")));
        }
        drive->session_ = session;
        drive->provider_.source.ptr = drive.get();
        drive->provider_.read_callback = h2_read_body;

        // h2_builder(): the two windows the machine's profile picks and the frame ceiling, which is
        // what the edge may send us at most per frame (masque_h2.rs:71-78). No server push, which
        // the Rust's h2 client never accepts either. ENABLE_CONNECT_PROTOCOL (RFC 8441 §3) is
        // the other half of sending :protocol: without it the edge reads an extended CONNECT
        // as malformed and answers 400.
        const FlowControl flow = h2_flow(settings);
        const std::array<nghttp2_settings_entry, 4> entries{{
            {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, flow.initial_stream_window},
            {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, flow.max_frame_size},
            {NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1},
        }};
        if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE,
                                    const_cast<nghttp2_settings_entry*>(entries.data()),
                                    entries.size()) != 0) {
            return std::unexpected(Stop::failed(prefixed("masque", "h2 handshake: no settings")));
        }
        if (flow.initial_connection_window > 0) {
            // The connection-level window is local state in nghttp2, not a setting; setting it
            // queues the WINDOW_UPDATE that grows it past the 64 KiB default.
            if (nghttp2_session_set_local_window_size(session, NGHTTP2_FLAG_NONE, 0,
                                                      flow.initial_connection_window) != 0) {
                return std::unexpected(
                    Stop::failed(prefixed("masque", "h2 handshake: no connection window")));
            }
        }

        std::vector<nghttp2_nv> nv;
        nv.reserve(drive->fields_.size());
        for (const auto& [name, value] : drive->fields_) {
            nv.push_back(nghttp2_nv{
                const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(name.data())),
                const_cast<std::uint8_t*>(reinterpret_cast<const std::uint8_t*>(value.data())),
                name.size(), value.size(), 0});
        }
        drive->stream_id_ = nghttp2_submit_request2(session, nullptr, nv.data(), nv.size(),
                                                     &drive->provider_, nullptr);
        if (drive->stream_id_ < 0) {
            return std::unexpected(Stop::failed(prefixed(
                "masque", "send_request: " + std::string(nghttp2_strerror(drive->stream_id_)))));
        }
        return drive;
    }

    [[nodiscard]] std::int32_t stream_id() const { return stream_id_; }
    [[nodiscard]] std::optional<std::uint16_t> status() const { return status_; }
    [[nodiscard]] bool status_final() const { return status_final_; }
    [[nodiscard]] bool ended() const { return ended_; }
    [[nodiscard]] const std::optional<Stop>& failure() const { return failure_; }

    // connection.ping_pong() (masque_h2.rs:440-442, 555-579): h2's opaque ping is nghttp2's PING
    // frame with the same eight bytes, and its pong is the answer that carries the ACK flag. The
    // `Option` the Rust unwraps there has no counterpart to fail -- an nghttp2 client session can
    // always submit a PING -- so "h2 connection does not support ping" is unreachable, not dropped.
    [[nodiscard]] std::expected<void, std::string> send_ping(
        const std::array<std::uint8_t, 8>& opaque) {
        const int rv = nghttp2_submit_ping(session_, NGHTTP2_FLAG_NONE, opaque.data());
        if (rv != 0) return std::unexpected(nghttp2_strerror(rv));
        sent_ping_ = opaque;
        return {};
    }

    // The pong `poll_pong` would have handed back (masque_h2.rs:566): the ACK of the ping this
    // session sent, read once and then forgotten.
    [[nodiscard]] bool take_pong() {
        if (!pong_) return false;
        pong_ = false;
        return true;
    }

    // `send.send_data(Bytes::new(), true)` (masque_h2.rs:687, 695): END_STREAM on the request
    // stream. The deferred body source hands it once everything it holds has gone, so the closing
    // frame never overtakes a capsule still queued behind it.
    void finish() {
        finish_ = true;
        if (stream_id_ >= 0) nghttp2_session_resume_data(session_, stream_id_);
    }
    // Whether the closing frame has been handed to nghttp2, which is when it is on its way out.
    [[nodiscard]] bool stream_finished() const { return eof_; }

    // One turn: whatever the session has queued goes out, then at most `limit` is waited for the
    // edge, and every record that arrives is fed through it. Nothing about the answer is decided
    // here -- that is the caller's, on the accessors above.
    [[nodiscard]] std::expected<void, Stop> pump(Millis limit) {
        if (const int rv = nghttp2_session_send(session_); rv != 0) {
            return std::unexpected(failed("h2: " + std::string(nghttp2_strerror(rv))));
        }
        if (failure_) return std::unexpected(*failure_);

        Millis wait = limit;
        std::array<std::uint8_t, 16 * 1024> buffer{};
        for (;;) {
            auto got = tls_->read(std::span(buffer).first(16 * 1024), wait);
            if (!got) {
                if (got.error().timed_out) break; // nothing more in this window
                return std::unexpected(*failure_ = got.error());
            }
            if (*got == 0) {
                ended_ = true;
                break;
            }
            const nghttp2_ssize used =
                nghttp2_session_mem_recv2(session_, buffer.data(), *got);
            if (used < 0) {
                return std::unexpected(
                    *failure_ = failed("h2 answer: " + std::string(nghttp2_strerror(static_cast<int>(used)))));
            }
            if (const int rv = nghttp2_session_send(session_); rv != 0) {
                return std::unexpected(*failure_ = failed("h2: " + std::string(nghttp2_strerror(rv))));
            }
            if (failure_) return std::unexpected(*failure_);
            // Only the first read waits; whatever is already buffered goes through at once.
            wait = Millis::zero();
        }
        return {};
    }

    // send_capsule (masque_h2.rs:664-680's body write): queue framed bytes on the request stream
    // and let the deferred source pick them up.
    void submit(std::vector<std::uint8_t> framed) {
        queued_.insert(queued_.end(), framed.begin(), framed.end());
        if (stream_id_ >= 0) nghttp2_session_resume_data(session_, stream_id_);
    }

    // The DATA chunks that arrived, as the request stream's body, taken whole by the caller's
    // capsule parser -- Rust's `capsules.push(&chunk)`.
    [[nodiscard]] std::vector<std::uint8_t> take_body() { return std::move(inbound_); }

    // The bytes a body source has not handed over yet, so a caller can see a capsule still queued.
    [[nodiscard]] std::size_t queued() const { return queued_.size() - at_; }

    // Everything below is the state nghttp2's C callbacks write. They are free functions, because
    // that is what the library takes, so the members they touch are public and the functions that
    // wrap them are public statics; the data itself stays private.
    [[nodiscard]] Stop failed(std::string text) {
        Stop stop = Stop::failed(prefixed("masque", text));
        if (!failure_) failure_ = stop;
        return *failure_;
    }

    void mark_ended() { ended_ = true; }
    void record(Stop stop) {
        if (!failure_) failure_ = stop;
    }

    // The send callback: what nghttp2 produced goes straight onto the TLS connection.
    static nghttp2_ssize send_span(void* user_data, const std::uint8_t* data, std::size_t length) {
        auto* drive = static_cast<H2Drive*>(user_data);
        if (auto sent = drive->tls_->write(std::span(data, length), drive->deadline_); !sent) {
            drive->failure_ = sent.error();
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return static_cast<nghttp2_ssize>(length);
    }

    // The request stream's body: the queued capsules, and no END_STREAM until finish() asks for one
    // -- a CONNECT-IP request stream stays open for the life of the tunnel.
    static nghttp2_ssize read_body(void* user_data, std::uint8_t* into, std::size_t room,
                                   std::uint32_t* flags) {
        auto* drive = static_cast<H2Drive*>(user_data);
        if (drive->at_ >= drive->queued_.size()) {
            drive->queued_.clear();
            drive->at_ = 0;
            if (drive->finish_) {
                // The closing frame: an empty DATA with END_STREAM, what Rust's
                // `send_data(Bytes::new(), true)` is (masque_h2.rs:687, 695).
                if (flags != nullptr) *flags |= NGHTTP2_DATA_FLAG_EOF;
                drive->eof_ = true;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        const std::size_t piece =
            std::min(room, drive->queued_.size() - drive->at_);
        std::memcpy(into, drive->queued_.data() + drive->at_, piece);
        drive->at_ += piece;
        if (drive->at_ >= drive->queued_.size()) {
            drive->queued_.clear();
            drive->at_ = 0;
        }
        return static_cast<nghttp2_ssize>(piece);
    }

    static int on_header(void* user_data, const std::uint8_t* name, std::size_t name_len,
                         const std::uint8_t* value, std::size_t value_len) {
        auto* drive = static_cast<H2Drive*>(user_data);
        if (name_len != 7 || std::memcmp(name, ":status", 7) != 0) return 0;
        std::uint32_t status = 0;
        for (std::size_t i = 0; i < value_len; ++i) {
            const char c = static_cast<char>(value[i]);
            if (c < '0' || c > '9') return 0;
            status = status * 10u + static_cast<std::uint32_t>(c - '0');
        }
        drive->status_ = static_cast<std::uint16_t>(status);
        return 0;
    }

    static int on_frame_recv(void* user_data, const nghttp2_frame* frame) {
        auto* drive = static_cast<H2Drive*>(user_data);
        switch (frame->hd.type) {
            case NGHTTP2_HEADERS:
                // An interim (1xx) answer is not the answer; the Rust's response future resolves on
                // the final one (masque_h2.rs:303-306).
                if (drive->status_.value_or(0) >= 200) drive->status_final_ = true;
                if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) drive->ended_ = true;
                return 0;
            case NGHTTP2_DATA:
                if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) drive->ended_ = true;
                return 0;
            case NGHTTP2_RST_STREAM:
                drive->ended_ = true;
                return 0;
            case NGHTTP2_GOAWAY:
                drive->ended_ = true;
                return 0;
            case NGHTTP2_PING:
                // The keepalive's pong (masque_h2.rs:566-579). A PING without the ACK is the edge's
                // own, which nghttp2 answers by itself the way h2's driver does.
                drive->observe_ping(frame);
                return 0;
            default:
                return 0;
        }
    }

    void observe_ping(const nghttp2_frame* frame) {
        if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) return;
        if (!sent_ping_) return;
        if (frame->hd.length != sent_ping_->size()) return;
        if (std::memcmp(sent_ping_->data(), frame->ping.opaque_data, sent_ping_->size()) != 0) return;
        sent_ping_.reset();
        pong_ = true;
    }

    static int on_data_chunk(void* user_data, const std::uint8_t* data, std::size_t length) {
        auto* drive = static_cast<H2Drive*>(user_data);
        drive->inbound_.insert(drive->inbound_.end(), data, data + length);
        return 0;
    }

    // The stream is done. An error code that is not NO_ERROR is Rust's `Some(Err(e))` arm of the
    // body poll (masque_h2.rs:355-357); a clean close is its `None` arm (358-360).
    static void note_close(void* user_data, std::uint32_t error_code) {
        auto* drive = static_cast<H2Drive*>(user_data);
        drive->mark_ended();
        if (error_code != NGHTTP2_NO_ERROR) {
            drive->record(Stop::failed(prefixed(
                "masque", "h2 body: stream closed with error " + std::to_string(error_code))));
        }
    }

    static void note_error(void* user_data, const char* message) {
        auto* drive = static_cast<H2Drive*>(user_data);
        if (message == nullptr) return;
        drive->record(Stop::failed(prefixed("masque", std::string("h2 answer: ") + message)));
    }

private:
    nghttp2_session* session_ = nullptr;
    std::unique_ptr<Tls> tls_;
    Deadline deadline_{Millis{0}};
    std::int32_t stream_id_ = -1;
    nghttp2_data_provider2 provider_{};
    std::vector<std::pair<std::string, std::string>> fields_;
    std::vector<std::uint8_t> queued_;
    std::size_t at_ = 0;
    std::vector<std::uint8_t> inbound_;
    std::optional<std::uint16_t> status_;
    bool status_final_ = false;
    bool ended_ = false;
    bool finish_ = false;
    bool eof_ = false;
    // The keepalive PING the session has outstanding and the pong the loop has not read yet.
    std::optional<std::array<std::uint8_t, 8>> sent_ping_;
    bool pong_ = false;
    std::optional<Stop> failure_;
};

// The C callbacks: nghttp2 takes function pointers, so they are free functions and the session's
// user_data is the drive.
nghttp2_ssize h2_send(nghttp2_session*, const std::uint8_t* data, std::size_t length, int,
                     void* user_data) {
    return H2Drive::send_span(user_data, data, length);
}

int h2_header(nghttp2_session*, const nghttp2_frame*, const std::uint8_t* name,
              std::size_t name_len, const std::uint8_t* value, std::size_t value_len, std::uint8_t,
              void* user_data) {
    return H2Drive::on_header(user_data, name, name_len, value, value_len);
}

int h2_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    return H2Drive::on_frame_recv(user_data, frame);
}

int h2_data_chunk(nghttp2_session*, std::uint8_t, std::int32_t, const std::uint8_t* data,
                  std::size_t length, void* user_data) {
    return H2Drive::on_data_chunk(user_data, data, length);
}

int h2_stream_close(nghttp2_session*, std::int32_t, std::uint32_t error_code, void* user_data) {
    H2Drive::note_close(user_data, error_code);
    return 0;
}

int h2_error(nghttp2_session*, int, const char* message, size_t, void* user_data) {
    H2Drive::note_error(user_data, message);
    return 0;
}

nghttp2_ssize h2_read_body(nghttp2_session*, std::int32_t, std::uint8_t* into, std::size_t room,
                           std::uint32_t* flags, nghttp2_data_source*, void* user_data) {
    return H2Drive::read_body(user_data, into, room, flags);
}

// The verify's probe: one build_dns_probe_packet for the run (masque_h2.rs:320) and a fresh
// encode_datagram_capsule around it every time one goes out (321-322, 345-346, 365-366).
class Prober {
public:
    explicit Prober(const H2TunnelConfig& cfg)
        : packet_(probe_packet(cfg)), framed_(masque::encode_datagram_capsule(packet_)) {}

    [[nodiscard]] const std::vector<std::uint8_t>& capsule() const { return framed_; }

private:
    std::vector<std::uint8_t> packet_;
    std::vector<std::uint8_t> framed_;
};

// Every whole capsule the body holds, in order, counted the way the Rust's inner drain loop counts
// them: one success per Capsule::Datagram, whatever it carries, and a parse error only stops this
// drain (masque_h2.rs:338-353).
std::size_t count_datagrams(masque::CapsuleParser& parser) {
    std::size_t datagrams = 0;
    for (;;) {
        auto next = parser.next();
        if (!next) break;                  // Err(_) => break
        if (!next->has_value()) break;     // Ok(None) => break
        if (next->value().kind == masque::Capsule::Kind::Datagram) ++datagrams;
        // Ok(Some(_)) => continue: an Address Assign or a route advertisement is not an answer to
        // the probe, and verify_h2 has no use for it.
    }
    return datagrams;
}

// ---------------------------------------------------------------------------
// The run loop's own helpers (masque_h2.rs:386-657).

// How long the tunnel's turn may sit on the socket before it looks at the netstack's queue and the
// control channel again. Rust's select wakes the instant either has an item, because mpsc::recv is
// an event; the port's queues are polled, so the wait needs a bound that is a latency and never a
// decision. Two milliseconds, which is a fifth of a probe's round trip and under a frame of video.
constexpr Millis RUN_POLL_SLICE{2};

// The framing a batch is measured against while it is gathered: a type-0 varint and a length varint
// in front of each packet. The cut itself is masque_h2.hpp's outbound_frame, which is what reads
// H2_SEND_BATCH_BYTES for real; this only bounds how far ahead of it the queue is peeked, and it
// bounds it high so that a frame never has to leave a staged packet behind.
constexpr std::size_t CAPSULE_OVERHEAD = 4;

// tokio's interval with MissedTickBehavior::Skip (masque_h2.rs:517, 521): the tick fires on the
// boundary and missed boundaries are passed over, never made up as a burst.
void skip_ahead(Clock::time_point& at, Millis period, Clock::time_point now) {
    at += period;
    while (at <= now) at += period;
}

// The next wake-up, if it is closer than what the wait already allows.
void tighten(Millis& wait, Clock::time_point now, Clock::time_point at) {
    if (at <= now) {
        wait = Millis::zero();
        return;
    }
    const Millis until = std::chrono::duration_cast<Millis>(at - now);
    if (until < wait) wait = until;
}

// Duration's Debug format, which is what "[h2] no PING response from edge within {:?}" prints
// (masque_h2.rs:544). Every value the switch can produce is whole seconds.
std::string duration_text(Millis span) {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(span).count();
    if (seconds >= 0 && static_cast<Millis>(seconds) == span) {
        return std::to_string(seconds) + "s";
    }
    return std::to_string(span.count()) + "ms";
}

// tls.ssl().selected_alpn_protocol(), the name the edge chose (masque_h2.rs:418). Nothing when the
// handshake negotiated no ALPN at all, which is what Rust's unwrap_or(b"") leaves as an empty string.
std::string alpn_text(SSL* ssl) {
    const unsigned char* wire = nullptr;
    unsigned length = 0;
    SSL_get0_alpn_selected(ssl, &wire, &length);
    if (wire == nullptr || length == 0) return {};
    return std::string(reinterpret_cast<const char*>(wire), length);
}

// close_sender (masque_h2.rs:661-668): END_STREAM on the request stream and at most
// SENDER_CLOSE_GRACE of patience for the send path to hand it over. Whatever the wait answers, the
// run stops waiting there, exactly as Rust's `let _ = timeout(...)` does.
void close_sender(H2Drive& drive) {
    drive.finish();
    const auto until = Clock::now() + SENDER_CLOSE_GRACE;
    while (!drive.stream_finished() && Clock::now() < until) {
        static_cast<void>(drive.pump(Millis{5}));
    }
}

} // namespace

// ---------------------------------------------------------------------------
// The public surface of the runtime.

std::expected<std::unique_ptr<TcpIo>, std::string>
connect_tcp(const SocketAddr& peer, std::optional<Millis> budget) {
    const int family = peer.ip.v4 ? AF_INET : AF_INET6;
    const SOCKET socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        return std::unexpected(prefixed("io", winsock_reason(WSAGetLastError())));
    }
    // Rust's dial() gives HemeraError::Io for every way the stream does not come up; the error text
    // a DialSocket hands back is already that, so it is built here and never re-prefixed.
    u_long mode = 1;
    ::ioctlsocket(socket, FIONBIO, &mode);
    struct Guard {
        SOCKET socket;
        bool ok = false;
        ~Guard() {
            if (!ok) ::closesocket(socket);
        }
    } guard{socket};

    const sockaddr_storage storage = to_storage(peer);
    if (::connect(socket, reinterpret_cast<const sockaddr*>(&storage),
                  static_cast<int>(storage_len(storage))) == 0) {
        BOOL nodelay = TRUE;
        ::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                     static_cast<int>(sizeof nodelay));
        guard.ok = true;
        return std::unique_ptr<TcpIo>(new WinTcpIo(socket));
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        return std::unexpected(prefixed("io", winsock_reason(WSAGetLastError())));
    }

    auto io = std::make_unique<WinTcpIo>(socket);
    // From here the WinTcpIo owns the handle, on every path out, so the guard stands down.
    guard.ok = true;
    // `budget` bounds the connect itself; without one the operating system's own timeout is the only
    // bound, which is all the Rust's un-timed dial() has either, so the wait is sliced forever.
    const Millis slice = budget.has_value() ? *budget : Millis{1000};
    const auto stop_at = Clock::now() + slice;
    for (;;) {
        const Millis left =
            stop_at > Clock::now()
                ? std::chrono::duration_cast<Millis>(stop_at - Clock::now())
                : Millis::zero();
        if (io->wait(left > Millis::zero() ? left : Millis{1}, true)) {
            int error = 0;
            int len = static_cast<int>(sizeof error);
            if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len) !=
                0) {
                return std::unexpected(prefixed("io", winsock_reason(WSAGetLastError())));
            }
            if (error != 0) {
                return std::unexpected(prefixed("io", winsock_reason(error)));
            }
            BOOL nodelay = TRUE;
            ::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                         static_cast<int>(sizeof nodelay));
            return std::unique_ptr<TcpIo>(std::move(io));
        }
        if (!budget) continue;
        if (Clock::now() >= stop_at) {
            return std::unexpected(
                prefixed("io", "the connect to " + peer.to_string() + " did not answer in time"));
        }
    }
}

std::expected<std::unique_ptr<TcpIo>, std::string> connect_via_proxy(
    const up::Upstream& proxy, const SocketAddr& peer, std::optional<Millis> budget) {
    // The handshake's own budget: HANDSHAKE_TIMEOUT_MS, inside what the caller still has.
    const Millis allowance = std::min(Millis{up::HANDSHAKE_TIMEOUT_MS},
                                      budget.value_or(Millis{up::HANDSHAKE_TIMEOUT_MS}));
    auto connected = connect_socket_via_proxy(proxy, peer, allowance);
    if (!connected) return std::unexpected(connected.error());
    const SOCKET socket = *connected;
    BOOL nodelay = TRUE;
    ::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                 static_cast<int>(sizeof nodelay));
    u_long mode = 1;
    ::ioctlsocket(socket, FIONBIO, &mode);
    return std::unique_ptr<TcpIo>(new WinTcpIo(socket));
}

// dial() (masque_h2.rs:209-216): the proxy's stream when one is on, egress's connect when not.
// The announce lines ride the observer so the carrier never learns which arm answered.
std::expected<std::unique_ptr<TcpIo>, std::string> dial(const SocketAddr& peer,
                                                        const Settings& settings,
                                                        std::optional<Millis> budget,
                                                        transport::Observer* observer) {
    std::vector<std::string> announced;
    const std::optional<up::Upstream> proxy = up::configured(settings, announced);
    for (const std::string& line : announced) note(observer, line);
    if (proxy) return connect_via_proxy(*proxy, peer, budget);
    return connect_tcp(peer, budget);
}

std::expected<Millis, std::string> verify_h2_with(const H2TunnelConfig& cfg, Millis timeout,
                                                 const Settings& settings, const DialSocket& dial,
                                                 transport::Observer* observer) {
    const auto start = Clock::now();
    const Deadline deadline(timeout);
    // data_check_enabled is read once, as the Rust does at the top of verify_h2 (masque_h2.rs:281).
    const bool data_check = data_check_enabled(settings);
    const Prober probe(cfg);

    // connect_tls: the dial, the shaped handshake and its one ECH retry, all inside the run's
    // deadline (masque_h2.rs:284). Its Err is already an HemeraError's words; its timeout is the
    // Rust's one sentence.
    auto brought_up = connect_tls(cfg, settings, dial, deadline, observer);
    if (!brought_up) return std::unexpected(render(brought_up.error()));
    // The h2 crate's handshake fails when the edge does not speak h2; nghttp2 would instead put
    // a preface on the wire and read the reset back, so the check the handshake implies is said
    // here, in the open, before anything is sent.
    if (const std::string alpn = alpn_text((*brought_up)->ssl()); alpn != "h2") {
        return std::unexpected(
            prefixed("masque", "h2 handshake: edge negotiated '" + alpn + "', not h2"));
    }

    auto h2 = H2Drive::open(std::move(*brought_up), cfg, settings, deadline);
    if (!h2) return std::unexpected(render(h2.error()));
    std::unique_ptr<H2Drive> stream = std::move(*h2);

    // h2.ready() then send_request, then the response head (masque_h2.rs:295-306). The request is
    // already queued on the session, so the first pump puts the ClientHello-complete connection's
    // preface, SETTINGS and HEADERS on the wire.
    masque::CapsuleParser capsules;
    while (!stream->status_final() && !stream->ended()) {
        if (deadline.expired()) {
            return std::unexpected(prefixed("other", "h2 verify timeout"));
        }
        if (auto went = stream->pump(std::min(deadline.left(), DATA_PROBE_RESEND)); !went) {
            return std::unexpected(render(went.error()));
        }
        if (stream->failure()) return std::unexpected(stream->failure()->text);
    }
    if (!stream->status_final()) {
        return std::unexpected(prefixed("masque", "h2 stream closed before data"));
    }
    if (const auto checked = check_status(stream->status().value_or(0)); !checked) {
        std::string why;
        for (std::vector<std::uint8_t> body = stream->take_body(); !body.empty();
             body = stream->take_body()) {
            why += std::string(reinterpret_cast<const char*>(body.data()), body.size());
            if (why.size() > 300) break;
        }
        if (!why.empty() && observer != nullptr) {
            observer->on_note(std::string("[h2] connect-ip body: ") + why.substr(0, 300));
        }
        return std::unexpected(prefixed("masque", checked.error()));
    }

    if (!data_check) {
        // HEMERA_MASQUE_NO_DATA_CHECK: the answer's status is the whole check (masque_h2.rs:314-316).
        return std::chrono::duration_cast<Millis>(Clock::now() - start);
    }

    // The data plane: the probe goes out, and DATA_PROBE_REQUIRED_SUCCESSES answers have to come
    // back inside `timeout`, with the probe going out again every DATA_PROBE_RESEND while it waits
    // (masque_h2.rs:318-369).
    stream->submit(probe.capsule());
    std::uint32_t successes = 0;
    auto last_probe = Clock::now();
    for (;;) {
        if (deadline.expired()) {
            return std::unexpected(prefixed("other", "h2 verify timeout"));
        }
        const Millis since = std::chrono::duration_cast<Millis>(Clock::now() - last_probe);
        const Millis until_resend = since >= DATA_PROBE_RESEND ? Millis::zero()
                                                                : DATA_PROBE_RESEND - since;
        const Millis wait = std::min(deadline.left(), until_resend);

        if (auto went = stream->pump(wait); !went) {
            if (!went.error().timed_out) return std::unexpected(went.error().text);
        }
        std::vector<std::uint8_t> body = stream->take_body();
        while (!body.empty()) {
            static_cast<void>(capsules.push(body));
            const std::size_t datagrams = count_datagrams(capsules);
            if (datagrams > 0) {
                successes += static_cast<std::uint32_t>(datagrams);
                last_probe = Clock::now();
                if (successes >= DATA_PROBE_REQUIRED_SUCCESSES) {
                    return std::chrono::duration_cast<Millis>(Clock::now() - start);
                }
                // One probe answered, the next goes out at once (masque_h2.rs:345-347).
                stream->submit(probe.capsule());
            }
            body = stream->take_body();
        }
        if (stream->failure()) return std::unexpected(stream->failure()->text);
        if (stream->ended()) {
            return std::unexpected(prefixed("masque", "h2 stream closed before data"));
        }
        if (std::chrono::duration_cast<Millis>(Clock::now() - last_probe) >= DATA_PROBE_RESEND) {
            stream->submit(probe.capsule());
            last_probe = Clock::now();
        }
    }
}

// run (masque_h2.rs:386-657): the tunnel loop. It shares the whole bring-up with verify_h2_with --
// the same connect_tls with its one ECH retry and its ech_required rule, the same H2Drive with the
// same flow control, request fields and capsule queue -- and then keeps driving that session while
// the tunnel lives: the CONNECT-IP body in, the DATAGRAM capsules out, the keepalive PING, the
// validation and pong deadlines, and every arm that closes it.
//
// The shape differs from the Rust in exactly one way, and it is worth naming: the Rust has three
// tasks (the connection driver, the send task, this loop) and the port has one thread. They can be
// one because the port's session is driven by whoever turns it, so the driver task is this loop's
// own pump(), and the send task's queue is the request stream's deferred body source -- a frame in
// flight is what Rust's send_capsule waiting for the edge's window comes to, and it is the same
// backpressure on the netstack's queue. Everything the three tasks decide is decided here in the
// same order, with the same `biased;` priorities.
std::expected<void, std::string> run_with(const H2TunnelConfig& cfg, const Settings& settings,
                                          const DialSocket& dial, const TunnelSeams& seams) {
    transport::Observer* observer = seams.observer;
    const bool data_check = data_check_enabled(settings);   // 394, read once as the Rust reads it
    const Prober probe(cfg);                               // 395: one probe packet for the run
    bool ready_fired = false;                              // 397
    std::uint32_t validate_successes = 0;                  // 398

    // log_or_debug's two levels (96-102) are the Observer's to read off the line, as
    // masque_h2.hpp:293-295 documents, so cfg.quiet is not carried down here; every line below is
    // the Rust's text, prefix included, and nothing else.

    // ready_tx, fired exactly once (390, 509-514, 627-633).
    const auto fire_ready = [&seams, &ready_fired] {
        if (ready_fired) return;
        ready_fired = true;
        if (seams.ready) seams.ready();
    };

    note(observer, "[h2] connecting tcp to " + cfg.peer.to_string());   // 400

    const FragmentConfig frag_cfg = FragmentConfig::configured(settings);   // 402
    if (frag_cfg.enabled) {                                                 // 404-411
        note(observer, "[h2] fragmenting client hello: size=" +
                           std::to_string(frag_cfg.size_min) + ".." + std::to_string(frag_cfg.size_max) +
                           " delay=" + std::to_string(frag_cfg.delay_min_ms) + ".." +
                           std::to_string(frag_cfg.delay_max_ms) + "ms");
    }

    // 413: the dial, the shaped handshake, the ECH retry. Un-bounded, because the Rust awaits it
    // bare -- and a handshake that went without the ECH key it was given never gets here at all,
    // which is connect_tls's own rule, the same one verify_h2_with runs on.
    const Deadline bring_up = Deadline::open_ended();
    auto tls = connect_tls(cfg, settings, dial, bring_up, observer);
    if (!tls) return std::unexpected(run_render(tls.error()));
    // Same ALPN rule as verify_h2_with above: no preface at a server that did not pick h2.
    if (const std::string alpn = alpn_text((*tls)->ssl()); alpn != "h2") {
        return std::unexpected(
            prefixed("masque", "h2 handshake: edge negotiated '" + alpn + "', not h2"));
    }
    note(observer, "[h2] tls established; alpn=" + alpn_text((*tls)->ssl()));   // 414-420

    // 422-425, 444-449, 451-460: h2_builder().handshake(tls), the driver task, h2.ready() and
    // send_request(req, false). One open() makes the session with the flow control of h2_flow and
    // the field set of connect_request_fields and queues the request on it; the driver task is this
    // loop's pump, and 440-442's ping_pong is the PING the same session submits.
    auto drive = H2Drive::open(std::move(*tls), cfg, settings, bring_up);
    if (!drive) return std::unexpected(run_render(drive.error()));
    // The session, for the turn that follows: `drive` is the expected that owns it, and its
    // value is the unique_ptr the calls below go through.
    H2Drive& h2 = **drive;

    // 430-438: the ceiling on a download, said out loud.
    const FlowControl flow = h2_flow(settings);
    note(observer,
         "[h2] flow control: stream window " + std::to_string(flow.initial_stream_window / 1024) +
             "KB, connection window " + std::to_string(flow.initial_connection_window / 1024) +
             "KB, max frame " + std::to_string(H2_MAX_FRAME_SIZE / 1024) + "KB");

    note(observer, "[h2] connect-ip request sent to " + cfg.authority);   // 461-464

    masque::CapsuleParser capsules;   // 482: one parser for the life of the stream
    // 466-468: the response head. Nothing else runs while it waits, as nothing else does in Rust --
    // the send task is only spawned once the answer is in -- so the netstack's packets stay in its
    // own queue until here. The wait is sliced only so the socket read has a bound; the Rust's has
    // none, and no decision turns on the slicing.
    while (!h2.status_final() && !h2.ended()) {
        if (const auto went = h2.pump(DATA_PROBE_RESEND); !went) {
            return std::unexpected(run_render(went.error()));
        }
        if (h2.failure()) return std::unexpected(h2.failure()->text);
    }
    if (!h2.status_final()) {
        // resp_fut's Err arm (466-468). What ended the stream is already classified by the session;
        // a clean close with no head is h2's own "connection closed".
        return std::unexpected(h2.ended()
                                   ? prefixed("masque", "await response: connection closed")
                                   : prefixed("masque", "await response: the stream never answered"));
    }
    const std::uint16_t status = h2.status().value_or(0);
    note(observer, "[h2] connect-ip status: " + std::to_string(status));   // 470-473
    if (const auto checked = check_status(status); !checked) {
        // The edge often says why in the body (a 400 with an empty body says nothing, which is
        // itself an answer). Pump until the stream ends or two seconds pass so the DATA behind
        // the HEADERS arrives, then read.
        const auto body_until = Clock::now() + std::chrono::milliseconds(2000);
        for (;;) {
            if (auto went = h2.pump(std::chrono::milliseconds(100)); !went) break;
            if (h2.failure() || h2.ended()) break;
            if (Clock::now() >= body_until) break;
        }
        std::string why;
        for (std::vector<std::uint8_t> chunk = h2.take_body(); !chunk.empty();
             chunk = h2.take_body()) {
            why += std::string(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            if (why.size() > 2000) break;
        }
        if (!why.empty()) note(observer, "[h2] connect-ip body: " + why.substr(0, 2000));
        return std::unexpected(prefixed("masque", checked.error()));       // 474-479
    }

    // 494-514: the data-plane probe goes out and the deadline is armed, or the tunnel is ready at
    // once when the check is off. The queue in front of Rust's send task is 16 deep and its try_send
    // drops what will not fit; here the capsules go on the request stream's own deferred body, which
    // every turn hands over, so nothing is ever dropped for want of room.
    std::optional<Clock::time_point> validate_deadline;
    if (data_check) {
        if (h2.ended()) {
            note(observer, "[h2] initial data-plane probe: the send path is gone");   // 502
        } else {
            h2.submit(probe.capsule());
        }
        validate_deadline = Clock::now() + validation_timeout(settings);
        note(observer, "[h2] validating data-plane (end-to-end probe) before exposing socks5");
    } else {
        fire_ready();
    }

    // 516-524: the timers. tokio's interval fires its first tick immediately, so the probe goes out
    // again on the turn the loop starts and the first keepalive PING goes out as soon as the data
    // plane has proved itself.
    const Millis probe_period = DATA_PROBE_RESEND;
    const Millis keepalive_period = h2_keepalive_interval(settings);
    const Millis keepalive_timeout = h2_keepalive_timeout(settings);
    auto next_probe = Clock::now();
    auto next_keepalive = Clock::now();
    bool awaiting_pong = false;
    std::optional<Clock::time_point> pong_deadline;

    // pump_outbound's batch, between turns: what try_recv has already taken out of the netstack's
    // queue for the frame being built. outbound_frame cuts it, so nothing staged here is left
    // behind -- it is only the look-ahead.
    std::vector<std::vector<std::uint8_t>> staged;

    for (;;) {
        const auto now = Clock::now();

        // 527-539: the validation deadline. The edge accepts the control stream and drops the
        // traffic; that is not a tunnel, and it is said in those words.
        if (data_check && !ready_fired && validate_deadline && now >= *validate_deadline) {
            note(observer,
                 "[h2] data-plane validation timed out; edge accepts control but drops traffic");
            close_sender(h2);
            return std::unexpected(prefixed(
                "masque", "h2 data-plane validation timeout (handshake ok, no traffic)"));
        }
        // 541-550: the pong deadline, the stalled connection.
        if (pong_deadline && now >= *pong_deadline) {
            note(observer, "[h2] no PING response from edge within " +
                               duration_text(keepalive_timeout) + "; connection is stalled");
            close_sender(h2);
            return std::unexpected(prefixed("masque", "h2 keepalive timeout"));
        }

        // 555-564: the keepalive PING, armed only once the data plane has proved itself and only
        // while the last one is unanswered.
        if (ready_fired && !awaiting_pong && now >= next_keepalive) {
            skip_ahead(next_keepalive, keepalive_period, now);
            std::array<std::uint8_t, 8> opaque{};
            if (RAND_bytes(opaque.data(), static_cast<int>(opaque.size())) != 1) {
                note(observer, "[h2] keepalive ping send failed: no opaque data");
            } else if (const auto sent = h2.send_ping(opaque); sent) {
                awaiting_pong = true;
                pong_deadline = Clock::now() + keepalive_timeout;
                note(observer, "[h2] keepalive ping sent");
            } else {
                note(observer, "[h2] keepalive ping send failed: " + sent.error());
            }
        }

        // 581-586: the probe, once more every DATA_PROBE_RESEND while the data plane is proving
        // itself. Rust's dropped-resend arm is the 16-deep sender queue being full; the frame goes
        // straight on the stream here, so what it reports is a stream that is already gone.
        if (data_check && !ready_fired && now >= next_probe) {
            skip_ahead(next_probe, probe_period, now);
            if (h2.ended()) {
                note(observer, "[h2] data-plane probe resend was dropped");
            } else {
                h2.submit(probe.capsule());
            }
        }

        // 590-599: the control queue. A queue that has ended is recv()'s None, which is the same arm
        // as Close; no queue at all means nothing closes the tunnel from outside (masque_h2.hpp:298).
        if (seams.control != nullptr) {
            const std::optional<quic::Control> ctrl =
                seams.control->gone() ? std::optional<quic::Control>{quic::Control::Close}
                                      : seams.control->try_recv();
            if (ctrl && *ctrl == quic::Control::Close) {
                close_sender(h2);
                note(observer, "[h2] closing tunnel");
                return {};
            }
            // Control::Migrate is the arm this carrier has no answer for (597): the stream is the
            // connection, so there is nothing to move.
        }

        // 601-613: the send path's outcome. It closes on its own when the netstack drops the queue
        // it reads (693-697), and it errors when the stream went away with capsules still on it
        // (729) -- which the biased select puts ahead of the closed body below.
        if (seams.outbound != nullptr && seams.outbound->gone()) {
            h2.finish();
            static_cast<void>(h2.pump(Millis::zero()));   // the frame goes out before the run ends
            note(observer, "[h2] send path closed");
            return {};
        }
        if (h2.ended() && h2.queued() > 0) {
            const std::string error = prefixed("masque", "h2 stream closed");
            note(observer, "[h2] send: " + error);
            return std::unexpected(error);
        }

        // pump_outbound (672-716): the packet at the head of the queue and whatever is already
        // behind it, gathered into one frame, out on the stream. One frame in flight is the port's
        // send_capsule waiting for capacity (718-736): the queue is not read again until what it
        // handed over is on the wire, so a closed window is backpressure and not a buffer.
        if (seams.outbound != nullptr && h2.queued() == 0) {
            std::size_t gathered = 0;
            while (gathered < H2_SEND_BATCH_BYTES) {
                auto next = seams.outbound->try_recv();
                if (!next) break;
                gathered += next->size() + CAPSULE_OVERHEAD;
                staged.push_back(std::move(*next));
            }
            if (!staged.empty()) {
                if (h2.ended()) {
                    const std::string error = prefixed("masque", "h2 stream closed");
                    note(observer, "[h2] send: " + error);
                    return std::unexpected(error);
                }
                const SendFrame frame = outbound_frame(staged);
                h2.submit(std::move(frame.data));
                staged.erase(staged.begin(),
                             staged.begin() + static_cast<std::ptrdiff_t>(frame.taken));
            }
        }

        // The wait: the earliest thing the select would have woken for -- the validation deadline,
        // the next probe, the next keepalive tick, and 588's sleep_until_deadline(pong_deadline) --
        // and never longer than the poll bound that the two queues are read on.
        Millis wait = RUN_POLL_SLICE;
        if (data_check && !ready_fired) {
            tighten(wait, now, next_probe);
            if (validate_deadline) tighten(wait, now, *validate_deadline);
        }
        if (ready_fired && !awaiting_pong) tighten(wait, now, next_keepalive);
        if (pong_deadline) tighten(wait, now, *pong_deadline);
        // A packet the frame did not take goes out on the next turn with no socket wait in front of
        // it. The look-ahead bound above makes that impossible, and this costs nothing to be sure.
        if (!staged.empty()) wait = Millis::zero();

        if (const auto went = h2.pump(wait); !went) {
            // 645-647 with 444-448: in Rust every socket write is the connection driver's, so a
            // write failure is what that driver ends on and what this loop's body poll answers with.
            const std::string text = went.error().text;
            note(observer, "[h2] connection driver ended: " + text);
            note(observer, "[h2] recv body error: " + text);
            return std::unexpected(text);
        }

        // 566-579: the pong. It outranks the body arm below, as it outranks it in the select.
        if (awaiting_pong) {
            if (h2.take_pong()) {
                awaiting_pong = false;
                pong_deadline = std::nullopt;
                note(observer, "[h2] keepalive pong received");
            } else if (h2.ended() || h2.failure()) {
                const std::string reason =
                    h2.failure() ? h2.failure()->text : std::string("the connection closed");
                note(observer, "[h2] keepalive ping failed: " + reason);
                close_sender(h2);
                return std::unexpected(prefixed("masque", "h2 keepalive: " + reason));
            }
        }

        // 615-654: the request stream's body. nghttp2 answers the edge's flow control by itself,
        // which is Rust's release_capacity(chunk.len()) at 618.
        std::vector<std::uint8_t> body = h2.take_body();
        while (!body.empty()) {
            static_cast<void>(capsules.push(body));   // 619
            const masque::Drained drained = masque::drain_capsules(capsules);   // 620, 738-788

            // The datagrams for the netstack. No sink means the packets are counted and delivered
            // nowhere (masque_h2.hpp:287-289); a closed one stops the drain, as Rust's TrySendError
            // arm does, and leaves the tunnel running.
            for (const std::vector<std::uint8_t>& packet : drained.packets) {
                if (seams.inbound == nullptr) continue;
                const transport::Room room = seams.inbound->try_send(packet);
                if (room == transport::Room::Full) {
                    note(observer, "[h2] inbound queue full, dropping datagram");   // 757-759
                    continue;
                }
                if (room == transport::Room::Closed) break;                          // 760
            }

            for (const masque::EdgeAssignment& a : drained.assigned) {               // 763-775
                note(observer, "[h2] edge assigned " + a.text());
                if (seams.assigned != nullptr) {
                    const quic::AssignedAddr addr{a.ip, a.prefix};
                    static_cast<void>(seams.assigned->try_send(addr));                // addr_tx
                }
            }
            if (drained.routes > 0) {                                                 // 776-778
                note(observer,
                     "[h2] received " + std::to_string(drained.routes) + " route advertisements");
            }
            for (std::size_t i = 0; i < drained.discarded; ++i) {                     // 750
                note(observer, "[h2] discarding a datagram that is not an ip packet");
            }
            if (drained.parse_error) {                                                // 782
                note(observer, "[h2] capsule parse: " + *drained.parse_error);
            }

            // The validation: one round trip per body chunk that carried a datagram, which is Rust's
            // `got_data` -- one increment for the whole drain, not one per datagram, and a datagram
            // the queue had no room for still counts.
            if (drained.delivered && !ready_fired) {                                   // 621-642
                ++validate_successes;
                note(observer, "[h2] data-plane round-trip " +
                                   std::to_string(validate_successes) + "/" +
                                   std::to_string(DATA_PROBE_REQUIRED_SUCCESSES) + " confirmed");
                if (validate_successes >= DATA_PROBE_REQUIRED_SUCCESSES) {
                    fire_ready();
                    validate_deadline = std::nullopt;
                    note(observer,
                         "[h2] tunnel validated (end-to-end data confirmed); exposing socks5");
                } else if (h2.ended()) {
                    note(observer, "[h2] follow-up data-plane probe was dropped");
                } else {
                    h2.submit(probe.capsule());
                }
            }
            body = h2.take_body();
        }

        if (h2.failure()) {   // 645-647: Some(Err(e)) out of the body poll
            note(observer, "[h2] recv body error: " + h2.failure()->text);
            return std::unexpected(h2.failure()->text);
        }
        if (h2.ended()) {     // 649-652: None, the edge ended the request stream
            note(observer, "[h2] server closed stream");
            return {};
        }
    }
}

} // namespace hemera::core::masque_h2
