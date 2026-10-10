// https.rs's sending half, on raw Winsock and BoringSSL. Read it next to the Rust: `send` is the
// deadline around `exchange`, `exchange` is the ECH loop and the two gates after it, and the two
// carriers are the two ways the request goes out.
//
// Nothing here shapes the ClientHello: `configuration()` is a client context and one call to
// tls.hpp's `Fingerprint::apply`, which is exactly what https.rs:139-149 writes. Nor does anything
// here open a socket of its own: the dial goes through egress, so the RFC 8305 order, the socket
// mark and the connect error texts stay the ones the rest of the port uses.
//
// It is blocking and thread-based, as the rest of this port is: BoringSSL driven over a memory BIO
// pair, and one deadline covering the resolve, the connect, the handshake and the whole exchange --
// which is what `tokio::time::timeout(timeout, exchange)` is in the Rust. The errors this file
// returns are bare until a caller of ours gives them their kind, so each kind prefix is written
// once, at the place the Rust writes it.

#define NOMINMAX
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "https_runtime.hpp"

#include "dns.hpp"
#include "egress.hpp"
#include "fragment.hpp"
#include "https.hpp"
#include "settings.hpp"
#include "tls.hpp"
#include "upstream.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hemera::core::https {
namespace {

// tls.hpp declares straight into hemera::core; this is the alias transport.cpp uses for it.
namespace tls = ::hemera::core;

using Millis = std::chrono::milliseconds;
using Clock = std::chrono::steady_clock;

// ---- why a step did not complete ---------------------------------------------------------------

// A step that stopped. A timeout is deliberately not a message: https.rs wraps the whole exchange in
// `tokio::time::timeout` and writes one sentence for it, so every place the deadline runs out
// reports this and `send` renders that sentence, while a real failure carries its own bare text and
// the caller that reached Rust's `?` adds the kind -- which is where each `prefixed` below sits.
struct Stop {
    std::string text;
    bool timed_out = false;

    [[nodiscard]] static Stop failed(std::string text) { return Stop{std::move(text), false}; }
    [[nodiscard]] static Stop timeout() { return Stop{{}, true}; }
};

// An `HemeraError`'s printed text: the kind, then its message.
std::string prefixed(std::string_view kind, std::string_view text) {
    return std::string(kind) + ": " + std::string(text);
}

// ---- the clock ---------------------------------------------------------------------------------

// The exchange's one deadline, cut short where the Rust cuts it short.
class Deadline {
public:
    explicit Deadline(Millis total) : total_(total), end_(Clock::now() + total) {}

    // The same deadline, no later than `cap` from now: the upstream proxy's own handshake gets
    // HANDSHAKE_TIMEOUT, which is what https.rs's `open` wraps in `tokio::time::timeout`.
    [[nodiscard]] Deadline capped_by(Millis cap) const {
        Deadline shorter = *this;
        const Clock::time_point soon = Clock::now() + cap;
        if (soon < shorter.end_) shorter.end_ = soon;
        return shorter;
    }

    [[nodiscard]] Millis left() const {
        const Clock::time_point now = Clock::now();
        if (now >= end_) return Millis::zero();
        return std::chrono::duration_cast<Millis>(end_ - now);
    }

    [[nodiscard]] bool passed() const { return Clock::now() >= end_; }

    // https.rs's `timeout.as_secs()`, the number in "did not answer within {}s".
    [[nodiscard]] std::uint64_t seconds() const {
        return std::chrono::duration_cast<std::chrono::seconds>(total_).count();
    }

private:
    Millis total_;
    Clock::time_point end_;
};

// ---- the socket --------------------------------------------------------------------------------

// Winsock's own words for a code, phrased exactly as egress.cpp phrases them, so the text a socket
// failure answers with is the same text whatever opened the socket.
std::string socket_error(int code) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "socket error %d", code);
    return std::string(buffer);
}

std::string socket_error() { return socket_error(WSAGetLastError()); }

// The connected stream `dial` hands the handshake: egress' own TcpStream -- its race, its mark, its
// error texts -- with the waits the exchange's deadline bounds. egress.cpp has the same waiting
// shape inside its own file, but a file-local helper of another module is not reachable from here,
// and its `ByteStream::write` takes a cancellation flag rather than a deadline, which is the one
// thing a hung proxy must not be allowed to do to this exchange.
class Stream {
public:
    Stream() = default;
    explicit Stream(std::unique_ptr<egress::Socket> socket) : socket_(std::move(socket)) {}
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&&) = default;
    Stream& operator=(Stream&&) = default;

    [[nodiscard]] SOCKET fd() const {
        return socket_ == nullptr ? INVALID_SOCKET : static_cast<SOCKET>(socket_->handle());
    }
    [[nodiscard]] bool open() const { return socket_ != nullptr; }
    // `let _ = tcp.set_nodelay(true)`, which both Rust's dial sites write and neither acts on.
    void set_nodelay() {
        if (socket_ != nullptr) (void)socket_->set_nodelay();
    }

    // select over the remaining budget. Out of budget is the exchange's timeout, not an error.
    [[nodiscard]] std::expected<void, Stop> wait(bool for_write, const Deadline& deadline) const {
        const Millis left = deadline.left();
        if (left <= Millis::zero()) return std::unexpected(Stop::timeout());
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd(), &set);
        TIMEVAL slice{};
        slice.tv_sec = static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(left).count());
        slice.tv_usec = static_cast<long>(
            std::chrono::duration_cast<std::chrono::microseconds>(left % std::chrono::seconds(1))
                .count());
        const int got = for_write ? ::select(0, nullptr, &set, nullptr, &slice)
                                  : ::select(0, &set, nullptr, nullptr, &slice);
        if (got == SOCKET_ERROR) return std::unexpected(Stop::failed("select: " + socket_error()));
        if (got == 0) return std::unexpected(Stop::timeout());
        return {};
    }

    // Bytes off the wire; none at all is the peer's end, which is what lets an HTTP/1.1 answer read
    // to the close finish, as Rust's `read` returning 0 does.
    [[nodiscard]] std::expected<std::size_t, Stop> read(std::span<std::uint8_t> into,
                                                        const Deadline& deadline) const {
        for (;;) {
            if (auto ready = wait(false, deadline); !ready) return std::unexpected(ready.error());
            const int got = ::recv(fd(), reinterpret_cast<char*>(into.data()),
                                   static_cast<int>(into.size()), 0);
            if (got > 0) return static_cast<std::size_t>(got);
            if (got == 0) return std::size_t{0};
            if (WSAGetLastError() == WSAEWOULDBLOCK) continue; // spurious readiness
            return std::unexpected(Stop::failed("recv: " + socket_error()));
        }
    }

    // Rust's `read_exact`: false is the connection ending before the bytes did, which is the io
    // error Rust answers with ("failed to fill whole buffer").
    [[nodiscard]] std::expected<bool, Stop> read_exact(std::span<std::uint8_t> into,
                                                       const Deadline& deadline) const {
        std::size_t got = 0;
        while (got < into.size()) {
            const auto piece = read(into.subspan(got), deadline);
            if (!piece) return std::unexpected(piece.error());
            if (*piece == 0) return false;
            got += *piece;
        }
        return true;
    }

    // Rust's `write_all`, bounded by the deadline the caller is under.
    [[nodiscard]] std::expected<void, Stop> write(std::span<const std::uint8_t> bytes,
                                                  const Deadline& deadline) const {
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            if (auto ready = wait(true, deadline); !ready) return std::unexpected(ready.error());
            const int wrote = ::send(fd(), reinterpret_cast<const char*>(bytes.data() + sent),
                                     static_cast<int>(bytes.size() - sent), 0);
            if (wrote > 0) {
                sent += static_cast<std::size_t>(wrote);
                continue;
            }
            if (wrote < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            return std::unexpected(Stop::failed("send: " + socket_error()));
        }
        return {};
    }

private:
    std::unique_ptr<egress::Socket> socket_;
};

// upstream.rs:279-281 -- `open` reaches the proxy with a plain egress::tcp_connect, never with
// `open` again, so the proxy's own endpoint is dialled with no proxy in front of it. dial() reads
// the proxy out of whatever Settings it is handed, which makes "this map without HEMERA_UPSTREAM"
// exactly Rust's direct connect: the same egress race and the same socket marking, no recursion.
Settings proxy_settings(const Settings& settings);

std::expected<Stream, Stop> through_proxy(const upstream::Upstream& proxy, const Settings& settings,
                                          std::string_view host, std::uint16_t port,
                                          const Deadline& deadline);

// https.rs's `dial`: through the upstream proxy when there is one, which looks a name up itself, or
// else straight, with the socket mark. `address` is where the connection goes, which is not always
// the HTTP host.
//
// One tie-break, and it is the Rust's: tokio's timeout fires on its own wake-up, so a step that ran
// out of the whole exchange's budget ends as "did not answer within {}s" rather than as whatever the
// step would have complained about. Every failure here is therefore judged by the clock first.
std::expected<Stream, Stop> dial(std::string_view address, std::uint16_t port,
                                 const Deadline& deadline, const Settings& settings,
                                 std::vector<std::string>* notes) {
    std::vector<std::string> announced;
    const std::optional<upstream::Upstream> proxy = upstream::configured(settings, announced);
    if (notes != nullptr) {
        for (std::string& line : announced) notes->push_back(std::move(line));
    }

    // Rust's egress::tcp_connect_host has no timeout of its own; the exchange's is the only bound on
    // it, and it is the one this hands over.
    auto direct = [&](std::string_view host,
                      std::uint16_t number) -> std::expected<Stream, Stop> {
        const Millis left = deadline.left();
        if (left <= Millis::zero()) return std::unexpected(Stop::timeout());
        egress::Stop never_asked;
        auto connected = egress::tcp_connect_host(host, number, std::optional<Millis>(left),
                                                 never_asked);
        if (!connected) {
            if (deadline.passed()) return std::unexpected(Stop::timeout());
            // HemeraError::Io through `?`, which is what upstream.rs's `open` returns; the direct
            // path is the one https.rs wraps in "connect to {authority}".
            return std::unexpected(Stop::failed(prefixed(
                "io", "connect to " + authority(host, number) + ": " + connected.error())));
        }
        Stream stream(std::move(*connected));
        stream.set_nodelay();
        return stream;
    };

    if (proxy) {
        auto through = through_proxy(*proxy, settings, address, port, deadline);
        if (!through && through.error().timed_out) return std::unexpected(through.error());
        if (!through) return std::unexpected(Stop::failed(through.error().text));
        return through;
    }

    // The one place https.rs names the authority it could not reach.
    auto straight = direct(address, port);
    if (!straight) {
        if (straight.error().timed_out) return std::unexpected(straight.error());
        return std::unexpected(Stop::failed(prefixed(
            "api", "connect to " + authority(address, port) + ": " + straight.error().text)));
    }
    return straight;
}

// `authority` as upstream.rs's http_connect writes it into its CONNECT line: an address with
// SocketAddr's own text, a name with the port put straight after it. Unlike https.hpp's authority(),
// this never leaves 443 out.
std::string proxy_authority(std::string_view host, std::uint16_t port) {
    const std::optional<IpAddress> ip = parse_address(host);
    if (ip) return SocketAddr{*ip, port}.to_string();
    return std::string(host) + ":" + std::to_string(port);
}

// What a step that ran out of the proxy's own ten seconds becomes, once the exchange's own deadline
// has been ruled out first: Rust's `open` wraps the whole attempt in `tokio::time::timeout`.
std::expected<Stream, Stop> proxy_timed_out(const upstream::Upstream& proxy,
                                           const Deadline& deadline) {
    if (deadline.passed()) return std::unexpected(Stop::timeout());
    return std::unexpected(
        Stop::failed(prefixed("other", upstream::connect_timed_out(proxy))));
}

Settings proxy_settings(const Settings& settings) {
    Settings cleared{settings};
    cleared.values.erase("HEMERA_UPSTREAM");
    return cleared;
}

// upstream.rs's `connect_host` and `open`: the proxy's own endpoint dialled, then the greeting, the
// authentication and the request, all of it inside HANDSHAKE_TIMEOUT. A name goes to a socks5 proxy
// for it to look up, as the Rust sends it, so that no DNS query for it leaves this machine.
std::expected<Stream, Stop> through_proxy(const upstream::Upstream& proxy, const Settings& settings,
                                          std::string_view host, std::uint16_t port,
                                          const Deadline& deadline) {
    const Deadline attempt = deadline.capped_by(Millis(upstream::HANDSHAKE_TIMEOUT_MS));

    auto stream = dial(proxy.host, proxy.port, attempt, proxy_settings(settings), nullptr);
    if (!stream) return std::unexpected(stream.error());

    const auto timed = [&attempt, &deadline](const Stop& stop) {
        if (!stop.timed_out) return false;
        (void)attempt;
        (void)deadline;
        return true;
    };

    // The bytes of the handshake with the proxy, every one of them under the attempt's deadline.
    const auto write = [&stream, &attempt](std::span<const std::uint8_t> bytes) {
        return stream->write(bytes, attempt);
    };
    const auto read = [&stream, &attempt](std::span<std::uint8_t> into) {
        auto filled = stream->read_exact(into, attempt);
        if (!filled) return std::expected<bool, Stop>{std::unexpected(filled.error())};
        if (!*filled) {
            return std::expected<bool, Stop>{
                std::unexpected(Stop::failed("failed to fill whole buffer"))};
        }
        return filled;
    };
    // Whether the failure was the clock, and so the ten seconds rather than the exchange's budget.
    const auto out_of_time = [&]() {
        return proxy_timed_out(proxy, attempt);
    };

    if (proxy.kind == upstream::Kind::Socks5) {
        std::array<std::uint8_t, 2> answer{};
        if (const auto greeted = write(upstream::greet_request(proxy.wants_auth())); !greeted) {
            if (greeted.error().timed_out) return out_of_time();
            return std::unexpected(Stop::failed(prefixed("io", greeted.error().text)));
        }
        if (const auto got = read(answer); !got) {
            if (got.error().timed_out) return out_of_time();
            return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
        }
        if (const auto checked = upstream::check_greeting(proxy.wants_auth(), answer); !checked) {
            return std::unexpected(Stop::failed(prefixed("other", checked.error())));
        }
        if (answer[1] == upstream::AUTH_USERPASS) {
            const auto login = upstream::authenticate_request(proxy.user, proxy.password);
            if (!login) {
                return std::unexpected(Stop::failed(prefixed("other", login.error())));
            }
            if (const auto sent = write(*login); !sent) {
                if (sent.error().timed_out) return out_of_time();
                return std::unexpected(Stop::failed(prefixed("io", sent.error().text)));
            }
            std::array<std::uint8_t, 2> password_answer{};
            if (const auto got = read(password_answer); !got) {
                if (got.error().timed_out) return out_of_time();
                return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
            }
            if (const auto checked = upstream::check_auth_answer(password_answer); !checked) {
                return std::unexpected(Stop::failed(prefixed("other", checked.error())));
            }
        }

        // connect_host: an address is asked for directly, a name by the proxy itself.
        const std::optional<IpAddress> literal = parse_address(host);
        std::expected<std::vector<std::uint8_t>, std::string> request =
            literal ? upstream::encode_request(upstream::CMD_CONNECT,
                                               upstream::SocketTarget{{}, *literal, port})
                    : upstream::encode_name_request(upstream::CMD_CONNECT, host, port);
        if (!request) {
            return std::unexpected(
                Stop::failed(prefixed("other", "the upstream request could not be written: " +
                                               request.error())));
        }
        if (const auto sent = write(*request); !sent) {
            if (sent.error().timed_out) return out_of_time();
            return std::unexpected(Stop::failed(prefixed("io", sent.error().text)));
        }

        // read_reply: the head, the bound address behind it and the port behind that. A connect does
        // not use the bound address, but it has to be read past for the stream to be usable.
        std::array<std::uint8_t, 4> head{};
        if (const auto got = read(head); !got) {
            if (got.error().timed_out) return out_of_time();
            return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
        }
        const auto atyp = upstream::check_reply_head(head);
        if (!atyp) return std::unexpected(Stop::failed(prefixed("other", atyp.error())));
        std::size_t skip = 0;
        if (*atyp == upstream::ATYP_V4) skip = 4;
        else if (*atyp == upstream::ATYP_V6) skip = 16;
        else if (*atyp == upstream::ATYP_NAME) {
            std::array<std::uint8_t, 1> length{};
            if (const auto got = read(length); !got) {
                if (got.error().timed_out) return out_of_time();
                return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
            }
            skip = length[0];
        }
        std::array<std::uint8_t, 16> address{};
        if (skip > 0) {
            const auto rest = read(std::span(address).first(skip));
            if (!rest) {
                if (rest.error().timed_out) return out_of_time();
                return std::unexpected(Stop::failed(prefixed("io", rest.error().text)));
            }
        }
        std::array<std::uint8_t, 2> bound_port{};
        if (const auto got = read(bound_port); !got) {
            if (got.error().timed_out) return out_of_time();
            return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
        }
        return stream;
    }

    // An http proxy: the CONNECT, and its answer read a byte at a time to the empty line, as
    // upstream.rs's http_connect does.
    const std::string connect = upstream::connect_request(proxy, proxy_authority(host, port));
    const std::span<const std::uint8_t> request(
        reinterpret_cast<const std::uint8_t*>(connect.data()), connect.size());
    if (const auto sent = write(request); !sent) {
        if (sent.error().timed_out) return out_of_time();
        return std::unexpected(Stop::failed(prefixed("io", sent.error().text)));
    }
    std::vector<std::uint8_t> head;
    std::array<std::uint8_t, 1> byte{};
    for (;;) {
        if (head.size() > upstream::MAX_HTTP_CONNECT_HEAD) {
            return std::unexpected(
                Stop::failed(prefixed("other", upstream::HTTP_OVERSIZED_ANSWER)));
        }
        const auto got = read(byte);
        if (!got) {
            if (got.error().timed_out) return out_of_time();
            // Rust's read of zero bytes: the proxy hung up before it answered.
            if (got.error().text == "failed to fill whole buffer") {
                return std::unexpected(
                    Stop::failed(prefixed("other", upstream::HTTP_CLOSED_BEFORE_ANSWER)));
            }
            return std::unexpected(Stop::failed(prefixed("io", got.error().text)));
        }
        head.push_back(byte[0]);
        if (head.size() >= 4 && head[head.size() - 4] == '\r' && head[head.size() - 3] == '\n' &&
            head[head.size() - 2] == '\r' && head[head.size() - 1] == '\n') {
            break;
        }
    }
    if (const auto answer = upstream::connect_answer(head); !answer) {
        return std::unexpected(Stop::failed(prefixed("other", answer.error())));
    }
    (void)timed;
    return stream;
}

// ---- BoringSSL over a memory BIO pair ----------------------------------------------------------

void clear_ssl_error() {
    while (ERR_get_error() != 0) {
    }
}

// Everything BoringSSL left on the error queue, in one line, and `fallback` when it left nothing.
// `ECH_REJECTED` has to be readable here, because it is the only thing https.rs keys the ECH retry
// on, and it is BoringSSL's own reason word for the rejection, so ERR_error_string carries it.
std::string ssl_error_text(std::string_view fallback) {
    std::string text;
    for (;;) {
        const std::uint32_t code = ERR_get_error();
        if (code == 0) break;
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof buffer);
        if (!text.empty()) text += "; ";
        text += buffer;
    }
    if (text.empty()) return std::string(fallback);
    return text;
}

// The queue without taking it, for the one thing that carries no code: a connection that ended with
// no alert behind it.
[[nodiscard]] bool queue_empty() { return ERR_peek_error() == 0; }

struct SslFree {
    void operator()(SSL* ssl) const { SSL_free(ssl); }
};
struct CtxFree {
    void operator()(SSL_CTX* ctx) const { SSL_CTX_free(ctx); }
};
struct BioFree {
    void operator()(BIO* bio) const { BIO_free(bio); }
};

using OwnedSsl = std::unique_ptr<SSL, SslFree>;
using OwnedCtx = std::unique_ptr<SSL_CTX, CtxFree>;
using OwnedBio = std::unique_ptr<BIO, BioFree>;

// Both buffers of the pair, comfortably past the largest record either half can write, so that a
// record is never split across the wait that feeds it.
constexpr std::size_t PAIR_BUFFER = 64 * 1024;

// The socket, the SSL on it, and the machine end of the memory BIO pair that joins the two. The SSL
// owns the pair's other end, so it is freed first and that end with it.
class Link {
public:
    Link() = default;
    Link(const Link&) = delete;
    Link& operator=(const Link&) = delete;
    Link(Link&&) = default;
    Link& operator=(Link&&) = default;

    // The SSL of `ctx`, before there is a socket: https.rs puts the ECH key on the configuration
    // before it dials, and a key BoringSSL cannot offer has to stop the request before it sends so
    // much as a SYN.
    [[nodiscard]] static std::expected<Link, Stop> build(OwnedCtx ctx) {
        if (ctx == nullptr) {
            return std::unexpected(Stop::failed(ssl_error_text("no TLS context")));
        }
        Link link;
        link.ctx_ = std::move(ctx);
        link.ssl_.reset(SSL_new(link.ctx_.get()));
        if (link.ssl_ == nullptr) {
            return std::unexpected(Stop::failed(ssl_error_text("SSL_new failed")));
        }
        return link;
    }

    // `socket`, joined to the SSL.
    [[nodiscard]] std::expected<void, Stop> attach(Stream socket, const Settings& settings) {
        BIO* side = nullptr;
        BIO* machine = nullptr;
        if (BIO_new_bio_pair(&side, PAIR_BUFFER, &machine, PAIR_BUFFER) != 1) {
            clear_ssl_error();
            return std::unexpected(Stop::failed("no BIO pair for the handshake"));
        }
        // Both halves on one end, so the handshake never reads its own writes.
        SSL_set_bio(ssl_.get(), side, side);
        machine_.reset(machine);
        socket_ = std::move(socket);
        fragmenter_ = FragmentWriter(FragmentConfig::configured(settings));
        return {};
    }

    [[nodiscard]] SSL* ssl() const { return ssl_.get(); }

    // What SSL has produced, onto the wire.
    [[nodiscard]] std::expected<void, Stop> flush(const Deadline& deadline) {
        std::array<std::uint8_t, 16 * 1024> buffer{};
        for (;;) {
            const int got = BIO_read(machine_.get(), buffer.data(),
                                     static_cast<int>(buffer.size()));
            if (got <= 0) return {};
            std::span<const std::uint8_t> rest(buffer.data(), static_cast<std::size_t>(got));
            while (!rest.empty()) {
                std::size_t piece = rest.size();
                std::uint64_t delay_ms = 0;
                if (const auto plan = fragmenter_.plan(rest)) {
                    piece = std::min(plan->len, rest.size());
                    delay_ms = plan->delay_ms;
                }
                auto sent = socket_.write(rest.first(piece), deadline);
                if (!sent) return std::unexpected(sent.error());
                fragmenter_.advance(piece);
                rest = rest.subspan(piece);
                if (delay_ms > 0) ::Sleep(static_cast<DWORD>(delay_ms));
            }
        }
    }

    // One of the peer's records, into the handshake, after whatever SSL has queued has gone out --
    // which is also what empties the pair as far as it can be emptied. The read is cut to what the
    // pair has room for, so the whole of it always goes in.
    [[nodiscard]] std::expected<bool, Stop> feed(const Deadline& deadline) {
        fragmenter_.stop();
        if (auto out = flush(deadline); !out) return std::unexpected(out.error());
        const std::size_t room = BIO_ctrl_get_write_guarantee(machine_.get());
        if (room == 0) {
            return std::unexpected(Stop::failed("the handshake buffer would not take the record"));
        }
        std::array<std::uint8_t, 4096> buffer{};
        const std::size_t ask = std::min(buffer.size(), room);
        const auto got = socket_.read(std::span(buffer).first(ask), deadline);
        if (!got) return std::unexpected(got.error());
        if (*got == 0) return false;
        const int written = BIO_write(machine_.get(), buffer.data(), static_cast<int>(*got));
        if (written < 0 || static_cast<std::size_t>(written) != *got) {
            return std::unexpected(
                Stop::failed(ssl_error_text("the record would not go into the handshake")));
        }
        return true;
    }

    // The full TLS handshake of `link`, whose socket the caller has already attached.
    [[nodiscard]] std::expected<void, Stop> handshake(const Deadline& deadline) {
        for (;;) {
            const int done = SSL_connect(ssl_.get());
            // Whatever the ClientHello or the next flight produced goes out before anything is
            // waited for.
            if (auto out = flush(deadline); !out) return std::unexpected(out.error());
            if (done == 1) return {};
            const int error = SSL_get_error(ssl_.get(), done);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                if (error == SSL_ERROR_WANT_WRITE) {
                    if (auto ready = socket_.wait(true, deadline); !ready) {
                        return std::unexpected(ready.error());
                    }
                    continue;
                }
                if (auto ready = socket_.wait(false, deadline); !ready) {
                    return std::unexpected(ready.error());
                }
                const auto more = feed(deadline);
                if (!more) return std::unexpected(more.error());
                if (!*more) {
                    clear_ssl_error();
                    return std::unexpected(
                        Stop::failed("the connection ended in the middle of the handshake"));
                }
                continue;
            }
            if (error == SSL_ERROR_ZERO_RETURN) {
                clear_ssl_error();
                return std::unexpected(
                    Stop::failed("the connection ended in the middle of the handshake"));
            }
            return std::unexpected(Stop::failed(ssl_error_text("the handshake was refused")));
        }
    }

    // Application bytes off the TLS connection: none at all is its end, whether the peer sent a
    // close_notify or not, which is what BoringSSL tells alike and what https.rs leaves to the
    // answer's grammar to judge.
    [[nodiscard]] std::expected<std::size_t, Stop> read(std::span<std::uint8_t> into,
                                                        const Deadline& deadline) {
        for (;;) {
            const int got = SSL_read(ssl_.get(), into.data(), static_cast<int>(into.size()));
            if (got > 0) return static_cast<std::size_t>(got);
            const int error = SSL_get_error(ssl_.get(), got);
            if (error == SSL_ERROR_ZERO_RETURN) return std::size_t{0};
            if (error == SSL_ERROR_SYSCALL) {
                // A bare end of the connection leaves nothing on the queue; anything else there is a
                // real failure and says so.
                if (queue_empty()) {
                    clear_ssl_error();
                    return std::size_t{0};
                }
                return std::unexpected(Stop::failed(ssl_error_text("the read failed")));
            }
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                return std::unexpected(Stop::failed(ssl_error_text("the read failed")));
            }
            if (auto out = flush(deadline); !out) return std::unexpected(out.error());
            if (error == SSL_ERROR_WANT_WRITE) {
                if (auto ready = socket_.wait(true, deadline); !ready) {
                    return std::unexpected(ready.error());
                }
                continue;
            }
            if (auto ready = socket_.wait(false, deadline); !ready) {
                return std::unexpected(ready.error());
            }
            const auto more = feed(deadline);
            if (!more) return std::unexpected(more.error());
            if (!*more) return std::size_t{0};
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
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                return std::unexpected(Stop::failed(ssl_error_text("the write failed")));
            }
            if (auto out = flush(deadline); !out) return std::unexpected(out.error());
            if (error == SSL_ERROR_WANT_WRITE) {
                if (auto ready = socket_.wait(true, deadline); !ready) {
                    return std::unexpected(ready.error());
                }
                continue;
            }
            if (auto ready = socket_.wait(false, deadline); !ready) {
                return std::unexpected(ready.error());
            }
            const auto more = feed(deadline);
            if (!more) return std::unexpected(more.error());
            if (!*more) {
                clear_ssl_error();
                return std::unexpected(
                    Stop::failed("the connection ended in the middle of the request"));
            }
        }
        return {};
    }

private:
    OwnedCtx ctx_;
    OwnedBio machine_;
    OwnedSsl ssl_;
    Stream socket_;
    FragmentWriter fragmenter_{FragmentConfig::disabled()};
};

// https.rs's `configuration`: the fingerprint's TLS, offering HTTP/2 then HTTP/1.1. Server-certificate
// verification comes off with the fingerprint, which is what lets the server name be neither the HTTP
// host nor the address; the whole of the shaping is the one `apply` below.
std::expected<OwnedCtx, Stop> configuration(const Fingerprint& fingerprint) {
    OwnedCtx ctx(SSL_CTX_new(TLS_client_method()));
    if (ctx == nullptr) {
        return std::unexpected(Stop::failed(ssl_error_text("SSL_CTX_new failed")));
    }
    if (const auto shaped =
            fingerprint.apply(ctx.get(), std::span<const std::uint8_t>(ALPN_H2_HTTP1));
        !shaped) {
        return std::unexpected(Stop::failed(ssl_error_text(shaped.error())));
    }
    return ctx;
}

// ---- one handshake, and the retry the server can ask for ---------------------------------------

// What every attempt of the loop needs besides whether it is the retry: the request, the key it
// offers, and the two things the Rust reads off the process as it goes.
struct Attempt {
    const Request& request;
    const Fingerprint& fingerprint;
    // https.rs's `Option<&mut Vec<u8>>`: the caller's key, which a retry replaces in place, which is
    // what account.rs's remember_api_ech then keeps.
    std::optional<std::vector<std::uint8_t>>* ech = nullptr;
    std::string_view address;
    std::uint16_t port = 0;
    const Deadline& deadline;
    const Settings& settings;
    std::vector<std::string>* notes = nullptr;
};

// A handshake that went, or one that says go round again with the key the server handed back --
// which is already in the caller's key by then, so all the loop has to do is try.
struct Hello {
    Link link;
    bool retry = false;
};

std::expected<Hello, Stop> hello(const Attempt& attempt_state, bool retried) {
    auto ctx = configuration(attempt_state.fingerprint);
    if (!ctx) return std::unexpected(ctx.error());

    auto link = Link::build(std::move(*ctx));
    if (!link) return std::unexpected(link.error());

    if (attempt_state.ech != nullptr) {
        // BoringSSL takes a key it offers nothing from, and the name would go in the clear; and the
        // dial has not happened yet, so nothing goes out at all.
        // The pointer is to the optional, so the key is two dereferences away.
        const std::vector<std::uint8_t>& key = **attempt_state.ech;
        if (const auto usable = tls::ensure_offerable(key); !usable) {
            return std::unexpected(Stop::failed(prefixed("ech", usable.error())));
        }
        if (SSL_set1_ech_config_list(link->ssl(), key.data(), key.size()) != 1) {
            clear_ssl_error();
            return std::unexpected(
                Stop::failed(ssl_error_text("SSL_set1_ech_config_list failed")));
        }
    }

    auto socket = dial(attempt_state.address, attempt_state.port, attempt_state.deadline,
                       attempt_state.settings, attempt_state.notes);
    if (!socket) return std::unexpected(socket.error());
    if (auto joined = link->attach(std::move(*socket), attempt_state.settings); !joined) {
        return std::unexpected(joined.error());
    }

    // tokio_boring::connect(config, name, tcp) is the server name and the hostname check; with
    // verification off, what is left of it is the name, and with ECH on BoringSSL puts it inside the
    // encrypted ClientHello and sends its public name in the clear instead.
    const std::string name(server_name(attempt_state.request));
    if (!name.empty() && SSL_set_tlsext_host_name(link->ssl(), name.c_str()) != 1) {
        return std::unexpected(Stop::failed(ssl_error_text("the server name was refused")));
    }

    if (auto went = link->handshake(attempt_state.deadline); went) {
        Hello done;
        done.link = std::move(*link);
        return done;
    } else if (went.error().timed_out) {
        return std::unexpected(went.error());
    } else {
        // https.rs's `message`, the text it both keys the retry on and puts in the error.
        const std::string message = went.error().text;

        // BoringSSL reports a key the server turned down as ECH_REJECTED, and only then hands out the
        // key the server sent back. The retry is at most once, and `extract_ech_retry_configs` is the
        // port's `usable_retry`: an empty answer, and a list BoringSSL cannot offer, both answer
        // nothing. What the Rust adds on that second branch is a warn line naming the reason; this
        // port's gate hands back only the verdict, so the reason stays inside tls.cpp.
        std::optional<std::vector<std::uint8_t>> retry;
        if (attempt_state.ech != nullptr && !retried &&
            message.find("ECH_REJECTED") != std::string::npos) {
            retry = tls::extract_ech_retry_configs(link->ssl());
        }
        if (!retry) {
            return std::unexpected(Stop::failed(prefixed(
                "tls", "handshake with " + authority(attempt_state.address, attempt_state.port) +
                           ": " + message)));
        }

        // log::debug's line, to the caller's sink.
        if (attempt_state.notes != nullptr) {
            attempt_state.notes->push_back(
                "[https] " + authority(attempt_state.address, attempt_state.port) +
                " turned the ECH key down; offering the one it handed back (" +
                std::to_string(retry->size()) + " bytes)");
        }
        *attempt_state.ech = std::move(*retry);
        Hello again;
        again.retry = true;
        return again;
    }
}

// ---- HTTP/1.1, with the grammar half's reader --------------------------------------------------

std::expected<Response, Stop> over_http1(Link& link, const Request& request,
                                         const Deadline& deadline) {
    const std::vector<std::pair<std::string, std::string>> fields(request.headers.begin(),
                                                                  request.headers.end());
    const std::vector<std::uint8_t> wire =
        http1_request(request.method, request.host, request.port, request.path, fields,
                      request.body);

    if (auto sent = link.write(wire, deadline); !sent) {
        return std::unexpected(
            Stop::failed(prefixed("api", "http/1.1: " + sent.error().text)));
    }

    Http1Answer answer;
    std::array<std::uint8_t, 8192> chunk{};
    for (;;) {
        auto read = link.read(chunk, deadline);
        if (!read) {
            if (read.error().timed_out) return std::unexpected(read.error());
            return std::unexpected(
                Stop::failed(prefixed("api", "http/1.1: " + read.error().text)));
        }
        // The connection ended, with a close_notify or without one: whether the answer came whole is
        // for `finish` to say, exactly as Rust's `Ok(0) => break` leaves it.
        if (*read == 0) break;
        auto whole = answer.push(std::span(chunk).first(*read));
        if (!whole) {
            return std::unexpected(Stop::failed(prefixed("api", whole.error())));
        }
        if (*whole) break;
    }

    auto finished = answer.finish();
    if (!finished) {
        return std::unexpected(Stop::failed(prefixed("api", finished.error())));
    }
    Response response;
    response.status = finished->status;
    // http::HeaderMap::append, which is what the Rust does field by field; the names come back in
    // the case the server wrote them, and every reader here matches them case-insensitively.
    response.headers = std::move(finished->fields);
    response.body = std::move(finished->body);
    response.protocol = "http/1.1";
    return response;
}

// ---- HTTP/2, through nghttp2 -------------------------------------------------------------------

// What an h2 answer is made of as it comes in: one request, one stream, its head and body gathered
// here. Every callback below writes into it and reads nothing else, and each of them returns
// nghttp2's own verdict for what the Rust's h2 client would have stopped on.
struct H2Answer {
    Link* link = nullptr;
    const Deadline* deadline = nullptr;
    std::int32_t stream_id = -1;
    // Whether the request has been given to nghttp2 to write, which tells a failure of the exchange
    // from a failure of the answer.
    bool request_on_the_wire = false;

    // The answer as it stands: the head once it has come, and the body as its DATA frames arrive.
    std::uint16_t status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
    bool head_seen = false;
    bool whole = false;

    // The header block being read, which is what tells an interim answer from the answer, and the
    // answer from its trailers.
    std::uint16_t block_status = 0;
    std::vector<std::pair<std::string, std::string>> block_fields;
    std::size_t block_size = 0;

    // The failure this file has already put into HemeraError's words, and the bare text of one the
    // caller has yet to frame.
    std::optional<std::string> stop;
    std::optional<std::string> io;
    std::string nghttp2_error;
};

nghttp2_ssize h2_send(nghttp2_session*, const std::uint8_t* data, std::size_t length, int,
                      void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (auto sent = answer->link->write(std::span(data, length), *answer->deadline); !sent) {
        answer->io = sent.error().text;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return static_cast<nghttp2_ssize>(length);
}

int h2_begin_headers(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->hd.stream_id != answer->stream_id) return 0;
    // The size cap, and the block itself, are per header block, as h2 counts them.
    answer->block_status = 0;
    answer->block_fields.clear();
    answer->block_size = 0;
    return 0;
}

int h2_header(nghttp2_session*, const nghttp2_frame* frame, const std::uint8_t* name,
              std::size_t name_len, const std::uint8_t* value, std::size_t value_len, uint8_t,
              void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (frame->hd.type != NGHTTP2_HEADERS || frame->hd.stream_id != answer->stream_id) return 0;

    // MAX_HEADER_LIST is what the Rust's builder sets and what h2 enforces as it decodes a block:
    // name and value, plus the 32 bytes RFC 7541 (4.2) counts for every field. nghttp2 reports the
    // setting to the peer but does not enforce it locally, so it is enforced here.
    answer->block_size += name_len + value_len + 32;
    if (answer->block_size > static_cast<std::size_t>(MAX_HEADER_LIST)) {
        answer->stop = prefixed("api", "h2 answer: the header list is over " +
                                           std::to_string(MAX_HEADER_LIST) + " bytes");
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    const std::string_view field(reinterpret_cast<const char*>(name), name_len);
    std::string text(reinterpret_cast<const char*>(value), value_len);
    if (!field.empty() && field.front() == ':') {
        if (field == ":status") {
            unsigned parsed = 0;
            const auto read =
                std::from_chars(text.data(), text.data() + text.size(), parsed);
            if (read.ec != std::errc{} ||
                read.ptr != text.data() + text.size() ||
                parsed > std::numeric_limits<std::uint16_t>::max()) {
                answer->stop = prefixed("api", "h2 answer: " + text + " is no status");
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            answer->block_status = static_cast<std::uint16_t>(parsed);
        }
        // :method, :scheme and :authority are the request's; an answer carries nothing else that a
        // caller of this reads.
        return 0;
    }
    answer->block_fields.emplace_back(std::string(field), std::move(text));
    return 0;
}

int h2_data_chunk(nghttp2_session*, uint8_t, std::int32_t stream_id, const std::uint8_t* data,
                  std::size_t length, void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (stream_id != answer->stream_id) return 0;
    answer->body.insert(answer->body.end(), data, data + length);
    // The same check https.rs makes after the chunk has been taken in, and the same words: over, not
    // at, the limit.
    if (answer->body.size() > MAX_BODY) {
        answer->stop = prefixed("api", "the answer is too large");
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    return 0;
}

int h2_frame_recv(nghttp2_session*, const nghttp2_frame* frame, void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (frame->hd.stream_id != answer->stream_id) return 0;
    const bool end_stream = (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS: {
            const bool interim = answer->block_status >= 100 && answer->block_status < 200;
            if (interim) {
                // An interim answer is passed over, as h2's client does with its informational
                // responses: the block is dropped and the stream stays open for the answer.
                answer->block_status = 0;
                answer->block_fields.clear();
                answer->block_size = 0;
                return 0;
            }
            if (answer->head_seen) return 0; // trailers, which the Rust's parts never carry
            answer->head_seen = true;
            answer->status = answer->block_status;
            answer->headers = std::move(answer->block_fields);
            answer->block_fields.clear();
            if (end_stream) answer->whole = true;
            return 0;
        }
        case NGHTTP2_DATA:
            if (end_stream) answer->whole = true;
            return 0;
        case NGHTTP2_RST_STREAM:
            answer->stop =
                prefixed("api", "h2 answer: the server reset the stream");
            return 0;
        default:
            return 0;
    }
}

int h2_error_message(nghttp2_session*, int, const char* message, std::size_t length,
                     void* user_data) {
    auto* answer = static_cast<H2Answer*>(user_data);
    if (message != nullptr) answer->nghttp2_error.assign(message, length);
    return 0;
}

// The request body, which the Rust hands over whole with `send_data(body, true)`: the frames it
// comes out in are nghttp2's, bounded by whatever window the server has given.
struct BodySource {
    std::span<const std::uint8_t> bytes;
    std::size_t at = 0;
};

nghttp2_ssize h2_read_body(nghttp2_session*, std::int32_t, std::uint8_t* into, std::size_t room,
                            uint32_t* flags, nghttp2_data_source* source, void*) {
    auto* body = static_cast<BodySource*>(source->ptr);
    if (room == 0) return 0;
    const std::size_t piece = std::min(room, body->bytes.size() - body->at);
    std::memcpy(into, body->bytes.data() + body->at, piece);
    body->at += piece;
    if (body->at >= body->bytes.size()) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(piece);
}

// The Rust's `failed(what, e)` for h2: "h2 {what}: {e}", as an api error. Which `what` it is follows
// how far the exchange got; nghttp2's own words stand in for h2::Error's Display.
std::string h2_failed(const H2Answer& answer, std::string_view what, std::string_view reason) {
    std::string text = prefixed("api", "h2 " + std::string(what) + ": ");
    if (!reason.empty()) {
        text += reason;
    } else if (answer.io) {
        text += *answer.io;
    } else if (!answer.nghttp2_error.empty()) {
        text += answer.nghttp2_error;
    } else {
        text += "the stream did not finish";
    }
    return text;
}

std::expected<Response, Stop> over_http2(Link& link, const Request& request,
                                        const Deadline& deadline) {
    // The header block, in the order https.rs builds it: the URI's pseudo headers, the caller's
    // fields, then content-length. nghttp2 copies both halves, so nothing here has to outlive the
    // call.
    const std::vector<std::pair<std::string, std::string>> fields = request_fields(request);
    std::vector<nghttp2_nv> nv;
    nv.reserve(fields.size());
    for (const auto& [name, value] : fields) {
        nv.push_back(nghttp2_nv{const_cast<std::uint8_t*>(
                                    reinterpret_cast<const std::uint8_t*>(name.data())),
                                const_cast<std::uint8_t*>(
                                    reinterpret_cast<const std::uint8_t*>(value.data())),
                                name.size(), value.size(), NGHTTP2_NV_FLAG_NONE});
    }

    BodySource body;
    if (request.body) body.bytes = *request.body;
    nghttp2_data_provider2 provider{};
    provider.source.ptr = &body;
    provider.read_callback = h2_read_body;

    H2Answer answer;
    answer.link = &link;
    answer.deadline = &deadline;

    nghttp2_session_callbacks* callbacks = nullptr;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
        return std::unexpected(Stop::failed(prefixed("api", "h2 handshake: out of memory")));
    }
    struct Callbacks {
        nghttp2_session_callbacks* callbacks;
        ~Callbacks() { nghttp2_session_callbacks_del(callbacks); }
    } callbacks_guard{callbacks};
    nghttp2_session_callbacks_set_send_callback2(callbacks, h2_send);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_data_chunk);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_frame_recv);
    nghttp2_session_callbacks_set_error_callback2(callbacks, h2_error_message);

    nghttp2_session* session = nullptr;
    if (nghttp2_session_client_new2(&session, callbacks, &answer, nullptr) != 0) {
        return std::unexpected(Stop::failed(prefixed("api", "h2 handshake: no session")));
    }
    struct Session {
        nghttp2_session* session;
        ~Session() { nghttp2_session_del(session); }
    } session_guard{session};

    // As the Rust's builder, and nothing more: no server push, whose streams would cost memory
    // MAX_BODY does not count, and Chrome's header-list cap. The windows and the frame size stay at
    // the h2 defaults the Rust leaves them at.
    const std::array<nghttp2_settings_entry, 2> entries{{
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST},
    }};
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, entries.data(), entries.size()) != 0) {
        return std::unexpected(Stop::failed(prefixed("api", "h2 handshake: no settings")));
    }

    // send_request(head, body.is_none()): no provider is the END_STREAM on the head itself.
    answer.stream_id = nghttp2_submit_request2(session, nullptr, nv.data(), nv.size(),
                                               request.body ? &provider : nullptr, nullptr);
    if (answer.stream_id < 0) {
        return std::unexpected(
            Stop::failed(h2_failed(answer, "request", nghttp2_strerror(answer.stream_id))));
    }

    // The one loop: what the session has queued goes out, what the peer says comes in, until the
    // answer is whole or the session has nothing left to do. nghttp2 writes through the link, so a
    // blocked socket ends it on the deadline like any other step.
    std::array<std::uint8_t, 16 * 1024> buffer{};
    while (!answer.whole && !answer.stop) {
        if (const int sent = nghttp2_session_send(session); sent != 0) {
            if (answer.stop) return std::unexpected(Stop::failed(*answer.stop));
            return std::unexpected(Stop::failed(h2_failed(
                answer, answer.request_on_the_wire ? "answer" : "handshake",
                nghttp2_strerror(sent))));
        }
        answer.request_on_the_wire = true;
        if (answer.whole || answer.stop) break;
        if (nghttp2_session_want_read(session) == 0 && nghttp2_session_want_write(session) == 0) {
            // The session is finished with: no answer came, and none is going to.
            break;
        }

        auto read = link.read(std::span(buffer).first(4096), deadline);
        if (!read) {
            if (read.error().timed_out) return std::unexpected(read.error());
            return std::unexpected(Stop::failed(h2_failed(
                answer, answer.head_seen ? "answer body" : "handshake", read.error().text)));
        }
        if (*read == 0) {
            if (!answer.whole) {
                return std::unexpected(Stop::failed(
                    h2_failed(answer, answer.head_seen ? "answer body" : "answer",
                              "the connection ended before the answer did")));
            }
            break;
        }
        const nghttp2_ssize used =
            nghttp2_session_mem_recv2(session, buffer.data(), static_cast<std::size_t>(*read));
        if (used < 0) {
            if (answer.stop) return std::unexpected(Stop::failed(*answer.stop));
            return std::unexpected(
                Stop::failed(h2_failed(answer, "answer", nghttp2_strerror(static_cast<int>(used)))));
        }
    }

    if (answer.stop) return std::unexpected(Stop::failed(*answer.stop));
    if (!answer.whole || !answer.head_seen) {
        if (!answer.nghttp2_error.empty()) {
            return std::unexpected(
                Stop::failed(prefixed("api", "h2 answer: " + answer.nghttp2_error)));
        }
        return std::unexpected(
            Stop::failed(prefixed("api", "h2 answer: the server never answered")));
    }

    Response response;
    response.status = answer.status;
    response.headers = std::move(answer.headers);
    response.body = std::move(answer.body);
    response.protocol = "h2";
    return response;
}

// ---- exchange, and the gate both handshakes have to clear ---------------------------------------

std::expected<Response, Stop> exchange(const Attempt& attempt_state) {
    bool retried = false;
    Link link;
    for (;;) {
        auto went = hello(attempt_state, retried);
        if (!went) return std::unexpected(went.error());
        if (went->retry) {
            // The key the server handed back is now the caller's, the hello that turned the old one
            // down is dropped with its connection, and the loop makes it again -- as https.rs does.
            retried = true;
            continue;
        }
        link = std::move(went->link);
        break;
    }

    // Nothing goes over a handshake that went without the key it was given: the server name would be
    // in the clear. This is the second of the two gates, and it holds for the retried handshake
    // exactly as for the first.
    if (attempt_state.ech != nullptr && !tls::ech_accepted(link.ssl())) {
        return std::unexpected(
            Stop::failed(prefixed("ech", "the handshake went without ECH")));
    }

    const unsigned char* selected = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(link.ssl(), &selected, &length);
    const std::string_view chosen =
        selected == nullptr ? std::string_view{} : std::string_view(
                                                       reinterpret_cast<const char*>(selected),
                                                       length);

    if (chose_http2(chosen)) return over_http2(link, attempt_state.request, attempt_state.deadline);
    return over_http1(link, attempt_state.request, attempt_state.deadline);
}

} // namespace

std::expected<Response, std::string> send(const Request& request, const Fingerprint& fingerprint,
                                          std::optional<std::vector<std::uint8_t>>* ech,
                                          Millis timeout, const Call& call) {
    // A caller that brings no settings is the Rust core reading its own environment, which is what
    // https.rs's `dial` and `tls::Fingerprint::configured` both reach. The map is built once per
    // call, and only when the caller has not already brought one.
    std::optional<Settings> from_environment;
    if (call.settings == nullptr) from_environment = settings_from_environment();
    const Settings& settings = call.settings != nullptr ? *call.settings : *from_environment;

    const Deadline deadline(timeout);
    const auto [address, port] = target(request);
    // A caller holds its ECH key in an optional and passes its address; an empty one is Rust's
    // `ech: None` -- `Option<Vec<u8>>::as_mut()` hands out no `&mut` -- and treating it that way is
    // what keeps hello() from dereferencing nothing. Nothing is lost: an empty list was never
    // offerable, ensure_offerable turns it down.
    if (ech != nullptr && !ech->has_value()) ech = nullptr;
    const Attempt attempt_state{request, fingerprint, ech, address, port, deadline, settings,
                                call.notes};

    auto answer = exchange(attempt_state);
    if (answer) return std::move(*answer);
    if (answer.error().timed_out) {
        return std::unexpected(prefixed(
            "api", authority(request.host, request.port) + " did not answer within " +
                   std::to_string(deadline.seconds()) + "s"));
    }
    return std::unexpected(std::move(answer.error().text));
}

} // namespace hemera::core::https
