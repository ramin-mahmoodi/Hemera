#pragma once

#include "dns.hpp"
#include "settings.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aether::core::egress {

// Port of egress.rs: what an outgoing socket carries before it is opened, and the opening itself.
// The Rust borrows its sockets from tokio, which owns the event loop; this core has no runtime, so
// tcp_connect, tcp_connect_host and udp_bind are written straight onto Winsock: a non-blocking
// handle with select() behind every wait, sliced so the caller's Stop is seen while waiting. That
// is the only divergence -- no address family, ordering rule, delay or error string of the Rust
// changes, and the RFC 8305 race keeps its one-attempt-per-failure and per-iteration delay arms.

using Millis = std::chrono::milliseconds;

// A Winsock SOCKET as an integer, so no windows.h type reaches this header. Owned by whichever
// object takes it; closing it is that object's drop, which is Rust's dropped future.
using Handle = std::uintptr_t;

// WSAStartup, once per process. The Rust has tokio do it; this core does it here so every module
// that opens a socket shares one initialisation. False means nothing socket-shaped can start.
[[nodiscard]] bool winsock_ready();

// The cancellation flag of a wait. A Rust future is dropped at its await point when the caller
// gives up; a blocking wait has no await point, so each one is sliced and this flag is read
// between slices.
//
// A flag can be given a parent, which is how tokio's task tree is reproduced: aborting a parent
// task aborts its children, so asking a child's stop asks the parent's too. The parent pointer is
// set once, before any thread that reads the flag can see the child.
class Stop {
public:
    void set() { asked_.store(true, std::memory_order_relaxed); }

    // This flag, or the one above it.
    [[nodiscard]] bool asked() const {
        return asked_.load(std::memory_order_relaxed) || (parent_ && parent_->asked());
    }

    void parent(const Stop* above) { parent_ = above; }

private:
    std::atomic<bool> asked_{false};
    const Stop* parent_ = nullptr;
};

// The port-only outcome of a wait ended by that flag. Rust has no such string, because it never
// names why a dropped future ended; every reader of it treats it as "this client is gone" and
// stops without writing an answer, which is what dropping the task does.
inline constexpr std::string_view STOPPED = "stopped: the caller gave up on the wait";

// Whether an error text is that outcome.
[[nodiscard]] bool is_stopped(std::string_view error);

// The two `std::io::ErrorKind` values socks.rs branches on, carried the way this core carries
// every other failure: a fixed prefix on the message, so the kind survives the std::expected
// boundary and the caller takes the same arm the Rust does. Nothing else about the message is
// Rust's -- the Rust's own text comes from the operating system.
//
//   TIMED_OUT is ErrorKind::TimedOut, which handle_direct and relay_http_direct branch on by
//   naming the timeout themselves; DENIED is ErrorKind::PermissionDenied, which is what decides
//   between REP_NOT_ALLOWED and REP_GENERAL, and between a 403 and a 502.
inline constexpr std::string_view TIMED_OUT = "timed-out: ";
inline constexpr std::string_view DENIED = "denied: ";

[[nodiscard]] bool is_timeout(std::string_view error);
[[nodiscard]] bool is_denied(std::string_view error);

// One read attempt: the four arms of Rust's `match timeout(wait, sock.read(&mut buf)).await`.
struct ReadAttempt {
    enum class Kind {
        Bytes,   // Rust's Ok(n) with n above zero.
        End,     // Rust's Ok(0): the peer closed its half.
        Timeout, // Rust's Err(_elapsed), and the stop being asked, which a caller tells apart
                 // through Stop::asked().
        Failure, // Rust's Ok(Err(error)).
    };

    Kind kind = Kind::Bytes;
    std::size_t count = 0; // Bytes: how many landed in the buffer.
    std::string error;     // Failure: what the socket said.
};

// The read/write half of a stream: Rust's `AsyncRead + AsyncWrite`, which a TcpStream, a split
// tunnel half and a gateway's answer all are.
class ByteStream {
public:
    virtual ~ByteStream() = default;

    // Up to `len` bytes. `wait` of zero is Rust's un-timed read, which ends on bytes, EOF, an
    // error or the stop and never on Timeout.
    [[nodiscard]] virtual ReadAttempt read(std::uint8_t* out, std::size_t len, Millis wait,
                                          Stop& stop) = 0;
    // write_all followed by flush.
    [[nodiscard]] virtual std::expected<void, std::string> write(std::span<const std::uint8_t> bytes,
                                                                Stop& stop) = 0;
    // shutdown(Write): the half-close the linger waits behind.
    [[nodiscard]] virtual std::expected<void, std::string> shutdown_write() = 0;
};

// egress::tcp_connect's TcpStream.
class Socket final : public ByteStream {
public:
    // Takes ownership of a connected, non-blocking handle. peer_addr() and local_addr() are read
    // here rather than at each use: the Rust asks them at the call site and lets the `?` end the
    // client, and a connected Windows socket answers both, so nothing that can fail is lost. A
    // handle this cannot wrap is closed before the error comes back.
    [[nodiscard]] static std::expected<std::unique_ptr<Socket>, std::string> adopt(Handle handle);

    ~Socket() override;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    [[nodiscard]] const SocketAddr& peer() const;
    [[nodiscard]] const SocketAddr& local() const;
    [[nodiscard]] Handle handle() const;

    [[nodiscard]] ReadAttempt read(std::uint8_t* out, std::size_t len, Millis wait,
                                  Stop& stop) override;
    [[nodiscard]] std::expected<void, std::string> write(std::span<const std::uint8_t> bytes,
                                                        Stop& stop) override;
    [[nodiscard]] std::expected<void, std::string> shutdown_write() override;

    // Rust's `let _ = stream.set_nodelay(true)`: the answer is handed back and ignored.
    [[nodiscard]] std::expected<void, std::string> set_nodelay();

    // socket2's set_tcp_keepalive onto SIO_KEEPALIVE_VALS. Idle and interval are the two numbers
    // Windows takes; the Rust's with_retries(4) is gated to the Unix platforms, so there is no
    // Windows counterpart to it and none is invented.
    [[nodiscard]] std::expected<void, std::string> apply_keepalive(Millis idle, Millis interval);

private:
    explicit Socket(Handle handle, const SocketAddr& peer, const SocketAddr& local);

    Handle handle_ = 0;
    SocketAddr peer_{};
    SocketAddr local_{};
};

// A datagram and where it came from: recv_from's (n, from) pair.
struct Datagram {
    SocketAddr from;
    std::vector<std::uint8_t> data;
};

// egress::udp_bind's UdpSocket.
class DatagramSocket final {
public:
    [[nodiscard]] static std::expected<std::unique_ptr<DatagramSocket>, std::string>
    adopt(Handle handle);

    ~DatagramSocket();
    DatagramSocket(const DatagramSocket&) = delete;
    DatagramSocket& operator=(const DatagramSocket&) = delete;

    [[nodiscard]] const SocketAddr& local() const;
    [[nodiscard]] Handle handle() const;

    // nullopt is "nothing arrived yet" -- the wait elapsed or the stop was asked, which the caller
    // tells apart through Stop::asked(). An error is the socket itself failing, which is Rust's
    // `Err(_) => break` arm. A datagram is up to 65535 bytes, as Rust's buffers are.
    [[nodiscard]] std::expected<std::optional<Datagram>, std::string> recv_from(Millis wait,
                                                                               Stop& stop);
    [[nodiscard]] std::expected<void, std::string> send_to(const SocketAddr& to,
                                                          std::span<const std::uint8_t> data,
                                                          Stop& stop);

private:
    explicit DatagramSocket(Handle handle, const SocketAddr& local);

    Handle handle_ = 0;
    SocketAddr local_{};
};

// egress::apply: what the mark asks of a socket before it is used. Windows has no SO_MARK, which is
// the Rust's `let _ = socket; Ok(())` arm, so here nothing is applied and nothing can fail; a Linux
// port belongs in egress.cpp and sets it when mark() is non-zero.
[[nodiscard]] std::expected<void, std::string> apply(Handle socket);

// tokio::net::lookup_host((host, port)): every address the name has, in the order the system
// answers them, each with `port`. A host that is already an address answers with that one address.
[[nodiscard]] std::expected<std::vector<SocketAddr>, std::string> lookup(std::string_view host,
                                                                       std::uint16_t port);

// egress::tcp_connect. `timeout` is the caller's own deadline for the attempt -- Rust wraps this
// call in one at its call sites -- and no timeout is Rust's untimed await.
[[nodiscard]] std::expected<std::unique_ptr<Socket>, std::string>
tcp_connect(const SocketAddr& address, std::optional<Millis> timeout, Stop& stop);

// egress::tcp_connect_host: the addresses a name has, interleaved, raced for the first one that
// connects.
[[nodiscard]] std::expected<std::unique_ptr<Socket>, std::string>
tcp_connect_host(std::string_view host, std::uint16_t port, std::optional<Millis> timeout,
                 Stop& stop);

// egress::udp_bind.
[[nodiscard]] std::expected<std::unique_ptr<DatagramSocket>, std::string>
udp_bind(const SocketAddr& address);

// `AETHER_MARK` as a firewall mark: decimal, or hex behind `0x`, and nothing else.
[[nodiscard]] std::optional<std::uint32_t> parse_mark(std::string_view value);

// The mark outgoing sockets carry, which `init` decides and leaves unset on a platform that
// cannot mark.
[[nodiscard]] std::uint32_t mark();

// Reads `AETHER_MARK`. A mark that cannot be read is an error the caller stops on; a platform
// that has no marking is a note, and the mark stays unset, which is what the Rust core does.
[[nodiscard]] std::expected<std::uint32_t, std::string> init(const Settings& settings,
                                                              std::vector<std::string>& notes);

// The addresses a name resolved to, in the order to try them: one of the family of the first,
// then one of the other, by turns, each family in its own order (RFC 8305, 4).
[[nodiscard]] std::vector<std::pair<IpAddress, std::uint16_t>> interleaved(
    std::vector<std::pair<IpAddress, std::uint16_t>> addresses);

// How long an attempt runs alone before the next starts beside it (RFC 8305, 5).
inline constexpr int CONNECTION_ATTEMPT_DELAY_MS = 250;

} // namespace aether::core::egress
