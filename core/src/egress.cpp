#include "egress.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

namespace aether::core::egress {
namespace {

std::atomic<std::uint32_t> current_mark{0};

std::once_flag k_wsa_once;
bool k_wsa_ready = false;

// How long a wait sleeps before it looks at the Stop flag again. Rust is woken by its runtime the
// instant a future is dropped; here the price of noticing is one slice.
constexpr long long k_io_slice_ms = 200;
constexpr long long k_connect_slice_ms = 50;

std::string last_socket_error() {
    char buf[64];
    std::snprintf(buf, sizeof buf, "socket error %d", WSAGetLastError());
    return std::string(buf);
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

std::expected<SocketAddr, std::string> peer_name(SOCKET fd) {
    sockaddr_storage storage{};
    int len = static_cast<int>(sizeof storage);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&storage), &len) != 0) {
        return std::unexpected("getpeername: " + last_socket_error());
    }
    return from_sockaddr(storage, len);
}

std::expected<SocketAddr, std::string> local_name(SOCKET fd) {
    sockaddr_storage storage{};
    int len = static_cast<int>(sizeof storage);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&storage), &len) != 0) {
        return std::unexpected("getsockname: " + last_socket_error());
    }
    return from_sockaddr(storage, len);
}

std::expected<void, std::string> nonblocking(SOCKET fd) {
    u_long value = 1;
    if (::ioctlsocket(fd, FIONBIO, &value) != 0) {
        return std::unexpected("FIONBIO: " + last_socket_error());
    }
    return {};
}

// One connection attempt: the body of egress::tcp_connect, which is the socket of the address'
// own family, marked before it is opened, non-blocking, and connected. Defined below the race that
// calls it, and declared here so that race can.
[[nodiscard]] std::expected<std::unique_ptr<Socket>, std::string>
connect_one_body(const SocketAddr& address, std::optional<Millis> timeout, Stop& stop);

// select() for one direction, sliced, with the caller's deadline and stop flag watched between the
// slices. A slice never runs past the deadline, so the wait ends where the Rust's timeout would.
// False means "no" and leaves the reason to `timed_out`, the stop and WSAGetLastError().
bool ready(int which, SOCKET fd, long long slice_ms, std::optional<Millis> deadline,
           std::chrono::steady_clock::time_point began, Stop& stop, bool& timed_out) {
    timed_out = false;
    while (!stop.asked()) {
        long long wait_ms = slice_ms;
        if (deadline) {
            const auto spent =
                std::chrono::duration_cast<Millis>(std::chrono::steady_clock::now() - began);
            if (spent >= *deadline) {
                timed_out = true;
                return false;
            }
            wait_ms = std::min(slice_ms, std::max<long long>(1, deadline->count() - spent.count()));
        }

        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        timeval tv{};
        tv.tv_sec = static_cast<long>(wait_ms / 1000);
        tv.tv_usec = static_cast<long>((wait_ms % 1000) * 1000);
        const int got = which == 0 ? ::select(0, &set, nullptr, nullptr, &tv)
                                   : ::select(0, nullptr, &set, nullptr, &tv);
        if (got == SOCKET_ERROR) return false;
        if (got > 0) return true;
        if (deadline) {
            const auto spent =
                std::chrono::duration_cast<Millis>(std::chrono::steady_clock::now() - began);
            if (spent >= *deadline) {
                timed_out = true;
                return false;
            }
        }
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// The public surface.

bool winsock_ready() {
    std::call_once(k_wsa_once, [] {
        WSADATA data{};
        k_wsa_ready = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
    });
    return k_wsa_ready;
}

bool is_stopped(std::string_view error) {
    return error == STOPPED;
}

bool is_timeout(std::string_view error) {
    return error.starts_with(TIMED_OUT);
}

bool is_denied(std::string_view error) {
    return error.starts_with(DENIED);
}

std::optional<std::uint32_t> parse_mark(std::string_view value) {
    value = trim(value);
    int base = 10;
    if (value.starts_with("0x") || value.starts_with("0X")) {
        value = value.substr(2);
        base = 16;
    }

    std::uint32_t out = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), out, base);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) return std::nullopt;
    return out;
}

std::uint32_t mark() {
    return current_mark.load(std::memory_order_relaxed);
}

std::expected<std::uint32_t, std::string> init(const Settings& settings,
                                               std::vector<std::string>& notes) {
    const auto raw = settings.get("AETHER_MARK");
    if (!raw || trim(*raw).empty()) {
        current_mark.store(0, std::memory_order_relaxed);
        return 0;
    }

    const std::string_view text = trim(*raw);
    const auto wanted = parse_mark(text);
    if (!wanted) {
        return std::unexpected(
            "'" + std::string(text) + "' is not a socket mark; give a number such as 255 or 0xff");
    }
    if (*wanted == 0) {
        current_mark.store(0, std::memory_order_relaxed);
        return 0;
    }

    // SO_MARK is Linux and Android only, and this core builds for Windows, so the mark is never
    // stored. A Linux port belongs here, and stores it only once a probe socket accepts it.
    notes.push_back("[-] --mark only works on Linux and Android; sockets stay unmarked here");
    return 0;
}

std::vector<std::pair<IpAddress, std::uint16_t>> interleaved(
    std::vector<std::pair<IpAddress, std::uint16_t>> addresses) {
    if (addresses.empty()) return {};

    const bool lead_v4 = addresses.front().first.v4;
    std::vector<std::pair<IpAddress, std::uint16_t>> lead;
    std::vector<std::pair<IpAddress, std::uint16_t>> other;
    for (const auto& entry : addresses) {
        (entry.first.v4 == lead_v4 ? lead : other).push_back(entry);
    }

    std::vector<std::pair<IpAddress, std::uint16_t>> order;
    order.reserve(addresses.size());
    for (std::size_t i = 0; i < lead.size() || i < other.size(); ++i) {
        if (i < lead.size()) order.push_back(lead[i]);
        if (i < other.size()) order.push_back(other[i]);
    }
    return order;
}

std::expected<void, std::string> apply(Handle socket) {
    // egress::apply on the platform this core builds for: `let _ = socket; Ok(())`. The mark is
    // unset here anyway, because init() cannot store one without SO_MARK. A Linux port sets
    // SO_MARK to mark() when it is non-zero and reports the socket error it answers with.
    (void)socket;
    return {};
}

namespace {

struct RaceResult {
    std::unique_ptr<Socket> socket; // it connected
    std::string error;              // it did not
};

struct RaceShared {
    std::mutex m;
    std::condition_variable ready;
    std::deque<RaceResult> results;
    std::size_t running = 0; // spawned and not yet taken: Rust's attempts.is_empty()
};

// One address's attempt, on its own thread, so the race has the shape Rust's FuturesUnordered
// gives it: the first to connect answers, the rest are dropped, and a dropped attempt closes the
// socket it opened.
void run_attempt(RaceShared& shared, const std::vector<SocketAddr>& addresses, std::size_t index,
                 const std::shared_ptr<Stop>& stop, std::optional<Millis> timeout) {
    RaceResult result;
    auto connected = connect_one_body(addresses[index], timeout, *stop);
    if (connected) {
        result.socket = std::move(*connected);
    } else {
        result.error = std::move(connected.error());
    }
    {
        std::lock_guard lock(shared.m);
        shared.results.push_back(std::move(result));
    }
    shared.ready.notify_one();
}

// egress::race: each attempt runs alone for `delay`, or until it fails, before the next starts
// beside it; the first to connect wins and the others are dropped; when all of them fail, the
// error of the last to fail.
std::expected<std::unique_ptr<Socket>, std::string> race(std::vector<SocketAddr> addresses,
                                                        Millis delay, std::optional<Millis> timeout,
                                                        Stop& stop) {
    RaceShared shared;
    std::vector<std::thread> workers;
    std::vector<std::shared_ptr<Stop>> stops;
    std::size_t waiting = 0; // Rust's `waiting` iterator over the addresses
    std::string last_error;

    auto start = [&shared, &workers, &stops, &addresses, &waiting, timeout](std::size_t index) {
        auto stop = std::make_shared<Stop>();
        stops.push_back(stop);
        ++shared.running;
        workers.emplace_back([&shared, &addresses, stop, index, timeout] {
            run_attempt(shared, addresses, index, stop, timeout);
        });
    };

    // Every way out joins every attempt thread: the winner's socket travels home with the caller
    // and every loser's closes itself.
    auto join_all = [&shared, &workers, &stops] {
        for (const auto& each : stops) each->set();
        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
        std::lock_guard lock(shared.m);
        shared.results.clear();
    };

    while (true) {
        if (shared.running == 0) {
            if (waiting < addresses.size()) {
                start(waiting++);
            } else {
                for (auto& worker : workers) {
                    if (worker.joinable()) worker.join();
                }
                std::lock_guard lock(shared.m);
                shared.results.clear();
                if (last_error.empty()) {
                    return std::unexpected("no address to connect to");
                }
                return std::unexpected(std::move(last_error));
            }
        }

        std::unique_lock lock(shared.m);
        const bool answered =
            shared.ready.wait_for(lock, delay, [&shared] { return !shared.results.empty(); });
        if (answered) {
            RaceResult result = std::move(shared.results.front());
            shared.results.pop_front();
            --shared.running;
            lock.unlock();

            if (result.socket) {
                std::unique_ptr<Socket> won = std::move(result.socket);
                join_all();
                return won;
            }
            last_error = std::move(result.error);
            // A failed attempt makes way for the next one at once.
            if (waiting < addresses.size()) start(waiting++);
        } else {
            lock.unlock();
            // The Connection Attempt Delay elapsed: the next address starts beside it.
            if (waiting < addresses.size()) start(waiting++);
        }

        if (stop.asked()) {
            join_all();
            return std::unexpected(std::string(STOPPED));
        }
    }
}

} // namespace

std::expected<std::vector<SocketAddr>, std::string> lookup(std::string_view host,
                                                           std::uint16_t port) {
    if (!winsock_ready()) return std::unexpected("WSAStartup failed");

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const std::string name(host);
    const std::string service = std::to_string(port);

    addrinfo* found = nullptr;
    const int code = ::getaddrinfo(name.c_str(), service.c_str(), &hints, &found);
    if (code != 0) {
        char text[256];
        std::snprintf(text, sizeof text, "%s", gai_strerrorA(code));
        return std::unexpected(std::string("lookup: ") + text);
    }

    // The order the system answers, which is the order tokio::net::lookup_host hands out.
    std::vector<SocketAddr> addresses;
    for (addrinfo* entry = found; entry != nullptr; entry = entry->ai_next) {
        if (entry->ai_addr == nullptr || entry->ai_addrlen == 0) continue;
        SocketAddr addr{};
        if (entry->ai_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
            addr.ip.v4 = true;
            std::memcpy(addr.ip.bytes.data() + 12, &v4->sin_addr.s_addr, 4);
            addr.port = ntohs(v4->sin_port);
        } else if (entry->ai_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
            addr.ip.v4 = false;
            std::memcpy(addr.ip.bytes.data(), &v6->sin6_addr, 16);
            addr.port = ntohs(v6->sin6_port);
        } else {
            continue;
        }
        addresses.push_back(addr);
    }
    ::freeaddrinfo(found);
    return addresses;
}

std::expected<std::unique_ptr<Socket>, std::string> tcp_connect(const SocketAddr& address,
                                                                std::optional<Millis> timeout,
                                                                Stop& stop) {
    return connect_one_body(address, timeout, stop);
}

std::expected<std::unique_ptr<Socket>, std::string> tcp_connect_host(std::string_view host,
                                                                     std::uint16_t port,
                                                                     std::optional<Millis> timeout,
                                                                     Stop& stop) {
    auto found = lookup(host, port);
    if (!found) return std::unexpected(found.error());
    if (found->empty()) {
        return std::unexpected(std::string(host) + " did not resolve to any address");
    }

    std::vector<std::pair<IpAddress, std::uint16_t>> entries;
    entries.reserve(found->size());
    for (const auto& address : *found) entries.emplace_back(address.ip, address.port);

    std::vector<SocketAddr> order;
    for (const auto& entry : interleaved(std::move(entries))) {
        order.push_back(SocketAddr{entry.first, entry.second});
    }

    return race(std::move(order), Millis(CONNECTION_ATTEMPT_DELAY_MS), timeout, stop);
}

// One connection attempt, the body of egress::tcp_connect: the socket of the address' own family,
// marked before it is opened, non-blocking, and connected. Declared in the helpers above because
// the race calls it before it is defined here.
namespace {

std::expected<std::unique_ptr<Socket>, std::string> connect_one_body(const SocketAddr& address,
                                                                    std::optional<Millis> timeout,
                                                                    Stop& stop) {
    if (!winsock_ready()) return std::unexpected("WSAStartup failed");

    const int family = address.is_ipv4() ? AF_INET : AF_INET6;
    const SOCKET fd = ::socket(family, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) return std::unexpected("socket: " + last_socket_error());

    if (const auto marked = apply(fd); !marked) {
        closesocket(fd);
        return std::unexpected(marked.error());
    }
    if (const auto loose = nonblocking(fd); !loose) {
        closesocket(fd);
        return std::unexpected(loose.error());
    }

    sockaddr_storage storage{};
    int len = 0;
    to_sockaddr(address, storage, len);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&storage), len) == SOCKET_ERROR) {
        const int code = WSAGetLastError();
        if (code != WSAEWOULDBLOCK) {
            closesocket(fd);
            return std::unexpected("connect: socket error " + std::to_string(code));
        }
    }

    // The completion of a non-blocking connect is writability with an empty SO_ERROR, which is
    // what tokio's connect future resolves to.
    const auto began = std::chrono::steady_clock::now();
    bool timed_out = false;
    if (!ready(1, fd, k_connect_slice_ms, timeout, began, stop, timed_out)) {
        closesocket(fd);
        if (stop.asked()) return std::unexpected(std::string(STOPPED));
        if (timed_out) return std::unexpected(std::string(TIMED_OUT) + "the connect did not complete");
        return std::unexpected("connect: " + last_socket_error());
    }

    int error = 0;
    int size = sizeof error;
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0) {
        closesocket(fd);
        return std::unexpected("getsockopt: " + last_socket_error());
    }
    if (error != 0) {
        closesocket(fd);
        return std::unexpected("connect: socket error " + std::to_string(error));
    }

    auto wrapped = Socket::adopt(fd);
    if (!wrapped) {
        closesocket(fd);
        return std::unexpected(wrapped.error());
    }
    return wrapped;
}

} // namespace

std::expected<std::unique_ptr<Socket>, std::string> Socket::adopt(Handle handle) {
    const SOCKET fd = static_cast<SOCKET>(handle);
    auto peer = peer_name(fd);
    if (!peer) {
        closesocket(fd);
        return std::unexpected(peer.error());
    }
    auto local = local_name(fd);
    if (!local) {
        closesocket(fd);
        return std::unexpected(local.error());
    }
    return std::unique_ptr<Socket>(new Socket(fd, *peer, *local));
}

Socket::Socket(Handle handle, const SocketAddr& peer, const SocketAddr& local)
    : handle_(handle), peer_(peer), local_(local) {}

Socket::~Socket() {
    if (handle_ != 0) {
        closesocket(static_cast<SOCKET>(handle_));
        handle_ = 0;
    }
}

const SocketAddr& Socket::peer() const { return peer_; }
const SocketAddr& Socket::local() const { return local_; }
Handle Socket::handle() const { return handle_; }

ReadAttempt Socket::read(std::uint8_t* out, std::size_t len, Millis wait, Stop& stop) {
    ReadAttempt attempt;
    std::optional<Millis> deadline;
    if (wait.count() > 0) deadline = wait;
    const auto began = std::chrono::steady_clock::now();

    while (true) {
        if (stop.asked()) {
            attempt.kind = ReadAttempt::Kind::Timeout;
            return attempt;
        }
        bool timed_out = false;
        if (!ready(0, static_cast<SOCKET>(handle_), k_io_slice_ms, deadline, began, stop,
                   timed_out)) {
            if (stop.asked() || timed_out) {
                attempt.kind = ReadAttempt::Kind::Timeout;
                return attempt;
            }
            attempt.kind = ReadAttempt::Kind::Failure;
            attempt.error = "select: " + last_socket_error();
            return attempt;
        }

        const int got = ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(out),
                               static_cast<int>(std::min<std::size_t>(len, 1u << 20)), 0);
        if (got == 0) {
            attempt.kind = ReadAttempt::Kind::End;
            return attempt;
        }
        if (got == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) continue; // spurious readiness
            attempt.kind = ReadAttempt::Kind::Failure;
            attempt.error = "recv: " + last_socket_error();
            return attempt;
        }
        attempt.kind = ReadAttempt::Kind::Bytes;
        attempt.count = static_cast<std::size_t>(got);
        return attempt;
    }
}

std::expected<void, std::string> Socket::write(std::span<const std::uint8_t> bytes, Stop& stop) {
    // Rust's write_all followed by flush; a non-blocking socket has flushed by the time every byte
    // has left it.
    std::size_t sent = 0;
    const auto began = std::chrono::steady_clock::now();
    while (sent < bytes.size()) {
        if (stop.asked()) return std::unexpected(std::string(STOPPED));
        bool timed_out = false;
        if (!ready(1, static_cast<SOCKET>(handle_), k_io_slice_ms, std::nullopt, began, stop,
                   timed_out)) {
            if (stop.asked()) return std::unexpected(std::string(STOPPED));
            return std::unexpected("select: " + last_socket_error());
        }

        const int wrote = ::send(static_cast<SOCKET>(handle_),
                                 reinterpret_cast<const char*>(bytes.data() + sent),
                                 static_cast<int>(bytes.size() - sent), 0);
        if (wrote == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
            return std::unexpected("send: " + last_socket_error());
        }
        if (wrote == 0) return std::unexpected("failed to write whole buffer");
        sent += static_cast<std::size_t>(wrote);
    }
    return {};
}

std::expected<void, std::string> Socket::shutdown_write() {
    if (::shutdown(static_cast<SOCKET>(handle_), SD_SEND) == SOCKET_ERROR) {
        return std::unexpected("shutdown: " + last_socket_error());
    }
    return {};
}

std::expected<void, std::string> Socket::set_nodelay() {
    int enable = 1;
    if (::setsockopt(static_cast<SOCKET>(handle_), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&enable), sizeof enable) != 0) {
        return std::unexpected("setsockopt: " + last_socket_error());
    }
    return {};
}

std::expected<void, std::string> Socket::apply_keepalive(Millis idle, Millis interval) {
    tcp_keepalive values{};
    values.onoff = 1;
    values.keepalivetime = static_cast<u_long>(idle.count());
    values.keepaliveinterval = static_cast<u_long>(interval.count());

    DWORD returned = 0;
    if (::WSAIoctl(static_cast<SOCKET>(handle_), SIO_KEEPALIVE_VALS, &values, sizeof values, nullptr,
                   0, &returned, nullptr, nullptr) == SOCKET_ERROR) {
        return std::unexpected("set_tcp_keepalive: " + last_socket_error());
    }
    return {};
}

std::expected<std::unique_ptr<DatagramSocket>, std::string> udp_bind(const SocketAddr& address) {
    if (!winsock_ready()) return std::unexpected("WSAStartup failed");

    // socket2's Domain::for_address(address): the family the address itself belongs to.
    const int family = address.is_ipv4() ? AF_INET : AF_INET6;
    const SOCKET fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCKET) return std::unexpected("socket: " + last_socket_error());

    if (const auto marked = apply(fd); !marked) {
        closesocket(fd);
        return std::unexpected(marked.error());
    }
    // Rust sets the handle non-blocking because it feeds it to its event loop; the port keeps it
    // non-blocking for the same reason and bounds every wait with a slice instead.
    if (const auto loose = nonblocking(fd); !loose) {
        closesocket(fd);
        return std::unexpected(loose.error());
    }

    sockaddr_storage storage{};
    int len = 0;
    to_sockaddr(address, storage, len);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&storage), len) != 0) {
        closesocket(fd);
        return std::unexpected("bind: " + last_socket_error());
    }

    auto bound = DatagramSocket::adopt(fd);
    if (!bound) return std::unexpected(bound.error());
    return bound;
}

std::expected<std::unique_ptr<DatagramSocket>, std::string> DatagramSocket::adopt(Handle handle) {
    const SOCKET fd = static_cast<SOCKET>(handle);
    auto local = local_name(fd);
    if (!local) {
        closesocket(fd);
        return std::unexpected(local.error());
    }
    return std::unique_ptr<DatagramSocket>(new DatagramSocket(fd, *local));
}

DatagramSocket::DatagramSocket(Handle handle, const SocketAddr& local)
    : handle_(handle), local_(local) {}

DatagramSocket::~DatagramSocket() {
    if (handle_ != 0) {
        closesocket(static_cast<SOCKET>(handle_));
        handle_ = 0;
    }
}

const SocketAddr& DatagramSocket::local() const { return local_; }
Handle DatagramSocket::handle() const { return handle_; }

std::expected<std::optional<Datagram>, std::string> DatagramSocket::recv_from(Millis wait,
                                                                              Stop& stop) {
    std::optional<Millis> deadline;
    if (wait.count() > 0) deadline = wait;
    const auto began = std::chrono::steady_clock::now();

    while (true) {
        if (stop.asked()) return std::optional<Datagram>{};
        bool timed_out = false;
        if (!ready(0, static_cast<SOCKET>(handle_), k_io_slice_ms, deadline, began, stop,
                   timed_out)) {
            if (stop.asked() || timed_out) return std::optional<Datagram>{};
            return std::unexpected("select: " + last_socket_error());
        }

        std::vector<std::uint8_t> buffer(65535);
        sockaddr_storage storage{};
        int len = static_cast<int>(sizeof storage);
        const int got = ::recvfrom(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(buffer.data()),
                                   static_cast<int>(buffer.size()), 0,
                                   reinterpret_cast<sockaddr*>(&storage), &len);
        if (got == SOCKET_ERROR) {
            const int code = WSAGetLastError();
            if (code == WSAEWOULDBLOCK) continue; // spurious readiness
            return std::unexpected("recvfrom: socket error " + std::to_string(code));
        }
        if (got == 0) continue; // an empty datagram ends nothing

        buffer.resize(static_cast<std::size_t>(got));
        Datagram datagram{from_sockaddr(storage, len), std::move(buffer)};
        return std::optional<Datagram>{std::move(datagram)};
    }
}

std::expected<void, std::string> DatagramSocket::send_to(const SocketAddr& to,
                                                         std::span<const std::uint8_t> data,
                                                         Stop& stop) {
    sockaddr_storage storage{};
    int len = 0;
    to_sockaddr(to, storage, len);

    const auto began = std::chrono::steady_clock::now();
    while (true) {
        if (stop.asked()) return std::unexpected(std::string(STOPPED));
        bool timed_out = false;
        if (!ready(1, static_cast<SOCKET>(handle_), k_io_slice_ms, std::nullopt, began, stop,
                   timed_out)) {
            if (stop.asked()) return std::unexpected(std::string(STOPPED));
            return std::unexpected("select: " + last_socket_error());
        }
        const int sent =
            ::sendto(static_cast<SOCKET>(handle_), reinterpret_cast<const char*>(data.data()),
                     static_cast<int>(data.size()), 0, reinterpret_cast<sockaddr*>(&storage), len);
        if (sent == SOCKET_ERROR) {
            const int code = WSAGetLastError();
            if (code == WSAEWOULDBLOCK) continue;
            return std::unexpected("sendto: socket error " + std::to_string(code));
        }
        if (static_cast<std::size_t>(sent) != data.size()) return std::unexpected("send: short write");
        return {};
    }
}

} // namespace aether::core::egress
