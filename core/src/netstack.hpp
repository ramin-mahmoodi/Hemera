#pragma once

// Port of netstack.rs: the userland network stack engine -- the connection table and its
// lifecycle, the TCP/UDP relay state machines, the datagram pump and the run-loop scheduling.
//
// The boundary netpacket.hpp drew is kept here: netpacket.cpp owns the pure loop *decisions*
// (decide_tcp/decide_udp, tcp_pending_admit, alloc_port, max_tcp_pending, the address helpers);
// this module is the engine those decisions were extracted from. What Rust gets from smoltcp
// (the TCP and UDP socket state machines, the interface dispatch) and from tokio (channels,
// clock, the select loop) is split as follows:
//
//   * The TCP/UDP state machines are real logic here, at packet level, built on netpacket's
//     codecs. They replace smoltcp for the behaviours netstack.rs relies on: the active open,
//     seq/ack bookkeeping, retransmission with exponential backoff, keepalive probes, the
//     inactivity timeout, the close/abort sequences and TIME_WAIT.
//   * Everything that needs a real socket, a TUN device or an async runtime sits behind the
//     small injectable interfaces below (PacketSink, DnsInterceptor, StackObserver) and an
//     injected `now` on every time-dependent call -- the host owns the clock and the sleeping;
//     tick() reports the delay the Rust select loop would have armed.
//
// Additions over the Rust file, required by the C++ core and flagged at each site: the DNS
// interception seam on the UDP:53 path, the sniffing hook on a connection's first written bytes
// and the per-connection routing decision (socks::decide_route over a routing::RuleSet). With no
// hooks configured the engine behaves exactly like netstack.rs.
//
// Device capabilities: StackDevice reports Medium::Ip, `max_transmission_unit = mtu` and
// `checksum.ipv4/tcp/udp = Checksum::Tx`, so every outbound packet carries a real checksum while
// inbound ones are not verified. Both halves are reproduced here; the verification is available
// behind Config::validate_checksums but off by default for parity.

#include "dns.hpp"       // IpAddress, SocketAddr
#include "netpacket.hpp" // codecs, TcpState, the loop-decision helpers, constants
#include "routing.hpp"   // RuleSet (the routing decision hook reads it)
#include "settings.hpp"  // Settings

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace hemera::core::netstack {

// The engine's clock: every deadline, timer and timestamp is one of these, handed in by the
// caller. Nothing here reads a wall clock (Rust's Instant::now() sites all become parameters).
using TimePoint = std::chrono::steady_clock::time_point;
using Millis = std::chrono::milliseconds;

// ---------------------------------------------------------------------------
// Injected seams.

// The outcome Rust's mpsc try_send reports, and what PacketSink answers.
enum class SendOutcome {
    Ok,
    Full,   // the far side is slow; Rust blocks (senders) or drops (flush_tx)
    Closed, // the far side is gone
};

// Where flush_tx hands finished packets: the TUN writer / tunnel channel in the live core. The
// engine never blocks on it -- a Full answer drops the packet and counts it, exactly like the
// Rust try_send in flush_tx.
struct PacketSink {
    virtual ~PacketSink() = default;
    virtual SendOutcome try_send(std::span<const std::uint8_t> packet) = 0;
};

// The DNS interception seam. Called for every UDP datagram an app sends to port 53 before it
// reaches the wire; a returned message is delivered straight back to the app as if it came from
// `dst`, and nothing is transmitted. nullopt forwards the datagram normally.
struct DnsInterceptor {
    virtual ~DnsInterceptor() = default;
    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>> intercept(
        const SocketAddr& dst, std::span<const std::uint8_t> query) = 0;
};

// The lines Rust sends to log:: and the events tests watch. Every method defaults to nothing.
struct StackObserver {
    virtual ~StackObserver() = default;
    // log::debug!("[netstack] dropped {n} outbound packets under pressure")
    virtual void on_drop_report(std::size_t total_dropped) { (void)total_dropped; }
    // log::info!("netstack addresses synchronized from edge capsule")
    virtual void on_addrs_synced() {}
    // The sniffing hook: the hostname sniff::sniff_hostname read off the connection's head.
    virtual void on_sniffed(std::size_t conn_id, std::string_view hostname) {
        (void)conn_id;
        (void)hostname;
    }
    // The routing decision a connection or datagram got (C++-side integration; see header note).
    virtual void on_route_decided(const SocketAddr& dst, routing::Action action) {
        (void)dst;
        (void)action;
    }
};

// ---------------------------------------------------------------------------
// TcpLimits: netstack.rs's struct, durations in milliseconds.

struct TcpLimits {
    Millis connect{netpacket::DEFAULT_CONNECT_SECS * 1000};     // HEMERA_TCP_CONNECT_SECS, 30 s
    Millis keepalive{netpacket::DEFAULT_KEEPALIVE_SECS * 1000}; // HEMERA_TCP_KEEPALIVE_SECS, 60 s
    Millis orphan_linger{netpacket::ORPHAN_LINGER_MS};          // ORPHAN_LINGER, 10 s

    // TcpLimits::from_env, through Settings the way the codebase requires: the same two
    // HEMERA_* variables, parsed by netpacket's keepalive_secs/connect_secs.
    [[nodiscard]] static TcpLimits from_settings(const Settings& settings);
};

// ---------------------------------------------------------------------------
// The bounded channels Rust's mpsc gives the engine. try_reserve/commit reproduce the permit
// API service_tcp and service_udp use for backpressure; a dropped Receiver closes the Sender
// side (that is how "the app went away" is discovered), and the last dropped Sender ends the
// Receiver (at_end), the way Rust's channel closes.

namespace detail {

template <class T>
struct ChannelShared {
    std::deque<T> queue;
    std::size_t capacity = 0;
    std::size_t reserved = 0;
    bool rx_alive = true;
    std::size_t senders = 0;
};

} // namespace detail

template <class T>
class Permit {
public:
    Permit() = default;
    Permit(const Permit&) = delete;
    Permit& operator=(const Permit&) = delete;
    Permit(Permit&& other) noexcept : shared_(std::move(other.shared_)) {}
    Permit& operator=(Permit&& other) noexcept {
        if (this != &other) {
            release();
            shared_ = std::move(other.shared_);
        }
        return *this;
    }
    ~Permit() { release(); }

    // Consumes the reserved slot; the value lands in the queue.
    void commit(T value) {
        if (!shared_) return;
        shared_->queue.push_back(std::move(value));
        if (shared_->reserved > 0) --shared_->reserved;
        shared_.reset();
    }

    [[nodiscard]] bool valid() const { return shared_ != nullptr; }

private:
    template <class>
    friend class Sender;

    explicit Permit(std::shared_ptr<detail::ChannelShared<T>> shared)
        : shared_(std::move(shared)) {}

    void release() {
        if (shared_) {
            if (shared_->reserved > 0) --shared_->reserved;
            shared_.reset();
        }
    }

    std::shared_ptr<detail::ChannelShared<T>> shared_;
};

template <class T>
class Sender {
public:
    Sender() = default;
    Sender(const Sender& other) : shared_(other.shared_) { retain(); }
    Sender& operator=(const Sender& other) {
        if (this != &other) {
            let_go();
            shared_ = other.shared_;
            retain();
        }
        return *this;
    }
    Sender(Sender&& other) noexcept : shared_(std::move(other.shared_)) {}
    Sender& operator=(Sender&& other) noexcept {
        if (this != &other) {
            let_go();
            shared_ = std::move(other.shared_);
        }
        return *this;
    }
    ~Sender() { let_go(); }

    [[nodiscard]] bool alive() const { return shared_ != nullptr; }
    // The Rust `resp.is_closed()` / TrySendError::Closed check: the receiving half is gone.
    [[nodiscard]] bool receiver_alive() const { return shared_ && shared_->rx_alive; }
    [[nodiscard]] std::size_t queued() const { return shared_ ? shared_->queue.size() : 0; }

    [[nodiscard]] SendOutcome try_send(T value) const {
        if (!shared_ || !shared_->rx_alive) return SendOutcome::Closed;
        if (shared_->queue.size() >= shared_->capacity) return SendOutcome::Full;
        shared_->queue.push_back(std::move(value));
        return SendOutcome::Ok;
    }

    // mpsc::Sender::try_reserve: Full when the queue plus outstanding permits is at capacity,
    // Closed when the receiver is gone. A dropped permit releases its reservation. `const` the
    // way a cloned Rust Sender is: the channel state lives behind the shared pointer, and the
    // app-side handles (TcpSender::send) hold their clone by const reference.
    [[nodiscard]] SendOutcome try_reserve(Permit<T>& out) const {
        if (!shared_ || !shared_->rx_alive) return SendOutcome::Closed;
        if (shared_->queue.size() + shared_->reserved >= shared_->capacity) {
            return SendOutcome::Full;
        }
        ++shared_->reserved;
        out = Permit<T>(shared_);
        return SendOutcome::Ok;
    }

private:
    template <class>
    friend class Channel;

    explicit Sender(std::shared_ptr<detail::ChannelShared<T>> shared)
        : shared_(std::move(shared)) {
        retain();
    }

    void retain() {
        if (shared_) ++shared_->senders;
    }
    void let_go() {
        if (shared_ && shared_->senders > 0) --shared_->senders;
        shared_.reset();
    }

    std::shared_ptr<detail::ChannelShared<T>> shared_;
};

template <class T>
class Receiver {
public:
    Receiver() = default;
    Receiver(const Receiver&) = delete;
    Receiver& operator=(const Receiver&) = delete;
    Receiver(Receiver&& other) noexcept : shared_(std::move(other.shared_)) {}
    Receiver& operator=(Receiver&& other) noexcept {
        if (this != &other) {
            close();
            shared_ = std::move(other.shared_);
        }
        return *this;
    }
    ~Receiver() { close(); }

    // Non-blocking recv(): the next value, or nothing while the queue is empty. Rust's None
    // (channel closed *and* drained) is at_end().
    [[nodiscard]] std::optional<T> recv() {
        if (!shared_ || shared_->queue.empty()) return std::nullopt;
        T value = std::move(shared_->queue.front());
        shared_->queue.pop_front();
        return value;
    }

    [[nodiscard]] bool at_end() const {
        return !shared_ || (shared_->queue.empty() && shared_->senders == 0);
    }
    [[nodiscard]] std::size_t queued() const { return shared_ ? shared_->queue.size() : 0; }

private:
    template <class>
    friend class Channel;

    explicit Receiver(std::shared_ptr<detail::ChannelShared<T>> shared)
        : shared_(std::move(shared)) {}

    void close() {
        if (shared_) shared_->rx_alive = false;
        shared_.reset();
    }

    std::shared_ptr<detail::ChannelShared<T>> shared_;
};

template <class T>
class Channel {
public:
    static std::pair<Sender<T>, Receiver<T>> bounded(std::size_t capacity) {
        auto shared = std::make_shared<detail::ChannelShared<T>>();
        shared->capacity = capacity;
        return {Sender<T>(shared), Receiver<T>(shared)};
    }
};

// ---------------------------------------------------------------------------
// DataIn: netstack.rs's enum, the only thing app handles write into the engine.

struct DataIn {
    enum class Kind { Tcp, TcpClose, Udp, UdpClose };

    Kind kind = Kind::TcpClose;
    std::size_t id = 0;
    SocketAddr dst;                    // Udp only
    std::vector<std::uint8_t> data;    // Tcp / Udp

    [[nodiscard]] static DataIn tcp(std::size_t id, std::vector<std::uint8_t> data) {
        DataIn d;
        d.kind = Kind::Tcp;
        d.id = id;
        d.data = std::move(data);
        return d;
    }
    [[nodiscard]] static DataIn tcp_close(std::size_t id) {
        DataIn d;
        d.kind = Kind::TcpClose;
        d.id = id;
        return d;
    }
    [[nodiscard]] static DataIn udp(std::size_t id, SocketAddr dst, std::vector<std::uint8_t> data) {
        DataIn d;
        d.kind = Kind::Udp;
        d.id = id;
        d.dst = dst;
        d.data = std::move(data);
        return d;
    }
    [[nodiscard]] static DataIn udp_close(std::size_t id) {
        DataIn d;
        d.kind = Kind::UdpClose;
        d.id = id;
        return d;
    }
};

// What service_udp delivers to a UdpConn: recv()'s (data, meta.endpoint) pair.
struct UdpInbound {
    SocketAddr from;
    std::vector<std::uint8_t> data;
};

// ---------------------------------------------------------------------------
// App-side connection handles: TcpConn / TcpSender / UdpConn / UdpSender with Rust's Drop
// semantics (an unsplit TcpConn drop sends TcpClose; a TcpSender drop always does), and the
// oneshot a connect answer travels through.

class TcpConn;
class TcpSender;

class TcpSender {
public:
    TcpSender() = default;
    TcpSender(std::size_t id, Sender<DataIn> data_in)
        : id_(id), data_in_(std::move(data_in)), live_(true) {}
    TcpSender(const TcpSender&) = delete;
    TcpSender& operator=(const TcpSender&) = delete;
    TcpSender(TcpSender&& other) noexcept
        : id_(other.id_), data_in_(std::move(other.data_in_)), live_(other.live_) {
        other.live_ = false;
    }
    TcpSender& operator=(TcpSender&& other) noexcept {
        if (this != &other) {
            if (live_) (void)data_in_.try_send(DataIn::tcp_close(id_));
            id_ = other.id_;
            data_in_ = std::move(other.data_in_);
            live_ = other.live_;
            other.live_ = false;
        }
        return *this;
    }
    // Drop for TcpSender: always closes, split or not (that is what into_split relies on).
    ~TcpSender() {
        if (live_) (void)data_in_.try_send(DataIn::tcp_close(id_));
    }

    [[nodiscard]] std::size_t id() const { return id_; }
    [[nodiscard]] bool valid() const { return live_; }

    // TcpSender::send. Rust awaits room on the data_in channel; the synchronous caller sees
    // Full and retries on a later tick -- that await point is the host runtime's job.
    [[nodiscard]] SendOutcome send(std::vector<std::uint8_t> data) const {
        return data_in_.try_send(DataIn::tcp(id_, std::move(data)));
    }
    void close() const { (void)data_in_.try_send(DataIn::tcp_close(id_)); }

private:
    std::size_t id_ = 0;
    Sender<DataIn> data_in_;
    bool live_ = false;
};

class TcpConn {
public:
    TcpConn() = default; // moved-from / invalid
    TcpConn(std::size_t id, Sender<DataIn> data_in, Receiver<std::vector<std::uint8_t>> from_stack)
        : id_(id), data_in_(std::move(data_in)), from_stack_(std::move(from_stack)), live_(true) {}
    TcpConn(const TcpConn&) = delete;
    TcpConn& operator=(const TcpConn&) = delete;
    TcpConn(TcpConn&& other) noexcept
        : id_(other.id_), data_in_(std::move(other.data_in_)),
          from_stack_(std::move(other.from_stack_)), live_(other.live_) {
        other.live_ = false;
    }
    TcpConn& operator=(TcpConn&& other) noexcept {
        if (this != &other) {
            if (live_ && !split_) (void)data_in_.try_send(DataIn::tcp_close(id_));
            id_ = other.id_;
            data_in_ = std::move(other.data_in_);
            from_stack_ = std::move(other.from_stack_);
            live_ = other.live_;
            split_ = other.split_;
            other.live_ = false;
        }
        return *this;
    }
    // Drop for TcpConn: closes the connection unless it was split (then TcpSender's Drop owns
    // the close), exactly like the Rust impl.
    ~TcpConn() {
        if (live_ && !split_) (void)data_in_.try_send(DataIn::tcp_close(id_));
    }

    [[nodiscard]] std::size_t id() const { return id_; }
    [[nodiscard]] bool valid() const { return live_; }

    [[nodiscard]] SendOutcome send(std::vector<std::uint8_t> data) const {
        return data_in_.try_send(DataIn::tcp(id_, std::move(data)));
    }
    void close() const { (void)data_in_.try_send(DataIn::tcp_close(id_)); }

    [[nodiscard]] Receiver<std::vector<std::uint8_t>>& from_stack() { return from_stack_; }

    // into_split(): hands the receiving half out and leaves a TcpSender whose Drop closes.
    std::pair<TcpSender, Receiver<std::vector<std::uint8_t>>> into_split() {
        split_ = true;
        return {TcpSender(id_, data_in_), std::move(from_stack_)};
    }

private:
    std::size_t id_ = 0;
    Sender<DataIn> data_in_;
    Receiver<std::vector<std::uint8_t>> from_stack_;
    bool live_ = false;
    bool split_ = false;
};

// The oneshot a connect answer travels through. Declared after TcpConn because the value it
// carries is one; `rx_alive` is the oneshot receiver's is_closed(), `filled` the send.
namespace detail {

struct ConnectSlot {
    bool rx_alive = true;  // the ticket still exists (the oneshot receiver)
    bool filled = false;   // an answer was sent
    std::optional<std::expected<TcpConn, std::string>> value;
};

} // namespace detail

// The oneshot receiver StackHandle::open_tcp awaits: ready() when the engine answered, take()
// yields the TcpConn or the refusal/timeout error. Dropping the ticket is Rust's
// `resp.is_closed()` -- service_tcp sees the connect as abandoned and tears the socket down.
class ConnectTicket {
public:
    ConnectTicket() = default;
    ConnectTicket(const ConnectTicket&) = delete;
    ConnectTicket& operator=(const ConnectTicket&) = delete;
    ConnectTicket(ConnectTicket&& other) noexcept : slot_(std::move(other.slot_)) {}
    ConnectTicket& operator=(ConnectTicket&& other) noexcept {
        if (this != &other) {
            abandon();
            slot_ = std::move(other.slot_);
        }
        return *this;
    }
    ~ConnectTicket() { abandon(); }

    [[nodiscard]] bool valid() const { return slot_ != nullptr; }
    [[nodiscard]] bool ready() const { return slot_ && slot_->filled; }
    // The engine-side abandoned check, exposed for tests.
    [[nodiscard]] bool abandoned() const { return !slot_ || !slot_->rx_alive; }

    // The answered value, once; nothing before it is filled or after it was taken.
    [[nodiscard]] std::optional<std::expected<TcpConn, std::string>> take() {
        if (!slot_ || !slot_->filled || !slot_->value) return std::nullopt;
        auto value = std::move(*slot_->value);
        slot_->value.reset();
        return value;
    }

private:
    friend class NetStack;

    explicit ConnectTicket(std::shared_ptr<detail::ConnectSlot> slot) : slot_(std::move(slot)) {}

    void abandon() {
        if (slot_) {
            slot_->rx_alive = false;
            // The Rust oneshot receiver's drop also drops a value the sender already put in:
            // an answered-but-unclaimed TcpConn runs its Drop (TcpClose) here.
            slot_->value.reset();
        }
        slot_.reset();
    }

    std::shared_ptr<detail::ConnectSlot> slot_;
};

class UdpConn;
class UdpSender;

class UdpSender {
public:
    UdpSender() = default;
    UdpSender(std::size_t id, Sender<DataIn> data_in)
        : id_(id), data_in_(std::move(data_in)), live_(true) {}
    UdpSender(const UdpSender&) = delete;
    UdpSender& operator=(const UdpSender&) = delete;
    UdpSender(UdpSender&& other) noexcept
        : id_(other.id_), data_in_(std::move(other.data_in_)), live_(other.live_) {
        other.live_ = false;
    }
    UdpSender& operator=(UdpSender&& other) noexcept {
        if (this != &other) {
            if (live_) (void)data_in_.try_send(DataIn::udp_close(id_));
            id_ = other.id_;
            data_in_ = std::move(other.data_in_);
            live_ = other.live_;
            other.live_ = false;
        }
        return *this;
    }
    ~UdpSender() {
        if (live_) (void)data_in_.try_send(DataIn::udp_close(id_));
    }

    [[nodiscard]] std::size_t id() const { return id_; }
    [[nodiscard]] bool valid() const { return live_; }

    [[nodiscard]] SendOutcome send_to(const SocketAddr& dst, std::vector<std::uint8_t> data) const {
        return data_in_.try_send(DataIn::udp(id_, dst, std::move(data)));
    }
    void close() const { (void)data_in_.try_send(DataIn::udp_close(id_)); }

private:
    std::size_t id_ = 0;
    Sender<DataIn> data_in_;
    bool live_ = false;
};

class UdpConn {
public:
    UdpConn() = default;
    UdpConn(std::size_t id, Sender<DataIn> data_in, Receiver<UdpInbound> from_stack)
        : id_(id), data_in_(std::move(data_in)), from_stack_(std::move(from_stack)), live_(true) {}
    UdpConn(const UdpConn&) = delete;
    UdpConn& operator=(const UdpConn&) = delete;
    UdpConn(UdpConn&& other) noexcept
        : id_(other.id_), data_in_(std::move(other.data_in_)),
          from_stack_(std::move(other.from_stack_)), live_(other.live_) {
        other.live_ = false;
    }
    UdpConn& operator=(UdpConn&& other) noexcept {
        if (this != &other) {
            if (live_ && !split_) (void)data_in_.try_send(DataIn::udp_close(id_));
            id_ = other.id_;
            data_in_ = std::move(other.data_in_);
            from_stack_ = std::move(other.from_stack_);
            live_ = other.live_;
            split_ = other.split_;
            other.live_ = false;
        }
        return *this;
    }
    ~UdpConn() {
        if (live_ && !split_) (void)data_in_.try_send(DataIn::udp_close(id_));
    }

    [[nodiscard]] std::size_t id() const { return id_; }
    [[nodiscard]] bool valid() const { return live_; }

    [[nodiscard]] SendOutcome send_to(const SocketAddr& dst, std::vector<std::uint8_t> data) const {
        return data_in_.try_send(DataIn::udp(id_, dst, std::move(data)));
    }
    void close() const { (void)data_in_.try_send(DataIn::udp_close(id_)); }

    [[nodiscard]] Receiver<UdpInbound>& from_stack() { return from_stack_; }

    std::pair<UdpSender, Receiver<UdpInbound>> into_split() {
        split_ = true;
        return {UdpSender(id_, data_in_), std::move(from_stack_)};
    }

private:
    std::size_t id_ = 0;
    Sender<DataIn> data_in_;
    Receiver<UdpInbound> from_stack_;
    bool live_ = false;
    bool split_ = false;
};

// ---------------------------------------------------------------------------
// The engine.

// What one tick() pass reports: the delay the Rust select loop would arm before the next
// iteration -- BACKPRESSURE_RETRY while anything is busy or deferred, else the sockets'
// poll_delay capped at MAX_IDLE_TICK once a connection exists, else the bare poll_delay
// (nothing, when no timer is armed).
struct TickResult {
    std::optional<Millis> delay;
};

// The socket state machines live in the .cpp; the table holds them by handle == conn id.
class TcpSocket;
class UdpSocket;

// How a socket hands a finished packet to the device's tx queue.
using PacketEmit = std::function<void(std::vector<std::uint8_t>)>;

class NetStack {
public:
    struct Config {
        // spawn()'s ipv4/ipv6 strings: "a.b.c.d" or with "/prefix", empty for none. Parsed by
        // netpacket::parse_v4/parse_v6, so a bad literal fails the spawn with Rust's message.
        std::string ipv4;
        std::string ipv6;
        std::size_t mtu = 1400;

        TcpLimits limits;

        // sysprofile's numbers (spawn reads them through the tier); defaults are the Medium
        // tier so a Config{} is a working stack. from_settings() fills them properly.
        std::size_t tcp_rx_buf = 1024 * 1024;
        std::size_t tcp_tx_buf = 256 * 1024;
        std::size_t udp_buf = 64 * 1024;
        std::size_t udp_meta_slots = 64; // netpacket::udp_meta(tier)
        std::size_t app_queue = 512;     // sysprofile::channel_capacity

        // Injected seams. All optional except outbound, which behaves as a permanently closed
        // channel when null (flush_tx then keeps packets queued, like Rust's break-on-Closed).
        PacketSink* outbound = nullptr;
        DnsInterceptor* dns = nullptr;
        StackObserver* observer = nullptr;

        // C++-side integration hooks (see the header note): when `routes` is set, every
        // open_tcp and every forwarded UDP datagram gets socks::decide_route's verdict and a
        // Block stops it; `sniff` (HEMERA_ROUTE_SNIFF) feeds a connection's first written bytes
        // to sniff::sniff_hostname and re-decides the route on the revealed name.
        const routing::RuleSet* routes = nullptr;
        bool sniff = true;

        // Inbound checksum verification. The Rust device (StackDevice::capabilities) sets
        // `checksum.ipv4/tcp/udp = Checksum::Tx`, i.e. smoltcp fills every outbound checksum but
        // verifies nothing it receives, so the default here is off for exact parity with the
        // reference. Turn it on to also reject packets whose IPv4 header or TCP/UDP checksum does
        // not match (structurally invalid packets are rejected either way).
        bool validate_checksums = false;

        // The initial sequence number a connect picks. smoltcp draws one at random; the default
        // here is a deterministic counter so packet-level tests are reproducible.
        std::function<std::uint32_t()> make_iss;

        // spawn()'s environment reads, all through Settings: sysprofile's buffers and channel
        // capacity, TcpLimits::from_env, and HEMERA_ROUTE_SNIFF.
        [[nodiscard]] static Config from_settings(const Settings& settings, std::string_view ipv4,
                                                  std::string_view ipv6, std::size_t mtu);
    };

    // spawn() / spawn_with_limits(): parse the addresses, assign them, arm the table. The
    // engine then runs on tick() calls from the host thread -- there is no internal task.
    [[nodiscard]] static std::expected<std::unique_ptr<NetStack>, std::string> spawn(
        const Config& config, TimePoint now);

    ~NetStack();
    NetStack(const NetStack&) = delete;
    NetStack& operator=(const NetStack&) = delete;
    NetStack(NetStack&&) = delete;
    NetStack& operator=(NetStack&&) = delete;

    // --- StackHandle surface ----------------------------------------------------------

    // Cmd::OpenTcp: allocates the local port (Rust's order: the port is consumed even when the
    // connect itself fails), starts the handshake and returns the oneshot ticket. The answer
    // -- the TcpConn, "connection refused" or "connection timed out" -- arrives on a later
    // tick through the ticket. Fails synchronously when the route table blocks the target or
    // the address family is not assigned ("connect: ...", the Rust resp.send(Err) paths).
    [[nodiscard]] std::expected<ConnectTicket, std::string> open_tcp(const SocketAddr& dst,
                                                                     TimePoint now);

    // Cmd::OpenUdp: binds a local port and answers immediately, as the Rust does.
    [[nodiscard]] std::expected<UdpConn, std::string> open_udp(TimePoint now);

    // Cmd::SetAddrs: merge_addrs over the current assignment (one family keeps the other),
    // then apply_addrs -- widened prefixes and the derived default gateways.
    void set_addrs(const std::optional<netpacket::TunnelAddr>& v4,
                   const std::optional<netpacket::TunnelAddr>& v6);

    // --- the datagram pump -------------------------------------------------------------

    // The inbound channel: packets from the TUN / tunnel, queued for the next tick's poll.
    // Never blocks (the Rust channel's backpressure belongs to the host runtime).
    void submit_inbound(std::vector<std::uint8_t> packet);

    // One iteration of netstack.rs's run() loop, in its exact order: iface.poll, service_tcp,
    // service_udp, flush_tx with the drop report, the deferred retry, the delay computation,
    // then the biased select arms -- ingest at most 1 + MAX_INGEST_PER_TICK inbound packets
    // and, while nothing is deferred, drain the data_in queue. `now` is this iteration's
    // Instant::now().
    TickResult tick(TimePoint now);

    // --- introspection (tests and the host) --------------------------------------------

    [[nodiscard]] std::size_t tcp_conn_count() const;
    [[nodiscard]] std::size_t udp_conn_count() const;
    // current_addrs(): the assignment as the interface holds it (widened prefixes).
    [[nodiscard]] netpacket::AddrPair current_addrs() const;
    [[nodiscard]] std::size_t tx_dropped() const;
    [[nodiscard]] std::size_t deferred_count() const;
    // The write backlog a connection carries (Rust's TcpState::pending); 0 for an unknown id.
    [[nodiscard]] std::size_t pending_len(std::size_t conn_id) const;
    [[nodiscard]] std::size_t device_tx_queued() const;
    [[nodiscard]] std::size_t inbound_queued() const;
    [[nodiscard]] const TcpLimits& limits() const;

private:
    explicit NetStack(Config config);

    // run-loop pieces, one per Rust function.
    PacketEmit emit_fn();
    void poll(TimePoint now);
    void process_packet(const std::vector<std::uint8_t>& packet, TimePoint now);
    void dispatch_tcp(const netpacket::TcpParsed& seg, const IpAddress& src, const IpAddress& dst,
                      TimePoint now, const PacketEmit& emit);
    UdpSocket* find_udp_socket(std::uint16_t port);
    bool service_tcp(TimePoint now);
    bool service_udp();
    std::size_t flush_tx();
    std::optional<DataIn> try_handle_data(DataIn datagram, TimePoint now);
    std::optional<Millis> poll_delay(TimePoint now) const;
    void ingest_inbound();
    void drain_data_in(TimePoint now);
    void apply_addrs(const std::optional<netpacket::TunnelAddr>& v4,
                     const std::optional<netpacket::TunnelAddr>& v6);

    // The interface's address state.
    [[nodiscard]] std::optional<IpAddress> local_addr_for(bool v4) const;
    [[nodiscard]] bool is_local_addr(const IpAddress& address) const;

    // The deterministic default behind Config::make_iss.
    std::uint32_t next_iss();

    // The sniffing hook on a connection's head bytes.
    void feed_sniff(std::size_t conn_id, std::span<const std::uint8_t> bytes, TimePoint now);

    // netstack.rs's struct TcpState (renamed here: the wire state machine's TcpState is
    // netpacket's, and the two meet in service_tcp).
    struct TcpConnState {
        std::size_t id = 0;
        Sender<std::vector<std::uint8_t>> to_app;
        std::optional<Receiver<std::vector<std::uint8_t>>> from_stack_rx; // until established
        std::shared_ptr<detail::ConnectSlot> connect_slot;                // Option<OpenTcpResp>
        bool slot_answered = false;                                       // the resp was sent
        TimePoint connect_deadline{};
        std::vector<std::uint8_t> pending;
        bool established = false;
        bool half_closed = false;
        std::optional<TimePoint> orphaned_at;
        bool aborted = false;
        SocketAddr remote;
        // The sniffing hook's state for this connection.
        std::vector<std::uint8_t> head;
        bool sniff_done = false;
        std::optional<std::string> sniffed;
    };

    struct UdpState {
        Sender<UdpInbound> to_app;
    };

    Config config_;
    TcpLimits limits_;

    // Interface state (smoltcp's Interface): the assignment and the derived default gateways.
    netpacket::AddrPair addrs_;
    std::optional<IpAddress> gateway_v4_;
    std::optional<IpAddress> gateway_v6_;
    std::size_t mtu_;

    // StackDevice plus the inbound channel that feeds it.
    std::deque<std::vector<std::uint8_t>> inbound_;
    std::deque<std::vector<std::uint8_t>> device_rx_;
    std::deque<std::vector<std::uint8_t>> device_tx_;

    // SocketSet, keyed by the same id as the connection table.
    std::map<std::size_t, std::unique_ptr<TcpSocket>> tcp_sockets_;
    std::map<std::size_t, std::unique_ptr<UdpSocket>> udp_sockets_;

    std::map<std::size_t, TcpConnState> tcp_conns_;
    std::map<std::size_t, UdpState> udp_conns_;

    std::size_t next_id_ = 1;
    std::uint16_t next_port_ = netpacket::PORT_FIRST;

    Sender<DataIn> data_in_tx_;
    Receiver<DataIn> data_in_rx_;
    std::deque<DataIn> deferred_;

    std::size_t tx_dropped_ = 0;
    std::size_t next_drop_report_ = netpacket::DROP_REPORT_STEP;
    std::uint32_t iss_counter_ = 0;
};

} // namespace hemera::core::netstack
