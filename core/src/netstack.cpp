// Port of netstack.rs: the userland network stack engine. See netstack.hpp for the boundary --
// the connection table, the run-loop scheduling and the datagram pump are line-by-line ports of
// the Rust; the TCP/UDP socket state machines replace the smoltcp sockets netstack.rs drives
// (smoltcp's exact timers are not public wire behaviour, so where smoltcp -- not netstack.rs --
// owns a rule, the code says so and follows the RFC smoltcp follows); and the host-facing seams
// (PacketSink, DnsInterceptor, StackObserver, the injected `now`) replace tokio's channels,
// clock and task.

#include "netstack.hpp"

#include "sniff.hpp"     // sniff_hostname, PEEK_BUDGET (the sniffing hook)
#include "socks.hpp"     // decide_route, Target, DNS_PORT, sniff_enabled (the routing hook)
#include "sysprofile.hpp" // the buffer sizes spawn() reads

#include <algorithm>
#include <cstring>
#include <limits>

namespace hemera::core::netstack {

namespace {

using netpacket::TcpState;

// --- little wire helpers (big-endian), the ones netpacket.cpp keeps private --------------------

void put16(std::uint8_t* at, std::uint16_t value) {
    at[0] = static_cast<std::uint8_t>(value >> 8);
    at[1] = static_cast<std::uint8_t>(value & 0xff);
}

std::uint16_t get16(const std::uint8_t* at) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(at[0]) << 8) | at[1]);
}

// --- RFC 1982 sequence arithmetic ---------------------------------------------------------------

bool seq_lt(std::uint32_t a, std::uint32_t b) {
    return static_cast<std::int32_t>(a - b) < 0;
}
bool seq_gt(std::uint32_t a, std::uint32_t b) { return seq_lt(b, a); }
std::uint32_t seq_add(std::uint32_t a, std::size_t n) {
    return a + static_cast<std::uint32_t>(n);
}

// --- timer constants the smoltcp socket used, now ours ------------------------------------------

// smoltcp's INITIAL_RETRANSMIT_TIMEOUT, doubled per RFC 6298 on every retransmission.
const Millis INITIAL_RTO{1000};
const Millis MAX_RTO{60000};
// smoltcp lingers in TIME_WAIT for 2*MSL. The netstack loop removes an established connection
// the tick it sees TimeWait, so this only outlives sockets the table already dropped.
const Millis TIME_WAIT_DELAY{60000};
// RFC 879's floor for what we may send when the peer named no MSS.
constexpr std::size_t DEFAULT_REMOTE_MSS = 536;
constexpr std::uint16_t MAX_WINDOW = 65535;

// --- whole-packet builders on top of netpacket's codecs ------------------------------------------

std::vector<std::uint8_t> build_tcp_packet(const IpAddress& src, std::uint16_t src_port,
                                           const IpAddress& dst, std::uint16_t dst_port,
                                           std::uint8_t flags, std::uint32_t seq,
                                           std::uint32_t ack, std::uint16_t window,
                                           std::span<const std::uint8_t> options,
                                           std::span<const std::uint8_t> payload) {
    netpacket::TcpSegment seg;
    seg.src_port = src_port;
    seg.dst_port = dst_port;
    seg.seq = seq;
    seg.ack = ack;
    seg.flags = flags;
    seg.window = window;
    seg.urgent_pointer = 0;
    seg.options.assign(options.begin(), options.end());

    if (src.v4) {
        netpacket::Ipv4Header ip;
        ip.src = src;
        ip.dst = dst;
        ip.ttl = netpacket::DEFAULT_TTL_V4;
        ip.protocol = netpacket::IPPROTO_TCP;
        return netpacket::build_ipv4_tcp(ip, seg, payload);
    }

    netpacket::Ipv6Header ip;
    ip.src = src;
    ip.dst = dst;
    ip.hop_limit = netpacket::DEFAULT_HOP_LIMIT_V6;
    ip.next_header = netpacket::IPPROTO_TCP;

    const std::size_t tcp_header_len = netpacket::TCP_MIN_HEADER + seg.options.size();
    const std::size_t seg_len = tcp_header_len + payload.size();
    std::vector<std::uint8_t> out(netpacket::IPV6_HEADER + seg_len, 0);
    std::span<std::uint8_t> whole{out};
    auto tcp_region = whole.subspan(netpacket::IPV6_HEADER, tcp_header_len);
    (void)netpacket::build_tcp_header(seg, tcp_region);
    if (!payload.empty()) {
        std::memcpy(out.data() + netpacket::IPV6_HEADER + tcp_header_len, payload.data(),
                    payload.size());
    }
    const std::vector<std::uint8_t> pseudo =
        netpacket::ipv6_pseudo(src, dst, netpacket::IPPROTO_TCP, seg_len);
    (void)netpacket::tcp_checksum(pseudo, tcp_region, whole.subspan(netpacket::IPV6_HEADER + tcp_header_len));
    (void)netpacket::build_ipv6_header(ip, seg_len, whole.first(netpacket::IPV6_HEADER));
    return out;
}

std::vector<std::uint8_t> build_udp_packet(const IpAddress& src, std::uint16_t src_port,
                                           const IpAddress& dst, std::uint16_t dst_port,
                                           std::span<const std::uint8_t> payload) {
    netpacket::UdpDatagram dg;
    dg.src_port = src_port;
    dg.dst_port = dst_port;

    if (!src.v4) {
        netpacket::Ipv6Header ip;
        ip.src = src;
        ip.dst = dst;
        ip.hop_limit = netpacket::DEFAULT_HOP_LIMIT_V6;
        ip.next_header = netpacket::IPPROTO_UDP;
        return netpacket::build_ipv6_udp(ip, dg, payload);
    }

    const std::size_t dgram_len = netpacket::UDP_HEADER + payload.size();
    std::vector<std::uint8_t> out(netpacket::IPV4_MIN_HEADER + dgram_len, 0);
    std::span<std::uint8_t> whole{out};
    auto udp_region = whole.subspan(netpacket::IPV4_MIN_HEADER, netpacket::UDP_HEADER);
    (void)netpacket::build_udp_header(dg, payload.size(), udp_region);
    if (!payload.empty()) {
        std::memcpy(out.data() + netpacket::IPV4_MIN_HEADER + netpacket::UDP_HEADER, payload.data(),
                    payload.size());
    }
    const std::vector<std::uint8_t> pseudo =
        netpacket::ipv4_pseudo(src, dst, netpacket::IPPROTO_UDP, dgram_len);
    (void)netpacket::udp_checksum(pseudo, udp_region,
                                  whole.subspan(netpacket::IPV4_MIN_HEADER + netpacket::UDP_HEADER));
    netpacket::Ipv4Header ip;
    ip.src = src;
    ip.dst = dst;
    ip.ttl = netpacket::DEFAULT_TTL_V4;
    ip.protocol = netpacket::IPPROTO_UDP;
    (void)netpacket::build_ipv4_header(ip, dgram_len, whole.first(netpacket::IPV4_MIN_HEADER));
    return out;
}

// --- inbound checksum validation (opt-in: see Config::validate_checksums) ------------------------
// The Rust device reports `checksum.ipv4/tcp/udp = Checksum::Tx`, so smoltcp fills every outbound
// checksum and verifies none of the inbound ones; process_packet mirrors that by default and only
// runs these helpers when the host asks for verification.

bool ipv4_header_checksum_ok(std::span<const std::uint8_t> packet, std::size_t header_len) {
    if (packet.size() < header_len + 2) return false;
    std::vector<std::uint8_t> header(packet.begin(), packet.begin() + static_cast<std::ptrdiff_t>(header_len));
    const std::uint16_t stored = get16(header.data() + 10);
    header[10] = 0;
    header[11] = 0;
    return netpacket::inet_checksum(header) == stored;
}

// `segment` is the L4 header + payload; the checksum field sits at `checksum_offset` inside it.
bool l4_checksum_ok(const std::vector<std::uint8_t>& pseudo, std::span<const std::uint8_t> segment,
                    std::size_t checksum_offset) {
    if (segment.size() < checksum_offset + 2) return false;
    const std::uint16_t stored = get16(segment.data() + checksum_offset);
    std::vector<std::uint8_t> combined;
    combined.reserve(pseudo.size() + segment.size());
    combined.insert(combined.end(), pseudo.begin(), pseudo.end());
    combined.insert(combined.end(), segment.begin(), segment.end());
    combined[pseudo.size() + checksum_offset] = 0;
    combined[pseudo.size() + checksum_offset + 1] = 0;
    return netpacket::inet_checksum_l4(combined) == stored;
}

// The MSS option (kind 2, len 4) out of a segment's options; the RFC 879 floor when absent.
std::size_t parse_mss_option(std::span<const std::uint8_t> options) {
    std::size_t i = 0;
    while (i + 1 < options.size()) {
        const std::uint8_t kind = options[i];
        if (kind == 0) break; // end of options
        if (kind == 1) {      // NOP
            ++i;
            continue;
        }
        const std::size_t len = options[i + 1];
        if (len < 2 || i + len > options.size()) break;
        if (kind == 2 && len == 4) {
            const std::uint16_t mss = get16(options.data() + i + 2);
            if (mss >= 64) return mss;
            return DEFAULT_REMOTE_MSS;
        }
        i += len;
    }
    return DEFAULT_REMOTE_MSS;
}

} // namespace

// ---------------------------------------------------------------------------
// TcpSocket: the smoltcp tcp::Socket netstack.rs drives, at packet level.

class TcpSocket {
public:
    struct Cfg {
        std::size_t rx_buf_size = 0;
        std::size_t tx_buf_size = 0;
        Millis keepalive{0}; // 0 disables, like smoltcp's set_keep_alive(None)
        Millis timeout{0};   // 0 disables, like smoltcp's set_timeout(None)
        std::size_t mtu = 1400;
    };

    TcpSocket(Cfg cfg, IpAddress local_ip, std::uint16_t local_port, SocketAddr remote,
              std::uint32_t iss, TimePoint now)
        : cfg_(cfg), local_ip_(local_ip), local_port_(local_port), remote_(remote), iss_(iss),
          snd_una_(iss), snd_nxt_(iss), last_rx_(now), last_tx_(now) {}

    // socket.connect(): arms the SYN; poll() dispatches it, the way smoltcp only emits during
    // the interface poll. A family with no local address can never be constructed (open_tcp
    // refuses first), so connect itself cannot fail here.
    void connect() {
        state_ = TcpState::SynSent;
        pending_syn_ = true;
        const std::size_t mss = local_mss();
        // RFC 6928's initial window, the size smoltcp starts its congestion controller at.
        cwnd_ = std::min<std::size_t>(4 * mss, std::max<std::size_t>(2 * mss, 4380));
        ssthresh_ = MAX_WINDOW;
    }

    [[nodiscard]] TcpState state() const { return state_; }
    [[nodiscard]] bool can_recv() const { return !rx_buf_.empty(); }
    // smoltcp's can_send is "the tx buffer is not full"; restricted to the states that may
    // still carry data, which is all netstack.rs ever asks it in.
    [[nodiscard]] bool can_send() const {
        return tx_buf_.size() < cfg_.tx_buf_size &&
               (state_ == TcpState::Established || state_ == TcpState::CloseWait);
    }

    // socket.send_slice(): copies what the tx buffer has room for and returns the count.
    std::size_t send_slice(std::span<const std::uint8_t> data) {
        const std::size_t free = cfg_.tx_buf_size - tx_buf_.size();
        const std::size_t taken = std::min(data.size(), free);
        if (taken > 0) {
            const auto first = data.begin();
            tx_buf_.insert(tx_buf_.end(), first, first + static_cast<std::ptrdiff_t>(taken));
        }
        return taken;
    }

    // socket.recv(|buf| (buf.len(), buf.to_vec())): one chunk holding everything buffered,
    // exactly the closure netstack.rs passes.
    std::vector<std::uint8_t> recv() {
        std::vector<std::uint8_t> chunk;
        if (rx_buf_.empty()) return chunk;
        chunk.assign(rx_buf_.begin(), rx_buf_.end());
        rx_buf_.clear();
        return chunk;
    }

    // socket.close(): the graceful half of the state machine.
    void close(TimePoint now, const PacketEmit& emit) {
        switch (state_) {
            case TcpState::Established:
                send_fin(now, emit);
                state_ = TcpState::FinWait1;
                break;
            case TcpState::CloseWait:
                send_fin(now, emit);
                state_ = TcpState::LastAck;
                break;
            case TcpState::SynSent:
            case TcpState::SynReceived:
                state_ = TcpState::Closed;
                emit_packet(now, netpacket::TCP_RST, snd_nxt_, 0, {}, {}, emit);
                retx_.clear();
                next_retransmit_.reset();
                break;
            default:
                break; // closing already in progress; smoltcp ignores close() there too
        }
    }

    // socket.abort(): an RST out, everything dropped.
    void abort(TimePoint now, const PacketEmit& emit) {
        if (state_ == TcpState::Closed) return;
        emit_packet(now, netpacket::TCP_RST, snd_nxt_, rcv_nxt_, {}, {}, emit);
        state_ = TcpState::Closed;
        retx_.clear();
        tx_buf_.clear();
        rx_buf_.clear();
        next_retransmit_.reset();
        time_wait_end_.reset();
    }

    // The interface's per-socket ingress: one validated, in-order-for-us TCP segment.
    void on_packet(const netpacket::TcpParsed& parsed, TimePoint now, const PacketEmit& emit) {
        if (state_ == TcpState::Closed) return;
        last_rx_ = now;
        const netpacket::TcpSegment& s = parsed.segment;

        if ((s.flags & netpacket::TCP_RST) != 0) {
            state_ = TcpState::Closed;
            retx_.clear();
            tx_buf_.clear();
            rx_buf_.clear();
            next_retransmit_.reset();
            time_wait_end_.reset();
            return;
        }

        if (state_ == TcpState::SynSent) {
            on_packet_syn_sent(parsed, now, emit);
            return;
        }

        // 1. The ACK half.
        if ((s.flags & netpacket::TCP_ACK) != 0) {
            if (seq_gt(s.ack, snd_nxt_)) {
                // An ack for data never sent: answer with our own segment and drop it.
                emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
                return;
            }
            if (seq_gt(s.ack, snd_una_)) {
                const std::uint32_t acked = s.ack - snd_una_; // < 2^31 apart, plain subtraction
                snd_una_ = s.ack;
                remote_window_ = s.window;
                retire_acked();
                grow_cwnd(acked);
                if (retx_.empty()) {
                    next_retransmit_.reset();
                    rto_ = INITIAL_RTO;
                } else {
                    next_retransmit_ = now + rto_;
                }
                if (fin_sent_ && seq_gt(snd_una_, fin_seq_)) fin_acked_ = true;
                switch (state_) {
                    case TcpState::FinWait1:
                        if (fin_acked_) state_ = TcpState::FinWait2;
                        break;
                    case TcpState::Closing:
                        if (fin_acked_) enter_time_wait(now);
                        break;
                    case TcpState::LastAck:
                        if (fin_acked_) state_ = TcpState::Closed;
                        break;
                    default:
                        break;
                }
                if (state_ == TcpState::Closed) return;
            } else {
                // A duplicate ack still reports the peer's window (a zero window may open).
                remote_window_ = s.window;
            }
        }

        // 2. The payload half.
        const bool may_receive = state_ == TcpState::Established ||
                                 state_ == TcpState::SynReceived ||
                                 state_ == TcpState::FinWait1 || state_ == TcpState::FinWait2;
        if (may_receive && !parsed.payload.empty()) {
            if (s.seq == rcv_nxt_) {
                ingest_payload(parsed.payload, now, emit);
            } else {
                // Out of order: the data is dropped and the last ack repeated (no SACK modelled,
                // matching the base smoltcp behaviour netstack.rs relies on).
                emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
            }
        }

        // 3. The FIN half.
        if ((s.flags & netpacket::TCP_FIN) != 0) {
            const std::uint32_t fin_at = seq_add(s.seq, parsed.payload.size());
            if (state_ == TcpState::CloseWait || state_ == TcpState::LastAck ||
                state_ == TcpState::TimeWait) {
                // A retransmitted FIN is re-acked.
                emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
            } else if (may_receive && fin_at == rcv_nxt_) {
                rcv_nxt_ = seq_add(rcv_nxt_, 1);
                emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
                switch (state_) {
                    case TcpState::Established:
                    case TcpState::SynReceived:
                        state_ = TcpState::CloseWait;
                        break;
                    case TcpState::FinWait1:
                        if (fin_acked_) {
                            enter_time_wait(now);
                        } else {
                            state_ = TcpState::Closing;
                        }
                        break;
                    case TcpState::FinWait2:
                    case TcpState::Closing:
                        enter_time_wait(now);
                        break;
                    default:
                        break;
                }
            } else if (may_receive) {
                // An out-of-order FIN: dup ack, nothing consumed.
                emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
            }
        }
    }

    // The per-socket half of iface.poll: pending SYN, the inactivity timeout, TIME_WAIT expiry,
    // retransmission, keepalive and the data dispatch.
    void poll(TimePoint now, const PacketEmit& emit) {
        if (state_ == TcpState::Closed) return;

        if (pending_syn_) {
            pending_syn_ = false;
            retx_.push_back(RetxEntry{iss_, {}, true, false});
            emit_packet(now, netpacket::TCP_SYN, iss_, 0, {}, mss_option(), emit);
            // The SYN occupies one sequence number, so the SYN-ACK acks iss + 1.
            snd_nxt_ = seq_add(iss_, 1);
            if (!next_retransmit_) next_retransmit_ = now + rto_;
        }

        // socket.set_timeout(keepalive * 3): no packet received for that long kills the socket.
        if (cfg_.timeout > Millis::zero() && now - last_rx_ >= cfg_.timeout) {
            abort(now, emit);
            return;
        }

        if (state_ == TcpState::TimeWait && time_wait_end_ && now >= *time_wait_end_) {
            state_ = TcpState::Closed;
            time_wait_end_.reset();
            return;
        }

        if (next_retransmit_ && now >= *next_retransmit_) {
            if (!retx_.empty()) {
                const RetxEntry& entry = retx_.front();
                if (entry.syn) {
                    emit_packet(now, netpacket::TCP_SYN, entry.seq, 0, {}, mss_option(), emit);
                } else if (entry.fin) {
                    emit_packet(now, netpacket::TCP_FIN | netpacket::TCP_ACK, entry.seq, rcv_nxt_,
                                {}, {}, emit);
                } else {
                    emit_packet(now, netpacket::TCP_ACK, entry.seq, rcv_nxt_, entry.data, {}, emit);
                }
                rto_ = std::min<Millis>(rto_ * 2, MAX_RTO);
                next_retransmit_ = now + rto_;
                // RFC 5681: a timeout halves ssthresh and restarts cwnd at one segment.
                const std::size_t flight = static_cast<std::uint32_t>(snd_nxt_ - snd_una_);
                ssthresh_ = std::max<std::size_t>(flight / 2, 2 * local_mss());
                cwnd_ = local_mss();
            } else if (remote_window_ == 0 && !tx_buf_.empty() &&
                       (state_ == TcpState::Established || state_ == TcpState::CloseWait)) {
                // A zero-window (persist) probe: one byte, not recorded for retransmission.
                const std::uint8_t probe = tx_buf_.front();
                emit_packet(now, netpacket::TCP_ACK, snd_nxt_, rcv_nxt_,
                            std::span<const std::uint8_t>(&probe, 1), {}, emit);
                rto_ = std::min<Millis>(rto_ * 2, MAX_RTO);
                next_retransmit_ = now + rto_;
            } else {
                next_retransmit_.reset();
            }
        }

        // socket.set_keep_alive(): an ack probe with seq one below snd_una while idle.
        if (cfg_.keepalive > Millis::zero() && retx_.empty() &&
            (state_ == TcpState::Established || state_ == TcpState::CloseWait)) {
            const TimePoint idle_since = std::max(last_rx_, last_tx_);
            if (now - idle_since >= cfg_.keepalive) {
                emit_packet(now, netpacket::TCP_ACK, snd_una_ - 1, rcv_nxt_, {}, {}, emit);
            }
        }

        dispatch_data(now, emit);

        // A stalled zero-window send arms the persist timer even with nothing in flight.
        if (remote_window_ == 0 && !tx_buf_.empty() && retx_.empty() && !next_retransmit_ &&
            (state_ == TcpState::Established || state_ == TcpState::CloseWait)) {
            next_retransmit_ = now + rto_;
        }
    }

    // iface.poll_delay's per-socket part: the earliest timer that could fire.
    [[nodiscard]] std::optional<TimePoint> next_deadline() const {
        if (state_ == TcpState::Closed) return std::nullopt;
        std::optional<TimePoint> best;
        const auto consider = [&best](TimePoint candidate) {
            if (!best || candidate < *best) best = candidate;
        };
        if (next_retransmit_) consider(*next_retransmit_);
        if (cfg_.keepalive > Millis::zero() && retx_.empty() &&
            (state_ == TcpState::Established || state_ == TcpState::CloseWait)) {
            consider(std::max(last_rx_, last_tx_) + cfg_.keepalive);
        }
        if (cfg_.timeout > Millis::zero()) consider(last_rx_ + cfg_.timeout);
        if (time_wait_end_) consider(*time_wait_end_);
        return best;
    }

    [[nodiscard]] bool matches(const IpAddress& local_ip, const IpAddress& remote_ip,
                               std::uint16_t local_port, std::uint16_t remote_port) const {
        return local_port_ == local_port && remote_.port == remote_port &&
               remote_.ip == remote_ip && local_ip_ == local_ip;
    }

    [[nodiscard]] std::uint16_t local_port() const { return local_port_; }
    [[nodiscard]] const SocketAddr& remote() const { return remote_; }

private:
    struct RetxEntry {
        std::uint32_t seq = 0;
        std::vector<std::uint8_t> data;
        bool syn = false;
        bool fin = false;
    };

    void on_packet_syn_sent(const netpacket::TcpParsed& parsed, TimePoint now,
                            const PacketEmit& emit) {
        const netpacket::TcpSegment& s = parsed.segment;
        if ((s.flags & netpacket::TCP_ACK) != 0) {
            if (s.ack != snd_nxt_) {
                // RFC 793: an ack for something we never sent gets a reset.
                emit_packet(now, netpacket::TCP_RST, s.ack, 0, {}, {}, emit);
                return;
            }
            snd_una_ = s.ack;
            retire_acked();
            if (retx_.empty()) {
                next_retransmit_.reset();
                rto_ = INITIAL_RTO;
            }
        }
        if ((s.flags & netpacket::TCP_SYN) == 0) return;

        irs_ = s.seq;
        rcv_nxt_ = seq_add(irs_, 1);
        remote_window_ = s.window;
        remote_mss_ = parse_mss_option(s.options);
        const bool acked = (s.flags & netpacket::TCP_ACK) != 0;
        state_ = acked ? TcpState::Established : TcpState::SynReceived;
        emit_packet(now, netpacket::TCP_ACK, snd_nxt_, rcv_nxt_, {}, {}, emit);
        if (acked) {
            retire_acked(); // the SYN itself
            if (retx_.empty()) {
                next_retransmit_.reset();
                rto_ = INITIAL_RTO;
            }
        }
        if (!parsed.payload.empty() && state_ != TcpState::Closed) {
            ingest_payload(parsed.payload, now, emit);
        }
    }

    void ingest_payload(std::span<const std::uint8_t> payload, TimePoint now,
                        const PacketEmit& emit) {
        const std::size_t free = cfg_.rx_buf_size - rx_buf_.size();
        const std::size_t take = std::min(payload.size(), free);
        if (take > 0) {
            const auto first = payload.begin();
            rx_buf_.insert(rx_buf_.end(), first, first + static_cast<std::ptrdiff_t>(take));
            rcv_nxt_ = seq_add(rcv_nxt_, take);
        }
        // Data is acked at once; a delayed-ack timer is not modelled (smoltcp's is bounded by
        // the same tick granularity the netstack loop polls at).
        emit_packet(now, netpacket::TCP_ACK, snd_una_, rcv_nxt_, {}, {}, emit);
    }

    void send_fin(TimePoint now, const PacketEmit& emit) {
        fin_seq_ = snd_nxt_;
        snd_nxt_ = seq_add(snd_nxt_, 1);
        fin_sent_ = true;
        retx_.push_back(RetxEntry{fin_seq_, {}, false, true});
        emit_packet(now, netpacket::TCP_FIN | netpacket::TCP_ACK, fin_seq_, rcv_nxt_, {}, {}, emit);
        if (!next_retransmit_) next_retransmit_ = now + rto_;
    }

    void enter_time_wait(TimePoint now) {
        state_ = TcpState::TimeWait;
        time_wait_end_ = now + TIME_WAIT_DELAY;
    }

    void retire_acked() {
        while (!retx_.empty()) {
            const RetxEntry& entry = retx_.front();
            const std::size_t consumed = entry.data.size() + (entry.syn ? 1 : 0) + (entry.fin ? 1 : 0);
            const std::uint32_t end = seq_add(entry.seq, consumed);
            if (seq_gt(end, snd_una_)) break;
            if (entry.fin) fin_acked_ = true;
            retx_.pop_front();
        }
    }

    void grow_cwnd(std::uint32_t acked_bytes) {
        const std::size_t mss = segment_mss();
        if (acked_bytes == 0 || mss == 0) return;
        if (cwnd_ == 0) cwnd_ = mss; // defensive: never divide by zero below
        if (cwnd_ < ssthresh_) {
            cwnd_ += std::min<std::size_t>(acked_bytes, mss); // slow start
        } else {
            // Congestion avoidance: cwnd += MSS * acked / cwnd, at least a byte.
            cwnd_ += std::max<std::size_t>(1, (mss * static_cast<std::size_t>(acked_bytes)) / cwnd_);
        }
    }

    void dispatch_data(TimePoint now, const PacketEmit& emit) {
        if (state_ != TcpState::Established && state_ != TcpState::CloseWait) return;
        if (tx_buf_.empty()) return;
        const std::size_t mss = segment_mss();
        if (mss == 0) return;
        std::size_t flight = static_cast<std::uint32_t>(snd_nxt_ - snd_una_);
        const std::size_t limit = std::min(cwnd_, static_cast<std::size_t>(remote_window_));
        while (!tx_buf_.empty() && flight < limit) {
            const std::size_t room = limit - flight;
            const std::size_t n = std::min({tx_buf_.size(), mss, room});
            if (n == 0) break;
            std::vector<std::uint8_t> payload(tx_buf_.begin(),
                                              tx_buf_.begin() + static_cast<std::ptrdiff_t>(n));
            tx_buf_.erase(tx_buf_.begin(), tx_buf_.begin() + static_cast<std::ptrdiff_t>(n));
            // PSH rides on the segment that empties the buffer, the way smoltcp pushes the tail.
            const std::uint8_t flags =
                netpacket::TCP_ACK | (tx_buf_.empty() ? netpacket::TCP_PSH : 0);
            retx_.push_back(RetxEntry{snd_nxt_, payload, false, false});
            emit_packet(now, flags, snd_nxt_, rcv_nxt_, payload, {}, emit);
            snd_nxt_ = seq_add(snd_nxt_, n);
            flight += n;
            if (!next_retransmit_) next_retransmit_ = now + rto_;
        }
    }

    [[nodiscard]] std::size_t local_mss() const {
        const std::size_t overhead =
            (local_ip_.v4 ? netpacket::IPV4_MIN_HEADER : netpacket::IPV6_HEADER) +
            netpacket::TCP_MIN_HEADER;
        return cfg_.mtu > overhead ? cfg_.mtu - overhead : 64;
    }
    [[nodiscard]] std::size_t segment_mss() const {
        return std::min(local_mss(), remote_mss_);
    }

    [[nodiscard]] std::vector<std::uint8_t> mss_option() const {
        const std::uint16_t mss = static_cast<std::uint16_t>(std::min<std::size_t>(local_mss(), 0xffff));
        std::vector<std::uint8_t> option(4, 0);
        option[0] = 2;
        option[1] = 4;
        put16(option.data() + 2, mss);
        return option;
    }

    [[nodiscard]] std::uint16_t advertise_window() const {
        const std::size_t free = cfg_.rx_buf_size - rx_buf_.size();
        return static_cast<std::uint16_t>(std::min<std::size_t>(free, MAX_WINDOW));
    }

    void emit_packet(TimePoint now, std::uint8_t flags, std::uint32_t seq, std::uint32_t ack,
                     std::span<const std::uint8_t> payload, std::span<const std::uint8_t> options,
                     const PacketEmit& emit) {
        last_tx_ = now;
        emit(build_tcp_packet(local_ip_, local_port_, remote_.ip, remote_.port, flags, seq, ack,
                              advertise_window(), options, payload));
    }

    Cfg cfg_;
    TcpState state_ = TcpState::Closed;
    IpAddress local_ip_;
    std::uint16_t local_port_ = 0;
    SocketAddr remote_;

    std::uint32_t iss_ = 0;
    std::uint32_t snd_una_ = 0;
    std::uint32_t snd_nxt_ = 0;
    std::uint32_t irs_ = 0;
    std::uint32_t rcv_nxt_ = 0;
    std::uint16_t remote_window_ = MAX_WINDOW;
    std::size_t remote_mss_ = DEFAULT_REMOTE_MSS;

    std::deque<std::uint8_t> tx_buf_;
    std::deque<std::uint8_t> rx_buf_;
    std::deque<RetxEntry> retx_;

    Millis rto_ = INITIAL_RTO;
    std::optional<TimePoint> next_retransmit_;
    TimePoint last_rx_;
    TimePoint last_tx_;

    bool pending_syn_ = false;
    bool fin_sent_ = false;
    bool fin_acked_ = false;
    std::uint32_t fin_seq_ = 0;
    std::optional<TimePoint> time_wait_end_;

    std::size_t cwnd_ = 0;
    std::size_t ssthresh_ = MAX_WINDOW;
};

// ---------------------------------------------------------------------------
// UdpSocket: the smoltcp udp::Socket -- a bound port with slotted packet buffers.

class UdpSocket {
public:
    struct Cfg {
        std::size_t buf_size = 0;    // udp_buf(): bytes per direction
        std::size_t meta_slots = 0;  // udp_meta(): datagram slots per direction
        std::size_t mtu = 1400;
    };

    UdpSocket(Cfg cfg, std::uint16_t port) : cfg_(cfg), port_(port) {}

    [[nodiscard]] std::uint16_t port() const { return port_; }
    [[nodiscard]] bool can_recv() const { return !rx_.empty(); }

    std::optional<UdpInbound> recv() {
        if (rx_.empty()) return std::nullopt;
        UdpInbound item = std::move(rx_.front());
        rx_.pop_front();
        rx_bytes_ -= item.data.size();
        return item;
    }

    // socket.send_slice(data, endpoint): queued when the tx slots and bytes have room and the
    // datagram fits the MTU; anything else is an error the Rust caller ignores with `let _ =`.
    [[nodiscard]] SendOutcome send_slice(std::span<const std::uint8_t> data, const SocketAddr& dst) {
        if (tx_.size() >= cfg_.meta_slots) return SendOutcome::Full;
        if (tx_bytes_ + data.size() > cfg_.buf_size) return SendOutcome::Full;
        const std::size_t ip_header = dst.ip.v4 ? netpacket::IPV4_MIN_HEADER : netpacket::IPV6_HEADER;
        if (ip_header + netpacket::UDP_HEADER + data.size() > cfg_.mtu) return SendOutcome::Full;
        std::vector<std::uint8_t> copy(data.begin(), data.end());
        tx_bytes_ += copy.size();
        tx_.push_back(TxItem{dst, std::move(copy)});
        return SendOutcome::Ok;
    }

    // The interface's ingress: queued when the rx slots and bytes have room, dropped otherwise
    // (smoltcp drops a datagram its packet buffer cannot hold).
    void deliver(const SocketAddr& from, std::span<const std::uint8_t> payload) {
        if (rx_.size() >= cfg_.meta_slots) return;
        if (rx_bytes_ + payload.size() > cfg_.buf_size) return;
        std::vector<std::uint8_t> copy(payload.begin(), payload.end());
        rx_bytes_ += copy.size();
        rx_.push_back(UdpInbound{from, std::move(copy)});
    }

    // The dispatch half of iface.poll: build every queued datagram into a packet.
    void poll(const std::optional<IpAddress>& local_v4, const std::optional<IpAddress>& local_v6,
              const PacketEmit& emit) {
        while (!tx_.empty()) {
            TxItem item = std::move(tx_.front());
            tx_.pop_front();
            tx_bytes_ -= item.data.size();
            const bool v4 = item.dst.ip.v4;
            if (v4 ? !local_v4.has_value() : !local_v6.has_value()) continue; // no source: dropped
            const IpAddress& src = v4 ? *local_v4 : *local_v6;
            emit(build_udp_packet(src, port_, item.dst.ip, item.dst.port, item.data));
        }
    }

private:
    struct TxItem {
        SocketAddr dst;
        std::vector<std::uint8_t> data;
    };

    Cfg cfg_;
    std::uint16_t port_ = 0;
    std::deque<UdpInbound> rx_;
    std::size_t rx_bytes_ = 0;
    std::deque<TxItem> tx_;
    std::size_t tx_bytes_ = 0;
};

// ---------------------------------------------------------------------------
// Limits, config and spawn.

TcpLimits TcpLimits::from_settings(const Settings& settings) {
    TcpLimits limits;
    // netstack.rs's tcp_connect_timeout() / tcp_keepalive(), env reads through Settings.
    limits.connect = Millis(static_cast<std::int64_t>(
        netpacket::connect_secs(settings.get("HEMERA_TCP_CONNECT_SECS"))) * 1000);
    limits.keepalive = Millis(static_cast<std::int64_t>(
        netpacket::keepalive_secs(settings.get("HEMERA_TCP_KEEPALIVE_SECS"))) * 1000);
    limits.orphan_linger = Millis(static_cast<std::int64_t>(netpacket::ORPHAN_LINGER_MS));
    return limits;
}

NetStack::Config NetStack::Config::from_settings(const Settings& settings, std::string_view ipv4,
                                                 std::string_view ipv6, std::size_t mtu) {
    Config config;
    config.ipv4.assign(ipv4);
    config.ipv6.assign(ipv6);
    config.mtu = mtu;
    config.tcp_rx_buf = sysprofile::netstack_tcp_rx_buf_bytes(settings);
    config.tcp_tx_buf = sysprofile::netstack_tcp_tx_buf_bytes(settings);
    config.udp_buf = sysprofile::netstack_udp_buf_bytes(settings);
    config.udp_meta_slots = netpacket::udp_meta(sysprofile::tuning(settings).tier);
    config.app_queue = sysprofile::channel_capacity(settings);
    config.limits = TcpLimits::from_settings(settings);
    config.sniff = socks::sniff_enabled(settings);
    return config;
}

NetStack::NetStack(Config config)
    : config_(std::move(config)), limits_(config_.limits), mtu_(config_.mtu) {
    auto channels = Channel<DataIn>::bounded(config_.app_queue);
    data_in_tx_ = std::move(channels.first);
    data_in_rx_ = std::move(channels.second);
}

NetStack::~NetStack() = default;

std::expected<std::unique_ptr<NetStack>, std::string> NetStack::spawn(const Config& config,
                                                                      TimePoint now) {
    (void)now; // Interface::new takes smoltcp's Instant::now(); no timer is armed before a socket exists.
    const auto v4 = netpacket::parse_v4(config.ipv4);
    if (!v4) return std::unexpected(v4.error());
    const auto v6 = netpacket::parse_v6(config.ipv6);
    if (!v6) return std::unexpected(v6.error());

    std::unique_ptr<NetStack> stack(new NetStack(config));
    stack->apply_addrs(*v4, *v6);
    return stack;
}

// ---------------------------------------------------------------------------
// Addresses (apply_addrs / current_addrs).

void NetStack::apply_addrs(const std::optional<netpacket::TunnelAddr>& v4,
                           const std::optional<netpacket::TunnelAddr>& v6) {
    addrs_ = netpacket::AddrPair{};
    if (v4) {
        netpacket::TunnelAddr widened = *v4;
        widened.prefix = netpacket::routable_prefix_v4(widened.prefix);
        addrs_.v4 = widened;
        // add_default_ipv4_route: the gateway survives until the next assignment names one.
        gateway_v4_ = netpacket::gateway_v4(*v4);
    }
    if (v6) {
        netpacket::TunnelAddr widened = *v6;
        widened.prefix = netpacket::routable_prefix_v6(widened.prefix);
        addrs_.v6 = widened;
        gateway_v6_ = netpacket::gateway_v6(*v6);
    }
}

netpacket::AddrPair NetStack::current_addrs() const { return addrs_; }

// ---------------------------------------------------------------------------
// The StackHandle surface (handle_cmd's three arms, called synchronously).

std::expected<ConnectTicket, std::string> NetStack::open_tcp(const SocketAddr& dst,
                                                             TimePoint now) {
    // C++-side integration: the routing decision table, consulted the way socks.rs consults it
    // before a connect (netstack.rs itself has no routing -- see the header note).
    if (config_.routes) {
        const auto action = socks::decide_route(*config_.routes, socks::Target::from_ip(dst.ip),
                                                std::nullopt, dst.port);
        if (config_.observer) config_.observer->on_route_decided(dst, action);
        if (action == routing::Action::Block) {
            return std::unexpected(std::string("blocked by route rules: ") + dst.to_string());
        }
    }

    // Rust's order: the port is allocated before the connect, so a failed connect still
    // consumes it.
    const std::uint16_t local_port = netpacket::alloc_port(next_port_);

    const bool v4 = dst.ip.v4;
    if (v4 ? !addrs_.v4.has_value() : !addrs_.v6.has_value()) {
        // socket.connect() against a family the interface has no address for fails in smoltcp
        // with no route; the answer travels back as `connect: {e:?}`.
        return std::unexpected(std::string("connect: no address assigned for the ") +
                               (v4 ? "ipv4" : "ipv6") + " family");
    }
    const IpAddress local_ip = v4 ? addrs_.v4->ip : addrs_.v6->ip;

    TcpSocket::Cfg cfg;
    cfg.rx_buf_size = config_.tcp_rx_buf;
    cfg.tx_buf_size = config_.tcp_tx_buf;
    cfg.keepalive = limits_.keepalive;                       // socket.set_keep_alive
    cfg.timeout = limits_.keepalive * 3;                     // socket.set_timeout(keepalive * 3)
    cfg.mtu = mtu_;

    const std::uint32_t iss = config_.make_iss ? config_.make_iss() : next_iss();
    auto socket = std::make_unique<TcpSocket>(cfg, local_ip, local_port, dst, iss, now);
    socket->connect(); // Nagle plays no part: every dispatch sends what it has, like set_nagle_enabled(false)

    const std::size_t id = next_id_;
    ++next_id_;
    tcp_sockets_.emplace(id, std::move(socket));

    auto channels = Channel<std::vector<std::uint8_t>>::bounded(config_.app_queue);
    TcpConnState state;
    state.id = id;
    state.to_app = std::move(channels.first);
    state.from_stack_rx = std::move(channels.second);
    state.connect_slot = std::make_shared<detail::ConnectSlot>();
    state.connect_deadline = now + limits_.connect;
    state.remote = dst;
    auto slot = state.connect_slot;
    tcp_conns_.emplace(id, std::move(state));
    return ConnectTicket(slot);
}

std::expected<UdpConn, std::string> NetStack::open_udp(TimePoint now) {
    (void)now;
    const std::uint16_t local_port = netpacket::alloc_port(next_port_);

    UdpSocket::Cfg cfg;
    cfg.buf_size = config_.udp_buf;
    cfg.meta_slots = config_.udp_meta_slots;
    cfg.mtu = mtu_;

    const std::size_t id = next_id_;
    ++next_id_;
    udp_sockets_.emplace(id, std::make_unique<UdpSocket>(cfg, local_port));

    auto channels = Channel<UdpInbound>::bounded(config_.app_queue);
    udp_conns_.emplace(id, UdpState{std::move(channels.first)});

    // Cmd::OpenUdp answers at once, before any poll.
    return UdpConn(id, data_in_tx_, std::move(channels.second));
}

void NetStack::set_addrs(const std::optional<netpacket::TunnelAddr>& v4,
                         const std::optional<netpacket::TunnelAddr>& v6) {
    // handle_cmd's SetAddrs arm: v4.or(current_v4), v6.or(current_v6), then apply_addrs.
    const auto merged = netpacket::merge_addrs(current_addrs(), netpacket::AddrPair{v4, v6});
    apply_addrs(merged.v4, merged.v6);
    if (config_.observer) config_.observer->on_addrs_synced();
}

// ---------------------------------------------------------------------------
// The datagram pump.

void NetStack::submit_inbound(std::vector<std::uint8_t> packet) {
    inbound_.push_back(std::move(packet));
}

PacketEmit NetStack::emit_fn() {
    // The device's tx queue: poll() drains device_rx_ inbound, flush_tx() hands device_tx_ to
    // the PacketSink. This is the smoltcp Device::transmit seam, made explicit.
    return [this](std::vector<std::uint8_t> packet) { device_tx_.push_back(std::move(packet)); };
}

TickResult NetStack::tick(TimePoint now) {
    // iface.poll (Rust wraps it in catch_unwind and clears the device queues on a panic; a C++
    // panic has no analogue, so the guard is simply absent).
    poll(now);

    const bool tcp_busy = service_tcp(now);
    const bool udp_busy = service_udp();
    const std::size_t dropped = flush_tx();

    if (dropped > 0) {
        // saturating_add
        tx_dropped_ = tx_dropped_ > std::numeric_limits<std::size_t>::max() - dropped
                          ? std::numeric_limits<std::size_t>::max()
                          : tx_dropped_ + dropped;
        if (tx_dropped_ >= next_drop_report_) {
            next_drop_report_ = tx_dropped_ + netpacket::DROP_REPORT_STEP;
            if (config_.observer) config_.observer->on_drop_report(tx_dropped_);
        }
    }

    // The deferred retry at the top of the loop body: one attempt per queued datagram, and the
    // first one that is still backpressured goes back and stops the pass.
    while (!deferred_.empty()) {
        DataIn datagram = std::move(deferred_.front());
        deferred_.pop_front();
        auto back = try_handle_data(std::move(datagram), now);
        if (back) {
            deferred_.push_front(std::move(*back));
            break;
        }
    }

    TickResult result;
    if (tcp_busy || udp_busy || !deferred_.empty()) {
        result.delay = Millis(static_cast<std::int64_t>(netpacket::BACKPRESSURE_RETRY_MS));
    } else {
        auto polled = poll_delay(now);
        if (tcp_conns_.empty() && udp_conns_.empty()) {
            result.delay = polled;
        } else {
            const Millis cap{static_cast<std::int64_t>(netpacket::MAX_IDLE_TICK_MS)};
            result.delay = polled && *polled < cap ? *polled : cap;
        }
    }

    // The biased select's arms, run synchronously: inbound first (bounded ingest), then the
    // data_in queue -- and only while nothing is deferred, exactly like the Rust arm guard.
    ingest_inbound();
    drain_data_in(now);
    return result;
}

void NetStack::ingest_inbound() {
    // inbound_rx.recv() then up to MAX_INGEST_PER_TICK try_recv() calls.
    if (inbound_.empty()) return;
    device_rx_.push_back(std::move(inbound_.front()));
    inbound_.pop_front();
    std::size_t n = 0;
    while (n < netpacket::MAX_INGEST_PER_TICK && !inbound_.empty()) {
        device_rx_.push_back(std::move(inbound_.front()));
        inbound_.pop_front();
        ++n;
    }
}

void NetStack::drain_data_in(TimePoint now) {
    if (!deferred_.empty()) return; // the Rust arm's `if deferred.is_empty()` guard
    auto first = data_in_rx_.recv();
    if (!first) return;
    if (auto back = try_handle_data(std::move(*first), now)) {
        deferred_.push_back(std::move(*back));
        return;
    }
    while (deferred_.empty()) {
        auto next = data_in_rx_.recv();
        if (!next) break;
        if (auto back = try_handle_data(std::move(*next), now)) {
            deferred_.push_back(std::move(*back));
        }
    }
}

std::optional<DataIn> NetStack::try_handle_data(DataIn datagram, TimePoint now) {
    switch (datagram.kind) {
        case DataIn::Kind::Tcp: {
            const auto it = tcp_conns_.find(datagram.id);
            if (it == tcp_conns_.end()) return std::nullopt;
            TcpConnState& st = it->second;
            const std::size_t max = netpacket::max_tcp_pending(config_.tcp_rx_buf);
            const netpacket::PendingAdmit admit =
                netpacket::tcp_pending_admit(st.pending.size(), max, datagram.data.size());
            if (admit.accepted > 0) {
                // The sniffing hook sees the head of what the app writes.
                feed_sniff(st.id, std::span<const std::uint8_t>(datagram.data).first(admit.accepted),
                           now);
                const auto first = datagram.data.begin();
                st.pending.insert(st.pending.end(), first,
                                  first + static_cast<std::ptrdiff_t>(admit.accepted));
            }
            if (admit.defers()) {
                const auto rest = datagram.data.begin() + static_cast<std::ptrdiff_t>(admit.accepted);
                return DataIn::tcp(datagram.id, std::vector<std::uint8_t>(rest, datagram.data.end()));
            }
            return std::nullopt;
        }
        case DataIn::Kind::TcpClose: {
            const auto it = tcp_conns_.find(datagram.id);
            if (it != tcp_conns_.end()) it->second.half_closed = true;
            return std::nullopt;
        }
        case DataIn::Kind::Udp: {
            const auto it = udp_conns_.find(datagram.id);
            if (it == udp_conns_.end()) return std::nullopt;
            // DNS interception (C++-side seam): a datagram to port 53 is offered to the
            // interceptor first; an answer it returns comes straight back to the app, nothing
            // reaches the wire. nullopt forwards the query normally.
            if (config_.dns && datagram.dst.port == socks::DNS_PORT) {
                auto response = config_.dns->intercept(datagram.dst, datagram.data);
                if (response) {
                    (void)it->second.to_app.try_send(UdpInbound{datagram.dst, std::move(*response)});
                    return std::nullopt;
                }
            }
            if (config_.routes) {
                const auto action =
                    socks::decide_route(*config_.routes, socks::Target::from_ip(datagram.dst.ip),
                                        std::nullopt, datagram.dst.port);
                if (config_.observer) config_.observer->on_route_decided(datagram.dst, action);
                if (action == routing::Action::Block) return std::nullopt; // dropped
            }
            const auto sock = udp_sockets_.find(datagram.id);
            if (sock != udp_sockets_.end()) {
                // Rust: `let _ = sock.send_slice(&data, to_ip_endpoint(dst));`
                (void)sock->second->send_slice(datagram.data, datagram.dst);
            }
            return std::nullopt;
        }
        case DataIn::Kind::UdpClose: {
            const auto it = udp_conns_.find(datagram.id);
            if (it != udp_conns_.end()) {
                udp_conns_.erase(it);
                udp_sockets_.erase(datagram.id);
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

void NetStack::feed_sniff(std::size_t conn_id, std::span<const std::uint8_t> bytes,
                          TimePoint now) {
    if (!config_.sniff) return;
    const auto it = tcp_conns_.find(conn_id);
    if (it == tcp_conns_.end()) return;
    TcpConnState& st = it->second;
    if (st.sniff_done) return;

    if (st.head.size() < PEEK_BUDGET) {
        const std::size_t room = PEEK_BUDGET - st.head.size();
        const std::size_t take = std::min(room, bytes.size());
        const auto first = bytes.begin();
        st.head.insert(st.head.end(), first, first + static_cast<std::ptrdiff_t>(take));
    }

    if (const auto name = sniff_hostname(st.head)) {
        st.sniffed = *name;
        st.sniff_done = true;
        if (config_.observer) config_.observer->on_sniffed(conn_id, *name);
        if (config_.routes) {
            // The route is re-decided on the revealed name, socks.rs's decide_route; a Block
            // tears the connection down the way the orphan path does.
            const auto action =
                socks::decide_route(*config_.routes, socks::Target::from_ip(st.remote.ip),
                                    std::string_view{*st.sniffed}, st.remote.port);
            if (config_.observer) config_.observer->on_route_decided(st.remote, action);
            if (action == routing::Action::Block) {
                const auto sock = tcp_sockets_.find(conn_id);
                if (sock != tcp_sockets_.end()) sock->second->abort(now, emit_fn());
                st.aborted = true;
            }
        }
    } else if (st.head.size() >= PEEK_BUDGET) {
        st.sniff_done = true; // the peek budget is spent; stop looking
    }
}

// ---------------------------------------------------------------------------
// service_tcp: the connection-table lifecycle, one pass.

bool NetStack::service_tcp(TimePoint now) {
    const PacketEmit emit = emit_fn();
    bool backpressured = false;

    std::vector<std::size_t> ids;
    ids.reserve(tcp_conns_.size());
    for (const auto& entry : tcp_conns_) ids.push_back(entry.first);

    for (const std::size_t id : ids) {
        const auto it = tcp_conns_.find(id);
        if (it == tcp_conns_.end()) continue;
        TcpConnState& st = it->second;

        if (st.aborted) {
            tcp_sockets_.erase(id);
            tcp_conns_.erase(it);
            continue;
        }
        const auto sock_it = tcp_sockets_.find(id);
        if (sock_it == tcp_sockets_.end()) {
            tcp_conns_.erase(it); // the table never outlives its socket; defensive
            continue;
        }
        TcpSocket& sock = *sock_it->second;

        netpacket::TcpInput in;
        in.state = sock.state();
        in.established = st.established;
        in.half_closed = st.half_closed;
        in.pending_empty = st.pending.empty();
        in.can_send = sock.can_send();
        in.can_recv = sock.can_recv();
        in.app_gone = !st.to_app.receiver_alive();
        in.connect_cancelled =
            st.slot_answered || !st.connect_slot || !st.connect_slot->rx_alive;
        in.connect_deadline = now >= st.connect_deadline;
        in.pending_len = st.pending.size();
        in.max_pending = netpacket::max_tcp_pending(config_.tcp_rx_buf);
        // Rust stamps orphaned_at inside the app_gone block before comparing it with the
        // linger; an app_gone connection delivers nothing in the recv loop, so stamping it
        // here -- before the decision -- is the same instant.
        if (in.app_gone && st.established) {
            if (!st.orphaned_at) st.orphaned_at = now;
            in.linger_elapsed = (now - *st.orphaned_at) >= limits_.orphan_linger;
        }
        const netpacket::TcpActions act = netpacket::decide_tcp(in);

        if (act.report_established) {
            st.established = true;
            if (!st.slot_answered && st.from_stack_rx) {
                // The oneshot answer: Ok(TcpConn{ id, from_stack, data_in }).
                TcpConn conn(id, data_in_tx_, std::move(*st.from_stack_rx));
                st.from_stack_rx.reset();
                st.connect_slot->value = std::expected<TcpConn, std::string>(std::move(conn));
                st.connect_slot->filled = true;
                st.slot_answered = true;
            }
        }

        if (act.report_refused) {
            if (!st.slot_answered) {
                st.connect_slot->value = std::unexpected(std::string("connection refused"));
                st.connect_slot->filled = true;
                st.slot_answered = true;
            }
            tcp_sockets_.erase(id);
            tcp_conns_.erase(it);
            continue;
        }

        if (!st.established) {
            if (act.report_timeout) {
                if (!st.slot_answered) {
                    st.connect_slot->value = std::unexpected(std::string("connection timed out"));
                    st.connect_slot->filled = true;
                    st.slot_answered = true;
                }
                tcp_sockets_.erase(id);
                tcp_conns_.erase(it);
            }
            continue; // the rest of the pass is the established path
        }

        if (act.send_pending) {
            // socket.send_slice(&st.pending).unwrap_or(0)
            const std::size_t sent = sock.send_slice(st.pending);
            if (sent > 0) {
                st.pending.erase(st.pending.begin(),
                                 st.pending.begin() + static_cast<std::ptrdiff_t>(sent));
                // Rust: if pending.len() * 4 < capacity, shrink_to(max_tcp_pending.min(cap)).
                // Only the allocation differs; shrink_to_fit is the C++ counterpart.
                if (st.pending.size() * 4 < st.pending.capacity()) st.pending.shrink_to_fit();
            }
        }

        if (act.close_for_half) sock.close(now, emit);

        // The recv loop: at most MAX_RECV_CHUNKS permits per pass, backpressure when the app
        // queue is full, orphan discovery when it is closed.
        std::size_t delivered = 0;
        bool app_gone = false;
        while (delivered < netpacket::MAX_RECV_CHUNKS) {
            Permit<std::vector<std::uint8_t>> permit;
            const SendOutcome reserved = st.to_app.try_reserve(permit);
            if (reserved == SendOutcome::Full) {
                backpressured = true;
                break;
            }
            if (reserved == SendOutcome::Closed) {
                app_gone = true;
                break;
            }
            if (!sock.can_recv()) break; // the unused permit drops, releasing its reservation
            std::vector<std::uint8_t> chunk = sock.recv();
            if (chunk.empty()) break;
            permit.commit(std::move(chunk));
            ++delivered;
        }

        if (app_gone) {
            if (act.abort) {
                if (sock.state() != netpacket::TcpState::Closed) sock.abort(now, emit);
                st.aborted = true;
                continue;
            }
            sock.close(now, emit);
        }

        // Rust re-reads the state after the orphan handling; the last three decisions use it.
        const netpacket::TcpState st_state = sock.state();
        if (act.close_closewait && st_state == netpacket::TcpState::CloseWait) sock.close(now, emit);
        if (act.clear_pending && st_state == netpacket::TcpState::TimeWait) {
            st.pending.clear();
            st.pending.shrink_to_fit();
        }
        if (netpacket::tcp_terminal(st_state) && st.established) {
            tcp_sockets_.erase(id);
            tcp_conns_.erase(it);
        }
    }

    return backpressured;
}

bool NetStack::service_udp() {
    bool backpressured = false;

    std::vector<std::size_t> ids;
    ids.reserve(udp_conns_.size());
    for (const auto& entry : udp_conns_) ids.push_back(entry.first);

    for (const std::size_t id : ids) {
        const auto it = udp_conns_.find(id);
        if (it == udp_conns_.end()) continue;
        UdpState& st = it->second;

        std::size_t delivered = 0;
        bool app_gone = false;
        while (delivered < netpacket::MAX_RECV_CHUNKS) {
            Permit<UdpInbound> permit;
            const SendOutcome reserved = st.to_app.try_reserve(permit);
            if (reserved == SendOutcome::Full) {
                backpressured = true;
                break;
            }
            if (reserved == SendOutcome::Closed) {
                app_gone = true;
                break;
            }
            const auto sock_it = udp_sockets_.find(id);
            if (sock_it == udp_sockets_.end()) break;
            if (!sock_it->second->can_recv()) break;
            auto item = sock_it->second->recv();
            if (!item) break;
            permit.commit(std::move(*item));
            ++delivered;
        }

        if (app_gone && netpacket::decide_udp(netpacket::UdpInput{true, backpressured}).remove) {
            udp_conns_.erase(it);
            udp_sockets_.erase(id);
        }
    }

    return backpressured;
}

// ---------------------------------------------------------------------------
// flush_tx and the interface poll.

std::size_t NetStack::flush_tx() {
    std::size_t dropped = 0;
    while (!device_tx_.empty()) {
        std::vector<std::uint8_t> packet = std::move(device_tx_.front());
        device_tx_.pop_front();
        const SendOutcome outcome =
            config_.outbound ? config_.outbound->try_send(packet) : SendOutcome::Closed;
        if (outcome == SendOutcome::Full) {
            ++dropped; // popped and lost, counted -- the Rust try_send(Full) arm
            continue;
        }
        if (outcome == SendOutcome::Closed) break; // the popped packet is lost, the rest stays
    }
    return dropped;
}

void NetStack::poll(TimePoint now) {
    const PacketEmit emit = emit_fn();

    // The device's Rx half: every queued packet through the IP dispatch.
    while (!device_rx_.empty()) {
        std::vector<std::uint8_t> packet = std::move(device_rx_.front());
        device_rx_.pop_front();
        process_packet(packet, now);
    }

    // The sockets' timers and their Tx half.
    for (auto& entry : tcp_sockets_) entry.second->poll(now, emit);

    const std::optional<IpAddress> local_v4 =
        addrs_.v4 ? std::optional<IpAddress>(addrs_.v4->ip) : std::nullopt;
    const std::optional<IpAddress> local_v6 =
        addrs_.v6 ? std::optional<IpAddress>(addrs_.v6->ip) : std::nullopt;
    for (auto& entry : udp_sockets_) entry.second->poll(local_v4, local_v6, emit);
}

void NetStack::process_packet(const std::vector<std::uint8_t>& packet, TimePoint now) {
    const PacketEmit emit = emit_fn();
    if (packet.empty()) return;
    const std::uint8_t version = packet[0] >> 4;

    if (version == 4) {
        const auto parsed = netpacket::parse_ipv4(packet);
        if (!parsed) return;
        if (config_.validate_checksums && !ipv4_header_checksum_ok(packet, parsed->header_len)) {
            return;
        }
        if (!is_local_addr(parsed->header.dst)) return;
        const IpAddress src = parsed->header.src;
        const IpAddress dst = parsed->header.dst;

        if (parsed->header.protocol == netpacket::IPPROTO_TCP) {
            const auto seg = netpacket::parse_tcp(parsed->payload);
            if (!seg) return;
            if (config_.validate_checksums) {
                const std::vector<std::uint8_t> pseudo = netpacket::ipv4_pseudo(
                    src, dst, netpacket::IPPROTO_TCP, seg->header_len + seg->payload.size());
                if (!l4_checksum_ok(pseudo, parsed->payload, 16)) return;
            }
            dispatch_tcp(*seg, src, dst, now, emit);
        } else if (parsed->header.protocol == netpacket::IPPROTO_UDP) {
            const auto dg = netpacket::parse_udp(parsed->payload);
            if (!dg) return;
            // An IPv4 UDP checksum of 0 means "not computed" and is legal; anything else must
            // match when verification is on.
            const std::uint16_t stored = get16(parsed->payload.data() + 6);
            if (config_.validate_checksums && stored != 0) {
                const std::vector<std::uint8_t> pseudo =
                    netpacket::ipv4_pseudo(src, dst, netpacket::IPPROTO_UDP, dg->length);
                if (!l4_checksum_ok(pseudo, parsed->payload, 6)) return;
            }
            UdpSocket* udp_sock = find_udp_socket(dg->datagram.dst_port);
            if (udp_sock) {
                udp_sock->deliver(SocketAddr{src, dg->datagram.src_port}, dg->payload);
            }
        }
        // Any other protocol (ICMP included) is dropped: smoltcp without a raw or icmp socket
        // registered has nothing to hand it to.
        return;
    }

    if (version != 6) return;
    const auto parsed = netpacket::parse_ipv6(packet);
    if (!parsed) return;
    if (!is_local_addr(parsed->header.dst)) return;
    const IpAddress src = parsed->header.src;
    const IpAddress dst = parsed->header.dst;

    if (parsed->header.next_header == netpacket::IPPROTO_TCP) {
        const auto seg = netpacket::parse_tcp(parsed->payload);
        if (!seg) return;
        if (config_.validate_checksums) {
            const std::vector<std::uint8_t> pseudo = netpacket::ipv6_pseudo(
                src, dst, netpacket::IPPROTO_TCP, seg->header_len + seg->payload.size());
            if (!l4_checksum_ok(pseudo, parsed->payload, 16)) return;
        }
        dispatch_tcp(*seg, src, dst, now, emit);
    } else if (parsed->header.next_header == netpacket::IPPROTO_UDP) {
        const auto dg = netpacket::parse_udp(parsed->payload);
        if (!dg) return;
        // Over IPv6 the UDP checksum is mandatory (RFC 8200): 0 is invalid.
        if (config_.validate_checksums) {
            const std::vector<std::uint8_t> pseudo =
                netpacket::ipv6_pseudo(src, dst, netpacket::IPPROTO_UDP, dg->length);
            if (!l4_checksum_ok(pseudo, parsed->payload, 6)) return;
        }
        UdpSocket* udp_sock = find_udp_socket(dg->datagram.dst_port);
        if (udp_sock) {
            udp_sock->deliver(SocketAddr{src, dg->datagram.src_port}, dg->payload);
        }
    }
}

UdpSocket* NetStack::find_udp_socket(std::uint16_t port) {
    for (auto& entry : udp_sockets_) {
        if (entry.second->port() == port) return entry.second.get();
    }
    return nullptr;
}

void NetStack::dispatch_tcp(const netpacket::TcpParsed& seg, const IpAddress& src,
                            const IpAddress& dst, TimePoint now, const PacketEmit& emit) {
    for (auto& entry : tcp_sockets_) {
        TcpSocket& sock = *entry.second;
        if (sock.matches(dst, src, seg.segment.dst_port, seg.segment.src_port)) {
            sock.on_packet(seg, now, emit);
            return;
        }
    }
    // Nothing owns this 4-tuple: smoltcp answers a non-RST segment with a reset.
    if ((seg.segment.flags & netpacket::TCP_RST) == 0) {
        const std::uint32_t rst_seq =
            (seg.segment.flags & netpacket::TCP_ACK) != 0 ? seg.segment.ack : 0;
        emit(build_tcp_packet(dst, seg.segment.dst_port, src, seg.segment.src_port,
                              netpacket::TCP_RST, rst_seq, 0, 0, {}, {}));
    }
}

std::optional<Millis> NetStack::poll_delay(TimePoint now) const {
    std::optional<TimePoint> best;
    for (const auto& entry : tcp_sockets_) {
        const auto deadline = entry.second->next_deadline();
        if (deadline && (!best || *deadline < *best)) best = *deadline;
    }
    if (!best) return std::nullopt;
    auto delay = std::chrono::duration_cast<Millis>(*best - now);
    if (delay < Millis::zero()) delay = Millis::zero();
    return delay;
}

// ---------------------------------------------------------------------------
// Introspection.

std::size_t NetStack::tcp_conn_count() const { return tcp_conns_.size(); }
std::size_t NetStack::udp_conn_count() const { return udp_conns_.size(); }
std::size_t NetStack::tx_dropped() const { return tx_dropped_; }
std::size_t NetStack::deferred_count() const { return deferred_.size(); }
std::size_t NetStack::device_tx_queued() const { return device_tx_.size(); }
std::size_t NetStack::inbound_queued() const { return inbound_.size(); }
const TcpLimits& NetStack::limits() const { return limits_; }

std::size_t NetStack::pending_len(std::size_t conn_id) const {
    const auto it = tcp_conns_.find(conn_id);
    return it == tcp_conns_.end() ? 0 : it->second.pending.size();
}

std::uint32_t NetStack::next_iss() {
    // smoltcp draws the ISS at random; the default here stays deterministic so packet-level
    // tests reproduce. Config::make_iss overrides.
    iss_counter_ += 1'000'000u;
    return iss_counter_;
}

std::optional<IpAddress> NetStack::local_addr_for(bool v4) const {
    if (v4) {
        return addrs_.v4 ? std::optional<IpAddress>(addrs_.v4->ip) : std::nullopt;
    }
    return addrs_.v6 ? std::optional<IpAddress>(addrs_.v6->ip) : std::nullopt;
}

bool NetStack::is_local_addr(const IpAddress& address) const {
    if (address.v4) return addrs_.v4 && addrs_.v4->ip == address;
    return addrs_.v6 && addrs_.v6->ip == address;
}

} // namespace hemera::core::netstack
