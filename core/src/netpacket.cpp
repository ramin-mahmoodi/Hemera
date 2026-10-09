// Port of netstack.rs's packet / address / accounting surface, plus the codecs netstack.rs drives
// through smoltcp (IPv4/IPv6/TCP/UDP/ICMPv6 wire forms, RFC 1071, MTU and fragmentation decisions).
// See netpacket.hpp for the boundary: nothing here touches a device, a task or smoltcp's state
// machine. Where smoltcp -- not netstack.rs -- owns the exact rule, the code says so.

#include "netpacket.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <string>
#include <system_error>

namespace hemera::core::netpacket {
namespace {

// --- little wire helpers, all explicit big-endian -------------------------------------------

void put16(std::uint8_t* at, std::uint16_t value) {
    at[0] = static_cast<std::uint8_t>(value >> 8);
    at[1] = static_cast<std::uint8_t>(value & 0xff);
}

void put32(std::uint8_t* at, std::uint32_t value) {
    at[0] = static_cast<std::uint8_t>(value >> 24);
    at[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    at[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    at[3] = static_cast<std::uint8_t>(value & 0xff);
}

std::uint16_t get16(const std::uint8_t* at) {
    return static_cast<std::uint16_t>((at[0] << 8) | at[1]);
}

std::uint32_t get32(const std::uint8_t* at) {
    return (static_cast<std::uint32_t>(at[0]) << 24) | (static_cast<std::uint32_t>(at[1]) << 16) |
           (static_cast<std::uint32_t>(at[2]) << 8) | static_cast<std::uint32_t>(at[3]);
}

// The four octets of an IPv4 IpAddress, which dns.hpp keeps in bytes[12..16].
const std::uint8_t* v4_octets(const IpAddress& address) {
    return address.bytes.data() + 12;
}

void put_v4(std::uint8_t* at, const IpAddress& address) {
    std::memcpy(at, v4_octets(address), 4);
}

void put_v6(std::uint8_t* at, const IpAddress& address) {
    std::memcpy(at, address.bytes.data(), 16);
}

IpAddress from_v4_bytes(const std::uint8_t* at) {
    IpAddress address;
    address.v4 = true;
    std::memcpy(address.bytes.data() + 12, at, 4);
    return address;
}

IpAddress from_v6_bytes(const std::uint8_t* at) {
    IpAddress address;
    address.v4 = false;
    std::memcpy(address.bytes.data(), at, 16);
    return address;
}

// The strip_cidr helper netstack.rs uses: the address half, with the /prefix dropped.
std::string_view strip_cidr(std::string_view text) {
    const auto slash = text.find('/');
    return slash == std::string_view::npos ? text : text.substr(0, slash);
}

// cidr_prefix: the /bits parsed as u8, or nothing when there is no slash or it does not parse as a
// plain u8 (Rust's p.parse::<u8>().ok() -- no trimming, no clamping, digits only, an optional '+').
std::optional<std::uint8_t> cidr_prefix(std::string_view text) {
    const auto slash = text.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    const std::string_view bits = text.substr(slash + 1);
    if (bits.empty()) return std::nullopt;

    std::string_view digits = bits;
    if (digits.front() == '+') digits.remove_prefix(1); // Rust's u8::from_str accepts a leading '+'
    if (digits.empty()) return std::nullopt;

    std::uint32_t value = 0;
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return std::nullopt;
    if (value > 255) return std::nullopt;
    return static_cast<std::uint8_t>(value);
}

} // namespace

// ---------------------------------------------------------------------------
// Checksum.

std::uint16_t inet_checksum(std::span<const std::uint8_t> data, std::uint32_t initial) {
    // Verbatim port of netstack.rs's checksum16 and masque.rs's ipv4_header_checksum: 16-bit words
    // big-endian, an odd trailing byte shifted left 8, carry-fold, complement. Accumulated in
    // uint32_t exactly as Rust does; a packet-sized input cannot overflow it (see the note below).
    //
    // Overflow bound: at most 65535 bytes -> 32768 words, each <= 0xFFFF, so the sum before folding
    // is < 2^31, well inside uint32_t. The fold step (sum & 0xffff) + (sum >> 16) can only shrink it.
    std::uint32_t sum = initial;
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += static_cast<std::uint32_t>(get16(data.data() + i));
    }
    if (i < data.size()) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t inet_checksum_l4(std::span<const std::uint8_t> data) {
    const std::uint16_t raw = inet_checksum(data);
    // smoltcp's L4 checksum() turns a computed 0 into 0xFFFF, because 0 means "not computed" and is
    // illegal for TCP, ICMPv6 and UDP-over-IPv6. netstack.rs's test helper keeps the raw value, but
    // its packets never landed on 0, so the two only differ where RFC says 0 must not be sent.
    return raw == 0 ? std::uint16_t{0xffff} : raw;
}

std::vector<std::uint8_t> ipv4_pseudo(const IpAddress& src, const IpAddress& dst,
                                      std::uint8_t protocol, std::size_t l4_len) {
    std::vector<std::uint8_t> out;
    out.reserve(12);
    const std::uint8_t* s = v4_octets(src);
    const std::uint8_t* d = v4_octets(dst);
    out.insert(out.end(), s, s + 4);
    out.insert(out.end(), d, d + 4);
    out.push_back(0);
    out.push_back(protocol);
    // The Rust casts the segment length to u16; anything wider is a caller bug, clamped to the
    // field it can actually carry so no silent truncation happens above here.
    const auto len = static_cast<std::uint16_t>(l4_len > 0xffff ? 0xffff : l4_len);
    out.push_back(static_cast<std::uint8_t>(len >> 8));
    out.push_back(static_cast<std::uint8_t>(len & 0xff));
    return out;
}

std::vector<std::uint8_t> ipv6_pseudo(const IpAddress& src, const IpAddress& dst,
                                      std::uint8_t next_header, std::size_t l4_len) {
    std::vector<std::uint8_t> out;
    out.reserve(40);
    out.insert(out.end(), src.bytes.begin(), src.bytes.end());
    out.insert(out.end(), dst.bytes.begin(), dst.bytes.end());
    // Upper-layer length, four bytes big-endian (RFC 2460 keeps this u32, unlike IPv4's u16).
    std::array<std::uint8_t, 4> len{};
    put32(len.data(), static_cast<std::uint32_t>(l4_len));
    out.insert(out.end(), len.begin(), len.end());
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    out.push_back(next_header);
    return out;
}

// ---------------------------------------------------------------------------
// IPv4.

std::expected<std::uint8_t, std::string> ipv4_ihl(std::size_t options_len) {
    if (options_len % 4 != 0) return std::unexpected("ipv4: options are not a multiple of 4 bytes");
    const std::size_t header = IPV4_MIN_HEADER + options_len;
    if (header > IPV4_MAX_HEADER) return std::unexpected("ipv4: header would exceed 60 bytes");
    return static_cast<std::uint8_t>(header / 4);
}

std::expected<std::size_t, std::string> build_ipv4_header(const Ipv4Header& header,
                                                          std::size_t payload_len,
                                                          std::span<std::uint8_t> out) {
    const auto ihl = ipv4_ihl(header.options.size());
    if (!ihl) return std::unexpected(ihl.error());
    const std::size_t header_len = IPV4_MIN_HEADER + header.options.size();

    const std::size_t total = header_len + payload_len;
    if (total > 0xffff) return std::unexpected("ipv4: total length would overflow 16 bits");
    if (out.size() < header_len) {
        return std::unexpected("ipv4: buffer is smaller than the header it must hold");
    }

    std::uint8_t* at = out.data();
    at[0] = static_cast<std::uint8_t>((4u << 4) | (*ihl & 0x0f));
    at[1] = header.tos;
    put16(at + 2, static_cast<std::uint16_t>(total));
    put16(at + 4, header.identification);
    // flags byte: DF (0x40) / MF (0x20) sit in bits 6 and 5; the reserved bit is dropped.
    at[6] = static_cast<std::uint8_t>((header.flags & 0x60) | ((header.fragment_offset >> 8) & 0x1f));
    at[7] = static_cast<std::uint8_t>(header.fragment_offset & 0xff);
    at[8] = header.ttl;
    at[9] = header.protocol;
    at[10] = 0;
    at[11] = 0;
    put_v4(at + 12, header.src);
    put_v4(at + 16, header.dst);
    if (!header.options.empty()) {
        std::memcpy(at + 20, header.options.data(), header.options.size());
    }

    const std::uint16_t csum = inet_checksum(std::span<const std::uint8_t>(at, header_len));
    put16(at + 10, csum);
    return header_len;
}

std::expected<Ipv4Packet, std::string> parse_ipv4(std::span<const std::uint8_t> buf) {
    if (buf.size() < IPV4_MIN_HEADER) {
        return std::unexpected("ipv4: buffer is shorter than the minimum header");
    }
    if ((buf[0] >> 4) != 4) {
        return std::unexpected("ipv4: version nibble is not 4");
    }
    const std::uint8_t ihl = buf[0] & 0x0f;
    if (ihl < IPV4_MIN_IHL) {
        return std::unexpected("ipv4: header length is less than 20 bytes");
    }
    const std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
    if (header_len > buf.size()) {
        return std::unexpected("ipv4: header claims more bytes than the buffer holds");
    }

    const std::uint16_t total = get16(buf.data() + 2);
    if (total < header_len) {
        return std::unexpected("ipv4: total length is smaller than the header");
    }
    if (total > buf.size()) {
        return std::unexpected("ipv4: total length claims more bytes than the buffer holds");
    }

    Ipv4Packet packet;
    packet.header_len = header_len;
    packet.total_length = total;
    packet.payload = buf.subspan(header_len, total - header_len);

    packet.header.ttl = buf[8];
    packet.header.protocol = buf[9];
    packet.header.tos = buf[1];
    packet.header.identification = get16(buf.data() + 4);
    packet.header.flags = buf[6] & 0x60;
    packet.header.fragment_offset = static_cast<std::uint16_t>(((buf[6] & 0x1f) << 8) | buf[7]);
    packet.header.src = from_v4_bytes(buf.data() + 12);
    packet.header.dst = from_v4_bytes(buf.data() + 16);
    packet.header.options.assign(buf.begin() + 20, buf.begin() + static_cast<std::ptrdiff_t>(header_len));

    // The classic reassembly trap: a fragment offset and payload that, summed in bytes, overflow
    // the 16-bit datagram the stack will try to rebuild. offset is in 8-byte units.
    const std::uint64_t start = static_cast<std::uint64_t>(packet.header.fragment_offset) * 8;
    const std::uint64_t end = start + packet.payload.size();
    if (end > 0xffff) {
        return std::unexpected("ipv4: fragment offset overflows the reassembly window");
    }
    return packet;
}

// ---------------------------------------------------------------------------
// IPv6.

std::expected<std::size_t, std::string> build_ipv6_header(const Ipv6Header& header,
                                                          std::size_t payload_len,
                                                          std::span<std::uint8_t> out) {
    if (payload_len > 0xffff) {
        return std::unexpected("ipv6: payload length would overflow 16 bits");
    }
    if (out.size() < IPV6_HEADER) {
        return std::unexpected("ipv6: buffer is shorter than the 40-byte header");
    }
    std::uint8_t* at = out.data();
    const std::uint32_t flow = header.flow_label & 0xfffff;
    at[0] = static_cast<std::uint8_t>((6u << 4) | (header.traffic_class >> 4));
    at[1] = static_cast<std::uint8_t>(((header.traffic_class & 0x0f) << 4) | ((flow >> 16) & 0x0f));
    at[2] = static_cast<std::uint8_t>((flow >> 8) & 0xff);
    at[3] = static_cast<std::uint8_t>(flow & 0xff);
    put16(at + 4, static_cast<std::uint16_t>(payload_len));
    at[6] = header.next_header;
    at[7] = header.hop_limit;
    put_v6(at + 8, header.src);
    put_v6(at + 24, header.dst);
    return IPV6_HEADER;
}

std::expected<Ipv6Packet, std::string> parse_ipv6(std::span<const std::uint8_t> buf) {
    if (buf.size() < IPV6_HEADER) {
        return std::unexpected("ipv6: buffer is shorter than 40 bytes");
    }
    if ((buf[0] >> 4) != 6) {
        return std::unexpected("ipv6: version nibble is not 6");
    }
    Ipv6Packet packet;
    packet.header.traffic_class = static_cast<std::uint8_t>(((buf[0] & 0x0f) << 4) | (buf[1] >> 4));
    packet.header.flow_label =
        (static_cast<std::uint32_t>(buf[1] & 0x0f) << 16) | (static_cast<std::uint32_t>(buf[2]) << 8) |
        buf[3];
    packet.payload_length = get16(buf.data() + 4);
    packet.header.next_header = buf[6];
    packet.header.hop_limit = buf[7];
    packet.header.src = from_v6_bytes(buf.data() + 8);
    packet.header.dst = from_v6_bytes(buf.data() + 24);

    const std::size_t need = IPV6_HEADER + static_cast<std::size_t>(packet.payload_length);
    if (need > buf.size()) {
        return std::unexpected("ipv6: payload length claims more bytes than the buffer holds");
    }
    packet.payload = buf.subspan(IPV6_HEADER, packet.payload_length);
    return packet;
}

// ---------------------------------------------------------------------------
// TCP.

std::expected<std::size_t, std::string> build_tcp_header(const TcpSegment& seg,
                                                         std::span<std::uint8_t> out) {
    if (seg.options.size() % 4 != 0) {
        return std::unexpected("tcp: options are not a multiple of 4 bytes");
    }
    const std::size_t header_len = TCP_MIN_HEADER + seg.options.size();
    if (header_len > IPV4_MAX_HEADER) { // 60, the same data-offset ceiling
        return std::unexpected("tcp: header would exceed 60 bytes");
    }
    if (out.size() < header_len) {
        return std::unexpected("tcp: buffer is smaller than the header it must hold");
    }
    std::uint8_t* at = out.data();
    put16(at + 0, seg.src_port);
    put16(at + 2, seg.dst_port);
    put32(at + 4, seg.seq);
    put32(at + 8, seg.ack);
    at[12] = static_cast<std::uint8_t>((header_len / 4) << 4); // data offset, reserved nibble 0
    at[13] = seg.flags;
    put16(at + 14, seg.window);
    at[16] = 0;
    at[17] = 0; // checksum, filled by tcp_checksum
    put16(at + 18, seg.urgent_pointer);
    if (!seg.options.empty()) {
        std::memcpy(at + 20, seg.options.data(), seg.options.size());
    }
    return header_len;
}

std::uint16_t tcp_checksum(std::span<const std::uint8_t> pseudo, std::span<std::uint8_t> header,
                          std::span<const std::uint8_t> payload) {
    // header's checksum field must already be zero. Sum pseudo + header + payload in one pass, the
    // way netstack.rs's build_tcp builds its `pseudo` vector and hands the whole thing to checksum16.
    std::vector<std::uint8_t> buf;
    buf.reserve(pseudo.size() + header.size() + payload.size());
    buf.insert(buf.end(), pseudo.begin(), pseudo.end());
    buf.insert(buf.end(), header.begin(), header.end());
    buf.insert(buf.end(), payload.begin(), payload.end());
    const std::uint16_t value = inet_checksum_l4(buf);
    put16(header.data() + 16, value);
    return value;
}

std::expected<TcpParsed, std::string> parse_tcp(std::span<const std::uint8_t> buf) {
    if (buf.size() < TCP_MIN_HEADER) {
        return std::unexpected("tcp: buffer is shorter than the 20-byte header");
    }
    const std::uint8_t offset_words = buf[12] >> 4;
    if (offset_words < 5) {
        return std::unexpected("tcp: data offset is less than 20 bytes");
    }
    const std::size_t header_len = static_cast<std::size_t>(offset_words) * 4;
    if (header_len > buf.size()) {
        return std::unexpected("tcp: header claims more bytes than the buffer holds");
    }

    TcpParsed parsed;
    parsed.header_len = header_len;
    parsed.segment.src_port = get16(buf.data() + 0);
    parsed.segment.dst_port = get16(buf.data() + 2);
    parsed.segment.seq = get32(buf.data() + 4);
    parsed.segment.ack = get32(buf.data() + 8);
    parsed.segment.flags = buf[13];
    parsed.segment.window = get16(buf.data() + 14);
    parsed.segment.urgent_pointer = get16(buf.data() + 18);
    parsed.segment.options.assign(buf.begin() + 20,
                                  buf.begin() + static_cast<std::ptrdiff_t>(header_len));
    parsed.payload = buf.subspan(header_len);
    return parsed;
}

// ---------------------------------------------------------------------------
// UDP.

std::expected<std::size_t, std::string> build_udp_header(const UdpDatagram& dg,
                                                         std::size_t payload_len,
                                                         std::span<std::uint8_t> out) {
    const std::size_t length = UDP_HEADER + payload_len;
    if (length > 0xffff) {
        return std::unexpected("udp: datagram length would overflow 16 bits");
    }
    if (out.size() < UDP_HEADER) {
        return std::unexpected("udp: buffer is shorter than the 8-byte header");
    }
    std::uint8_t* at = out.data();
    put16(at + 0, dg.src_port);
    put16(at + 2, dg.dst_port);
    put16(at + 4, static_cast<std::uint16_t>(length));
    at[6] = 0;
    at[7] = 0; // checksum, filled by udp_checksum
    return UDP_HEADER;
}

std::uint16_t udp_checksum(std::span<const std::uint8_t> pseudo, std::span<std::uint8_t> header,
                           std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> buf;
    buf.reserve(pseudo.size() + header.size() + payload.size());
    buf.insert(buf.end(), pseudo.begin(), pseudo.end());
    buf.insert(buf.end(), header.begin(), header.end());
    buf.insert(buf.end(), payload.begin(), payload.end());
    const std::uint16_t value = inet_checksum_l4(buf);
    put16(header.data() + 6, value);
    return value;
}

std::expected<UdpParsed, std::string> parse_udp(std::span<const std::uint8_t> buf) {
    if (buf.size() < UDP_HEADER) {
        return std::unexpected("udp: buffer is shorter than the 8-byte header");
    }
    const std::uint16_t length = get16(buf.data() + 4);
    if (length < UDP_HEADER) {
        return std::unexpected("udp: declared length is smaller than the header");
    }
    if (length > buf.size()) {
        return std::unexpected("udp: length claims more bytes than the buffer holds");
    }
    UdpParsed parsed;
    parsed.length = length;
    parsed.datagram.src_port = get16(buf.data() + 0);
    parsed.datagram.dst_port = get16(buf.data() + 2);
    parsed.payload = buf.subspan(UDP_HEADER, length - UDP_HEADER);
    return parsed;
}

// ---------------------------------------------------------------------------
// ICMPv6 echo.

std::expected<std::vector<std::uint8_t>, std::string> build_icmpv6_echo(const Icmpv6Echo& echo,
                                                                        const IpAddress& src,
                                                                        const IpAddress& dst) {
    if (echo.type != ICMPV6_ECHO_REQUEST && echo.type != ICMPV6_ECHO_REPLY) {
        return std::unexpected("icmpv6: not an echo request or reply");
    }
    if (src.v4 || dst.v4) {
        return std::unexpected("icmpv6: echo needs IPv6 endpoints");
    }
    const std::size_t message_len = ICMPV6_HEADER + echo.payload.size();
    if (message_len > 0xffff) {
        return std::unexpected("icmpv6: message too long for the IPv6 payload length");
    }

    std::vector<std::uint8_t> message(message_len, 0);
    message[0] = echo.type;
    message[1] = echo.code;
    put16(message.data() + 4, echo.identifier);
    put16(message.data() + 6, echo.sequence);
    if (!echo.payload.empty()) {
        std::memcpy(message.data() + ICMPV6_HEADER, echo.payload.data(), echo.payload.size());
    }

    const std::vector<std::uint8_t> pseudo =
        ipv6_pseudo(src, dst, IPPROTO_ICMPV6, message_len);
    std::vector<std::uint8_t> buf;
    buf.reserve(pseudo.size() + message.size());
    buf.insert(buf.end(), pseudo.begin(), pseudo.end());
    buf.insert(buf.end(), message.begin(), message.end());
    const std::uint16_t value = inet_checksum_l4(buf);
    put16(message.data() + 2, value);
    return message;
}

std::expected<Icmpv6Echo, std::string> parse_icmpv6(std::span<const std::uint8_t> buf,
                                                    const IpAddress& src, const IpAddress& dst) {
    if (buf.size() < ICMPV6_HEADER) {
        return std::unexpected("icmpv6: buffer is shorter than the 8-byte header");
    }
    if (src.v4 || dst.v4) {
        return std::unexpected("icmpv6: echo needs IPv6 endpoints");
    }
    const std::uint8_t type = buf[0];
    if (type != ICMPV6_ECHO_REQUEST && type != ICMPV6_ECHO_REPLY) {
        return std::unexpected("icmpv6: not an echo request or reply");
    }
    const std::uint16_t stored = get16(buf.data() + 2);

    // Recompute over pseudo + the message with the checksum field zeroed, and compare.
    std::vector<std::uint8_t> zeroed(buf.begin(), buf.end());
    zeroed[2] = 0;
    zeroed[3] = 0;
    const std::vector<std::uint8_t> pseudo =
        ipv6_pseudo(src, dst, IPPROTO_ICMPV6, buf.size());
    std::vector<std::uint8_t> acc;
    acc.reserve(pseudo.size() + zeroed.size());
    acc.insert(acc.end(), pseudo.begin(), pseudo.end());
    acc.insert(acc.end(), zeroed.begin(), zeroed.end());
    if (inet_checksum_l4(acc) != stored) {
        return std::unexpected("icmpv6: checksum does not match");
    }

    Icmpv6Echo echo;
    echo.type = type;
    echo.code = buf[1];
    echo.identifier = get16(buf.data() + 4);
    echo.sequence = get16(buf.data() + 6);
    echo.payload.assign(buf.begin() + ICMPV6_HEADER, buf.end());
    return echo;
}

// ---------------------------------------------------------------------------
// Whole-packet builders.

std::vector<std::uint8_t> build_ipv4_tcp(const Ipv4Header& ip, const TcpSegment& tcp,
                                         std::span<const std::uint8_t> payload) {
    const std::size_t ip_header_len = IPV4_MIN_HEADER + ip.options.size();
    const std::size_t tcp_header_len = TCP_MIN_HEADER + tcp.options.size();
    const std::size_t segment_len = tcp_header_len + payload.size();
    const std::size_t total = ip_header_len + segment_len;

    std::vector<std::uint8_t> out(total, 0);
    std::span<std::uint8_t> whole{out};

    // TCP first, checksum zeroed, then the pseudo-header that covers it, then the IP header.
    auto tcp_region = whole.subspan(ip_header_len, tcp_header_len);
    (void)build_tcp_header(tcp, tcp_region);
    std::memcpy(out.data() + ip_header_len + tcp_header_len, payload.data(), payload.size());

    const std::vector<std::uint8_t> pseudo =
        ipv4_pseudo(ip.src, ip.dst, IPPROTO_TCP, segment_len);
    (void)tcp_checksum(pseudo, tcp_region, payload);

    Ipv4Header filled = ip;
    filled.protocol = ip.protocol != 0 ? ip.protocol : IPPROTO_TCP;
    (void)build_ipv4_header(filled, segment_len, whole.first(ip_header_len));
    return out;
}

std::vector<std::uint8_t> build_ipv6_udp(const Ipv6Header& ip, const UdpDatagram& udp,
                                         std::span<const std::uint8_t> payload) {
    const std::size_t dgram_len = UDP_HEADER + payload.size();
    const std::size_t total = IPV6_HEADER + dgram_len;

    std::vector<std::uint8_t> out(total, 0);
    std::span<std::uint8_t> whole{out};

    auto udp_region = whole.subspan(IPV6_HEADER, UDP_HEADER);
    (void)build_udp_header(udp, payload.size(), udp_region);
    std::memcpy(out.data() + IPV6_HEADER + UDP_HEADER, payload.data(), payload.size());

    const std::vector<std::uint8_t> pseudo =
        ipv6_pseudo(ip.src, ip.dst, IPPROTO_UDP, dgram_len);
    (void)udp_checksum(pseudo, udp_region, payload);

    Ipv6Header filled = ip;
    filled.next_header = ip.next_header != 0 ? ip.next_header : IPPROTO_UDP;
    (void)build_ipv6_header(filled, dgram_len, whole.first(IPV6_HEADER));
    return out;
}

// ---------------------------------------------------------------------------
// Tunnel addresses.

std::expected<std::optional<TunnelAddr>, std::string> parse_v4(std::string_view text) {
    if (text.empty()) return std::optional<TunnelAddr>{std::nullopt};
    const auto address = parse_address(strip_cidr(text));
    if (!address || !address->v4) {
        return std::unexpected("bad ipv4 " + std::string(text));
    }
    TunnelAddr addr;
    addr.ip = *address;
    addr.prefix = cidr_prefix(text).value_or(32);
    return std::optional<TunnelAddr>{addr};
}

std::expected<std::optional<TunnelAddr>, std::string> parse_v6(std::string_view text) {
    if (text.empty()) return std::optional<TunnelAddr>{std::nullopt};
    const auto address = parse_address(strip_cidr(text));
    if (!address || address->v4) {
        return std::unexpected("bad ipv6 " + std::string(text));
    }
    TunnelAddr addr;
    addr.ip = *address;
    addr.prefix = cidr_prefix(text).value_or(128);
    return std::optional<TunnelAddr>{addr};
}

std::uint8_t routable_prefix_v4(std::uint8_t prefix) {
    return prefix >= 31 ? 24 : prefix;
}

std::uint8_t routable_prefix_v6(std::uint8_t prefix) {
    return prefix >= 127 ? 64 : prefix;
}

IpAddress gateway_v4(const TunnelAddr& local) {
    const std::uint8_t* o = v4_octets(local.ip);
    const std::uint8_t host = o[3] == 1 ? 2 : 1;
    IpAddress gw;
    gw.v4 = true;
    gw.bytes[12] = o[0];
    gw.bytes[13] = o[1];
    gw.bytes[14] = o[2];
    gw.bytes[15] = host;
    return gw;
}

IpAddress gateway_v6(const TunnelAddr& local) {
    IpAddress gw;
    gw.bytes = local.ip.bytes;
    gw.bytes[15] = gw.bytes[15] == 1 ? 2 : 1;
    return gw;
}

AddrPair merge_addrs(const AddrPair& current, const AddrPair& update) {
    AddrPair merged;
    merged.v4 = update.v4.has_value() ? update.v4 : current.v4;
    merged.v6 = update.v6.has_value() ? update.v6 : current.v6;
    return merged;
}

// ---------------------------------------------------------------------------
// MTU and fragmentation.

bool fits_mtu(std::size_t packet_len, std::size_t mtu) {
    return packet_len <= mtu;
}

std::expected<FragmentPlan, std::string> plan_ipv4_fragments(const Ipv4Header& header,
                                                             std::size_t l4_len, std::size_t mtu,
                                                             bool dont_fragment) {
    const auto ihl = ipv4_ihl(header.options.size());
    if (!ihl) return std::unexpected(ihl.error());
    const std::size_t header_len = IPV4_MIN_HEADER + header.options.size();

    const std::size_t whole = header_len + l4_len;
    if (whole > 0xffff) {
        return std::unexpected("ipv4: datagram exceeds the 16-bit total length");
    }
    if (whole <= mtu) {
        FragmentPlan plan;
        plan.needs = false;
        plan.mtu = mtu;
        plan.fragment_data = l4_len;
        plan.fragment_count = 1;
        return plan;
    }
    if (dont_fragment) {
        return std::unexpected("ipv4: DF is set but the packet exceeds the MTU");
    }
    if (mtu < header_len + 8) {
        return std::unexpected("ipv4: MTU is too small to carry a fragment");
    }

    // Every non-final fragment carries a payload that is a multiple of 8 bytes.
    std::size_t chunk = ((mtu - header_len) / 8) * 8;
    if (chunk == 0) return std::unexpected("ipv4: MTU leaves no room for a fragment payload");

    const std::size_t count = (l4_len + chunk - 1) / chunk;
    // The last fragment's offset is (count-1)*chunk; its own payload stays within the window
    // because the whole datagram already fit under 65535 (checked above).
    FragmentPlan plan;
    plan.needs = true;
    plan.mtu = mtu;
    plan.fragment_data = chunk;
    plan.fragment_count = count;
    return plan;
}

// ---------------------------------------------------------------------------
// Socket-table accounting.

std::uint16_t alloc_port(std::uint16_t& next_port) {
    const std::uint16_t port = next_port;
    next_port = port >= PORT_WRAP_AT ? PORT_FIRST : static_cast<std::uint16_t>(port + 1);
    return port;
}

std::size_t max_tcp_pending(std::size_t tcp_rx_buf) {
    // tcp_rx_buf().saturating_mul(2).max(64 * 1024)
    const std::size_t doubled = tcp_rx_buf > (std::numeric_limits<std::size_t>::max() / 2)
                                    ? std::numeric_limits<std::size_t>::max()
                                    : tcp_rx_buf * 2;
    return doubled > MIN_TCP_PENDING ? doubled : MIN_TCP_PENDING;
}

std::size_t udp_meta(sysprofile::Tier tier) {
    switch (tier) {
        case sysprofile::Tier::Low: return 32;
        case sysprofile::Tier::Medium: return 64;
        case sysprofile::Tier::High: return 128;
    }
    return 128;
}

PendingAdmit tcp_pending_admit(std::size_t pending_len, std::size_t max, std::size_t data_len) {
    // try_handle_data's DataIn::Tcp branch, kept pure.
    PendingAdmit admit;
    if (pending_len >= max) {
        admit.accepted = 0;
        admit.deferred = data_len;
        return admit;
    }
    const std::size_t space = max - pending_len;
    if (data_len <= space) {
        admit.accepted = data_len;
        admit.deferred = 0;
    } else {
        admit.accepted = space;
        admit.deferred = data_len - space;
    }
    return admit;
}

bool tcp_connected(TcpState state) {
    return state == TcpState::Established || state == TcpState::CloseWait;
}

bool tcp_terminal(TcpState state) {
    return state == TcpState::Closed || state == TcpState::TimeWait;
}

TcpActions decide_tcp(const TcpInput& in) {
    TcpActions out;
    const bool connected = tcp_connected(in.state);

    // Newly connected: report the established connection once.
    if (!in.established && connected) {
        out.report_established = true;
    }

    // Never established and already Closed/TimeWait: refuse and drop it.
    if (!in.established && tcp_terminal(in.state)) {
        out.report_refused = true;
        out.remove = true;
        return out;
    }

    // Still connecting: give up if the caller vanished or the deadline passed, and skip the rest.
    if (!in.established) {
        if (in.connect_cancelled || in.connect_deadline) {
            out.report_timeout = true;
            out.remove = true;
        }
        return out;
    }

    // Established path.
    out.send_pending = in.can_send && in.pending_len > 0;
    if (in.half_closed && in.pending_empty) {
        out.close_for_half = true;
    }
    if (in.app_gone) {
        // An orphan with data still queued, or one that lingered too long, is reset; otherwise it
        // is closed gently and given more time.
        if (in.can_recv || in.linger_elapsed) {
            out.abort = true;
        } else {
            out.close_orphan = true;
        }
    }
    if (in.state == TcpState::CloseWait) {
        out.close_closewait = true;
    }
    if (in.state == TcpState::TimeWait) {
        out.clear_pending = true;
    }
    if (tcp_terminal(in.state) && in.established) {
        out.remove = true;
    }
    return out;
}

UdpActions decide_udp(const UdpInput& in) {
    UdpActions out;
    out.remove = in.app_gone; // service_udp tears the conn down only when the app channel is gone
    return out;
}

// ---------------------------------------------------------------------------
// Timeout rules.

std::uint64_t parse_timeout_secs(std::optional<std::string_view> env, std::uint64_t fallback_secs) {
    // Rust: env.ok().and_then(parse::<u64>).filter(|&v| v > 0).map(|v| v.min(86_400)).unwrap_or(dflt)
    if (!env) return fallback_secs;
    std::string_view text = *env;
    if (text.empty()) return fallback_secs;
    if (text.front() == '+') text.remove_prefix(1);
    if (text.empty()) return fallback_secs;

    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return fallback_secs;
    }
    if (value == 0) return fallback_secs; // .filter(|&v| v > 0)
    return value > MAX_TIMEOUT_SECS ? MAX_TIMEOUT_SECS : value; // .min(86_400)
}

std::uint64_t keepalive_secs(std::optional<std::string_view> env) {
    return parse_timeout_secs(env, DEFAULT_KEEPALIVE_SECS);
}

std::uint64_t connect_secs(std::optional<std::string_view> env) {
    return parse_timeout_secs(env, DEFAULT_CONNECT_SECS);
}

} // namespace hemera::core::netpacket
