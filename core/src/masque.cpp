// Port of hemera/src/masque.rs (~452 lines) and of the protocol-codec surface of
// hemera/src/masque_h2.rs (~813 lines); see masque.hpp for what both files leave to the crates.
#include "masque.hpp"

#include "sysprofile.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <limits>
#include <random>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX // std::min and std::max are used below
#define NOMINMAX
#endif
#include <windows.h>

namespace hemera::core::masque {
namespace {

// The port the Rust formats into the CONNECT URI: `format!("{}:443", cfg.authority)`.
constexpr std::uint16_t CONNECT_PORT = 443;

constexpr std::uint8_t PROBE_TTL = 64;
constexpr std::uint8_t PROBE_PROTOCOL_UDP = 17;
constexpr std::uint16_t PROBE_DNS_PORT = 53;

constexpr std::size_t IPV4_HEADER_LEN = 20;
constexpr std::size_t UDP_HEADER_LEN = 8;

// The mask a varint of each width leaves behind, indexed by the two-bit tag, as octets applies it.
constexpr std::uint64_t k_varint_masks[4] = {
    0x3fULL, 0x3fffULL, 0x3fffffffULL, 0x3fffffffffffffffULL};

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::size_t saturating_add(std::size_t left, std::size_t right) {
    constexpr std::size_t max = std::numeric_limits<std::size_t>::max();
    return right > max - left ? max : left + right;
}

void push_be16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint16_t peek_be16(std::span<const std::uint8_t> data, std::size_t at) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[at]) << 8) | data[at + 1]);
}

// The varint at the end of `out`, once the caller has made sure `value` fits.
void push_varint(std::vector<std::uint8_t>& out, std::uint64_t value) {
    const std::size_t len = varint_len(value);
    const std::uint8_t prefix = len == 8 ? 0xc0 : len == 4 ? 0x80 : len == 2 ? 0x40 : 0x00;
    for (std::size_t i = len; i-- > 0;) {
        std::uint8_t byte = static_cast<std::uint8_t>(value >> (8 * i));
        // The tag lives in the two high bits of the first byte on the wire, which is the most
        // significant one this loop writes first.
        if (i + 1 == len) byte = static_cast<std::uint8_t>(byte | prefix);
        out.push_back(byte);
    }
}

std::uint16_t random_u16() {
    thread_local std::mt19937 generator{std::random_device{}()};
    return static_cast<std::uint16_t>(generator() & 0xffff);
}

// Rust's `random_range(20000..60000)`: 20000 up to and including 59999.
std::uint16_t random_source_port() {
    thread_local std::mt19937 generator{std::random_device{}()};
    std::uniform_int_distribution<unsigned> spread(20000, 59999);
    return static_cast<std::uint16_t>(spread(generator));
}

// An environment variable as the process really holds it: whether it is there at all, and what it
// says. settings_from_environment() reads the variables cli.rs names a flag for, so the map is the
// first place to look; this is the same call behind it, for the keys no flag covers. A variable set
// to nothing is present, which Rust's `std::env::var` also reports as Ok, so a switch keyed on
// presence alone (HEMERA_MASQUE_NO_DATA_CHECK) still fires on it.
std::pair<bool, std::string> environment_value(std::string_view key) {
    static thread_local std::wstring buffer;
    const std::wstring wide(key.begin(), key.end());

    const auto read = [&]() -> DWORD {
        SetLastError(ERROR_SUCCESS);
        return GetEnvironmentVariableW(wide.c_str(), buffer.data(),
                                       static_cast<DWORD>(buffer.size()));
    };

    DWORD size = read();
    if (size >= buffer.size()) {
        buffer.resize(size + 1);
        size = read();
    }
    if (size == 0) return {GetLastError() != ERROR_ENVVAR_NOT_FOUND, std::string{}};

    std::string value;
    value.reserve(size);
    for (const wchar_t c : std::wstring_view(buffer.data(), size)) {
        value += c < 0x100 ? static_cast<char>(c) : '?';
    }
    return {true, std::move(value)};
}

// A setting masque_h2.rs reads out of the process environment. The flag table of cli.rs names
// HEMERA_MASQUE_HTTP2, --h2-peer, --no-data-check and --validate-secs, so those land in Settings;
// the two keepalive switches have no flag at all and settings_from_environment() never absorbs
// them, so the environment is asked directly when the map is silent. A caller that does put one in
// Settings still wins, which is how a flag outranks a variable everywhere else in this port.
std::optional<std::string> setting_text(const Settings& settings, std::string_view key) {
    if (const std::string* found = settings.find(key)) return *found;

    if (const auto [present, value] = environment_value(key); present) return value;
    return std::nullopt;
}

// parse::<u64>() of the Rust: a whole number of ASCII digits, an optional leading '+', no spaces,
// nothing that does not fit.
std::optional<std::uint64_t> parse_u64_rust(std::string_view text) {
    if (text.starts_with('+')) text.remove_prefix(1);
    if (text.empty()) return std::nullopt;

    std::uint64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        constexpr std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
        if (value > (max - digit) / 10) return std::nullopt; // the overflow parse::<u64>() refuses
        value = value * 10 + digit;
    }
    return value;
}

// The `> 0` filter and the `.min(86_400)` clamp the three second-valued switches share. The value
// is read as it stands: Rust parses the environment without trimming it, and " 10" is no number.
std::uint64_t env_secs(const Settings& settings, std::string_view key, std::uint64_t fallback) {
    const std::optional<std::string> raw = setting_text(settings, key);
    if (!raw) return fallback;
    const std::optional<std::uint64_t> value = parse_u64_rust(*raw);
    if (!value || *value == 0) return fallback;
    return std::min<std::uint64_t>(*value, MAX_ENV_SECS);
}

// masque.rs's parse_address_assign: request_id, ip_version, that version's address, prefix_len,
// over and over until the value runs out.
std::expected<std::vector<AssignedAddress>, std::string> parse_address_assign(
    std::span<const std::uint8_t> value) {
    std::vector<AssignedAddress> out;
    std::span<const std::uint8_t> at = value;

    while (!at.empty()) {
        AssignedAddress entry;

        const auto request_id = read_varint(at);
        if (!request_id) return std::unexpected(request_id.error());
        entry.request_id = *request_id;

        if (at.empty()) return std::unexpected(capsule_error(k_buffer_too_short));
        entry.ip_version = at.front();
        at = at.subspan(1);

        if (entry.ip_version != 4 && entry.ip_version != 6) {
            return std::unexpected(
                capsule_error("bad ip version " + std::to_string(entry.ip_version)));
        }
        const std::size_t addr_len = entry.ip_version == 4 ? 4 : 16;
        if (at.size() < addr_len) return std::unexpected(capsule_error(k_buffer_too_short));
        entry.address.assign(at.begin(), at.begin() + static_cast<std::ptrdiff_t>(addr_len));
        at = at.subspan(addr_len);

        if (at.empty()) return std::unexpected(capsule_error(k_buffer_too_short));
        entry.prefix_len = at.front();
        at = at.subspan(1);

        out.push_back(std::move(entry));
    }

    return out;
}

// masque.rs's parse_route_advertisement: ip_version, the low and the high address of the range,
// and the protocol number it covers.
std::expected<std::vector<RouteAdvertisement>, std::string> parse_route_advertisement(
    std::span<const std::uint8_t> value) {
    std::vector<RouteAdvertisement> out;
    std::span<const std::uint8_t> at = value;

    while (!at.empty()) {
        RouteAdvertisement route;

        if (at.empty()) return std::unexpected(capsule_error(k_buffer_too_short));
        route.ip_version = at.front();
        at = at.subspan(1);

        if (route.ip_version != 4 && route.ip_version != 6) {
            return std::unexpected(
                capsule_error("bad ip version " + std::to_string(route.ip_version)));
        }
        const std::size_t addr_len = route.ip_version == 4 ? 4 : 16;
        if (at.size() < addr_len) return std::unexpected(capsule_error(k_buffer_too_short));
        route.start.assign(at.begin(), at.begin() + static_cast<std::ptrdiff_t>(addr_len));
        at = at.subspan(addr_len);

        if (at.size() < addr_len) return std::unexpected(capsule_error(k_buffer_too_short));
        route.end.assign(at.begin(), at.begin() + static_cast<std::ptrdiff_t>(addr_len));
        at = at.subspan(addr_len);

        if (at.empty()) return std::unexpected(capsule_error(k_buffer_too_short));
        route.protocol = at.front();
        at = at.subspan(1);

        out.push_back(std::move(route));
    }

    return out;
}

} // namespace

// ---- errors ------------------------------------------------------------------

std::string capsule_error(std::string_view reason) { return "capsule: " + std::string(reason); }

std::string masque_error(std::string_view reason) { return "masque: " + std::string(reason); }

// ---- the variable-length integer both framings are built from ----------------

std::size_t varint_len(std::uint64_t value) {
    if (value < 64) return 1;
    if (value < 16384) return 2;
    if (value < 1'073'741'824) return 4;
    return 8;
}

std::size_t varint_parse_len(std::uint8_t first) { return std::size_t{1} << (first >> 6); }

std::expected<std::uint64_t, std::string> read_varint(std::span<const std::uint8_t>& at) {
    if (at.empty()) return std::unexpected(capsule_error(k_buffer_too_short));
    const std::size_t tag = at.front() >> 6;
    const std::size_t len = std::size_t{1} << tag;
    if (len > at.size()) return std::unexpected(capsule_error(k_buffer_too_short));

    std::uint64_t value = 0;
    for (std::size_t i = 0; i < len; ++i) value = (value << 8) | at[i];
    value &= k_varint_masks[tag];

    at = at.subspan(len);
    return value;
}

bool append_varint(std::vector<std::uint8_t>& out, std::uint64_t value) {
    if (value > MAX_VAR_INT) return false;
    push_varint(out, value);
    return true;
}

// ---- the CONNECT request, on either carrier ----------------------------------

std::vector<HeaderField> connect_ip_request(std::string_view authority, std::string_view path) {
    return {
        HeaderField{":method", "CONNECT"},
        HeaderField{":protocol", std::string(CF_CONNECT_PROTOCOL)},
        HeaderField{":scheme", "https"},
        HeaderField{":authority", std::string(authority)},
        HeaderField{":path", std::string(path)},
        HeaderField{"user-agent", ""},
        HeaderField{"capsule-protocol", "?1"},
    };
}

std::string h2_connect_authority(std::string_view authority) {
    return std::string(authority) + ":" + std::to_string(CONNECT_PORT);
}

std::string h2_connect_uri(std::string_view authority) {
    return "https://" + h2_connect_authority(authority);
}

std::vector<HeaderField> h2_connect_request_fields(std::string_view authority) {
    // The H3 field set's two load-bearing members for the H2 carrier, minus :scheme/:path
    // (extended CONNECT omits them): without :protocol the edge reads a plain CONNECT and
    // answers 400, and without capsule-protocol it will not carry capsules.
    return {
        HeaderField{":method", "CONNECT"},
        HeaderField{":protocol", std::string(CF_CONNECT_PROTOCOL)},
        HeaderField{":authority", h2_connect_authority(authority)},
        // Empty on purpose, as it is in the Rust: the edge reads an absent user agent differently.
        HeaderField{"user-agent", ""},
        HeaderField{"capsule-protocol", "?1"},
    };
}

bool connect_succeeded(std::uint16_t status) { return status >= 200 && status < 300; }

std::string h2_connect_status_error(std::uint16_t status) {
    return masque_error("h2 connect-ip status " + std::to_string(status));
}

// ---- CONNECT-IP over HTTP/3: the QUIC datagram body --------------------------

std::uint64_t quarter_stream_id(std::uint64_t stream_id) { return stream_id / 4; }

std::expected<std::vector<std::uint8_t>, std::string> encode_ip_datagram(
    std::uint64_t stream_id, std::span<const std::uint8_t> ip_packet) {
    // Rust sizes a buffer with its own varint_len and lets octets fill it, where a value over
    // 2^62-1 aborts; refusing it here is the one divergence, and it cannot be reached from the
    // stream ids or packet lengths a tunnel actually carries.
    const std::uint64_t qsid = quarter_stream_id(stream_id);
    if (qsid > MAX_VAR_INT) return std::unexpected(capsule_error(k_varint_too_wide));

    std::vector<std::uint8_t> out;
    out.reserve(varint_len(qsid) + varint_len(CONNECT_IP_CONTEXT_ID) + ip_packet.size());
    push_varint(out, qsid);
    push_varint(out, CONNECT_IP_CONTEXT_ID);
    out.insert(out.end(), ip_packet.begin(), ip_packet.end());
    return out;
}

std::expected<std::optional<std::vector<std::uint8_t>>, std::string> decode_ip_datagram(
    std::span<const std::uint8_t> datagram, std::uint64_t expect_stream_id) {
    std::span<const std::uint8_t> at = datagram;

    const auto qsid = read_varint(at);
    if (!qsid) return std::unexpected(qsid.error());
    if (*qsid != quarter_stream_id(expect_stream_id)) return std::optional<std::vector<std::uint8_t>>{};

    const auto context_id = read_varint(at);
    if (!context_id) return std::unexpected(context_id.error());
    if (*context_id != CONNECT_IP_CONTEXT_ID) return std::optional<std::vector<std::uint8_t>>{};

    return std::vector<std::uint8_t>(at.begin(), at.end());
}

// ---- CONNECT-IP over HTTP/2: the capsules on the request stream -------------

std::size_t capsule_len(std::uint64_t kind, std::size_t value_len) {
    return varint_len(kind) + varint_len(static_cast<std::uint64_t>(value_len)) + value_len;
}

bool append_capsule(std::vector<std::uint8_t>& out, std::uint64_t kind,
                    std::span<const std::uint8_t> value) {
    // Both varints are checked before anything is written, so a refusal leaves `out` untouched.
    if (kind > MAX_VAR_INT) return false;
    if (static_cast<std::uint64_t>(value.size()) > MAX_VAR_INT) return false;
    push_varint(out, kind);
    push_varint(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    return true;
}

std::vector<std::uint8_t> encode_capsule(std::uint64_t kind, std::span<const std::uint8_t> value) {
    std::vector<std::uint8_t> out;
    out.reserve(capsule_len(kind, value.size()));
    static_cast<void>(append_capsule(out, kind, value));
    return out;
}

std::expected<std::vector<std::uint8_t>, std::string> encode_address_request(
    std::uint64_t request_id, std::uint8_t ip_version, std::uint8_t prefix_len) {
    if (request_id > MAX_VAR_INT) return std::unexpected(capsule_error(k_varint_too_wide));

    std::vector<std::uint8_t> value;
    value.reserve(varint_len(request_id) + 1 + 1);
    push_varint(value, request_id);
    value.push_back(ip_version);
    value.push_back(prefix_len);

    return encode_capsule(CAPSULE_ADDRESS_REQUEST, value);
}

std::vector<std::uint8_t> encode_datagram_capsule(std::span<const std::uint8_t> ip_packet) {
    return encode_capsule(CAPSULE_DATAGRAM, ip_packet);
}

void append_datagram_capsule(std::vector<std::uint8_t>& out,
                             std::span<const std::uint8_t> ip_packet) {
    static_cast<void>(append_capsule(out, CAPSULE_DATAGRAM, ip_packet));
}

bool looks_like_ip_packet(std::span<const std::uint8_t> data) {
    if (data.empty()) return false;
    const std::uint8_t version = static_cast<std::uint8_t>(data.front() >> 4);
    return (version == 4 || version == 6) && data.size() >= IPV4_HEADER_LEN;
}

std::optional<std::vector<std::uint8_t>> strip_datagram_context(
    std::span<const std::uint8_t> payload) {
    if (payload.empty()) return std::nullopt;

    // First reading: the h3 form, a context id in front of the packet. A context id that is not
    // zero leaves the payload to the second reading rather than being an error, as it is in Rust.
    std::span<const std::uint8_t> at = payload;
    const auto context_id = read_varint(at);
    if (context_id && *context_id == CONNECT_IP_CONTEXT_ID && looks_like_ip_packet(at)) {
        return std::vector<std::uint8_t>(at.begin(), at.end());
    }

    // Second reading: the h2 form, the bare packet the Cloudflare edge answers with.
    if (looks_like_ip_packet(payload)) {
        return std::vector<std::uint8_t>(payload.begin(), payload.end());
    }

    return std::nullopt;
}

bool CapsuleParser::push(std::span<const std::uint8_t> data) {
    if (saturating_add(buf_.size(), data.size()) > MAX_CAPSULE_BUF) {
        // Rust warns and drops both what it held and what just arrived; the caller logs it.
        buf_.clear();
        return false;
    }
    buf_.insert(buf_.end(), data.begin(), data.end());
    return true;
}

std::expected<std::optional<Capsule>, std::string> CapsuleParser::next() {
    std::span<const std::uint8_t> at = buf_;

    const auto kind = read_varint(at);
    if (!kind) return std::optional<Capsule>{};
    const auto length = read_varint(at);
    if (!length) return std::optional<Capsule>{};
    if (at.size() < *length) return std::optional<Capsule>{};

    const std::size_t value_len = static_cast<std::size_t>(*length);
    std::vector<std::uint8_t> value(at.begin(),
                                   at.begin() + static_cast<std::ptrdiff_t>(value_len));
    // The offset the two varints and the value add up to: Rust drains the capsule before it looks
    // inside it, so a value that fails to parse is gone from the buffer as well as refused.
    const std::size_t consumed = buf_.size() - at.size() + value_len;
    buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(consumed));

    Capsule capsule;
    switch (*kind) {
        case CAPSULE_ADDRESS_ASSIGN: {
            auto assigned = parse_address_assign(value);
            if (!assigned) return std::unexpected(assigned.error());
            capsule.kind = Capsule::Kind::AddressAssign;
            capsule.assigned = std::move(*assigned);
            break;
        }
        case CAPSULE_ADDRESS_REQUEST:
            capsule.kind = Capsule::Kind::AddressRequest;
            break;
        case CAPSULE_ROUTE_ADVERTISEMENT: {
            auto routes = parse_route_advertisement(value);
            if (!routes) return std::unexpected(routes.error());
            capsule.kind = Capsule::Kind::RouteAdvertisement;
            capsule.routes = std::move(*routes);
            break;
        }
        case CAPSULE_DATAGRAM:
            capsule.kind = Capsule::Kind::Datagram;
            capsule.value = std::move(value);
            break;
        default:
            capsule.kind = Capsule::Kind::Unknown;
            capsule.type_id = *kind;
            capsule.value = std::move(value);
            break;
    }

    return capsule;
}

std::optional<IpAddress> to_ip_address(std::uint8_t version, std::span<const std::uint8_t> bytes) {
    IpAddress ip;
    if (version == 4 && bytes.size() == 4) {
        ip.v4 = true;
        std::copy(bytes.begin(), bytes.end(), ip.bytes.begin() + 12);
        return ip;
    }
    if (version == 6 && bytes.size() == 16) {
        std::copy(bytes.begin(), bytes.end(), ip.bytes.begin());
        return ip;
    }
    return std::nullopt;
}

std::string EdgeAssignment::text() const {
    // Rust logs an `IpAddr`, whose Display has no brackets; the "[...]" form belongs to a SocketAddr
    // printing its port. dns.hpp only prints an address beside a port, so the port half and the
    // brackets around an IPv6 are taken back off. The Rust line is "edge assigned {}/{}".
    std::string whole = SocketAddr{ip, 0}.to_string();
    if (const std::size_t at = whole.find_last_of(':'); at != std::string::npos) {
        whole.erase(at);
    }
    if (whole.starts_with('[')) whole.erase(whole.begin());
    if (whole.ends_with(']')) whole.pop_back();
    return whole + "/" + std::to_string(prefix);
}

Drained drain_capsules(CapsuleParser& parser) {
    Drained out;

    for (;;) {
        auto capsule = parser.next();
        if (!capsule) {
            // Rust logs the reason at trace and stops draining; the bytes of that capsule are
            // already gone, so the next one is read from wherever the stream resumed.
            out.parse_error = capsule.error();
            break;
        }
        if (!*capsule) break; // nothing whole left in the buffer

        const Capsule& found = **capsule;
        switch (found.kind) {
            case Capsule::Kind::Datagram: {
                const auto packet = strip_datagram_context(found.value);
                if (!packet) {
                    // "[h2] discarding a datagram that is not an ip packet"
                    ++out.discarded;
                    continue;
                }
                out.delivered = true;
                out.packets.push_back(*packet);
                break;
            }
            case Capsule::Kind::AddressAssign:
                for (const AssignedAddress& entry : found.assigned) {
                    if (const auto ip = to_ip_address(entry.ip_version, entry.address)) {
                        out.assigned.push_back(EdgeAssignment{*ip, entry.prefix_len});
                    }
                }
                break;
            case Capsule::Kind::RouteAdvertisement:
                out.routes += found.routes.size();
                break;
            case Capsule::Kind::AddressRequest:
            case Capsule::Kind::Unknown:
                break;
        }
    }

    return out;
}

// ---- the HTTP/2 carrier: limits, flags and the shape a caller fills in -------

H2Flow h2_flow(const Settings& settings) {
    return H2Flow{sysprofile::h2_stream_window_bytes(settings),
                  sysprofile::h2_connection_window_bytes(settings), H2_MAX_FRAME_SIZE};
}

bool enabled(const Settings& settings) {
    const std::optional<std::string> raw = setting_text(settings, "HEMERA_MASQUE_HTTP2");
    if (!raw) return false;

    const std::string value = lowered(trim(*raw));
    // "h2" is this switch's own word; is_truthy() of settings.hpp does not know it.
    return value == "1" || value == "true" || value == "h2" || value == "yes" || value == "on";
}

SocketAddr h2_peer(const Settings& settings, const SocketAddr& quic_peer) {
    const std::optional<std::string> raw = setting_text(settings, "HEMERA_MASQUE_H2_PEER");
    if (raw) {
        // A value that is no `ip:port` is ignored rather than fatal, as Rust's failed parse is.
        if (const auto addr = parse_socket_addr(trim(*raw))) return *addr;
    }
    return quic_peer;
}

bool data_check_enabled(const Settings& settings) {
    // The presence of the key is the whole switch: `--no-data-check=` with an empty value turns
    // the check off, so is_truthy() has no part to play here. cli.rs's flag writes both this key
    // and HEMERA_WG_NO_DATA_CHECK, but only this one is the WireGuard-free MASQUE reading.
    return !setting_text(settings, "HEMERA_MASQUE_NO_DATA_CHECK").has_value();
}

std::chrono::seconds validation_timeout(const Settings& settings) {
    return std::chrono::seconds(
        env_secs(settings, "HEMERA_MASQUE_VALIDATE_SECS", VALIDATE_SECS_DEFAULT.count()));
}

std::chrono::seconds h2_keepalive_interval(const Settings& settings) {
    return std::chrono::seconds(
        env_secs(settings, "HEMERA_MASQUE_H2_KEEPALIVE_SECS", KEEPALIVE_INTERVAL_DEFAULT.count()));
}

std::chrono::seconds h2_keepalive_timeout(const Settings& settings) {
    return std::chrono::seconds(env_secs(settings, "HEMERA_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS",
                                         KEEPALIVE_TIMEOUT_DEFAULT.count()));
}

std::vector<std::vector<std::uint8_t>> default_expected_pins() {
    std::vector<std::vector<std::uint8_t>> pins;
    pins.reserve(std::size(MASQUE_PINS));
    for (const auto& pin : MASQUE_PINS) {
        pins.emplace_back(std::begin(pin), std::end(pin));
    }
    return pins;
}

H2TunnelConfig::H2TunnelConfig() : expected_pins(default_expected_pins()) {}

std::string H2TunnelConfig::describe() const {
    // Sizes of the key material, never the material itself.
    const std::size_t ech_len = ech_config_list ? ech_config_list->size() : 0;
    return "[h2] peer=" + peer.to_string() + " sni=" + sni + " authority=" + authority +
           " path=" + path + " cert=" + std::to_string(cert_pem.size()) + "B key=" +
           std::to_string(key_pem.size()) + "B ech=" + std::to_string(ech_len) + "B pins=" +
           std::to_string(expected_pins.size()) + " pin_endpoint=" +
           (pin_endpoint ? "on" : "off") + " quiet=" + (quiet ? "on" : "off");
}

SendBatch batch_datagram_capsules(std::span<const std::vector<std::uint8_t>> queued) {
    SendBatch batch;
    while (batch.taken < queued.size()) {
        // The first packet always goes in, and one more is added while the frame is still under
        // the limit -- which is how a frame can end up over it by the capsule that crossed.
        if (batch.taken > 0 && batch.frame.size() >= H2_SEND_BATCH_BYTES) break;
        append_datagram_capsule(batch.frame, queued[batch.taken]);
        ++batch.taken;
    }
    return batch;
}

// ---- the data-plane probe ----------------------------------------------------

std::uint16_t ipv4_header_checksum(std::span<const std::uint8_t> header) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < header.size(); i += 2) sum += peek_be16(header, i);
    if (i < header.size()) sum += static_cast<std::uint32_t>(header[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~static_cast<std::uint16_t>(sum));
}

std::vector<std::uint8_t> probe_dns_query(std::uint16_t id) {
    std::vector<std::uint8_t> query;
    query.reserve(32);

    push_be16(query, id);
    query.push_back(0x01); // desired recursion
    query.push_back(0x00);
    push_be16(query, 1);   // one question
    for (int i = 0; i < 6; ++i) query.push_back(0x00); // answer, authority, additional: none

    for (std::string_view label : {std::string_view("cloudflare"), std::string_view("com")}) {
        query.push_back(static_cast<std::uint8_t>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.push_back(0x00);
    push_be16(query, 1); // QTYPE A
    push_be16(query, 1); // QCLASS IN

    return query;
}

std::vector<std::uint8_t> build_dns_probe_packet(const IpAddress& src,
                                                 std::optional<std::uint16_t> dns_id,
                                                 std::optional<std::uint16_t> sport) {
    const std::vector<std::uint8_t> dns = probe_dns_query(dns_id.value_or(random_u16()));
    const auto udp_len = static_cast<std::uint16_t>(UDP_HEADER_LEN + dns.size());
    const auto total_len = static_cast<std::uint16_t>(IPV4_HEADER_LEN + udp_len);
    const std::uint16_t id = dns_id.value_or(random_u16());
    const std::uint16_t source_port = sport.value_or(random_source_port());

    std::vector<std::uint8_t> packet;
    packet.reserve(total_len);

    packet.push_back(0x45); // version 4, IHL 5
    packet.push_back(0x00); // DSCP and ECN
    push_be16(packet, total_len);
    push_be16(packet, id);
    push_be16(packet, 0x0000); // no flags, no fragment offset
    packet.push_back(PROBE_TTL);
    packet.push_back(PROBE_PROTOCOL_UDP);
    push_be16(packet, 0x0000); // the checksum, filled in below
    // The tunnel's own address. An IPv4 lives in the last four octets of dns.hpp's IpAddress; a
    // caller that has no v4 to offer gets zeros, which is Rust's UNSPECIFIED fallback.
    for (std::size_t i = 12; i < 16; ++i) packet.push_back(src.bytes[i]);
    for (const std::uint8_t octet : {std::uint8_t{8}, std::uint8_t{8}, std::uint8_t{8},
                                     std::uint8_t{8}}) {
        packet.push_back(octet);
    }

    const std::uint16_t checksum = ipv4_header_checksum({packet.data(), IPV4_HEADER_LEN});
    packet[10] = static_cast<std::uint8_t>(checksum >> 8);
    packet[11] = static_cast<std::uint8_t>(checksum & 0xff);

    push_be16(packet, source_port);
    push_be16(packet, PROBE_DNS_PORT);
    push_be16(packet, udp_len);
    push_be16(packet, 0x0000); // an UDP checksum the Rust never computes, and the edge never asks

    packet.insert(packet.end(), dns.begin(), dns.end());
    return packet;
}

bool rejected_ech(std::string_view message) {
    return message.find("ECH_REJECTED") != std::string_view::npos;
}

} // namespace hemera::core::masque
