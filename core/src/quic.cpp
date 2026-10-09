#include "quic.hpp"

#include "consts.hpp"
#include "sysprofile.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <random>

namespace hemera::core::quic {
namespace {

constexpr std::string_view kNoDataCheck = "HEMERA_MASQUE_NO_DATA_CHECK";
constexpr std::string_view kValidateSecs = "HEMERA_MASQUE_VALIDATE_SECS";
constexpr std::string_view kQuicV2 = "HEMERA_QUIC_V2";

// Rust's `str::parse::<u64>()`: digits only, with a leading `+` that from_chars refuses. Anything
// else, an empty string, stray text or an overflow included, is no value at all.
std::optional<std::uint64_t> parse_u64(std::string_view text) {
    if (text.starts_with('+')) text.remove_prefix(1);
    if (text.empty()) return std::nullopt;

    std::uint64_t value = 0;
    const auto read = std::from_chars(text.data(), text.data() + text.size(), value);
    if (read.ec != std::errc{} || read.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

void fill_random(std::uint8_t* out, std::size_t len) {
    // RAND_bytes rather than a local generator: a connection id is seen by anyone on the path, so
    // it has to be unpredictable, not merely different.
    if (RAND_bytes(out, static_cast<int>(len)) == 1) return;
    // Without the TLS library's entropy the operating system is asked, which fails loudly, rather
    // than writing identifiers anyone could guess.
    std::random_device device;
    for (std::size_t at = 0; at < len; ++at) out[at] = static_cast<std::uint8_t>(device());
}

std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);
    fill_random(out.data(), len);
    return out;
}

IpAddress any_address(bool v4) {
    IpAddress address;
    address.v4 = v4;
    return address;
}

} // namespace

std::size_t net_queue(const Settings& settings) {
    return sysprofile::channel_capacity(settings);
}

std::size_t TunnelConfig::datagram_budget() const {
    return std::clamp(max_datagram, MIN_DATAGRAM_SIZE, MAX_DATAGRAM_SIZE);
}

std::chrono::seconds validation_timeout(const Settings& settings) {
    std::uint64_t secs = 10;
    if (const auto named = settings.get(kValidateSecs)) {
        if (const auto parsed = parse_u64(*named)) {
            if (*parsed > 0) secs = std::min<std::uint64_t>(*parsed, 86'400);
        }
    }
    return std::chrono::seconds(secs);
}

bool data_check_enabled(const Settings& settings) {
    return settings.find(kNoDataCheck) == nullptr;
}

bool quic_v2_bait_enabled(const Settings& settings) {
    const auto named = settings.get(kQuicV2);
    if (!named) return true;
    const std::string_view value = *named;
    return !(value == "0" || value == "off" || value == "false" || value == "no");
}

std::array<std::uint8_t, 2> quic_varint2(std::uint64_t value) {
    const auto encoded = static_cast<std::uint16_t>((value & 0x3fff) | 0x4000);
    return {static_cast<std::uint8_t>(encoded >> 8), static_cast<std::uint8_t>(encoded & 0xff)};
}

std::vector<std::uint8_t> build_version_bait() {
    // A v2 Initial: header form and fixed bits set, the version field carrying QUIC v2, then two
    // random connection ids, a zero token length, the payload length, and four random bytes where
    // a packet number would be. The rest is zero to reach the minimum QUIC packet size.
    std::vector<std::uint8_t> pkt;
    pkt.reserve(QUIC_V2_BAIT_LEN);

    const std::vector<std::uint8_t> dcid = random_bytes(8);
    const std::vector<std::uint8_t> scid = random_bytes(8);

    pkt.push_back(0xc3);
    pkt.push_back(static_cast<std::uint8_t>(QUIC_V2_VERSION >> 24));
    pkt.push_back(static_cast<std::uint8_t>(QUIC_V2_VERSION >> 16));
    pkt.push_back(static_cast<std::uint8_t>(QUIC_V2_VERSION >> 8));
    pkt.push_back(static_cast<std::uint8_t>(QUIC_V2_VERSION & 0xff));
    pkt.push_back(static_cast<std::uint8_t>(dcid.size()));
    pkt.insert(pkt.end(), dcid.begin(), dcid.end());
    pkt.push_back(static_cast<std::uint8_t>(scid.size()));
    pkt.insert(pkt.end(), scid.begin(), scid.end());
    pkt.push_back(0x00);

    const std::size_t remaining = QUIC_V2_BAIT_LEN - pkt.size() - 2;
    for (const std::uint8_t byte : quic_varint2(static_cast<std::uint64_t>(remaining))) {
        pkt.push_back(byte);
    }
    for (const std::uint8_t byte : random_bytes(4)) pkt.push_back(byte);

    pkt.resize(QUIC_V2_BAIT_LEN, 0);
    return pkt;
}

SocketAddr bind_addr_for(const SocketAddr& peer) {
    return SocketAddr{any_address(peer.is_ipv4()), 0};
}

std::array<std::uint8_t, SCID_LEN> random_scid() {
    std::array<std::uint8_t, SCID_LEN> scid{};
    fill_random(scid.data(), scid.size());
    return scid;
}

std::string_view default_authority() { return "cloudflareaccess.com"; }

std::string_view default_path() { return "/"; }

std::string_view default_sni() { return CONNECT_SNI; }

const TransportParams& transport_params() {
    // quic.rs builds its h3 settings with h3::Config::new(), that is, the library's own defaults;
    // the engine leaves nghttp3's defaults alone for the same reason.
    static const TransportParams params;
    return params;
}

} // namespace hemera::core::quic
