#include "prober.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <numeric>
#include <random>
#include <system_error>

namespace aether::core::prober {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return out;
}

// Strict integer reads that mirror Rust's `str::parse::<T>()`: the whole slice must be consumed,
// no sign, no trailing space. Leading zeros are accepted (as Rust reads them), which std::from_chars
// also is.
template <typename T>
std::optional<T> parse_int(std::string_view text) {
    text = trim(text);
    if (text.empty()) return std::nullopt;
    T value{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

// The four octets of an IPv4 address as the u32 Rust's u32::from(Ipv4Addr) gives.
std::uint32_t v4_to_u32(const IpAddress& ip) {
    return (static_cast<std::uint32_t>(ip.bytes[12]) << 24) |
           (static_cast<std::uint32_t>(ip.bytes[13]) << 16) |
           (static_cast<std::uint32_t>(ip.bytes[14]) << 8) | static_cast<std::uint32_t>(ip.bytes[15]);
}

IpAddress u32_to_v4(std::uint32_t value) {
    IpAddress ip;
    ip.v4 = true;
    ip.bytes[12] = static_cast<std::uint8_t>(value >> 24);
    ip.bytes[13] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    ip.bytes[14] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    ip.bytes[15] = static_cast<std::uint8_t>(value & 0xff);
    return ip;
}

std::uint64_t ip_to_u64_prefix(const IpAddress& ip) {
    std::uint64_t out = 0;
    for (int i = 0; i < 8; ++i) {
        out = (out << 8) | ip.bytes[static_cast<std::size_t>(i)];
    }
    return out;
}

std::uint64_t ip_low_u64(const IpAddress& ip) {
    std::uint64_t out = 0;
    for (int i = 8; i < 16; ++i) {
        out = (out << 8) | ip.bytes[static_cast<std::size_t>(i)];
    }
    return out;
}

IpAddress u64s_to_v6(std::uint64_t high, std::uint64_t low) {
    IpAddress ip;
    ip.v4 = false;
    for (int i = 0; i < 8; ++i) {
        ip.bytes[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((high >> (56 - 8 * i)) & 0xff);
    }
    for (int i = 0; i < 8; ++i) {
        ip.bytes[static_cast<std::size_t>(8 + i)] =
            static_cast<std::uint8_t>((low >> (56 - 8 * i)) & 0xff);
    }
    return ip;
}

// The cidr address part before the '/', resolved through dns so a bad address yields nothing,
// which matches `ip.parse::<Ipv4Addr>().ok()?`.
std::optional<std::pair<IpAddress, std::uint8_t>> split_cidr(std::string_view cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    const auto address = parse_address(cidr.substr(0, slash));
    if (!address) return std::nullopt;
    const auto prefix = parse_int<std::uint32_t>(cidr.substr(slash + 1));
    if (!prefix || *prefix > 255) return std::nullopt;
    return std::pair{*address, static_cast<std::uint8_t>(*prefix)};
}

// Rust reads the prefix as u8; a value over 255 (or 128/32 for the family) is only ever seen in a
// malformed table, so it is kept at the u8 the shift arithmetic expects.

std::uint32_t bounded(const Random& rng, std::uint32_t bound) {
    // random_range(0..bound) in Rust is uniform; a modulo is used here. Divergence: the tail of a
    // range that does not divide 2^32 is slightly over-weighted. Scan sampling is a spread, not a
    // security boundary, so the exact distribution carries no behaviour the port must keep.
    return bound == 0 ? 0 : rng() % bound;
}

std::string ip_port(const ProbeResult& pr) {
    return render_ip(pr.ip) + ":" + std::to_string(pr.port);
}

std::string rtt_str(const ProbeResult& pr) {
    return " rtt=" + format_duration_debug(pr.rtt);
}

} // namespace

// ---- zero-trust prioritisation --------------------------------------------------------------

bool zero_trust_mode(const Settings& settings) {
    const auto value = settings.get("AETHER_TEAM");
    return value && !trim(*value).empty();
}

std::vector<std::string_view> prioritize(std::vector<std::string_view> all,
                                         std::vector<std::string_view> first, bool zero_trust) {
    if (!zero_trust) return all;

    std::vector<std::string_view> out;
    out.reserve(all.size());
    for (const auto& entry : first) {
        if (std::find(all.begin(), all.end(), entry) != all.end()) out.push_back(entry);
    }
    for (const auto& entry : all) {
        if (std::find(out.begin(), out.end(), entry) == out.end()) out.push_back(entry);
    }
    return out;
}

std::vector<std::string_view> masque_cidrs_v4(bool zero_trust) {
    const std::vector<std::string_view> all{std::begin(MASQUE_CIDRS_V4), std::end(MASQUE_CIDRS_V4)};
    const std::vector<std::string_view> first{std::begin(MASQUE_ZT_CIDRS_V4),
                                              std::end(MASQUE_ZT_CIDRS_V4)};
    return prioritize(all, first, zero_trust);
}

std::vector<std::string_view> masque_cidrs_v6(bool zero_trust) {
    const std::vector<std::string_view> all{std::begin(MASQUE_CIDRS_V6), std::end(MASQUE_CIDRS_V6)};
    const std::vector<std::string_view> first{std::begin(MASQUE_ZT_CIDRS_V6),
                                              std::end(MASQUE_ZT_CIDRS_V6)};
    return prioritize(all, first, zero_trust);
}

// ---- scan switches --------------------------------------------------------------------------

IpScan ip_scan_parse(std::string_view s) {
    const std::string text = lowered(trim(s));
    if (text == "6" || text == "v6" || text == "ipv6") return IpScan::V6;
    if (text == "both" || text == "all" || text == "dual") return IpScan::Both;
    return IpScan::V4;
}

std::string_view ip_scan_label(IpScan ip) {
    switch (ip) {
        case IpScan::V4: return "ipv4";
        case IpScan::V6: return "ipv6";
        case IpScan::Both: return "dual-stack";
    }
    return "ipv4";
}

bool ip_scan_want_v4(IpScan ip) { return ip == IpScan::V4 || ip == IpScan::Both; }
bool ip_scan_want_v6(IpScan ip) { return ip == IpScan::V6 || ip == IpScan::Both; }

EffectiveIp effective_ip(IpScan requested, bool host_has_ipv6) {
    EffectiveIp out;
    out.ip = requested;
    if (ip_scan_want_v6(requested) && !host_has_ipv6) {
        if (ip_scan_want_v4(requested)) {
            out.ip = IpScan::V4;
            out.log = std::string(FALLBACK_TO_V4_LOG);
        } else {
            out.ok = false;
            out.log = std::string(NO_V6_ROUTE_LOG);
        }
    }
    return out;
}

ScanMode scan_mode_parse(std::string_view s) {
    const std::string text = lowered(trim(s));
    if (text == "turbo" || text == "fast") return ScanMode::Turbo;
    if (text == "thorough" || text == "deep" || text == "pro") return ScanMode::Thorough;
    if (text == "verified" || text == "proven" || text == "stealth" || text == "quiet")
        return ScanMode::Verified;
    if (text == "ironclad" || text == "real" || text == "verify" || text == "guaranteed")
        return ScanMode::Ironclad;
    return ScanMode::Balanced;
}

std::string_view scan_mode_label(ScanMode mode) {
    switch (mode) {
        case ScanMode::Turbo: return "turbo";
        case ScanMode::Balanced: return "balanced";
        case ScanMode::Thorough: return "thorough";
        case ScanMode::Verified: return "verified";
        case ScanMode::Ironclad: return "ironclad";
    }
    return "balanced";
}

Strategy scan_strategy(ScanMode mode) {
    using namespace std::chrono_literals;
    switch (mode) {
        case ScanMode::Turbo:
            return Strategy{20, 6000ms, 45s,  0ms,  1, true,  false, 64};
        case ScanMode::Balanced:
            return Strategy{16, 6000ms, 120s, 20s,  6, false, false, 140};
        case ScanMode::Thorough:
            return Strategy{20, 10000ms, 300s, 30s, 0, false, true,  0};
        case ScanMode::Verified:
            return Strategy{16, 5000ms, 60s,  8s,   4, false, false, 48};
        case ScanMode::Ironclad:
            return Strategy{4,  15000ms, 180s, 15s,  3, false, false, 140};
    }
    return Strategy{};
}

WgScanMode wg_scan_mode_parse(std::string_view s) {
    const std::string text = lowered(trim(s));
    if (text == "turbo" || text == "fast") return WgScanMode::Turbo;
    if (text == "thorough" || text == "deep" || text == "pro") return WgScanMode::Thorough;
    if (text == "verified" || text == "proven" || text == "stealth" || text == "quiet")
        return WgScanMode::Verified;
    if (text == "ironclad" || text == "real" || text == "verify" || text == "guaranteed")
        return WgScanMode::Ironclad;
    return WgScanMode::Balanced;
}

std::string_view wg_scan_mode_label(WgScanMode mode) {
    switch (mode) {
        case WgScanMode::Turbo: return "turbo";
        case WgScanMode::Balanced: return "balanced";
        case WgScanMode::Thorough: return "thorough";
        case WgScanMode::Verified: return "verified";
        case WgScanMode::Ironclad: return "ironclad";
    }
    return "balanced";
}

WgStrategy wg_scan_strategy(WgScanMode mode) {
    using namespace std::chrono_literals;
    switch (mode) {
        case WgScanMode::Turbo:
            return WgStrategy{12, 5000ms, 30s,  0ms, 1, true,  false, 40,  1};
        case WgScanMode::Balanced:
            return WgStrategy{8,  7000ms, 80s,  12s, 5, false, false, 120, 3};
        case WgScanMode::Thorough:
            return WgStrategy{10, 9000ms, 250s, 25s, 0, false, true,  0,   4};
        case WgScanMode::Verified:
            return WgStrategy{10, 5000ms, 60s,  8s,  6, false, false, 48,  4};
        case WgScanMode::Ironclad:
            return WgStrategy{4,  15000ms, 180s, 15s, 3, false, false, 120, 3};
    }
    return WgStrategy{};
}

// ---- results and ranking --------------------------------------------------------------------

ProbeResult best_of(const ProbeResult& cur, const ProbeResult& next) {
    return cur.rtt <= next.rtt ? cur : next;
}

std::vector<WgProbeResult> distinct_by_ip(const std::vector<WgProbeResult>& found) {
    std::vector<WgProbeResult> sorted = found;
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const WgProbeResult& a, const WgProbeResult& b) { return a.rtt < b.rtt; });

    std::vector<IpAddress> seen;
    std::vector<WgProbeResult> out;
    out.reserve(sorted.size());
    for (const auto& pr : sorted) {
        if (std::find(seen.begin(), seen.end(), pr.ip) == seen.end()) {
            seen.push_back(pr.ip);
            out.push_back(pr);
        }
    }
    return out;
}

// ---- candidate construction -----------------------------------------------------------------

Random default_random() {
    return [] {
        thread_local std::mt19937 generator{std::random_device{}()};
        return static_cast<std::uint32_t>(generator());
    };
}

std::optional<std::pair<std::uint32_t, std::uint8_t>> parse_cidr_v4(std::string_view cidr) {
    const auto parts = split_cidr(cidr);
    if (!parts || !parts->first.v4) return std::nullopt;
    return std::pair{v4_to_u32(parts->first), parts->second};
}

std::optional<std::pair<IpAddress, std::uint8_t>> parse_cidr_v6(std::string_view cidr) {
    const auto parts = split_cidr(cidr);
    if (!parts || parts->first.v4) return std::nullopt;
    return parts;
}

std::vector<IpAddress> enumerate_cidr_v4(std::string_view cidr) {
    std::vector<IpAddress> out;
    const auto parsed = parse_cidr_v4(cidr);
    if (!parsed) return out;
    const auto [base, prefix] = *parsed;

    const std::uint32_t host_bits = 32u > prefix ? 32u - prefix : 0u;
    if (host_bits == 0) {
        out.push_back(u32_to_v4(base));
        return out;
    }
    if (host_bits > 12) return out;
    const std::uint32_t size = 1u << host_bits;
    // (1 .. size-1) exclusive upper in Rust == offsets 1 .. size-2 inclusive.
    for (std::uint32_t off = 1; off + 1 < size; ++off) {
        out.push_back(u32_to_v4(base + off));
    }
    return out;
}

std::vector<IpAddress> sample_cidr_v4(std::string_view cidr, std::size_t n, const Random& rng) {
    std::vector<IpAddress> out;
    const auto parsed = parse_cidr_v4(cidr);
    if (!parsed) return out;
    const auto [base, prefix] = *parsed;

    const std::uint32_t host_bits = 32u > prefix ? 32u - prefix : 0u;
    const std::uint32_t size = host_bits >= 32 ? 0xffffffffu : (1u << host_bits);
    if (size <= 2) {
        out.push_back(u32_to_v4(base));
        return out;
    }

    const std::uint32_t usable = size - 2;
    const std::uint32_t want = static_cast<std::uint32_t>(std::min<std::size_t>(n, usable));
    std::vector<std::uint32_t> chosen;
    chosen.reserve(want);
    // Rust fills to `want` by rejecting repeats; the offset lives in 1 .. usable.
    while (out.size() < want) {
        const std::uint32_t off = 1 + bounded(rng, usable);
        if (std::find(chosen.begin(), chosen.end(), off) == chosen.end()) {
            chosen.push_back(off);
            out.push_back(u32_to_v4(base + off));
        }
    }
    return out;
}

std::vector<IpAddress> sample_cidr_v6(std::string_view cidr, std::size_t n,
                                      std::vector<std::string_view> v4_cidrs, const Random& rng) {
    std::vector<IpAddress> out;
    const auto parsed = parse_cidr_v6(cidr);
    if (!parsed) return out;
    const auto [base_ip, prefix] = *parsed;

    const std::uint32_t host_bits = 128u > prefix ? 128u - prefix : 0u;
    if (host_bits == 0) {
        out.push_back(base_ip);
        return out;
    }

    const std::uint64_t base_high = ip_to_u64_prefix(base_ip);
    const std::uint64_t base_low = ip_low_u64(base_ip);

    std::vector<std::pair<std::uint32_t, std::uint8_t>> v4;
    v4.reserve(v4_cidrs.size());
    for (const auto& entry : v4_cidrs) {
        if (const auto cidr4 = parse_cidr_v4(entry)) v4.push_back(*cidr4);
    }

    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t embedded = 0;
        if (v4.empty()) {
            embedded = rng();
        } else {
            const auto& [b, p] = v4[bounded(rng, static_cast<std::uint32_t>(v4.size()))];
            const std::uint32_t sub = 32u > p ? 32u - p : 0u;
            const std::uint32_t host =
                sub == 0 ? 0 : (rng() & (sub >= 32 ? 0xffffffffu : ((1u << sub) - 1)));
            embedded = b | host;
        }
        // The embedded v4 host lands in the low 32 bits of the address; base keeps the prefix.
        out.push_back(u64s_to_v6(base_high, base_low | embedded));
    }
    return out;
}

std::vector<Candidate> build_candidates(const Strategy& st,
                                       const std::vector<std::uint16_t>& ports, IpScan ip,
                                       bool zero_trust, const Random& rng) {
    const std::uint16_t primary = ports.empty() ? 443 : ports.front();
    std::vector<Candidate> out;
    std::vector<Candidate> seen;

    auto insert = [&](const IpAddress& address, std::uint16_t port) {
        Candidate entry{address, port};
        if (std::find(seen.begin(), seen.end(), entry) == seen.end()) {
            seen.push_back(entry);
            out.push_back(entry);
        }
    };

    std::vector<IpAddress> seeds;
    for (const auto& s : MASQUE_SEEDS) {
        if (const auto a = parse_address(s)) seeds.push_back(*a);
    }
    std::vector<IpAddress> seeds6;
    for (const auto& s : MASQUE_SEEDS_V6) {
        if (const auto a = parse_address(s)) seeds6.push_back(*a);
    }

    if (ip_scan_want_v4(ip)) {
        for (const auto& a : seeds) insert(a, primary);

        std::vector<std::vector<IpAddress>> cidr_hosts;
        for (const auto& c : masque_cidrs_v4(zero_trust)) {
            cidr_hosts.push_back(st.full_subnet ? enumerate_cidr_v4(c)
                                                : sample_cidr_v4(c, st.sample_per_cidr, rng));
        }
        const std::size_t max_len =
            std::accumulate(cidr_hosts.begin(), cidr_hosts.end(), std::size_t{0},
                            [](std::size_t acc, const std::vector<IpAddress>& v) {
                                return std::max(acc, v.size());
                            });
        for (std::size_t i = 0; i < max_len; ++i) {
            for (const auto& hosts : cidr_hosts) {
                if (i < hosts.size()) insert(hosts[i], primary);
            }
        }
    }

    if (ip_scan_want_v6(ip)) {
        for (const auto& a : seeds6) insert(a, primary);

        const std::size_t per = st.sample_per_cidr == 0 ? 96 : st.sample_per_cidr;
        std::vector<std::vector<IpAddress>> cidr6;
        const std::vector<std::string_view> embed{std::begin(MASQUE_CIDRS_V4),
                                                 std::end(MASQUE_CIDRS_V4)};
        for (const auto& c : masque_cidrs_v6(zero_trust)) {
            cidr6.push_back(sample_cidr_v6(c, per, embed, rng));
        }
        const std::size_t max6 =
            std::accumulate(cidr6.begin(), cidr6.end(), std::size_t{0},
                            [](std::size_t acc, const std::vector<IpAddress>& v) {
                                return std::max(acc, v.size());
                            });
        for (std::size_t i = 0; i < max6; ++i) {
            for (const auto& hosts : cidr6) {
                if (i < hosts.size()) insert(hosts[i], primary);
            }
        }
    }

    if (ip_scan_want_v4(ip)) {
        for (const auto& a : seeds) {
            for (const auto port : ports) {
                if (port != primary) insert(a, port);
            }
        }
    }
    if (ip_scan_want_v6(ip)) {
        for (const auto& a : seeds6) {
            for (const auto port : ports) {
                if (port != primary) insert(a, port);
            }
        }
    }

    return out;
}

std::vector<Candidate> build_wg_candidates(const WgStrategy& st,
                                          const std::vector<std::uint16_t>& ports, IpScan ip,
                                          const std::vector<Candidate>& excluded,
                                          const WgCandidateSources& sources, const Random& rng) {
    std::vector<std::uint16_t> dedup_ports;
    for (const auto port : ports) {
        if (std::find(dedup_ports.begin(), dedup_ports.end(), port) == dedup_ports.end()) {
            dedup_ports.push_back(port);
        }
    }
    if (dedup_ports.empty()) dedup_ports.push_back(2408);

    std::vector<IpAddress> anchors;
    std::vector<IpAddress> pool;

    if (ip_scan_want_v4(ip)) {
        for (const auto& s : sources.anchors_v4) {
            if (const auto a = parse_address(s); a && a->v4) anchors.push_back(*a);
        }
        std::vector<std::vector<IpAddress>> cidr_hosts;
        for (const auto& c : sources.prefixes_v4) {
            cidr_hosts.push_back(st.full_subnet ? enumerate_cidr_v4(c)
                                               : sample_cidr_v4(c, st.sample_per_cidr, rng));
        }
        const std::size_t max_len =
            std::accumulate(cidr_hosts.begin(), cidr_hosts.end(), std::size_t{0},
                            [](std::size_t acc, const std::vector<IpAddress>& v) {
                                return std::max(acc, v.size());
                            });
        for (std::size_t i = 0; i < max_len; ++i) {
            for (const auto& hosts : cidr_hosts) {
                if (i < hosts.size()) pool.push_back(hosts[i]);
            }
        }
    }

    if (ip_scan_want_v6(ip)) {
        for (const auto& s : sources.anchors_v6) {
            if (const auto a = parse_address(s); a && !a->v4) anchors.push_back(*a);
        }
        const std::size_t per = st.sample_per_cidr == 0 ? 80 : st.sample_per_cidr;
        std::vector<std::vector<IpAddress>> cidr6;
        for (const auto& c : sources.prefixes_v6) {
            cidr6.push_back(sample_cidr_v6(c, per, sources.embed_v4, rng));
        }
        const std::size_t max6 =
            std::accumulate(cidr6.begin(), cidr6.end(), std::size_t{0},
                            [](std::size_t acc, const std::vector<IpAddress>& v) {
                                return std::max(acc, v.size());
                            });
        for (std::size_t i = 0; i < max6; ++i) {
            for (const auto& hosts : cidr6) {
                if (i < hosts.size()) pool.push_back(hosts[i]);
            }
        }
    }

    std::vector<IpAddress> ips;
    for (const auto& a : anchors) {
        if (std::find(ips.begin(), ips.end(), a) == ips.end()) ips.push_back(a);
    }
    for (const auto& a : pool) {
        if (std::find(ips.begin(), ips.end(), a) == ips.end()) ips.push_back(a);
    }

    std::vector<Candidate> out;
    std::vector<Candidate> seen;
    const std::size_t port_count = dedup_ports.size();

    auto push = [&](const IpAddress& address, std::uint16_t port) {
        Candidate entry{address, port};
        if (std::find(excluded.begin(), excluded.end(), entry) != excluded.end()) return;
        if (std::find(seen.begin(), seen.end(), entry) == seen.end()) {
            seen.push_back(entry);
            out.push_back(entry);
        }
    };

    const std::size_t waves = std::max<std::size_t>(st.pool_port_waves, 1);
    for (std::size_t wave = 0; wave < waves; ++wave) {
        for (std::size_t idx = 0; idx < ips.size(); ++idx) {
            push(ips[idx], dedup_ports[(idx + wave) % port_count]);
        }
    }

    return out;
}

// ---- hunt state machine ---------------------------------------------------------------------

MasqueHunt::MasqueHunt(const Strategy& st, time_point start)
    : st_(st), deadline_(start + st.overall_deadline) {}

time_point MasqueHunt::next_wake() const {
    if (quiet_until_) return std::min(*quiet_until_, deadline_);
    return deadline_;
}

void MasqueHunt::append_best(std::vector<std::string>& logs) const {
    if (best_) logs.push_back(best_gateway_line(*best_));
}

HuntStep MasqueHunt::on_result(const ProbeResult& pr, time_point now) {
    HuntStep step;
    step.logs.push_back(candidate_ok_line(pr));
    if (done_) {
        step.done = true;
        step.pick = result_;
        return step;
    }

    if (st_.early_exit_first) {
        step.done = true;
        step.early_exit = true;
        step.pick = pr;
        result_ = pr;
        done_ = true;
        return step;
    }

    best_ = best_ ? best_of(*best_, pr) : pr;
    ++found_;

    bool terminate = false;
    if (st_.target_successes > 0 && found_ >= st_.target_successes && !quiet_until_) {
        step.logs.push_back(reached_target_line(st_.target_successes));
        if (st_.quiet_after_first != std::chrono::milliseconds{0}) {
            quiet_until_ = now + st_.quiet_after_first;
        } else {
            terminate = true;
        }
    }

    if (terminate) {
        done_ = true;
        result_ = best_;
        append_best(step.logs);
        step.done = true;
        step.pick = result_;
    }
    return step;
}

HuntStep MasqueHunt::on_timeout(time_point /*now*/) {
    HuntStep step;
    if (best_) {
        step.logs.push_back(quiet_until_
                                ? "[+] no new gateways recently, finalizing selection"
                                : "[-] scan deadline reached");
    } else {
        step.logs.push_back("[-] scan deadline reached with no gateway");
    }
    append_best(step.logs);
    done_ = true;
    result_ = best_;
    step.done = true;
    step.pick = result_;
    return step;
}

HuntStep MasqueHunt::on_exhausted() {
    HuntStep step;
    append_best(step.logs);
    done_ = true;
    result_ = best_;
    step.done = true;
    step.pick = result_;
    return step;
}

WgHunt::WgHunt(const WgStrategy& st, std::size_t want, time_point start)
    : st_(st), want_(std::max<std::size_t>(want, 1)), deadline_(start + st.overall_deadline) {
    // hunt_wg_endpoints widens the search once asked for more than one endpoint.
    if (want_ > 1) {
        st_.early_exit_first = false;
        st_.target_successes = std::max(st_.target_successes, want_ * 3);
    }
}

time_point WgHunt::next_wake() const {
    if (quiet_until_) return std::min(*quiet_until_, deadline_);
    return deadline_;
}

std::vector<WgProbeResult> WgHunt::pick() const {
    auto picked = distinct_by_ip(verified_);
    if (picked.size() > want_) picked.resize(want_);
    return picked;
}

void WgHunt::append_picks(std::vector<std::string>& logs) const {
    for (const auto& pr : pick()) logs.push_back(wg_endpoint_line(pr));
}

WgHuntStep WgHunt::on_result(const WgProbeResult& pr, time_point now) {
    WgHuntStep step;
    step.logs.push_back(wg_candidate_ok_line(pr));
    if (done_) {
        step.done = true;
        step.picks = result_;
        return step;
    }

    if (st_.early_exit_first) {
        done_ = true;
        result_ = {pr};
        step.done = true;
        step.early_exit = true;
        step.picks = result_;
        return step;
    }

    verified_.push_back(pr);
    ++found_;

    bool terminate = false;
    if (distinct_by_ip(verified_).size() >= want_ && want_ > 1) {
        step.logs.push_back(wg_found_separate_line(want_));
        terminate = true;
    }

    if (!terminate && st_.target_successes > 0 && found_ >= st_.target_successes &&
        !quiet_until_) {
        step.logs.push_back(wg_reached_target_line(st_.target_successes));
        if (st_.quiet_after_first != std::chrono::milliseconds{0}) {
            quiet_until_ = now + st_.quiet_after_first;
        } else {
            terminate = true;
        }
    }

    if (terminate) {
        done_ = true;
        result_ = pick();
        append_picks(step.logs);
        step.done = true;
        step.picks = result_;
    }
    return step;
}

WgHuntStep WgHunt::on_timeout(time_point /*now*/) {
    WgHuntStep step;
    if (!verified_.empty()) {
        step.logs.push_back(quiet_until_ ? "[+] no new endpoints recently, finalizing selection"
                                         : "[-] scan deadline reached");
    } else {
        step.logs.push_back("[-] scan deadline reached with no endpoint");
    }
    append_picks(step.logs);
    done_ = true;
    result_ = pick();
    step.done = true;
    step.picks = result_;
    return step;
}

WgHuntStep WgHunt::on_exhausted() {
    WgHuntStep step;
    append_picks(step.logs);
    done_ = true;
    result_ = pick();
    step.done = true;
    step.picks = result_;
    return step;
}

// ---- ironclad HTTP probe --------------------------------------------------------------------

std::uint16_t http_probe_port(const Settings& settings) {
    // Rust does not trim here: `var().and_then(|v| v.parse()).unwrap_or(80)`, so " 80 " or "80\n"
    // fail their u16 parse and fall back to 80. The raw value is read strictly for that reason.
    const auto raw = settings.get("AETHER_IRONCLAD_PORT");
    if (!raw || raw->empty()) return 80;
    std::uint32_t value = 0;
    const auto parsed = std::from_chars(raw->data(), raw->data() + raw->size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != raw->data() + raw->size() || value > 65535) {
        return 80;
    }
    return static_cast<std::uint16_t>(value);
}

std::string http_probe_request() {
    return "GET " + std::string(HTTP_PROBE_PATH) + " HTTP/1.1\r\nHost: " +
           std::string(HTTP_PROBE_HOST) + "\r\nConnection: close\r\nUser-Agent: aether-ironclad\r\n\r\n";
}

bool http_probe_should_stop(std::string_view buffer) {
    return buffer.find("\r\n") != std::string_view::npos || buffer.size() >= 128;
}

std::string first_status_line(std::string_view response) {
    const std::size_t newline = response.find('\n');
    return std::string(trim(response.substr(0, newline)));
}

std::optional<std::uint16_t> http_status_code(std::string_view status_line) {
    // `status_line.split(' ')`: first token must start with "HTTP/", second parsed strictly.
    const std::size_t space = status_line.find(' ');
    if (space == std::string_view::npos) {
        // One token only: it must start with HTTP/ and then there is no code, so nothing.
        return std::nullopt;
    }
    const std::string_view version = status_line.substr(0, space);
    if (!version.starts_with("HTTP/")) return std::nullopt;

    std::string_view rest = status_line.substr(space + 1);
    const std::size_t next_space = rest.find(' ');
    const std::string_view code =
        next_space == std::string_view::npos ? rest : rest.substr(0, next_space);
    if (code.empty()) return std::nullopt;

    std::uint32_t value = 0;
    const auto parsed = std::from_chars(code.data(), code.data() + code.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != code.data() + code.size() || value > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

bool http_probe_passed(std::string_view response) {
    return http_status_code(first_status_line(response)) == 204;
}

// ---- log / message text builders ------------------------------------------------------------

std::string format_duration_debug(std::chrono::milliseconds ms) {
    const auto total = static_cast<std::int64_t>(ms.count());
    if (total == 0) return "0ns";
    // Only non-negative durations are formatted here (Rust's Duration cannot be negative).
    const std::uint64_t value = static_cast<std::uint64_t>(total);
    const std::uint64_t secs = value / 1000;
    const std::uint32_t nanos = static_cast<std::uint32_t>((value % 1000) * 1'000'000);

    if (secs > 0) {
        if (nanos == 0) return std::to_string(secs) + "s";
        std::string frac = std::format("{:09}", nanos);
        while (frac.size() > 1 && frac.back() == '0') frac.pop_back();
        return std::to_string(secs) + "." + frac + "s";
    }
    return std::to_string(value) + "ms";
}

std::string format_ports(const std::vector<std::uint16_t>& ports) {
    std::string out = "[";
    for (std::size_t i = 0; i < ports.size(); ++i) {
        if (i != 0) out += ", ";
        out += std::to_string(ports[i]);
    }
    out += "]";
    return out;
}

std::string render_ip(const IpAddress& ip) {
    if (ip.v4) {
        return std::format("{}.{}.{}.{}", static_cast<int>(ip.bytes[12]),
                           static_cast<int>(ip.bytes[13]), static_cast<int>(ip.bytes[14]),
                           static_cast<int>(ip.bytes[15]));
    }

    std::uint16_t groups[8]{};
    for (int i = 0; i < 8; ++i) {
        groups[i] = static_cast<std::uint16_t>((ip.bytes[2 * i] << 8) | ip.bytes[2 * i + 1]);
    }
    // Rust's Ipv6Addr Display compresses the single longest run of >= 2 zero groups, leftmost on a
    // tie, per RFC 5952.
    int best_start = -1;
    int best_len = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] == 0) {
            int j = i;
            while (j < 8 && groups[j] == 0) ++j;
            if (j - i > best_len) {
                best_len = j - i;
                best_start = i;
            }
            i = j;
        } else {
            ++i;
        }
    }

    const auto hex = [](std::uint16_t g) { return std::format("{:x}", g); };
    std::string out;
    if (best_len < 2) {
        for (int i = 0; i < 8; ++i) {
            if (i != 0) out += ":";
            out += hex(groups[i]);
        }
        return out;
    }
    for (int i = 0; i < best_start; ++i) {
        if (!out.empty()) out += ":";
        out += hex(groups[i]);
    }
    out += "::";
    bool first = true;
    for (int i = best_start + best_len; i < 8; ++i) {
        if (!first) out += ":";
        out += hex(groups[i]);
        first = false;
    }
    return out;
}

std::string scan_line(std::string_view mode_label, IpScan ip, std::size_t candidates,
                     const std::vector<std::uint16_t>& ports, std::size_t concurrency,
                     std::chrono::milliseconds per_probe, std::chrono::milliseconds budget) {
    return "[*] scan mode=" + std::string(mode_label) + " ip=" + std::string(ip_scan_label(ip)) +
           " candidates=" + std::to_string(candidates) + " ports=" + format_ports(ports) +
           " concurrency=" + std::to_string(concurrency) + " per_probe=" +
           format_duration_debug(per_probe) + " budget=" + format_duration_debug(budget);
}

std::string wg_scan_line(std::string_view mode_label, IpScan ip, std::size_t candidates,
                        const std::vector<std::uint16_t>& ports, std::size_t concurrency,
                        std::chrono::milliseconds per_probe, std::chrono::milliseconds budget) {
    return "[*] wireguard scan mode=" + std::string(mode_label) + " ip=" +
           std::string(ip_scan_label(ip)) + " candidates=" + std::to_string(candidates) +
           " ports=" + format_ports(ports) + " concurrency=" + std::to_string(concurrency) +
           " per_probe=" + format_duration_debug(per_probe) + " budget=" +
           format_duration_debug(budget);
}

std::string candidate_ok_line(const ProbeResult& pr) {
    return "[+] candidate ok " + ip_port(pr) + rtt_str(pr);
}

std::string wg_candidate_ok_line(const WgProbeResult& pr) {
    return "[+] wg candidate ok " + ip_port(pr) + rtt_str(pr);
}

std::string best_gateway_line(const ProbeResult& pr) {
    return "[+] best gateway " + ip_port(pr) + rtt_str(pr);
}

std::string wg_endpoint_line(const WgProbeResult& pr) {
    return "[+] wg endpoint " + ip_port(pr) + rtt_str(pr);
}

std::string reached_target_line(std::size_t target) {
    return "[+] reached target of " + std::to_string(target) + " gateways, selecting best";
}

std::string wg_reached_target_line(std::size_t target) {
    return "[+] reached target of " + std::to_string(target) + " endpoints, selecting best";
}

std::string wg_found_separate_line(std::size_t want) {
    return "[+] found " + std::to_string(want) + " endpoints on separate addresses";
}

std::string ironclad_verified_line(const ProbeResult& pr) {
    return "[+] ironclad verified " + ip_port(pr) + " real http round trip" + rtt_str(pr);
}

std::string wg_ironclad_verified_line(const WgProbeResult& pr) {
    return "[+] ironclad verified wg " + ip_port(pr) + " real http round trip" + rtt_str(pr);
}

} // namespace aether::core::prober
