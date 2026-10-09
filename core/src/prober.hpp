#pragma once

// Port of the scanning / endpoint-selection logic of prober.rs, plus the pure parts of
// wg_prober.rs and tunnelping.rs. Anything that needs a live socket, a QUIC/WireGuard session or
// a spawned task -- the real probes (verify_one / verify_one_wg / the verify_masque and h2 calls),
// host_has_ipv6(), the netstack + tunnel spawn inside masque_http_ping / wg_http_ping_established,
// and the async hunt_* loops themselves -- is left to the engine: this module gives it the exact
// decisions (candidate lists, budget/RTT/target state machine, ranking, the ironclad HTTP verdict)
// so they can be driven and tested without a network.

#include "aethernoize.hpp"
#include "dns.hpp"
#include "noize.hpp"
#include "settings.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aether::core::prober {

// Nested in `prober` on purpose: `aether::ScanMode` already exists in include/types.hpp (the
// supervisor's reduced enum that drops several Rust aliases), so the faithful full-mode enums live
// here to avoid an ambiguous `ScanMode`.

// A steady clock; every decision that turns on time takes `now` as a parameter so it is testable
// without sleeping, exactly like Rust's Instant arithmetic but injectable.
using clock = std::chrono::steady_clock;
using time_point = clock::time_point;

// A candidate is an address and a port to probe, the same pair Rust threads through the scan.
using Candidate = std::pair<IpAddress, std::uint16_t>;

// ---- constants a caller reads (prober.rs) ---------------------------------------------------

inline constexpr std::string_view MASQUE_DOCUMENTED_CIDRS_V4[] = {"162.159.197.0/24",
                                                                  "162.159.198.0/24"};

inline constexpr std::string_view MASQUE_DOH_CIDRS_V4[] = {"162.159.36.0/24", "162.159.46.0/24"};

inline constexpr std::string_view MASQUE_CIDRS_V4[] = {
    "162.159.196.0/24", "162.159.195.0/24", "162.159.192.0/24", "162.159.193.0/24",
    "162.159.204.0/24", "162.159.197.0/24", "162.159.198.0/24", "172.65.251.0/24",
    "188.114.96.0/24",  "188.114.97.0/24",  "188.114.98.0/24",  "188.114.99.0/24",
    "162.159.36.0/24",  "162.159.46.0/24",
};

inline constexpr std::string_view MASQUE_SEEDS[] = {
    "162.159.196.1", "162.159.195.1", "162.159.192.1", "162.159.197.3",
    "162.159.197.1", "162.159.198.2", "162.159.198.1", "162.159.193.1",
};

inline constexpr std::string_view MASQUE_VERIFIED_GATEWAYS[] = {
    "162.159.199.1", "162.159.199.2", "162.159.198.2", "162.159.198.1",
};

inline constexpr std::uint16_t MASQUE_ALT_PORTS[] = {1701, 8095, 500, 4500};

inline constexpr std::uint16_t MASQUE_PORTS[] = {443, 500, 1701, 4500, 4443, 8443, 8095};

inline constexpr std::string_view MASQUE_CIDRS_V6[] = {"2606:4700:d0::/48", "2606:4700:102::/48",
                                                      "2606:4700:d1::/48"};

inline constexpr std::string_view MASQUE_ZT_CIDRS_V4[] = {"162.159.197.0/24"};

inline constexpr std::string_view MASQUE_ZT_CIDRS_V6[] = {"2606:4700:102::/48"};

inline constexpr std::string_view MASQUE_SEEDS_V6[] = {
    "2606:4700:d0::a29f:c602", "2606:4700:d1::a29f:c602", "2606:4700:d0::a29f:c601",
    "2606:4700:d0::a29f:c001",
};

// The tcping budget a single ironclad round trip gets, from prober.rs.
inline constexpr std::chrono::milliseconds IRONCLAD_TCPING_TIMEOUT{10'000};
// The same budget for the WireGuard scan, from wg_prober.rs.
inline constexpr std::chrono::milliseconds WG_IRONCLAD_TCPING_TIMEOUT{10'000};

// ---- constants a caller reads (tunnelping.rs) -----------------------------------------------

inline constexpr int PING_MTU = 1280;
inline constexpr std::string_view HTTP_PROBE_HOST = "www.gstatic.com";
inline constexpr std::string_view HTTP_PROBE_PATH = "/generate_204";
// The http probe gives the response six seconds before it calls it a timeout.
inline constexpr std::chrono::seconds HTTP_PROBE_DEADLINE{6};

// ---- zero-trust prioritisation (prober.rs) --------------------------------------------------

// AETHER_TEAM set to anything but whitespace, exactly as zero_trust_mode() reads it.
[[nodiscard]] bool zero_trust_mode(const Settings& settings);

// The `all` list with every `first` entry that appears in it moved to the front, in `first`'s
// order, and the rest left in `all`'s order. Without a team the list is left alone. String
// equality is exact and case sensitive, matching Rust's `contains`.
[[nodiscard]] std::vector<std::string_view> prioritize(std::vector<std::string_view> all,
                                                       std::vector<std::string_view> first,
                                                       bool zero_trust);

[[nodiscard]] std::vector<std::string_view> masque_cidrs_v4(bool zero_trust);
[[nodiscard]] std::vector<std::string_view> masque_cidrs_v6(bool zero_trust);

// ---- scan switches (prober.rs / wg_prober.rs) -----------------------------------------------

enum class IpScan { V4, V6, Both };

// `s` trimmed and lower-cased: "6"/"v6"/"ipv6" is V6, "both"/"all"/"dual" is Both, anything else
// (including "4"/"v4"/"ipv4") is V4.
[[nodiscard]] IpScan ip_scan_parse(std::string_view s);
[[nodiscard]] std::string_view ip_scan_label(IpScan ip);
[[nodiscard]] bool ip_scan_want_v4(IpScan ip);
[[nodiscard]] bool ip_scan_want_v6(IpScan ip);

// The IPv6-fallback decision hunt_* makes once it knows whether the host has a native v6 route.
// Returns the effective scan family and the warn line the Rust core prints; `nullopt` means the
// scan cannot go on (IPv6-only on a host with no IPv6 route).
struct EffectiveIp {
    IpScan ip = IpScan::V4;
    bool ok = true; // false == NoCleanEndpoint
    std::string log;
};
[[nodiscard]] EffectiveIp effective_ip(IpScan requested, bool host_has_ipv6);

enum class ScanMode { Turbo, Balanced, Thorough, Verified, Ironclad };

// All of Rust's aliases: turbo|fast, thorough|deep|pro, verified|proven|stealth|quiet,
// ironclad|real|verify|guaranteed, and balanced for anything else.
[[nodiscard]] ScanMode scan_mode_parse(std::string_view s);
[[nodiscard]] std::string_view scan_mode_label(ScanMode mode);

struct Strategy {
    std::size_t concurrency = 0;
    std::chrono::milliseconds per_probe_timeout{0};
    std::chrono::milliseconds overall_deadline{0};
    std::chrono::milliseconds quiet_after_first{0};
    std::size_t target_successes = 0;
    bool early_exit_first = false;
    bool full_subnet = false;
    std::size_t sample_per_cidr = 0;

    [[nodiscard]] bool operator==(const Strategy&) const = default;
};

[[nodiscard]] Strategy scan_strategy(ScanMode mode);

enum class WgScanMode { Turbo, Balanced, Thorough, Verified, Ironclad };

[[nodiscard]] WgScanMode wg_scan_mode_parse(std::string_view s);
[[nodiscard]] std::string_view wg_scan_mode_label(WgScanMode mode);

struct WgStrategy {
    std::size_t concurrency = 0;
    std::chrono::milliseconds per_probe_timeout{0};
    std::chrono::milliseconds overall_deadline{0};
    std::chrono::milliseconds quiet_after_first{0};
    std::size_t target_successes = 0;
    bool early_exit_first = false;
    bool full_subnet = false;
    std::size_t sample_per_cidr = 0;
    std::size_t pool_port_waves = 0;

    [[nodiscard]] bool operator==(const WgStrategy&) const = default;
};

[[nodiscard]] WgStrategy wg_scan_strategy(WgScanMode mode);

// ---- results and ranking --------------------------------------------------------------------

struct ProbeResult {
    IpAddress ip;
    std::uint16_t port = 0;
    std::chrono::milliseconds rtt{0};

    [[nodiscard]] bool operator==(const ProbeResult&) const = default;
};

// Rust's separate WgProbeResult carries the same three fields.
using WgProbeResult = ProbeResult;

// The quicker of two results, keeping `cur` on a tie exactly like Rust's `cur.rtt <= pr.rtt` guard.
[[nodiscard]] ProbeResult best_of(const ProbeResult& cur, const ProbeResult& next);

// Order verified endpoints by RTT, then keep the quickest one per address. A stable sort means a
// tie keeps the order the results arrived in.
[[nodiscard]] std::vector<WgProbeResult> distinct_by_ip(const std::vector<WgProbeResult>& found);

// ---- candidate construction -----------------------------------------------------------------

// A generator of 32-bit randomness, injected so sampling is testable. Rust reaches for the global
// rand::rng(); here the caller supplies one (see default_random()).
using Random = std::function<std::uint32_t()>;

// A process-wide random source for the engine's use; the decision functions take their own.
[[nodiscard]] Random default_random();

[[nodiscard]] std::optional<std::pair<std::uint32_t, std::uint8_t>> parse_cidr_v4(
    std::string_view cidr);
[[nodiscard]] std::optional<std::pair<IpAddress, std::uint8_t>> parse_cidr_v6(
    std::string_view cidr);

// The usable hosts of a v4 CIDR: 1 .. size-2 (network and broadcast excluded), refusing ranges
// wider than a /20 (host_bits > 12) as Rust does. Empty on a bad CIDR.
[[nodiscard]] std::vector<IpAddress> enumerate_cidr_v4(std::string_view cidr);

// Up to `n` distinct hosts sampled from a v4 CIDR, offsets in 1 .. size-2. A CIDR with room for
// two or fewer addresses yields just the base.
[[nodiscard]] std::vector<IpAddress> sample_cidr_v4(std::string_view cidr, std::size_t n,
                                                   const Random& rng);

// Up to `n` addresses inside a v6 CIDR, the low 32 bits filled from a v4 host drawn at random out
// of `v4_cidrs` (or a bare random u32 when there are none), so v6 probes reuse the v4 edge space.
[[nodiscard]] std::vector<IpAddress> sample_cidr_v6(std::string_view cidr, std::size_t n,
                                                   std::vector<std::string_view> v4_cidrs,
                                                   const Random& rng);

// The MASQUE candidate list: seeds on the primary port, then the per-CIDR hosts round-robin
// across families, then the alternate ports over the seeds. Every entry de-duplicated.
[[nodiscard]] std::vector<Candidate> build_candidates(const Strategy& st,
                                                      const std::vector<std::uint16_t>& ports,
                                                      IpScan ip, bool zero_trust,
                                                      const Random& rng);

// The tables wireguard.rs owns, resolved by that module and handed in here so the WG scan can be
// built without prober.rs duplicating them. anchors_v4/prefixes_v4/prefixes_v6 are the already
// prioritized lists; anchors_v6 (WG_SEEDS_V6) and embed_v4 (WG_PREFIXES_V4) are the raw ones, as
// wg_prober.rs reads them.
struct WgCandidateSources {
    std::vector<std::string_view> anchors_v4;
    std::vector<std::string_view> prefixes_v4;
    std::vector<std::string_view> anchors_v6;
    std::vector<std::string_view> prefixes_v6;
    std::vector<std::string_view> embed_v4;
};

// The WireGuard candidate list: anchors and sampled pool merged, de-duplicated by address, then
// each address tried on a rotated port across up to pool_port_waves waves, cooling-down (excluded)
// endpoints skipped. An empty port list falls back to the WG default port 2408.
[[nodiscard]] std::vector<Candidate> build_wg_candidates(
    const WgStrategy& st, const std::vector<std::uint16_t>& ports, IpScan ip,
    const std::vector<Candidate>& excluded, const WgCandidateSources& sources, const Random& rng);

// ---- hunt state machine (the pure core of the async hunt_* loops) ---------------------------

// The engine drives these with each probe result as the real verify_one / verify_one_wg futures
// complete, and calls on_timeout() when the wake time next_wake() returns has passed, or
// on_exhausted() when the candidate stream runs dry. `result()` then gives the pick, and an empty
// result is AetherError::NoCleanEndpoint. The log lines Rust emits are returned in step order.

struct HuntStep {
    bool done = false;      // stop feeding the loop
    bool early_exit = false; // return this pick straight away, skipping the finalise lines
    std::vector<std::string> logs;
    std::optional<ProbeResult> pick; // for MasqueHunt; nullopt once done == no clean endpoint
};

struct WgHuntStep {
    bool done = false;
    bool early_exit = false;
    std::vector<std::string> logs;
    std::vector<WgProbeResult> picks; // up to `want` distinct addresses; empty == none found
};

class MasqueHunt {
public:
    MasqueHunt(const Strategy& st, time_point start);

    // A successful probe observed at `now` (only Ok results are fed in, as Rust does).
    [[nodiscard]] HuntStep on_result(const ProbeResult& pr, time_point now);
    // The budget expired at `now`: the quiet-after-first window or the overall deadline.
    [[nodiscard]] HuntStep on_timeout(time_point now);
    // No candidates left to try.
    [[nodiscard]] HuntStep on_exhausted();

    // When the loop must give up: min(quiet_until, deadline). Already-expired budgets are the
    // engine's to notice by calling on_timeout().
    [[nodiscard]] time_point next_wake() const;
    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] std::optional<ProbeResult> result() const { return result_; }

private:
    void append_best(std::vector<std::string>& logs) const;

    Strategy st_;
    time_point deadline_;
    std::optional<ProbeResult> best_;
    std::size_t found_ = 0;
    std::optional<time_point> quiet_until_;
    bool done_ = false;
    std::optional<ProbeResult> result_;
};

class WgHunt {
public:
    WgHunt(const WgStrategy& st, std::size_t want, time_point start);

    [[nodiscard]] WgHuntStep on_result(const WgProbeResult& pr, time_point now);
    [[nodiscard]] WgHuntStep on_timeout(time_point now);
    [[nodiscard]] WgHuntStep on_exhausted();

    [[nodiscard]] time_point next_wake() const;
    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] std::vector<WgProbeResult> result() const { return result_; }

private:
    std::vector<WgProbeResult> pick() const;
    void append_picks(std::vector<std::string>& logs) const;

    WgStrategy st_;
    std::size_t want_;
    time_point deadline_;
    std::vector<WgProbeResult> verified_;
    std::size_t found_ = 0;
    std::optional<time_point> quiet_until_;
    bool done_ = false;
    std::vector<WgProbeResult> result_;
};

// ---- ironclad HTTP probe (tunnelping.rs) ----------------------------------------------------

// AETHER_IRONCLAD_PORT parsed strictly as u16, defaulting to 80; no trimming, matching Rust's
// var().and_then(parse).unwrap_or(80).
[[nodiscard]] std::uint16_t http_probe_port(const Settings& settings);

// The exact bytes ironclad sends to prove the edge carries real traffic.
[[nodiscard]] std::string http_probe_request();

// The read loop stops once the buffer holds a "\r\n" or reaches 128 bytes.
[[nodiscard]] bool http_probe_should_stop(std::string_view buffer);

// The trimmed first line of a response, what the verdict reads.
[[nodiscard]] std::string first_status_line(std::string_view response);

// `HTTP/x.y CODE ...` -> CODE; nothing when the line is not a status line or the code is not u16.
[[nodiscard]] std::optional<std::uint16_t> http_status_code(std::string_view status_line);

// Whether a full response body means the probe passed: its first status line reads 204.
[[nodiscard]] bool http_probe_passed(std::string_view response);

// What one edge is pinged with, over either carrier. `timeout` bounds the whole attempt. The
// engine opens the throwaway tunnel with these and feeds the answer to http_probe_passed.
// Aliased: a member named `noize` would otherwise hide the namespace it is typed from.
using NoizeConfig = ::aether::core::noize::NoizeConfig;
using AetherNoizeConfig = ::aether::core::aethernoize::AetherNoizeConfig;

struct MasquePingParams {
    SocketAddr peer;
    std::string sni;
    std::string authority;
    std::string path;
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    // The ECHConfigList the handshake offers, that of the scan the check is part of.
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    NoizeConfig noize;
    IpAddress local_ipv4;
    std::string local_ipv4_text;
    std::string local_ipv6_text;
    std::chrono::milliseconds timeout{5000};
};

struct WgPingParams {
    IpAddress local_ipv4;
    IpAddress local_ipv6;
    AetherNoizeConfig aethernoize;
    std::chrono::milliseconds timeout{5000};
};

// ---- log / message text builders (Rust's exact strings) -------------------------------------

// Duration as Rust's {:?} prints it (whole ms granularity: "6s", "1.5s", "5ms", "0ns").
[[nodiscard]] std::string format_duration_debug(std::chrono::milliseconds ms);
// A port list as Rust's {:?} prints a Vec<u16>: "[443, 500]".
[[nodiscard]] std::string format_ports(const std::vector<std::uint16_t>& ports);
// An address as Rust's IpAddr Display prints it: dotted decimal, or compressed lower-case IPv6.
[[nodiscard]] std::string render_ip(const IpAddress& ip);

[[nodiscard]] std::string scan_line(std::string_view mode_label, IpScan ip, std::size_t candidates,
                                    const std::vector<std::uint16_t>& ports, std::size_t concurrency,
                                    std::chrono::milliseconds per_probe,
                                    std::chrono::milliseconds budget);
[[nodiscard]] std::string wg_scan_line(std::string_view mode_label, IpScan ip, std::size_t candidates,
                                       const std::vector<std::uint16_t>& ports,
                                       std::size_t concurrency, std::chrono::milliseconds per_probe,
                                       std::chrono::milliseconds budget);

[[nodiscard]] std::string candidate_ok_line(const ProbeResult& pr);
[[nodiscard]] std::string wg_candidate_ok_line(const WgProbeResult& pr);
[[nodiscard]] std::string best_gateway_line(const ProbeResult& pr);
[[nodiscard]] std::string wg_endpoint_line(const WgProbeResult& pr);
[[nodiscard]] std::string reached_target_line(std::size_t target); // "... gateways, selecting best"
[[nodiscard]] std::string wg_reached_target_line(std::size_t target); // "... endpoints, ..."
[[nodiscard]] std::string wg_found_separate_line(std::size_t want);
[[nodiscard]] std::string ironclad_verified_line(const ProbeResult& pr);
[[nodiscard]] std::string wg_ironclad_verified_line(const WgProbeResult& pr);

// The no-IPv6 warn lines effective_ip() produces, exposed so callers and tests share one copy.
inline constexpr std::string_view FALLBACK_TO_V4_LOG =
    "[-] host has no IPv6 route; falling back to IPv4-only scan";
inline constexpr std::string_view NO_V6_ROUTE_LOG =
    "[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity";

} // namespace aether::core::prober
