// Port of the orchestrator of hemera/src/lib.rs (pinned commit 6175b67). See coreflow.hpp for
// what is here, what is a seam, and what was deliberately left out.
//
// Two shapes of environment read appear throughout, and mixing them up changes behaviour:
//
//   raw(settings, key)     Rust's `std::env::var(k).ok()`. The value as it stands, present even
//                          when it is the empty string, and no trimming. lib.rs uses this for
//                          HEMERA_PEER, HEMERA_WG_PEER, HEMERA_PROTOCOL, HEMERA_NOIZE,
//                          HEMERA_GOOL_MODE, HEMERA_REPROVISION, HEMERA_QUICK_RECONNECT,
//                          HEMERA_CONFIG, HEMERA_WG_CONFIG, HEMERA_MASQUE_CONFIG, HEMERA_SOCKS,
//                          HEMERA_SCAN, HEMERA_IP, HEMERA_ECH, HEMERA_LOG_LEVEL, the presence
//                          checks of HEMERA_TEAM_ENDPOINT / HEMERA_MASQUE_HTTP2 / HEMERA_GATEWAY
//                          / HEMERA_WG_NO_PROFILE_RETRY, and the six second-valued knobs, which
//                          are read raw and then parsed without trimming.
//   env_value(settings, k) lib.rs's own helper: trimmed, and nothing when it trims to empty.
//                          HEMERA_REGISTER, the four warp-in-warp and four masque-in-masque
//                          endpoint keys, HEMERA_GOOL_INNER and the three gool_classic keys.
//
// One exception: HEMERA_MASQUE_MTU is read raw and then trimmed before it is parsed, which is
// what masque_tunnel_mtu does in the Rust.

#include "coreflow.hpp"

#include "consts.hpp"
#include "egress.hpp"
#include "stats.hpp"
#include "sysprofile.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <filesystem>
#include <vector>

namespace hemera::core::coreflow {
namespace {

// ---- the two environment readings -----------------------------------------------------------

[[nodiscard]] std::optional<std::string> raw(const Settings& settings, std::string_view key) {
    const std::string* found = settings.find(key);
    if (found == nullptr) return std::nullopt;
    return *found;
}

[[nodiscard]] bool has_key(const Settings& settings, std::string_view key) {
    return settings.find(key) != nullptr;
}

[[nodiscard]] std::string trim_str(std::string_view text) {
    return std::string(::hemera::core::trim(text));
}

[[nodiscard]] std::string lower(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

[[nodiscard]] bool eq_ignore(std::string_view left, std::string_view right) {
    return left.size() == right.size() && lower(left) == lower(right);
}

[[nodiscard]] bool ends_with(std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

[[nodiscard]] bool starts_with(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

// ---- the renderings a Rust format string used ------------------------------------------------

[[nodiscard]] std::string num(std::uint64_t value) { return std::to_string(value); }

// `{peer}` in Rust, which is SocketAddr's Display: `[v6]:port`, `v4:port`.
[[nodiscard]] std::string addr(const SocketAddr& peer) { return peer.to_string(); }

// `{ip}` in Rust, which is IpAddr's Display.
[[nodiscard]] std::string iptext(const IpAddress& ip) { return prober::render_ip(ip); }

// `{:?}` on a Duration in Rust.
[[nodiscard]] std::string dur(std::chrono::milliseconds ms) {
    return prober::format_duration_debug(ms);
}
[[nodiscard]] std::string dur(std::chrono::seconds secs) {
    return prober::format_duration_debug(std::chrono::duration_cast<std::chrono::milliseconds>(secs));
}

[[nodiscard]] std::string join(const std::vector<std::string>& parts, std::string_view separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out.append(separator);
        out.append(parts[i]);
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> bytes(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

[[nodiscard]] IpAddress unspecified_v4() {
    IpAddress ip{};
    ip.v4 = true;
    return ip;
}

[[nodiscard]] std::size_t sat_sub(std::size_t left, std::size_t right) {
    return left < right ? 0 : left - right;
}

[[nodiscard]] std::size_t clamp(std::size_t value, std::size_t low, std::size_t high) {
    return value < low ? low : (value > high ? high : value);
}

template <typename T>
[[nodiscard]] bool contains(const std::vector<T>& values, const T& wanted) {
    return std::find(values.begin(), values.end(), wanted) != values.end();
}

[[nodiscard]] std::vector<std::uint16_t> masque_ports() {
    return std::vector<std::uint16_t>(std::begin(prober::MASQUE_PORTS), std::end(prober::MASQUE_PORTS));
}

[[nodiscard]] std::vector<std::uint16_t> wg_ports() {
    return std::vector<std::uint16_t>(std::begin(wireguard::wg_ports), std::end(wireguard::wg_ports));
}

// lastconn::usable_peers hands back (address text, port) pairs; lib.rs holds SocketAddrs. An
// entry that is no longer an address is dropped here, as usable_peers already dropped it there.
[[nodiscard]] std::vector<SocketAddr> ring_of(const LastConnection& cached, std::string_view carrier) {
    std::vector<SocketAddr> ring;
    for (const auto& entry : ::hemera::core::usable_peers(cached, carrier)) {
        if (auto ip = ::hemera::core::parse_address(entry.first)) {
            ring.push_back(SocketAddr{*ip, entry.second});
        }
    }
    return ring;
}

// A prompt seam that was not supplied reads as a closed stdin, which is what prompt_line does
// when stdin is no terminal.
[[nodiscard]] std::optional<std::string> ask(const PromptLine& prompt, std::string_view text) {
    if (!prompt) return std::nullopt;
    return prompt(text);
}

// The two messages the port needs for a seam the engine did not supply. Neither has a Rust
// counterpart: a missing std::function is a wiring mistake, and saying so beats calling it.
constexpr std::string_view NO_BIND_SEAM = "coreflow was given no listener seam to check with";
constexpr std::string_view NO_ACCOUNT_SEAM = "coreflow was given no account exchange to call";

// ---- the phase numbers of the four flows ----------------------------------------------------

constexpr int PH_NONE = 0;

// MasqueFlow
constexpr int MA_ASSIGNED = 1;
constexpr int MA_RING = 2;
constexpr int MA_LASTGOOD = 3;
constexpr int MA_HUNT = 4;
constexpr int MA_TUNNEL = 5;
constexpr int MA_SLEEP_RETRY = 6;
constexpr int MA_SLEEP_END = 7;
constexpr int MA_SAVE = 8;

// WireguardFlow
constexpr int WG_ASSIGNED = 1;
constexpr int WG_RING = 2;
constexpr int WG_LASTGOOD = 3;
constexpr int WG_HUNT = 4;
constexpr int WG_TUNNEL = 5;
constexpr int WG_SLEEP_RETRY = 6;
constexpr int WG_SLEEP_END = 7;
constexpr int WG_SAVE = 8;
constexpr int WG_FORCED = 9;

// GoolFlow
constexpr int GO_HUNT = 4;
constexpr int GO_TUNNEL = 5;
constexpr int GO_SLEEP = 7;

// MimFlow
constexpr int MI_HUNT = 4;
constexpr int MI_TUNNEL = 5;
constexpr int MI_SLEEP = 7;

// Merges `from` into `into`: the notes go on the end and the request, if there is one, is taken.
// Every helper of a flow returns a FlowStep and the caller hands it back up, so this is what keeps
// the notes of a whole step together.
[[nodiscard]] FlowStep merge_into(FlowStep into, FlowStep&& from) {
    for (auto& note : from.notes) into.notes.push_back(std::move(note));
    if (from.request.has_value()) into.request = std::move(from.request);
    return into;
}

[[nodiscard]] FlowRequest sleep_request(std::chrono::seconds delay) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::Sleep;
    request.delay = delay;
    return request;
}

} // namespace

// ---- log lines ------------------------------------------------------------------------------

void note_debug(Notes& notes, std::string text) { notes.push_back(Note{Level::Debug, std::move(text)}); }
void note_info(Notes& notes, std::string text) { notes.push_back(Note{Level::Info, std::move(text)}); }
void note_warn(Notes& notes, std::string text) { notes.push_back(Note{Level::Warn, std::move(text)}); }
void note_error(Notes& notes, std::string text) { notes.push_back(Note{Level::Error, std::move(text)}); }

std::vector<std::string> texts(const Notes& notes) {
    std::vector<std::string> out;
    out.reserve(notes.size());
    for (const auto& note : notes) out.push_back(note.text);
    return out;
}

bool has_text(const Notes& notes, std::string_view needle) {
    for (const auto& note : notes) {
        if (note.text.find(needle) != std::string::npos) return true;
    }
    return false;
}

// ---- errors ---------------------------------------------------------------------------------

std::string Error::display() const {
    switch (kind) {
        case ErrorKind::Io:
            return "io: " + message;
        case ErrorKind::Quic:
            return "quic: " + message;
        case ErrorKind::H3:
            return "h3: " + message;
        case ErrorKind::Tls:
            return "tls: " + message;
        case ErrorKind::Ech:
            return "ech: " + message;
        case ErrorKind::Masque:
            return "masque: " + message;
        // The two variants that carry no message of their own.
        case ErrorKind::NoCleanEndpoint:
            return std::string(NO_CLEAN_ENDPOINT);
        case ErrorKind::Cancelled:
            return "cancelled";
        case ErrorKind::Capsule:
            return "capsule: " + message;
        case ErrorKind::Api:
            return "api: " + message;
        case ErrorKind::IdentityRefused:
            return "identity refused: " + message;
        case ErrorKind::Other:
            break;
    }
    return "other: " + message;
}

Error Error::other(std::string message) { return Error{ErrorKind::Other, std::move(message)}; }

Error Error::no_clean_endpoint() { return Error{ErrorKind::NoCleanEndpoint, {}}; }

Error Error::identity_refused(std::string reason) {
    return Error{ErrorKind::IdentityRefused, std::move(reason)};
}

// ---- seams ----------------------------------------------------------------------------------

void wire_signals(const Cancel& cancel, const SignalInstaller& installer) {
    if (installer) installer(cancel);
}

void unset(Settings& settings, std::string_view key) {
    settings.values.erase(std::string(key));
}

// ---- small readers of lib.rs ----------------------------------------------------------------

std::optional<std::string> env_value(const Settings& settings, std::string_view key) {
    const auto value = raw(settings, key);
    if (!value.has_value()) return std::nullopt;
    std::string trimmed = trim_str(*value);
    if (trimmed.empty()) return std::nullopt;
    return trimmed;
}

std::optional<std::uint64_t> parse_u64_strict(std::string_view text) {
    std::size_t index = 0;
    if (index < text.size() && text[index] == '+') ++index;
    if (index >= text.size()) return std::nullopt;

    constexpr std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t value = 0;
    for (; index < text.size(); ++index) {
        const char digit = text[index];
        if (digit < '0' || digit > '9') return std::nullopt;
        const auto add = static_cast<std::uint64_t>(digit - '0');
        if (value > (limit - add) / 10) return std::nullopt;
        value = value * 10 + add;
    }
    return value;
}

IpAddress parse_local_v4(std::string_view text) {
    const auto slash = text.find('/');
    const std::string_view head = slash == std::string_view::npos ? text : text.substr(0, slash);
    if (const auto ip = ::hemera::core::parse_address(head)) {
        if (ip->v4) return *ip;
    }
    return unspecified_v4();
}

bool scan_keyword(std::string_view value) {
    const std::string lowered = lower(value);
    return lowered == "auto" || lowered == "scan" || lowered == "none" || lowered == "off" ||
           lowered == "0";
}

bool wiw_scan_requested(const Settings& settings) {
    const auto value = env_value(settings, WIW_LIST_ENV);
    return value.has_value() && scan_keyword(*value);
}

std::size_t masque_tunnel_mtu(const Settings& settings) {
    if (const auto value = raw(settings, MTU_ENV)) {
        if (const auto parsed = parse_u64_strict(trim_str(*value))) {
            if (*parsed >= 576 && *parsed <= 1500) return static_cast<std::size_t>(*parsed);
        }
    }
    return masque_h2::enabled(settings) ? H2_TUNNEL_MTU : TUNNEL_MTU;
}

std::string_view masque_carrier(const Settings& settings) {
    return masque_h2::enabled(settings) ? ::hemera::core::CARRIER_MASQUE_H2
                                        : ::hemera::core::CARRIER_MASQUE_H3;
}

std::string derive_sibling_path(std::string_view base, std::string_view suffix) {
    std::size_t dir_end = 0;
    for (std::size_t i = base.size(); i-- > 0;) {
        if (base[i] == '/' || base[i] == '\\') {
            dir_end = i + 1;
            break;
        }
    }
    const std::string_view file = base.substr(dir_end);
    const auto dot = file.rfind('.');
    if (dot == std::string_view::npos) {
        return std::string(base) + "-" + std::string(suffix);
    }
    const std::size_t at = dir_end + dot;
    return std::string(base.substr(0, at)) + "-" + std::string(suffix) + std::string(base.substr(at));
}

std::string lastconn_path(std::string_view config_path) {
    return derive_sibling_path(config_path, "lastconn");
}

std::optional<std::string> team_scope(const Settings& settings) {
    const auto team = zerotrust::TeamSettings::from_env(settings);
    if (!team.has_value()) return std::nullopt;
    return team->team;
}

std::string warp_config_path(const Settings& settings, std::string_view base) {
    if (const auto path = raw(settings, WG_CONFIG_ENV)) return *path;
    if (const auto team = team_scope(settings)) return derive_sibling_path(base, "team-" + *team);
    return std::string(base);
}

std::string masque_config_path(const Settings& settings, std::string_view base) {
    if (const auto path = raw(settings, MASQUE_CONFIG_ENV)) return *path;
    if (const auto team = team_scope(settings)) return derive_sibling_path(base, "team-" + *team);
    return derive_sibling_path(base, "masque");
}

bool keep_saved_identity(const Settings& settings) {
    const auto value = raw(settings, REPROVISION_ENV);
    if (!value.has_value()) return true;
    return !(*value == "0" || *value == "off" || *value == "false");
}

bool gool_classic(const Settings& settings) {
    const auto mode = raw(settings, GOOL_MODE_ENV);
    if (mode.has_value() && (*mode == "wiw" || *mode == "wg" || *mode == "classic")) return true;
    for (const std::string_view key : {WIW_OUTER_ENV, WIW_INNER_ENV, WIW_LIST_ENV}) {
        if (env_value(settings, key).has_value()) return true;
    }
    return false;
}

std::string noize_profile(const Settings& settings) {
    return raw(settings, NOIZE_ENV).value_or("firewall");
}

std::string hemeranoize_profile(const Settings& settings) {
    return raw(settings, NOIZE_ENV).value_or("balanced");
}

std::string wg_primary_profile(const Settings& settings) {
    return raw(settings, NOIZE_ENV).value_or("balanced");
}

std::string noize_profile_line(std::string_view profile) {
    return "[+] obfuscation profile: " + std::string(profile);
}

std::string hemeranoize_profile_line(std::string_view profile) {
    return "[+] hemeranoize profile: " + std::string(profile);
}

std::string wg_primary_profile_line(std::string_view profile) {
    return "[+] hemeranoize primary profile: " + std::string(profile);
}

NoizeConfig noize_config(const Settings& settings, Notes& notes) {
    const std::string profile = noize_profile(settings);
    note_info(notes, noize_profile_line(profile));
    return noize::from_profile(profile);
}

HemeraNoizeConfig hemeranoize_config(const Settings& settings, Notes& notes) {
    const std::string profile = hemeranoize_profile(settings);
    note_info(notes, hemeranoize_profile_line(profile));
    return hemeranoize::from_profile(profile);
}

std::vector<std::pair<std::string, HemeraNoizeConfig>> wg_profile_candidates(const Settings& settings,
                                                                            Notes& notes) {
    const std::string primary = wg_primary_profile(settings);
    note_info(notes, wg_primary_profile_line(primary));

    std::vector<std::string> names{primary};
    if (!has_key(settings, NO_PROFILE_RETRY_ENV)) {
        for (const std::string_view fallback : {"balanced", "aggressive", "light", "off"}) {
            bool present = false;
            for (const auto& name : names) {
                if (eq_ignore(name, fallback)) {
                    present = true;
                    break;
                }
            }
            if (!present) names.emplace_back(fallback);
        }
    }

    std::vector<std::pair<std::string, HemeraNoizeConfig>> out;
    out.reserve(names.size());
    for (const auto& name : names) out.emplace_back(name, hemeranoize::from_profile(name));
    return out;
}

std::string base_config_path(const Settings& settings) {
    return raw(settings, CONFIG_ENV).value_or(std::string(DEFAULT_CONFIG));
}

SocketAddr socks_listen(const Settings& settings) {
    if (const auto value = raw(settings, SOCKS_ENV)) {
        if (const auto parsed = ::hemera::core::parse_socket_addr(*value)) return *parsed;
    }
    const auto fallback = ::hemera::core::parse_socket_addr(DEFAULT_SOCKS_LISTEN);
    return fallback.value_or(SocketAddr{});
}

HttpProxyListen http_proxy_listen(const Settings& settings) {
    const auto value = raw(settings, HTTP_PROXY_ENV);
    if (!value.has_value()) return {};
    const std::string trimmed = trim_str(*value);
    if (trimmed.empty()) return {};
    if (const auto parsed = ::hemera::core::parse_socket_addr(trimmed)) {
        return HttpProxyListen{*parsed, std::nullopt};
    }
    return HttpProxyListen{std::nullopt, unparsable_http_proxy_warning(trimmed)};
}

std::string unparsable_http_proxy_warning(std::string_view trimmed) {
    return "[-] ignoring an unparsable http proxy address: " + std::string(trimmed);
}

std::string log_level_of(const Settings& settings) {
    if (const auto value = raw(settings, LOG_LEVEL_ENV)) {
        const std::string lowered = lower(trim_str(*value));
        if (lowered == "error" || lowered == "warn" || lowered == "info" || lowered == "debug" ||
            lowered == "trace") {
            return lowered;
        }
    }
    return "info";
}

std::string log_default_filter(const Settings& settings) {
    return "info,hemera=" + log_level_of(settings);
}

std::string version_line() { return "Hemera v" + std::string(CORE_VERSION); }

std::chrono::seconds env_secs(const Settings& settings, std::string_view key,
                              std::uint64_t fallback) {
    if (const auto value = raw(settings, key)) {
        if (const auto parsed = parse_u64_strict(*value)) {
            if (*parsed > 0) {
                return std::chrono::seconds(static_cast<std::int64_t>(std::min<std::uint64_t>(*parsed, 86'400)));
            }
        }
    }
    return std::chrono::seconds(static_cast<std::int64_t>(fallback));
}

std::chrono::seconds masque_reconnect_delay(const Settings& settings) {
    return env_secs(settings, MASQUE_RECONNECT_ENV, 2);
}

std::chrono::seconds masque_startup_timeout(const Settings& settings) {
    return env_secs(settings, MASQUE_STARTUP_ENV, 30);
}

std::chrono::seconds mim_inner_startup(const Settings& settings) {
    return std::min(masque_startup_timeout(settings), MIM_INNER_STARTUP_CAP);
}

std::chrono::seconds wg_reconnect_delay(const Settings& settings) {
    return env_secs(settings, WG_RECONNECT_ENV, 2);
}

std::chrono::seconds wg_endpoint_cooldown(const Settings& settings) {
    return env_secs(settings, WG_COOLDOWN_ENV, 300);
}

std::chrono::seconds wg_tunnel_validate_timeout(const Settings& settings) {
    return env_secs(settings, WG_VALIDATE_ENV, 10);
}

std::uint16_t wg_keepalive_secs(const Settings& settings) {
    if (const auto value = raw(settings, WG_KEEPALIVE_ENV)) {
        if (const auto parsed = parse_u64_strict(*value)) {
            if (*parsed > 0 && *parsed <= std::numeric_limits<std::uint16_t>::max()) {
                return static_cast<std::uint16_t>(*parsed);
            }
        }
    }
    return 5;
}

// ---- the two-hop endpoints ------------------------------------------------------------------

std::expected<WiwEndpoints, Error> WiwEndpoints::checked() const {
    if (outer.has_value() && inner.has_value() && outer->ip == inner->ip) {
        return std::unexpected(Error::other(same_edge_error(outer->ip)));
    }
    return *this;
}

std::string same_edge_error(const IpAddress& ip) {
    return "the two hops need separate edges, but both point at " + iptext(ip);
}

std::string endpoint_no_port_error(std::string_view text, const IpAddress& address) {
    const SocketAddr example{address, WG_EXAMPLE_PORT};
    return std::string(text) +
           " carries no port, and the port is required; write it out, as in " + addr(example);
}

std::string endpoint_nonsense_error(std::string_view text) {
    return "'" + std::string(text) +
           "' is not an endpoint; write an address and a port together, such as 162.159.192.1:" +
           num(WG_EXAMPLE_PORT);
}

std::string too_many_endpoints_error(std::size_t found) {
    return "warp-in-warp has two hops, but " + num(found) + " addresses were given";
}

std::string bad_peer_address_error(std::string_view raw_peer) {
    return "bad peer address " + std::string(raw_peer);
}

std::expected<SocketAddr, Error> parse_endpoint(std::string_view raw_text) {
    const std::string text = trim_str(raw_text);

    // The one narrowing against the Rust: dns::parse_socket_addr refuses port 0, which std::net's
    // parse accepts. Nothing in lib.rs pins a hop on port 0, so no decision changes.
    if (const auto peer = ::hemera::core::parse_socket_addr(text)) return *peer;

    std::optional<IpAddress> portless = ::hemera::core::parse_address(text);
    if (!portless.has_value() && text.size() >= 2 && text.front() == '[' && text.back() == ']') {
        portless = ::hemera::core::parse_address(text.substr(1, text.size() - 2));
    }

    if (portless.has_value()) {
        return std::unexpected(Error::other(endpoint_no_port_error(text, *portless)));
    }
    return std::unexpected(Error::other(endpoint_nonsense_error(text)));
}

std::expected<std::vector<SocketAddr>, Error> parse_endpoint_list(std::string_view raw_text) {
    std::vector<SocketAddr> peers;

    std::size_t start = 0;
    for (;;) {
        std::size_t end = raw_text.find_first_of(",; ", start);
        const bool last = end == std::string_view::npos;
        if (last) end = raw_text.size();

        const std::string_view part = raw_text.substr(start, end - start);
        if (!trim_str(part).empty()) {
            auto parsed = parse_endpoint(part);
            if (!parsed.has_value()) return std::unexpected(parsed.error());
            peers.push_back(*parsed);
        }

        if (last) break;
        start = end + 1;
    }

    switch (peers.size()) {
        case 0:
            return std::unexpected(Error::other(std::string(NO_ENDPOINT_GIVEN)));
        case 1:
        case 2:
            return peers;
        default:
            return std::unexpected(Error::other(too_many_endpoints_error(peers.size())));
    }
}

std::expected<WiwEndpoints, Error> nested_endpoints_of(const Settings& settings,
                                                      std::string_view list_key,
                                                      std::string_view outer_key,
                                                      std::string_view inner_key) {
    WiwEndpoints chosen;

    if (const auto list = env_value(settings, list_key)) {
        if (!scan_keyword(*list)) {
            auto peers = parse_endpoint_list(*list);
            if (!peers.has_value()) return std::unexpected(peers.error());
            if (!peers->empty()) chosen.outer = peers->front();
            if (peers->size() > 1) chosen.inner = (*peers)[1];
        }
    }

    if (const auto value = env_value(settings, outer_key)) {
        auto parsed = parse_endpoint(*value);
        if (!parsed.has_value()) return std::unexpected(parsed.error());
        chosen.outer = *parsed;
    }

    if (const auto value = env_value(settings, inner_key)) {
        auto parsed = parse_endpoint(*value);
        if (!parsed.has_value()) return std::unexpected(parsed.error());
        chosen.inner = *parsed;
    }

    return chosen.checked();
}

std::expected<WiwEndpoints, Error> wiw_endpoints_of(const Settings& settings) {
    return nested_endpoints_of(settings, WIW_LIST_ENV, WIW_OUTER_ENV, WIW_INNER_ENV);
}

std::expected<WiwEndpoints, Error> mim_endpoints_of(const Settings& settings) {
    return nested_endpoints_of(settings, MIM_LIST_ENV, MIM_OUTER_ENV, MIM_INNER_ENV);
}

std::expected<WiwEndpoints, Error> wiw_endpoints_with_fallback(const Settings& settings) {
    auto chosen = wiw_endpoints_of(settings);
    if (!chosen.has_value()) return std::unexpected(chosen.error());
    if (chosen->outer.has_value()) return *chosen;

    auto forced = env_value(settings, WG_PEER_ENV);
    if (!forced.has_value()) forced = env_value(settings, PEER_ENV);
    if (!forced.has_value()) return *chosen;

    auto peers = parse_endpoint_list(*forced);
    if (!peers.has_value()) return std::unexpected(peers.error());
    if (!peers->empty()) chosen->outer = peers->front();
    if (!chosen->inner.has_value() && peers->size() > 1) chosen->inner = (*peers)[1];

    return chosen->checked();
}

// ---- protocols ------------------------------------------------------------------------------

Protocol protocol_parse(std::string_view raw_text) {
    const std::string value = lower(trim_str(raw_text));
    if (value == "wg" || value == "wireguard") return Protocol::WireGuard;
    if (value == "gool" || value == "wiw" || value == "warp-in-warp" || value == "warpinwarp") {
        return Protocol::WarpInWarp;
    }
    if (value == "mim" || value == "m2" || value == "masque-in-masque" || value == "masqueinmasque") {
        return Protocol::MasqueInMasque;
    }
    return Protocol::Masque;
}

std::string_view protocol_label(Protocol protocol) {
    switch (protocol) {
        case Protocol::Masque:
            return "MASQUE";
        case Protocol::WireGuard:
            return "WireGuard";
        case Protocol::WarpInWarp:
            return "WARP-in-WARP (gool)";
        case Protocol::MasqueInMasque:
            return "MASQUE-in-MASQUE";
    }
    return "MASQUE";
}

std::string ignored_wiw_warning(Protocol protocol) {
    return std::string("[-] the warp-in-warp endpoints you set are ignored on ") +
           std::string(protocol_label(protocol)) + "; they only apply to --gool";
}

std::string ignored_mim_warning(Protocol protocol) {
    return std::string("[-] the masque-in-masque endpoints you set are ignored on ") +
           std::string(protocol_label(protocol)) + "; they only apply to --mim";
}

// ---- --register -----------------------------------------------------------------------------

std::string register_bad_value_error(std::string_view other) {
    return "--register takes masque, wg, gool, mim or all, not '" + std::string(other) + "'";
}

std::expected<RegisterSet, Error> register_set_parse(std::string_view value) {
    const std::string lowered = lower(trim_str(value));
    if (lowered == "all") return RegisterSet{true, true, true, true};
    if (lowered == "masque") return RegisterSet{false, false, true, false};
    if (lowered == "wg" || lowered == "wireguard" || lowered == "warp") {
        return RegisterSet{true, false, false, false};
    }
    if (lowered == "gool" || lowered == "wiw" || lowered == "warp-in-warp") {
        return RegisterSet{true, true, false, false};
    }
    if (lowered == "mim" || lowered == "masque-in-masque") {
        return RegisterSet{false, false, true, true};
    }
    return std::unexpected(Error::other(register_bad_value_error(lowered)));
}

std::expected<std::optional<RegisterSet>, Error> register_request(const Settings& settings) {
    const auto value = env_value(settings, REGISTER_ENV);
    if (!value.has_value()) return std::optional<RegisterSet>{};
    auto parsed = register_set_parse(*value);
    if (!parsed.has_value()) return std::unexpected(parsed.error());
    return std::optional<RegisterSet>{*parsed};
}

std::vector<RegistrationTarget> register_plan(const RegisterSet& wanted, const Settings& settings,
                                             std::string_view base_config) {
    const std::string wireguard = warp_config_path(settings, base_config);
    const std::string masque = masque_config_path(settings, base_config);

    std::vector<RegistrationTarget> plan;
    if (wanted.wireguard) plan.push_back(RegistrationTarget{"wireguard", wireguard, false});
    if (wanted.wireguard_inner) {
        plan.push_back(RegistrationTarget{"wireguard inner",
                                          derive_sibling_path(wireguard, "secondary"), false});
    }
    if (wanted.masque) plan.push_back(RegistrationTarget{"masque", masque, true});
    if (wanted.masque_inner) {
        plan.push_back(RegistrationTarget{"masque inner", derive_sibling_path(masque, "secondary"),
                                          true});
    }
    return plan;
}

std::string identity_ready_line(std::string_view label, const Identity& identity) {
    return "[+] " + std::string(label) + " identity ready: device=" + identity.device_id +
           " ipv4=" + identity.ipv4 + " ipv6=" + identity.ipv6;
}

std::string identities_ready_line(const std::vector<std::string>& ready) {
    return "[+] identities ready: " + join(ready, ", ");
}

// ---- prompts --------------------------------------------------------------------------------

std::string scan_mode_prompt(std::string_view tip) {
    return std::string(tip) + std::string(SCAN_MODE_PROMPT);
}

std::string protocol_prompt(const std::optional<std::string>& team) {
    // lib.rs numbers its entries as it builds them; with tor and psiphon out of this product the
    // four base entries are followed straight by the Zero Trust one, and `last` is 5.
    std::string zero_trust = team.has_value()
                                 ? "  [5] Zero Trust: signed in to " + *team + ", pick another team\n"
                                 : "  [5] Zero Trust: sign in to an organization (WARP for teams)\n";
    return std::string("\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  "
                       "[2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n  "
                       "[4] MASQUE-in-MASQUE (two masque hops, for a different exit address)\n") +
           zero_trust + "Choose [1-5] (default 1): ";
}

std::string team_enrol_prompt(const std::vector<std::string>& known) {
    if (known.empty()) return std::string(TEAM_ENROL_PROMPT_BLANK);
    return "\nZero Trust organization.\n  already enrolled: " + join(known, ", ") +
           "\nTeam name from <team>.cloudflareaccess.com, or blank to reuse '" + known.front() +
           "': ";
}

std::string quick_reconnect_prompt(const LastConnection& cached) {
    return "\nLast working gateway: " + cached.peer + " (profile '" + cached.profile +
           "')\nReconnect to it now without rescanning? [Y/n]: ";
}

std::string select_scan_mode_str(const Settings& settings, std::string_view tip,
                                const PromptLine& prompt) {
    if (const auto value = raw(settings, SCAN_ENV)) return *value;

    const std::string answer = ask(prompt, scan_mode_prompt(tip)).value_or(std::string());
    if (answer == "1") return "turbo";
    if (answer == "3") return "thorough";
    if (answer == "4") return "verified";
    if (answer == "5") return "ironclad";
    return "balanced";
}

ScanMode select_scan_mode(const Settings& settings, const PromptLine& prompt) {
    if (const auto value = raw(settings, SCAN_ENV)) return prober::scan_mode_parse(*value);

    const std::string answer = ask(prompt, std::string(SCAN_MODE_PROMPT)).value_or(std::string());
    if (answer == "1") return ScanMode::Turbo;
    if (answer == "3") return ScanMode::Thorough;
    if (answer == "4") return ScanMode::Verified;
    if (answer == "5") return ScanMode::Ironclad;
    return ScanMode::Balanced;
}

IpScan select_ip_version(const Settings& settings, const PromptLine& prompt) {
    if (const auto value = raw(settings, IP_ENV)) return prober::ip_scan_parse(*value);

    const std::string answer = ask(prompt, std::string(IP_VERSION_PROMPT)).value_or(std::string());
    if (answer == "2") return IpScan::V6;
    if (answer == "3") return IpScan::Both;
    return IpScan::V4;
}

std::pair<std::string, IpScan> scan_settings_from_env(const Settings& settings) {
    const std::string mode = raw(settings, SCAN_ENV).value_or(std::string());
    const auto ip_value = raw(settings, IP_ENV);
    const IpScan ip = ip_value.has_value() ? prober::ip_scan_parse(*ip_value) : IpScan::V4;
    return {mode, ip};
}

bool verified_scan_selected(const Settings& settings, const ScanSettings& cached) {
    const std::string named = cached.has_value() ? cached->first
                                                 : raw(settings, SCAN_ENV).value_or(std::string());
    return prober::scan_mode_parse(named) == ScanMode::Verified;
}

Protocol select_gool(Settings& settings, const PromptLine& prompt) {
    const std::string answer = ask(prompt, std::string(GOOL_PROMPT)).value_or(std::string());
    if (answer == "2") settings.set(GOOL_MODE_ENV, "classic");
    return Protocol::WarpInWarp;
}

void select_masque_transport(Settings& settings, const PromptLine& prompt, Notes&) {
    // HEMERA_MASQUE_HTTP2 and HEMERA_PEER are presence checks: an empty value still skips the ask.
    if (has_key(settings, MASQUE_HTTP2_ENV) || has_key(settings, PEER_ENV)) return;

    const std::string answer =
        ask(prompt, std::string(MASQUE_TRANSPORT_PROMPT)).value_or(std::string());
    if (answer == "2") settings.set(MASQUE_HTTP2_ENV, "1");
}

Protocol select_protocol(Settings& settings, std::string_view base_config, const PromptLine& prompt,
                         const zerotrust::Hooks& hooks, const ListDir& list_dir, Notes& notes) {
    if (const auto value = raw(settings, PROTOCOL_ENV)) return protocol_parse(*value);

    for (;;) {
        const std::string answer = ask(prompt, protocol_prompt(team_scope(settings)))
                                       .value_or(std::string());
        if (answer == "2") return Protocol::WireGuard;
        if (answer == "3") return select_gool(settings, prompt);
        if (answer == "4") return Protocol::MasqueInMasque;
        if (answer == "5") {
            TeamDeps team;
            team.prompt = prompt;
            team.hooks = hooks;
            team.list_dir = list_dir;
            enrol_zero_trust(settings, base_config, team, notes);
            continue;
        }
        return Protocol::Masque;
    }
}

// ---- zero trust enrolment -------------------------------------------------------------------

std::vector<std::string> enrolled_teams_from_names(std::string_view base,
                                                  const std::vector<std::string>& names) {
    std::size_t dir_end = 0;
    for (std::size_t i = base.size(); i-- > 0;) {
        if (base[i] == '/' || base[i] == '\\') {
            dir_end = i + 1;
            break;
        }
    }
    const std::string_view file = base.substr(dir_end);
    const auto dot = file.rfind('.');
    const std::string_view stem = dot == std::string_view::npos ? file : file.substr(0, dot);
    const std::string prefix = std::string(stem) + "-team-";

    std::vector<std::string> teams;
    for (const auto& name : names) {
        if (!starts_with(name, prefix)) continue;
        std::string_view rest(name.data() + prefix.size(), name.size() - prefix.size());
        if (!ends_with(rest, ".toml")) continue;
        rest.remove_suffix(5);
        if (rest.empty()) continue;
        if (ends_with(rest, "-secondary") || ends_with(rest, "-lastconn")) continue;

        const std::string team(rest);
        if (!contains(teams, team)) teams.push_back(team);
    }
    std::sort(teams.begin(), teams.end());
    return teams;
}

std::vector<std::string> enrolled_teams(std::string_view base, const ListDir& list_dir) {
    std::size_t dir_end = 0;
    for (std::size_t i = base.size(); i-- > 0;) {
        if (base[i] == '/' || base[i] == '\\') {
            dir_end = i + 1;
            break;
        }
    }
    // std::fs::read_dir's failure is an empty list, which is what a missing seam reads as too.
    if (!list_dir) return {};
    const std::string dir = dir_end == 0 ? "." : std::string(base.substr(0, dir_end));
    return enrolled_teams_from_names(base, list_dir(dir));
}

void enrol_zero_trust(Settings& settings, std::string_view base_config, const TeamDeps& team,
                      Notes& notes) {
    const std::vector<std::string> known = enrolled_teams(base_config, team.list_dir);

    const std::string answer = trim_str(ask(team.prompt, team_enrol_prompt(known))
                                            .value_or(std::string()));

    std::string team_name;
    if (answer.empty()) {
        if (known.empty()) {
            note_info(notes, "[*] Zero Trust skipped; staying on personal WARP");
            return;
        }
        team_name = known.front();
    } else {
        const auto normalized = zerotrust::normalize_team(answer);
        if (!normalized.has_value()) {
            note_warn(notes, "[-] '" + answer + "' is not a usable team name");
            return;
        }
        team_name = *normalized;
    }

    settings.set(TEAM_ENV, team_name);

    if (contains(known, team_name)) {
        note_info(notes, "[+] reusing the saved enrolment for team " + team_name +
                             "; no sign-in needed");
        return;
    }

    bool needs_method = false;
    {
        const auto from_env = zerotrust::TeamSettings::from_env(settings);
        if (!from_env.has_value()) {
            unset(settings, TEAM_ENV);
            return;
        }
        needs_method = !(from_env->token.has_value() || from_env->has_service_token() ||
                         from_env->email.has_value());
    }

    if (needs_method) {
        const std::string email =
            trim_str(ask(team.prompt, std::string(TEAM_EMAIL_PROMPT)).value_or(std::string()));
        if (email.empty()) {
            note_warn(notes, "[-] no email given; staying on personal WARP");
            unset(settings, TEAM_ENV);
            return;
        }
        settings.set(ACCESS_EMAIL_ENV, email);
    }

    const auto from_env = zerotrust::TeamSettings::from_env(settings);
    if (!from_env.has_value()) {
        unset(settings, TEAM_ENV);
        return;
    }

    std::vector<std::string> sign_in_notes;
    const auto token = zerotrust::resolve_token(*from_env, team.hooks, sign_in_notes);
    for (const auto& line : sign_in_notes) note_info(notes, line);

    if (token.has_value()) {
        note_info(notes,
                  "[+] signed in to team " + team_name + "; now pick the transport to use");
        return;
    }

    note_error(notes, "[-] Zero Trust sign-in failed: " + token.error());
    note_warn(notes, "[-] staying on personal WARP");
    unset(settings, TEAM_ENV);
    unset(settings, ACCESS_EMAIL_ENV);
}

// ---- the account layer lib.rs drives --------------------------------------------------------

namespace {

// The two errors config::load and config::save raise, which are HemeraError::Other in the Rust.
[[nodiscard]] Error file_error(std::string_view message) {
    return Error::other(std::string(message));
}

[[nodiscard]] EnrolOutcome enrol_outcome_of(
    const std::expected<account::MasqueEnrollment, Error>& result) {
    EnrolOutcome outcome;
    if (result.has_value()) {
        outcome.kind = EnrolOutcome::Kind::Enrolled;
        outcome.enrollment = *result;
        return outcome;
    }
    outcome.error = result.error();
    if (result.error().kind == ErrorKind::IdentityRefused) {
        outcome.kind = EnrolOutcome::Kind::Refused;
        // The warn line prints the reason inside the variant, not its Display.
        outcome.reason = result.error().message;
        return outcome;
    }
    outcome.kind = EnrolOutcome::Kind::Failed;
    outcome.reason = result.error().display();
    return outcome;
}

[[nodiscard]] Identity with_certificate(Identity identity,
                                        const account::MasqueEnrollment& enrollment) {
    identity.cert_pem.assign(enrollment.cert_pem.begin(), enrollment.cert_pem.end());
    identity.key_pem.assign(enrollment.key_pem.begin(), enrollment.key_pem.end());
    identity.cert_issued_at = enrollment.issued_at;
    return identity;
}

} // namespace

std::string enrolling_team_line(const zerotrust::TeamSettings& team) {
    return "[*] enrolling this device into the Zero Trust organization " + team.team + " (" +
           team.team_domain() + ")";
}

std::string gateway_proxy_debug_line(std::string_view gateway_proxy) {
    return std::string("[zerotrust] the organization offers a gateway proxy at ") +
           std::string(gateway_proxy) + "; pass --gateway to route http through it";
}

std::string assigned_endpoint_line(std::string_view peer) {
    return "[+] the organization assigned endpoint " + std::string(peer) +
           "; trying it before scanning";
}

Identity adopt_team_profile(Settings& settings, Identity identity, const AccountSeams& seams,
                            Notes& notes) {
    if (!team_scope(settings).has_value()) return identity;

    if (seams.refresh_profile) identity = seams.refresh_profile(std::move(identity));

    if (!identity.gateway_proxy.empty()) {
        if (has_key(settings, GATEWAY_ENV)) {
            if (seams.set_gateway_proxy) seams.set_gateway_proxy(identity.gateway_proxy);
        } else {
            note_debug(notes, gateway_proxy_debug_line(identity.gateway_proxy));
        }
    }

    if (!identity.assigned_endpoint.empty() && !has_key(settings, PEER_ENV)) {
        const auto protocol = raw(settings, PROTOCOL_ENV);
        const bool wireguard_port =
            protocol.has_value() && (*protocol == "wg" || *protocol == "gool");
        const std::string peer =
            identity.assigned_endpoint + ":" + num(wireguard_port ? WG_EXAMPLE_PORT : 443);
        if (::hemera::core::parse_socket_addr(peer).has_value()) {
            note_info(notes, assigned_endpoint_line(peer));
            settings.set(TEAM_ENDPOINT_ENV, peer);
        }
    }

    return identity;
}

std::expected<Identity, Error> provision_account(const Settings& settings, const AccountSeams& seams,
                                                Notes& notes) {
    const auto team = zerotrust::TeamSettings::from_env(settings);
    if (team.has_value()) {
        note_info(notes, enrolling_team_line(*team));
        if (!seams.provision_team) return std::unexpected(Error::other(std::string(NO_ACCOUNT_SEAM)));
        auto identity = seams.provision_team(::hemera::core::DEFAULT_MODEL,
                                             ::hemera::core::DEFAULT_LOCALE, *team);
        if (!identity.has_value()) return std::unexpected(identity.error());
        if (seams.refresh_profile) return seams.refresh_profile(std::move(*identity));
        return *identity;
    }

    if (!seams.provision_wg) return std::unexpected(Error::other(std::string(NO_ACCOUNT_SEAM)));
    return seams.provision_wg(::hemera::core::DEFAULT_MODEL, ::hemera::core::DEFAULT_LOCALE);
}

std::string loaded_warp_identity_line(std::string_view config_path) {
    return "[+] loaded existing warp identity from " + std::string(config_path);
}

std::string loaded_masque_identity_line(std::string_view config_path) {
    return "[+] loaded existing masque identity from " + std::string(config_path);
}

std::string no_warp_identity_line() {
    return "[+] no warp identity found; provisioning dedicated wireguard account";
}

std::string no_masque_identity_line() {
    return "[+] no masque identity found; provisioning dedicated masque account";
}

std::string saved_warp_identity_line(std::string_view config_path) {
    return "[+] provisioned and saved new warp identity to " + std::string(config_path);
}

std::string saved_masque_identity_line(std::string_view config_path) {
    return "[+] provisioned and saved new masque identity to " + std::string(config_path);
}

std::string replace_refused_warp_line() {
    return "[*] registering a fresh wireguard account to replace the refused identity";
}

std::string replace_refused_masque_line() {
    return "[*] registering a fresh masque account to replace the refused identity";
}

std::string needs_certificate_line() {
    return "[+] masque identity needs a certificate; enrolling masque key";
}

std::string saved_identity_refused_line(std::string_view reason) {
    return "[-] the saved masque identity was refused: " + std::string(reason);
}

std::string warp_enabled_line() { return "[+] warp enabled for the masque device"; }

std::string warp_enable_failed_line(std::string_view error) {
    return std::string("[!] could not enable warp for the masque device, the edge may refuse it: ") +
           std::string(error);
}

std::expected<Identity, Error> load_or_provision_warp(const Settings& settings,
                                                     const std::string& config_path,
                                                     const AccountSeams& seams, Notes& notes) {
    auto loaded = ::hemera::core::load_identity(config_path);
    if (!loaded.has_value()) return std::unexpected(file_error(loaded.error()));

    if (!loaded->has_value()) {
        std::filesystem::path p(config_path);
        std::string fname = p.filename().string();
        if (fname.starts_with("hemera")) {
            std::filesystem::path alt_path = p.parent_path() / ("aether" + fname.substr(6));
            if (std::filesystem::exists(alt_path)) {
                auto alt_loaded = ::hemera::core::load_identity(alt_path.string());
                if (alt_loaded.has_value() && alt_loaded->has_value()) {
                    loaded = std::move(alt_loaded);
                }
            }
        }
    }

    if (loaded->has_value()) {
        note_info(notes, loaded_warp_identity_line(config_path));
        // adopt_team_profile writes HEMERA_TEAM_ENDPOINT, which MasqueFlow reads back from this
        // same Settings later; the const on `settings` only promises not to alter the caller's
        // view from here, and Rust's environment is global, so the write has to get through.
        Identity identity = adopt_team_profile(const_cast<Settings&>(settings),
                                               std::move(**loaded), seams, notes);
        if (!identity.refused) {
            if (auto saved = ::hemera::core::save_identity(config_path, identity); !saved.has_value()) {
                return std::unexpected(file_error(saved.error()));
            }
            return identity;
        }
        if (!keep_saved_identity(settings)) return identity;
        note_warn(notes, replace_refused_warp_line());
    }

    note_info(notes, no_warp_identity_line());
    auto provisioned = provision_account(settings, seams, notes);
    if (!provisioned.has_value()) return std::unexpected(provisioned.error());

    Identity identity = adopt_team_profile(const_cast<Settings&>(settings),
                                           std::move(*provisioned), seams, notes);
    if (auto saved = ::hemera::core::save_identity(config_path, identity); !saved.has_value()) {
        return std::unexpected(file_error(saved.error()));
    }
    note_info(notes, saved_warp_identity_line(config_path));
    return identity;
}

std::expected<Identity, Error> load_or_enrol_masque(const Settings& settings,
                                                   const std::string& config_path,
                                                   const AccountSeams& seams, Notes& notes) {
    auto loaded = ::hemera::core::load_identity(config_path);
    if (!loaded.has_value()) return std::unexpected(file_error(loaded.error()));

    if (!loaded->has_value()) {
        std::filesystem::path p(config_path);
        std::string fname = p.filename().string();
        if (fname.starts_with("hemera")) {
            std::filesystem::path alt_path = p.parent_path() / ("aether" + fname.substr(6));
            if (std::filesystem::exists(alt_path)) {
                auto alt_loaded = ::hemera::core::load_identity(alt_path.string());
                if (alt_loaded.has_value() && alt_loaded->has_value()) {
                    loaded = std::move(alt_loaded);
                }
            }
        }
    }

    if (!loaded->has_value()) {
        // Fallback: check if an existing WARP account exists so we don't register from scratch
        const std::string base_cfg = base_config_path(settings);
        const std::string warp_path = warp_config_path(settings, base_cfg);
        auto warp_loaded = ::hemera::core::load_identity(warp_path);
        if (!warp_loaded.has_value() || !warp_loaded->has_value()) {
            std::filesystem::path wp(warp_path);
            std::string wname = wp.filename().string();
            if (wname.starts_with("hemera")) {
                std::filesystem::path alt_wp = wp.parent_path() / ("aether" + wname.substr(6));
                if (std::filesystem::exists(alt_wp)) {
                    warp_loaded = ::hemera::core::load_identity(alt_wp.string());
                }
            }
        }
        if (warp_loaded.has_value() && warp_loaded->has_value() && !(*warp_loaded)->device_id.empty()) {
            loaded = std::move(warp_loaded);
        }
    }

    if (loaded->has_value()) {
        note_info(notes, loaded_masque_identity_line(config_path));

        std::optional<Identity> refused;
        if ((*loaded)->has_masque_credentials()) {
            Identity identity = adopt_team_profile(const_cast<Settings&>(settings),
                                                   std::move(**loaded), seams, notes);
            if (!identity.refused) {
                if (auto saved = ::hemera::core::save_identity(config_path, identity);
                    !saved.has_value()) {
                    return std::unexpected(file_error(saved.error()));
                }
                return identity;
            }
            refused = std::move(identity);
        } else {
            note_info(notes, needs_certificate_line());
            Identity identity = std::move(**loaded);
            if (!seams.ensure_masque_enrolled) {
                return std::unexpected(Error::other(std::string(NO_ACCOUNT_SEAM)));
            }
            const auto outcome = enrol_outcome_of(seams.ensure_masque_enrolled(identity));
            switch (outcome.kind) {
                case EnrolOutcome::Kind::Enrolled: {
                    Identity enrolled = with_certificate(std::move(identity), outcome.enrollment);
                    if (auto saved = ::hemera::core::save_identity(config_path, enrolled);
                        !saved.has_value()) {
                        return std::unexpected(file_error(saved.error()));
                    }
                    return enrolled;
                }
                case EnrolOutcome::Kind::Refused:
                    note_warn(notes, saved_identity_refused_line(outcome.reason));
                    identity.refused = true;
                    refused = std::move(identity);
                    break;
                case EnrolOutcome::Kind::Failed:
                    return std::unexpected(outcome.error);
            }
        }

        if (!keep_saved_identity(settings)) return *refused;
        note_warn(notes, replace_refused_masque_line());
    }

    note_info(notes, no_masque_identity_line());
    auto provisioned = provision_account(settings, seams, notes);
    if (!provisioned.has_value()) return std::unexpected(provisioned.error());

    if (!seams.ensure_masque_enrolled) {
        return std::unexpected(Error::other(std::string(NO_ACCOUNT_SEAM)));
    }
    auto enrollment = seams.ensure_masque_enrolled(*provisioned);
    if (!enrollment.has_value()) return std::unexpected(enrollment.error());

    Identity identity =
        with_certificate(std::move(*provisioned), *enrollment);
    identity = adopt_team_profile(const_cast<Settings&>(settings), std::move(identity),
                                  seams, notes);
    if (auto saved = ::hemera::core::save_identity(config_path, identity); !saved.has_value()) {
        return std::unexpected(file_error(saved.error()));
    }
    note_info(notes, saved_masque_identity_line(config_path));
    return identity;
}

std::expected<Identity, Error> load_or_provision_masque(const Settings& settings,
                                                       const std::string& config_path,
                                                       const AccountSeams& seams, Notes& notes) {
    auto identity = load_or_enrol_masque(settings, config_path, seams, notes);
    if (!identity.has_value()) return std::unexpected(identity.error());
    if (identity->refused) return *identity;

    if (!seams.enable_warp) return std::unexpected(Error::other(std::string(NO_ACCOUNT_SEAM)));
    const auto enabled = seams.enable_warp(identity->device_id, identity->access_token);
    if (enabled.has_value()) {
        note_info(notes, warp_enabled_line());
    } else {
        note_warn(notes, warp_enable_failed_line(enabled.error().display()));
    }
    return *identity;
}

std::expected<std::vector<std::string>, Error> register_identities(
    const Settings& settings, const RegisterSet& wanted, std::string_view base_config,
    const AccountSeams& seams, Notes& notes) {
    std::vector<std::string> ready;
    for (const auto& target : register_plan(wanted, settings, base_config)) {
        auto identity = target.over_masque
                            ? load_or_provision_masque(settings, target.path, seams, notes)
                            : load_or_provision_warp(settings, target.path, seams, notes);
        if (!identity.has_value()) return std::unexpected(identity.error());
        note_info(notes, identity_ready_line(target.label, *identity));
        ready.push_back(target.label);
    }
    note_info(notes, identities_ready_line(ready));
    return ready;
}

// ---- ECH ------------------------------------------------------------------------------------

std::string ech_from_api_line(std::size_t key_bytes) {
    return "[+] offering the ECHConfigList the WARP API took (" + num(key_bytes) + " bytes)";
}

std::expected<std::optional<std::vector<std::uint8_t>>, Error> resolve_ech(
    const Settings& settings, const EchTransport& transport, Notes& notes) {
    const auto setting = raw(settings, ECH_ENV);
    if (setting.has_value() && !setting->empty()) {
        if (const auto key = account::api_ech_in_use()) {
            note_info(notes, ech_from_api_line(key->size()));
            return key;
        }
    }

    const auto key = ::hemera::core::ech_key(
        settings, ::hemera::core::EchPurpose::Session,
        [&]() -> std::expected<std::vector<std::uint8_t>, std::string> {
            return ::hemera::core::fetch_ech_config(settings, transport);
        });
    if (!key.has_value()) {
        if (setting.has_value() && lower(trim_str(*setting)) == "auto") {
            note_info(notes, "ECH auto lookup failed; continuing without ECH");
            return std::nullopt;
        }
        return std::unexpected(Error{ErrorKind::Ech, key.error()});
    }
    if (!key->has_value()) note_info(notes, std::string(ECH_OFF_LINE));
    return *key;
}

// ---- start-up -------------------------------------------------------------------------------

std::expected<Startup, Error> startup(const std::vector<std::string>& args, Settings& settings,
                                     const StartupHooks& hooks) {
    Startup out;

    std::string cli_error;
    const CliOutcome outcome = apply_cli(args, settings, cli_error);
    out.cli = outcome;
    if (outcome == CliOutcome::Failure) return std::unexpected(Error::other(cli_error));
    if (outcome == CliOutcome::Version) {
        out.kind = Startup::Kind::Exit;
        out.banner = version_line();
        return out;
    }
    if (outcome == CliOutcome::Help) {
        out.kind = Startup::Kind::Exit;
        out.banner = usage_text();
        return out;
    }

    out.log_filter = log_default_filter(settings);
    out.banner = version_line();
    note_info(out.notes, out.banner);

    out.sysprofile = sysprofile::summary(sysprofile::tuning(settings));
    note_info(out.notes, out.sysprofile);

    // egress::init's notes are the info lines it logs; a mark that cannot be read stops the core.
    std::vector<std::string> egress_notes;
    const auto mark = egress::init(settings, egress_notes);
    for (const auto& line : egress_notes) note_info(out.notes, line);
    if (!mark.has_value()) return std::unexpected(Error::other(mark.error()));

    ::hemera::core::init(settings); // stats::init
    if (hooks.spawn_stats_reporter) hooks.spawn_stats_reporter();
    if (hooks.install_netstack_guard) hooks.install_netstack_guard();

    // A cipher string or a group list BoringSSL does not take, or an address the calls to the WARP
    // API cannot use, stops the core here, with its option named.
    if (const auto checked = ::hemera::core::check_tls_options(settings); !checked.has_value()) {
        return std::unexpected(Error{ErrorKind::Tls, checked.error()});
    }
    if (const auto checked = account::check_enroll_address(settings); !checked.has_value()) {
        // account:: hands its text back already rendered, "api: " on the front (account.hpp:84),
        // and display() would put the kind on a second time.
        std::string reason = checked.error();
        constexpr std::string_view kind = "api: ";
        if (reason.rfind(kind, 0) == 0) reason.erase(0, kind.size());
        return std::unexpected(Error{ErrorKind::Api, std::move(reason)});
    }
    // The key of the WARP API calls of an earlier run of the library is not this run's.
    account::forget_api_ech();

    out.base_config = base_config_path(settings);

    // A registration serves no proxy, so it needs none of the listeners checked below.
    const auto wanted = register_request(settings);
    if (!wanted.has_value()) return std::unexpected(wanted.error());
    out.register_set = *wanted;
    if (wanted->has_value()) {
        out.kind = Startup::Kind::Register;
        return out;
    }

    if (!hooks.bind_listener) return std::unexpected(Error::other(std::string(NO_BIND_SEAM)));

    out.listen = socks_listen(settings);
    if (const auto bound = hooks.bind_listener("socks5", out.listen); !bound.has_value()) {
        return std::unexpected(Error{ErrorKind::Io, bound.error()});
    }

    const auto http = http_proxy_listen(settings);
    if (http.warning.has_value()) note_warn(out.notes, *http.warning);
    out.http_proxy = http.listen;
    if (http.listen.has_value()) {
        if (const auto bound = hooks.bind_listener("http proxy", *http.listen); !bound.has_value()) {
            return std::unexpected(Error{ErrorKind::Io, bound.error()});
        }
    }

    const auto pinned_wiw = wiw_endpoints_of(settings);
    if (!pinned_wiw.has_value()) return std::unexpected(pinned_wiw.error());
    out.pinned_wiw = *pinned_wiw;

    const auto pinned_mim = mim_endpoints_of(settings);
    if (!pinned_mim.has_value()) return std::unexpected(pinned_mim.error());
    out.pinned_mim = *pinned_mim;

    if (const auto value = raw(settings, PROTOCOL_ENV)) {
        out.protocol = protocol_parse(*value);
    } else if (!out.pinned_wiw.is_empty()) {
        out.protocol = Protocol::WarpInWarp;
    } else if (!out.pinned_mim.is_empty()) {
        out.protocol = Protocol::MasqueInMasque;
    } else if (has_key(settings, PEER_ENV) || has_key(settings, WG_PEER_ENV)) {
        out.protocol = Protocol::Masque;
    } else {
        out.protocol = select_protocol(settings, out.base_config, hooks.prompt, hooks.team.hooks,
                                      hooks.team.list_dir, out.notes);
    }

    if (out.protocol != Protocol::WarpInWarp && !out.pinned_wiw.is_empty()) {
        note_warn(out.notes, ignored_wiw_warning(out.protocol));
    }
    if (out.protocol != Protocol::MasqueInMasque && !out.pinned_mim.is_empty()) {
        note_warn(out.notes, ignored_mim_warning(out.protocol));
    }

    out.classic_gool = gool_classic(settings);
    return out;
}

// ---- the dispatch ---------------------------------------------------------------------------

RunPlan run_plan(const Settings& settings, Protocol protocol, bool classic_gool,
                 std::string_view base_config) {
    RunPlan plan;
    switch (protocol) {
        case Protocol::Masque:
            plan.kind = RunKind::Masque;
            plan.primary_path = masque_config_path(settings, base_config);
            plan.lastconn = lastconn_path(plan.primary_path);
            plan.starts_ech_session = true;
            plan.asks_masque_transport = true;
            break;
        case Protocol::WireGuard:
            plan.kind = RunKind::WireGuard;
            plan.primary_path = warp_config_path(settings, base_config);
            plan.lastconn = lastconn_path(plan.primary_path);
            break;
        case Protocol::WarpInWarp:
            // `Protocol::WarpInWarp if !gool_classic()` is matched first in the Rust.
            if (!classic_gool) {
                plan.kind = RunKind::GoolOverMasque;
                plan.primary_path = masque_config_path(settings, base_config);
                plan.gool_inner_path = derive_sibling_path(plan.primary_path, "gool");
                plan.lastconn = lastconn_path(plan.primary_path);
                plan.starts_ech_session = true;
                plan.asks_masque_transport = true;
            } else {
                plan.kind = RunKind::ClassicGool;
                plan.primary_path = warp_config_path(settings, base_config);
                plan.secondary_path = derive_sibling_path(plan.primary_path, "secondary");
            }
            break;
        case Protocol::MasqueInMasque:
            plan.kind = RunKind::Mim;
            plan.primary_path = masque_config_path(settings, base_config);
            plan.secondary_path = derive_sibling_path(plan.primary_path, "secondary");
            plan.starts_ech_session = true;
            plan.asks_masque_transport = true;
            break;
    }
    return plan;
}

std::string identity_ready_line(const Identity& identity) {
    return "[+] identity ready: device=" + identity.device_id + " ipv4=" + identity.ipv4 +
           " ipv6=" + identity.ipv6;
}

std::string gool_plan_line(const Identity& identity, std::string_view inner_path) {
    return "[+] gool: masque device=" + identity.device_id +
           " carries the wireguard identity in " + std::string(inner_path);
}

std::string pair_ready_line(const Identity& outer, const Identity& inner) {
    return "[+] outer device=" + outer.device_id + " ipv4=" + outer.ipv4 + " | inner device=" +
           inner.device_id + " ipv4=" + inner.ipv4;
}

// ---- budgets, ranges and inner-hop candidates ----------------------------------------------

std::pair<std::size_t, std::size_t> mim_inner_budget(std::size_t outer_mtu,
                                                    const SocketAddr& inner_peer, bool h2) {
    if (h2) {
        const std::size_t mtu = clamp(sat_sub(outer_mtu, 100), 576, 1500);
        return {quic::MAX_DATAGRAM_SIZE, mtu};
    }

    const std::size_t headers = inner_peer.is_ipv4() ? 28 : 48;
    const std::size_t datagram =
        clamp(sat_sub(outer_mtu, headers), quic::MIN_DATAGRAM_SIZE, quic::MAX_DATAGRAM_SIZE);
    const std::size_t mtu = clamp(sat_sub(datagram, MASQUE_DATAGRAM_OVERHEAD), 576, 1500);
    return {datagram, mtu};
}

std::optional<std::array<std::uint8_t, 3>> edge_network(const IpAddress& ip) {
    if (!ip.v4) return std::nullopt;
    return std::array<std::uint8_t, 3>{ip.bytes[12], ip.bytes[13], ip.bytes[14]};
}

void spread_hops(std::vector<SocketAddr>& found) {
    if (found.size() < 2) return;
    const auto network = edge_network(found[0].ip);
    for (std::size_t other = 0; other < found.size(); ++other) {
        if (edge_network(found[other].ip) == network) continue;
        if (other >= 1) std::swap(found[1], found[other]);
        return;
    }
}

std::vector<SocketAddr> masque_verified_ladder(const SocketAddr& outer, std::size_t count) {
    if (!outer.is_ipv4()) return {};

    std::vector<SocketAddr> out;
    std::vector<SocketAddr> seen;
    const auto outer_network = edge_network(outer.ip);

    std::vector<IpAddress> verified;
    for (const std::string_view entry : prober::MASQUE_VERIFIED_GATEWAYS) {
        if (const auto ip = ::hemera::core::parse_address(entry)) verified.push_back(*ip);
    }

    const auto push = [&](const IpAddress& ip, std::uint16_t port) {
        if (ip == outer.ip) return;
        const SocketAddr peer{ip, port};
        if (contains(seen, peer)) return;
        seen.push_back(peer);
        out.push_back(peer);
    };

    for (const auto& ip : verified) {
        if (edge_network(ip) != outer_network) push(ip, MASQUE_INNER_PORT);
    }
    for (const auto& ip : verified) push(ip, MASQUE_INNER_PORT);
    for (const std::uint16_t port : prober::MASQUE_ALT_PORTS) {
        for (const auto& ip : verified) push(ip, port);
    }

    const std::size_t limit = std::max<std::size_t>(count, 1);
    if (out.size() > limit) out.resize(limit);
    return out;
}

std::vector<SocketAddr> sibling_candidates(const SocketAddr& outer, std::size_t count,
                                          const Random& rng) {
    std::vector<SocketAddr> out;
    if (count == 0) return out;

    // rand's random_range(a..=b), as an injected 32-bit draw. The modulo keeps the port's own
    // sampling tests reproducible; the bias is far smaller than the ranges here.
    const auto draw = [&](std::uint32_t span) -> std::uint32_t {
        if (!rng || span == 0) return 0;
        return rng() % span;
    };

    if (outer.ip.v4) {
        const std::uint8_t own = outer.ip.bytes[15];
        std::vector<std::uint8_t> hosts;
        hosts.reserve(253);
        for (std::uint32_t host = 1; host <= 254; ++host) {
            if (static_cast<std::uint8_t>(host) != own) hosts.push_back(static_cast<std::uint8_t>(host));
        }
        for (std::size_t index = hosts.size(); index-- > 1;) {
            const std::uint32_t other = draw(static_cast<std::uint32_t>(index) + 1);
            std::swap(hosts[index], hosts[other]);
        }
        for (std::size_t i = 0; i < hosts.size() && out.size() < count; ++i) {
            IpAddress ip = outer.ip;
            ip.bytes[15] = hosts[i];
            out.push_back(SocketAddr{ip, MASQUE_INNER_PORT});
        }
        return out;
    }

    const std::uint16_t own = static_cast<std::uint16_t>((outer.ip.bytes[14] << 8) | outer.ip.bytes[15]);
    std::vector<std::uint16_t> seen;
    // Rust's guard is `seen.len() < count * 8`, which only grows on a hit; the draw bound beside it
    // cannot fire with a real generator and keeps a degenerate injected one from spinning.
    const std::size_t draw_bound = count * 64 + 64;
    for (std::size_t draws = 0; out.size() < count && seen.size() < count * 8 && draws < draw_bound;
         ++draws) {
        const auto candidate = static_cast<std::uint16_t>(1 + draw(65'535));
        if (candidate == own || contains(seen, candidate)) continue;
        seen.push_back(candidate);

        IpAddress ip = outer.ip;
        ip.bytes[14] = static_cast<std::uint8_t>(candidate >> 8);
        ip.bytes[15] = static_cast<std::uint8_t>(candidate & 0xff);
        out.push_back(SocketAddr{ip, MASQUE_INNER_PORT});
    }
    return out;
}

std::vector<SocketAddr> inner_masque_candidates(const SocketAddr& outer, std::size_t count,
                                               bool verified, const Random& rng) {
    std::vector<SocketAddr> out;
    std::vector<SocketAddr> seen;

    if (verified) {
        const std::size_t room = std::max<std::size_t>(sat_sub(count, 2), 1);
        for (const auto& peer : masque_verified_ladder(outer, room)) {
            if (contains(seen, peer)) continue;
            seen.push_back(peer);
            out.push_back(peer);
        }
    }

    for (const auto& peer : sibling_candidates(outer, count, rng)) {
        if (out.size() >= count) break;
        if (contains(seen, peer)) continue;
        seen.push_back(peer);
        out.push_back(peer);
    }

    const std::size_t limit = std::max<std::size_t>(count, 1);
    if (out.size() > limit) out.resize(limit);
    return out;
}

// ---- the hunts ------------------------------------------------------------------------------

std::string masque_selected_line(const ProbeResult& best) {
    return "[+] selected MASQUE gateway " + iptext(best.ip) + ":" + num(best.port) + " (rtt " +
           dur(best.rtt) + ")";
}

std::string using_forced_peer_line(const SocketAddr& peer) {
    return "[+] using forced peer " + addr(peer) + " (probe skipped)";
}

std::string selected_protocol_line(Protocol protocol) {
    return std::string("[+] selected protocol: ") + std::string(protocol_label(protocol));
}

std::string using_edge_line(const SocketAddr& peer) {
    return "[+] using cloudflare edge " + addr(peer);
}

std::string using_edge_pair_line(const SocketAddr& outer, const SocketAddr& inner) {
    return "[+] using cloudflare edge " + addr(outer) + " (outer) and " + addr(inner) + " (inner)";
}

MasqueProbeParams masque_probe_for(const Settings& settings, const Identity& identity,
                                  const std::optional<std::vector<std::uint8_t>>& ech, IpScan ip,
                                  Notes& notes) {
    MasqueProbeParams params;
    params.sni = std::string(::hemera::core::CONNECT_SNI);
    params.authority = std::string(quic::default_authority());
    params.path = std::string(quic::default_path());
    params.cert_pem = identity.cert_pem;
    params.key_pem = identity.key_pem;
    params.ech_config_list = ech;
    params.noise = noize_config(settings, notes);
    params.ports = masque_ports();
    params.ip = ip;
    params.local_ipv4 = parse_local_v4(identity.ipv4);
    return params;
}

std::expected<WgProbeParams, Error> wg_probe_for(const Settings&, const Identity& identity,
                                                const HemeraNoizeConfig& noise, IpScan ip,
                                                std::vector<SocketAddr> excluded, Notes&) {
    WgProbeParams params;
    params.private_key = identity.wg_private_key;
    params.peer_public_key = identity.wg_peer_public_key;
    params.client_id = identity.client_id;

    const auto local = ::hemera::core::parse_address(identity.ipv4);
    if (!local.has_value() || !local->v4) {
        return std::unexpected(Error::other(std::string(INVALID_IPV4)));
    }
    params.local_ipv4 = *local;
    params.noise = noise;
    params.ports = wg_ports();
    params.ip = ip;
    params.excluded = std::move(excluded);
    return params;
}

std::string wg_hunting_line(std::size_t want) {
    return "[*] hunting for " + num(want) +
           " working WireGuard endpoint(s) (handshake + data-plane verification)";
}

std::string wg_avoid_line(std::size_t avoid) {
    return "[*] the scan leaves out " + num(avoid) +
           " address(es) already taken by the other hop";
}

std::string wg_selected_line(const WgProbeResult& picked) {
    return "[+] selected WireGuard endpoint " + iptext(picked.ip) + ":" + num(picked.port) +
           " (rtt " + dur(picked.rtt) + ")";
}

std::vector<SocketAddr> wg_excluded_for(const std::vector<IpAddress>& avoid) {
    const auto ports = wg_ports();
    std::vector<SocketAddr> excluded;
    excluded.reserve(avoid.size() * ports.size());
    for (const auto& address : avoid) {
        for (const std::uint16_t port : ports) excluded.push_back(SocketAddr{address, port});
    }
    return excluded;
}

std::expected<std::vector<SocketAddr>, Error> pick_wg_peers(
    const std::vector<WgProbeResult>& found, const std::vector<IpAddress>& avoid, std::size_t want) {
    std::vector<WgProbeResult> picked;
    for (const auto& result : found) {
        if (picked.size() >= want) break;
        if (contains(avoid, result.ip)) continue;
        picked.push_back(result);
    }
    if (picked.empty()) return std::unexpected(Error::no_clean_endpoint());

    std::vector<SocketAddr> peers;
    peers.reserve(picked.size());
    for (const auto& result : picked) peers.push_back(SocketAddr{result.ip, result.port});
    return peers;
}

std::optional<std::string> forced_peer_for(const Settings& settings, Protocol protocol) {
    switch (protocol) {
        case Protocol::Masque:
        case Protocol::MasqueInMasque:
            return raw(settings, PEER_ENV);
        case Protocol::WireGuard:
        case Protocol::WarpInWarp: {
            auto forced = raw(settings, WG_PEER_ENV);
            if (!forced.has_value()) forced = raw(settings, PEER_ENV);
            return forced;
        }
    }
    return std::nullopt;
}

std::expected<SocketAddr, Error> parse_forced_peer(std::string_view raw_peer) {
    if (const auto parsed = ::hemera::core::parse_socket_addr(raw_peer)) return *parsed;
    return std::unexpected(Error::other(bad_peer_address_error(raw_peer)));
}

// ---- the quick checks -----------------------------------------------------------------------

quic::VerifyParams quick_verify_quic_params(const Settings& settings, const Identity& identity,
                                           const SocketAddr& peer,
                                           const std::optional<std::vector<std::uint8_t>>& ech,
                                           Notes& notes) {
    quic::VerifyParams params;
    params.peer = peer;
    params.sni = std::string(::hemera::core::CONNECT_SNI);
    params.authority = std::string(quic::default_authority());
    params.path = std::string(quic::default_path());
    params.cert_pem = bytes(identity.cert_pem);
    params.key_pem = bytes(identity.key_pem);
    params.ech_config_list = ech;
    params.noize = noize_config(settings, notes);
    params.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(QUICK_VERIFY_TIMEOUT);
    params.local_ipv4 = parse_local_v4(identity.ipv4);
    return params;
}

masque_h2::H2TunnelConfig quick_verify_h2_config(const Settings& settings, const Identity& identity,
                                                const SocketAddr& peer,
                                                const std::optional<std::vector<std::uint8_t>>& ech,
                                                Notes& notes) {
    masque_h2::H2TunnelConfig config;
    config.peer = masque_h2::h2_peer(settings, peer);
    config.sni = std::string(::hemera::core::CONNECT_SNI);
    config.authority = std::string(quic::default_authority());
    config.path = std::string(quic::default_path());
    config.cert_pem = bytes(identity.cert_pem);
    config.key_pem = bytes(identity.key_pem);
    config.local_ipv4 = parse_local_v4(identity.ipv4);
    config.quiet = true;
    config.pin_endpoint = true;
    config.expected_pins = masque_h2::default_expected_pins();
    config.ech_config_list = ech;
    // The HTTP/2 carrier takes no junk packets, but lib.rs builds the QUIC parameters first and
    // noize_config() logs on the way, so the line is still written.
    (void)noize_config(settings, notes);
    return config;
}

bool want_quick_reconnect(const Settings& settings, const LastConnection& cached,
                          const PromptLine& prompt) {
    if (const auto value = raw(settings, QUICK_RECONNECT_ENV)) {
        if (*value == "1" || *value == "true" || *value == "yes" || *value == "on") return true;
        if (*value == "0" || *value == "false" || *value == "no" || *value == "off") return false;
    }

    const auto answer = ask(prompt, quick_reconnect_prompt(cached));
    if (!answer.has_value()) return true;
    return !eq_ignore(*answer, "n") && !eq_ignore(*answer, "no");
}

std::vector<SocketAddr> ring_peers(const LastConnection& cached, std::string_view carrier) {
    return ring_of(cached, carrier);
}

// ---- establishing a hop ---------------------------------------------------------------------

SocketAddr masque_dial_peer(const Settings& settings, const SocketAddr& peer) {
    // run_masque_tunnel and run_gool_tunnel: `if h2 { masque_h2::h2_peer(peer) } else { peer }`.
    if (masque_h2::enabled(settings)) return masque_h2::h2_peer(settings, peer);
    return peer;
}

std::string masque_transport_h2_line(std::string_view label, const SocketAddr& peer,
                                     std::size_t mtu) {
    return "[+] [" + std::string(label) + "] MASQUE transport: HTTP/2 (TCP) to " + addr(peer) +
           " (inner mtu " + num(mtu) + ")";
}

std::string masque_transport_h3_line(std::string_view label, const SocketAddr& peer, std::size_t mtu,
                                     std::size_t datagram_budget) {
    return "[+] [" + std::string(label) + "] MASQUE transport: HTTP/3 (QUIC) to " + addr(peer) +
           " (inner mtu " + num(mtu) + ", datagram " + num(datagram_budget) + ")";
}

MasqueHopParams establish_masque_params(const Settings& settings, const Identity& identity,
                                        const SocketAddr& peer,
                                        const std::optional<std::vector<std::uint8_t>>& ech, bool h2,
                                        std::size_t mtu, std::size_t datagram, bool version_bait,
                                        std::chrono::seconds startup, std::string_view label,
                                        Notes& notes) {
    MasqueHopParams params;
    params.h2 = h2;
    params.label = std::string(label);
    params.mtu = mtu;
    params.datagram = datagram;
    params.version_bait = version_bait;
    params.startup = startup;

    if (h2) {
        masque_h2::H2TunnelConfig config;
        config.peer = peer;
        config.sni = std::string(::hemera::core::CONNECT_SNI);
        config.authority = std::string(quic::default_authority());
        config.path = std::string(quic::default_path());
        config.cert_pem = bytes(identity.cert_pem);
        config.key_pem = bytes(identity.key_pem);
        config.local_ipv4 = parse_local_v4(identity.ipv4);
        config.quiet = false;
        config.pin_endpoint = true;
        config.expected_pins = masque_h2::default_expected_pins();
        config.ech_config_list = ech;
        params.h2_config = std::move(config);
        params.transport_line = masque_transport_h2_line(label, peer, mtu);
        return params;
    }

    quic::TunnelConfig config;
    config.peer = peer;
    config.sni = std::string(::hemera::core::CONNECT_SNI);
    config.authority = std::string(quic::default_authority());
    config.path = std::string(quic::default_path());
    config.cert_pem = bytes(identity.cert_pem);
    config.key_pem = bytes(identity.key_pem);
    config.ech_config_list = ech;
    // The Rust builds noize_config() into the config before the transport line is logged, and
    // noize_config writes the profile line on the way.
    config.noize = noize_config(settings, notes);
    config.local_ipv4 = parse_local_v4(identity.ipv4);
    config.quiet = false;
    config.max_datagram = datagram;
    config.version_bait = version_bait;
    params.quic_config = std::move(config);
    // `{cfg.datagram_budget()}`, exactly as the Rust formats it after the config is built.
    params.transport_line =
        masque_transport_h3_line(label, peer, mtu, params.quic_config.datagram_budget());
    return params;
}

std::string startup_verdict_error(std::string_view label, StartupVerdict verdict,
                                  std::string_view detail, std::chrono::milliseconds startup) {
    const std::string tag(label);
    switch (verdict) {
        case StartupVerdict::Ready:
            return {};
        case StartupVerdict::ExitedBeforeValidation:
            return "[" + tag + "] tunnel exited before validation";
        case StartupVerdict::FailedBeforeValidation:
            return "[" + tag + "] tunnel failed before validation: " + std::string(detail);
        case StartupVerdict::JoinError:
            return "[" + tag + "] tunnel task join error: " + std::string(detail);
        case StartupVerdict::TimedOut:
            break;
    }
    return "[" + tag + "] tunnel startup timed out after " + dur(startup);
}

std::string tunnel_exited_error(std::string_view error) {
    return "tunnel exited: " + std::string(error);
}

std::string tunnel_join_error(std::string_view error) {
    return "tunnel task join error: " + std::string(error);
}

std::expected<WgEstablish, Error> establish_wg_params(const Settings& settings,
                                                      const Identity& identity, std::size_t mtu,
                                                      bool obfuscate, std::uint16_t keepalive,
                                                      std::string_view label, Notes& notes) {
    WgEstablish establish;
    establish.label = std::string(label);
    establish.mtu = mtu;
    establish.obfuscate = obfuscate;
    establish.keepalive = keepalive;
    establish.private_key = identity.wg_private_key;
    establish.peer_public_key = identity.wg_peer_public_key;
    establish.client_id = identity.client_id;

    // identity.ipv4.parse::<Ipv4Addr>() first, as in the Rust: a bad address stops the hop before
    // hemeranoize_config gets to log its profile line.
    const auto local = ::hemera::core::parse_address(identity.ipv4);
    if (!local.has_value() || !local->v4) {
        return std::unexpected(Error::other(std::string(INVALID_IPV4)));
    }
    establish.local_ipv4 = *local;

    establish.profile =
        obfuscate ? hemeranoize_config(settings, notes) : hemeranoize::from_profile("off");
    establish.validate_timeout = wg_tunnel_validate_timeout(settings);
    return establish;
}

std::string wg_validating_line(std::string_view label, const SocketAddr& peer) {
    return "[*] [" + std::string(label) + "] validating WireGuard tunnel with " + addr(peer) +
           " (handshake + data-plane)...";
}

std::string wg_validated_line(std::string_view label) {
    return "[+] [" + std::string(label) + "] wireguard tunnel validated (end-to-end data confirmed)";
}

std::string wg_validation_error(std::string_view label, std::string_view error) {
    return "[" + std::string(label) + "] tunnel failed validation: " + std::string(error);
}

std::string wg_tunnel_closed_line(std::string_view label) {
    return "[-] [" + std::string(label) + "] wireguard tunnel closed";
}

std::string wg_tunnel_exited_line(std::string_view label, std::string_view error) {
    return "[-] [" + std::string(label) + "] wireguard tunnel exited: " + std::string(error);
}

std::string wg_tunnel_exited_error(std::string_view label, std::string_view error) {
    return "[" + std::string(label) + "] " + std::string(error);
}

std::string wg_tunnel_validating_line(const SocketAddr& peer) {
    return "[*] validating WireGuard tunnel with " + addr(peer) +
           " (handshake + data-plane) before exposing socks5...";
}

std::string wg_tunnel_validation_error(std::string_view error) {
    return "tunnel failed validation: " + std::string(error);
}

std::string wg_tunnel_run_exited_error(std::string_view error) {
    return "wireguard tunnel exited: " + std::string(error);
}

std::expected<WgEstablish, Error> wiw_outer_establish(const Settings& settings,
                                                      const Identity& primary, Notes& notes) {
    // establish_wg(&primary, peer, TUNNEL_MTU, true, 5, "outer")
    return establish_wg_params(settings, primary, TUNNEL_MTU, /*obfuscate=*/true,
                               WIW_OUTER_KEEPALIVE, OUTER_LABEL, notes);
}

std::expected<WgEstablish, Error> wiw_inner_establish(const Settings& settings,
                                                      const Identity& secondary, Notes& notes) {
    // establish_wg(&secondary, forwarder, INNER_MTU, false, 20, "inner")
    return establish_wg_params(settings, secondary, INNER_MTU, /*obfuscate=*/false,
                               WIW_INNER_KEEPALIVE, INNER_LABEL, notes);
}

std::expected<WgEstablish, Error> gool_inner_establish(const Settings& settings,
                                                       const Identity& inner_identity, Notes& notes) {
    // establish_wg(&inner_identity, forwarder, INNER_MTU, false, 25, "inner")
    return establish_wg_params(settings, inner_identity, INNER_MTU, /*obfuscate=*/false,
                               GOOL_INNER_KEEPALIVE, INNER_LABEL, notes);
}

// ---- masque-in-masque ------------------------------------------------------------------------

std::string mim_establishing_line(const SocketAddr& peer) {
    return "[*] establishing outer MASQUE tunnel to " + addr(peer) + "...";
}

std::string mim_too_small_warning(std::size_t outer_mtu) {
    // The Rust string is split across two source lines with a trailing-backslash continuation; the
    // text that reaches the log has one space between "quic" and "datagram".
    return "[-] the outer link carries " + num(outer_mtu) +
           " bytes, too little for an inner quic datagram; raise HEMERA_MASQUE_MTU or use --h2 "
           "for both hops";
}

std::string mim_trying_line(const SocketAddr& inner_peer, const SocketAddr& forwarder) {
    return "[*] trying inner MASQUE edge " + addr(inner_peer) + " through the outer tunnel via " +
           addr(forwarder);
}

std::string mim_inner_ok_line(const SocketAddr& inner_peer) {
    return "[+] inner MASQUE tunnel established through " + addr(inner_peer);
}

std::string mim_inner_fail_line(const SocketAddr& inner_peer, std::string_view error) {
    return "[-] inner edge " + addr(inner_peer) +
           " does not serve masque from inside the tunnel: " + std::string(error);
}

std::string mim_ready_line(const SocketAddr& outer, const SocketAddr& inner_peer) {
    return "[+] masque-in-masque ready: " + addr(outer) + " (outer) and " + addr(inner_peer) +
           " (inner)";
}

std::vector<MimAttempt> mim_inner_plan(std::size_t outer_mtu, bool h2, const SocketAddr& outer,
                                       const std::vector<SocketAddr>& inner_peers) {
    std::vector<MimAttempt> plan;
    for (const SocketAddr& inner_peer : inner_peers) {
        // run_masque_in_masque walks the candidates whose address is not the outer one.
        if (inner_peer.ip == outer.ip) continue;

        const auto budget = mim_inner_budget(outer_mtu, inner_peer, h2);
        MimAttempt attempt;
        attempt.inner_peer = inner_peer;
        attempt.datagram = budget.first;
        attempt.mtu = budget.second;
        attempt.warn_too_small = !h2 && (attempt.datagram + 28 > outer_mtu);
        attempt.forwarder_kind = h2 ? "tcp" : "udp";
        plan.push_back(std::move(attempt));
    }
    return plan;
}

// ---- classic warp-in-warp -------------------------------------------------------------------

std::expected<void, Error> warp_in_warp_precheck(const SocketAddr& outer,
                                                 const SocketAddr& inner_peer) {
    if (inner_peer.ip == outer.ip) {
        return std::unexpected(Error::other(same_edge_error(outer.ip)));
    }
    return {};
}

std::string wiw_outer_line(const SocketAddr& peer) {
    return "[*] establishing outer WARP tunnel to " + addr(peer) + "...";
}

std::string wiw_forwarder_line(const SocketAddr& inner_peer, const SocketAddr& forwarder) {
    return "[+] inner endpoint " + addr(inner_peer) + " tunneled through outer warp via " +
           addr(forwarder);
}

// ---- gool over masque -----------------------------------------------------------------------

std::expected<std::vector<SocketAddr>, Error> gool_inner_peers(const Settings& settings,
                                                               const Identity& identity) {
    if (const auto value = env_value(settings, GOOL_INNER_ENV)) {
        auto parsed = parse_endpoint(*value);
        if (!parsed.has_value()) return std::unexpected(parsed.error());
        return std::vector<SocketAddr>{*parsed};
    }

    std::vector<SocketAddr> peers;
    std::vector<std::string> named;
    named.push_back(trim_str(identity.assigned_endpoint));
    for (const std::string_view seed : wireguard::wg_seeds_v4) {
        named.emplace_back(seed);
    }
    for (const std::string& host : named) {
        const auto ip = ::hemera::core::parse_address(host);
        if (!ip.has_value()) continue;
        const SocketAddr peer{*ip, WG_EXAMPLE_PORT};
        if (!contains(peers, peer)) peers.push_back(peer);
    }
    return peers;
}

std::vector<GoolAttempt> gool_attempt_plan(const std::vector<SocketAddr>& candidates) {
    // 'peers: for inner_peer ... for attempt in 1..=GOOL_INNER_ATTEMPTS
    std::vector<GoolAttempt> plan;
    for (const SocketAddr& candidate : candidates) {
        for (std::uint32_t attempt = 1; attempt <= GOOL_INNER_ATTEMPTS; ++attempt) {
            plan.push_back(GoolAttempt{candidate, attempt});
        }
    }
    return plan;
}

std::string gool_attempt_line(const SocketAddr& inner_peer, const SocketAddr& forwarder) {
    return "[*] wireguard to " + addr(inner_peer) +
           " rides inside the masque tunnel via " + addr(forwarder);
}

std::string gool_attempt_fail_line(const SocketAddr& inner_peer, std::uint32_t attempt,
                                   std::string_view error) {
    return "[-] inner wireguard " + addr(inner_peer) + " attempt " + num(attempt) +
           " failed: " + std::string(error);
}

std::string gool_ready_line(const SocketAddr& peer, const SocketAddr& inner_peer) {
    return "[+] gool ready: masque " + addr(peer) + " carries wireguard " + addr(inner_peer);
}

bool gool_remembers(const Settings& settings, const Identity& inner_identity,
                    const IpAddress& inner_ip) {
    // The identity's assigned endpoint is replaced when it is not already the working address and
    // HEMERA_GOOL_INNER does not pin one.
    return inner_identity.assigned_endpoint != iptext(inner_ip) &&
           !env_value(settings, GOOL_INNER_ENV).has_value();
}

std::string gool_remember_line(const IpAddress& inner_ip) {
    return "[+] gool remembers " + iptext(inner_ip) + " as its wireguard endpoint";
}

std::string gool_identity_loaded_line(std::string_view inner_path) {
    return "[+] loaded the gool wireguard identity from " + std::string(inner_path);
}

std::string gool_identity_saved_line(std::string_view inner_path, const Identity& identity) {
    return "[+] gool wireguard identity registered from inside warp and saved to " +
           std::string(inner_path) + ": device=" + identity.device_id + " ipv4=" + identity.ipv4;
}

std::string gool_enable_warp_warn(std::string_view error) {
    return "[-] could not enable warp on the gool identity: " + std::string(error);
}

// The pinned-hop lines run_gool and run_mim write.
std::string pinned_pair_line(std::string_view what, const SocketAddr& outer,
                             const SocketAddr& inner) {
    return "[+] " + std::string(what) + " endpoints given by hand: " + addr(outer) +
           " (outer) and " + addr(inner) + " (inner); the scan is skipped";
}

std::string gool_pinned_outer_line(const SocketAddr& outer) {
    return "[+] outer warp-in-warp endpoint given by hand: " + addr(outer) +
           "; scanning for the inner one";
}

std::string gool_pinned_inner_line(const SocketAddr& inner) {
    return "[+] inner warp-in-warp endpoint given by hand: " + addr(inner) +
           "; scanning for the outer one";
}

std::string mim_pinned_outer_line(const SocketAddr& outer) {
    return "[+] outer masque-in-masque endpoint given by hand: " + addr(outer) +
           "; the inner one is chosen for you";
}

std::string mim_pinned_inner_line(const SocketAddr& inner) {
    return "[+] inner masque-in-masque endpoint given by hand: " + addr(inner) +
           "; scanning for the outer one";
}

// ---- the reconnect loops --------------------------------------------------------------------

// The tasks each run_* pushes into its TaskGuard, in push order; the guard's drop aborts them all.
std::vector<std::string_view> guard_tasks(RunShape shape, bool http) {
    std::vector<std::string_view> tasks;
    switch (shape) {
        case RunShape::MasqueTunnel:
            // run_masque_tunnel: socks first, then http.
            tasks.push_back(SOCKS_TASK);
            if (http) tasks.push_back(HTTP_TASK);
            break;
        case RunShape::WireguardTunnel:
            // run_wireguard_tunnel: socks first, then http.
            tasks.push_back(SOCKS_TASK);
            if (http) tasks.push_back(HTTP_TASK);
            break;
        case RunShape::MasqueInMasque:
            // run_masque_in_masque: http first, then socks.
            if (http) tasks.push_back(HTTP_TASK);
            tasks.push_back(SOCKS_TASK);
            break;
        case RunShape::WarpInWarp:
            // run_warp_in_warp: outer, inner, http, socks.
            tasks.push_back(OUTER_TASK);
            tasks.push_back(INNER_TASK);
            if (http) tasks.push_back(HTTP_TASK);
            tasks.push_back(SOCKS_TASK);
            break;
        case RunShape::GoolTunnel:
            // run_gool_tunnel: http first, then socks.
            if (http) tasks.push_back(HTTP_TASK);
            tasks.push_back(SOCKS_TASK);
            break;
    }
    return tasks;
}

std::vector<std::string_view> explicit_aborts(RunShape shape, Winner winner) {
    std::vector<std::string_view> aborts;
    switch (shape) {
        case RunShape::MasqueTunnel:
        case RunShape::WireguardTunnel:
            // The exit-policy arm returns early and aborts nothing by hand.
            if (winner != Winner::Policy) {
                aborts.push_back(HTTP_TASK);
                aborts.push_back(SOCKS_TASK);
            }
            break;
        case RunShape::MasqueInMasque:
        case RunShape::GoolTunnel:
            // select arms checked in order: outer, inner, socks -- each skipped when it won.
            if (winner != Winner::Outer) aborts.push_back(OUTER_TASK);
            if (winner != Winner::Inner) aborts.push_back(INNER_TASK);
            if (winner != Winner::Socks) aborts.push_back(SOCKS_TASK);
            break;
        case RunShape::WarpInWarp:
            // run_warp_in_warp aborts the http task unconditionally, then the same three.
            aborts.push_back(HTTP_TASK);
            if (winner != Winner::Outer) aborts.push_back(OUTER_TASK);
            if (winner != Winner::Inner) aborts.push_back(INNER_TASK);
            if (winner != Winner::Socks) aborts.push_back(SOCKS_TASK);
            break;
    }
    return aborts;
}

std::string join_outcome(std::string_view what, const JoinOutcome& outcome) {
    switch (outcome.kind) {
        case JoinOutcome::Kind::Completed:
            return std::string(what) + " stopped";
        case JoinOutcome::Kind::Failed:
            return outcome.error;
        case JoinOutcome::Kind::Cancelled:
            return std::string(what) + " was cancelled";
        case JoinOutcome::Kind::Panicked:
            break;
    }
    return std::string(what) + " panicked: " + outcome.error;
}

TaskGuard::~TaskGuard() { abort_all(); }

TaskGuard::TaskGuard(TaskGuard&& other) noexcept : handles_(std::move(other.handles_)) {
    other.handles_.clear();
}

TaskGuard& TaskGuard::operator=(TaskGuard&& other) noexcept {
    if (this != &other) {
        abort_all();
        handles_ = std::move(other.handles_);
        other.handles_.clear();
    }
    return *this;
}

void TaskGuard::push(Abort handle) { handles_.push_back(std::move(handle)); }

void TaskGuard::abort_all() {
    // Rust drains the Vec, so each handle is aborted exactly once, in push order.
    for (Abort& handle : handles_) {
        if (handle) handle();
    }
    handles_.clear();
}

// ---- the reconnect warn lines ---------------------------------------------------------------

std::string tunnel_closed_line(std::string_view what) {
    return "[-] " + std::string(what) + " closed; reconnecting";
}

std::string tunnel_ended_line(std::string_view what, std::string_view error) {
    return "[-] " + std::string(what) + " ended: " + std::string(error) + "; reconnecting";
}

std::string no_usable_masque_line(std::string_view error) {
    return "[-] no usable MASQUE gateway found: " + std::string(error) + "; rescanning shortly";
}

std::string no_usable_warp_line(std::string_view error) {
    return "[-] no usable WARP endpoint found: " + std::string(error) + "; rescanning shortly";
}

std::string no_usable_wireguard_line(std::string_view error) {
    return "[-] no usable WireGuard endpoint found: " + std::string(error) + "; rescanning shortly";
}

// run_masque
std::string verifying_assigned_line(const SocketAddr& assigned) {
    return "[*] verifying the endpoint the organization assigned: " + addr(assigned);
}

std::string assigned_works_line(const SocketAddr& assigned) {
    return "[+] the assigned endpoint " + addr(assigned) + " works; skipping the scan";
}

std::string assigned_failed_line(const SocketAddr& assigned) {
    return "[-] the assigned endpoint " + addr(assigned) +
           " did not answer; falling back to scanning";
}

std::string verifying_cached_line(const SocketAddr& peer) {
    return "[*] verifying cached gateway " + addr(peer) + " before reuse";
}

std::string cached_works_line(const SocketAddr& peer) {
    return "[+] cached gateway " + addr(peer) + " still works; skipping scan";
}

std::string cached_dead_line(const SocketAddr& peer) {
    return "[-] cached gateway " + addr(peer) + " no longer answers; trying the next one";
}

std::string retrying_last_good_line(const SocketAddr& peer) {
    return "[*] retrying last known-good gateway " + addr(peer) + " before rescanning";
}

std::string last_good_dead_line(const SocketAddr& peer) {
    return "[-] last known-good gateway " + addr(peer) + " no longer responds; rescanning";
}

std::string saved_lastconn_profile(const Settings& settings) {
    // run_masque saves HEMERA_NOIZE as it stands, or "firewall": the same reading as noize_profile.
    return noize_profile(settings);
}

// run_wireguard
std::string wg_assigned_works_line(const SocketAddr& assigned, std::string_view name,
                                   std::chrono::milliseconds rtt) {
    return "[+] the assigned endpoint " + addr(assigned) + " works with profile '" +
           std::string(name) + "' (rtt " + dur(rtt) + "); skipping the scan";
}

std::string wg_assigned_failed_line(const SocketAddr& assigned, std::string_view name,
                                    std::string_view error) {
    return "[-] assigned endpoint " + addr(assigned) + " failed profile '" + std::string(name) +
           "': " + std::string(error);
}

std::string wg_assigned_gave_up_line(const SocketAddr& assigned) {
    return "[-] the assigned endpoint " + addr(assigned) +
           " did not pass validation; falling back to scanning";
}

std::string wg_cached_verifying_line(const SocketAddr& peer) {
    return "[*] verifying cached WireGuard endpoint " + addr(peer) + " before reuse";
}

std::string wg_cached_works_line(const SocketAddr& peer, std::chrono::milliseconds rtt) {
    return "[+] cached endpoint " + addr(peer) + " still works (rtt " + dur(rtt) + "); skipping scan";
}

std::string wg_cached_dead_line(const SocketAddr& peer, std::string_view error) {
    return "[-] cached endpoint " + addr(peer) + " no longer answers (" + std::string(error) +
           "); trying the next one";
}

std::string wg_retrying_last_good_line(const SocketAddr& peer) {
    return "[*] retrying last known-good WireGuard endpoint " + addr(peer) + " before rescanning";
}

std::string wg_last_good_dead_line(const SocketAddr& peer, std::string_view error) {
    return "[-] last known-good endpoint " + addr(peer) + " no longer responds (" +
           std::string(error) + "); rescanning";
}

std::string wg_cooling_down_line(const SocketAddr& peer, std::uint32_t fails,
                                 std::chrono::seconds cooldown) {
    return "[-] endpoint " + addr(peer) + " failed " + num(fails) + " times in a row; excluding it "
                                                                                       "for " +
           dur(cooldown);
}

std::string wg_hunt_profile_line(std::string_view name) {
    return "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, "
           "hemeranoize='" +
           std::string(name) + "')";
}

std::string wg_hunt_selected_line(const SocketAddr& peer, std::string_view name) {
    return "[+] selected WireGuard endpoint " + addr(peer) + " using hemeranoize profile '" +
           std::string(name) + "'";
}

std::string wg_hunt_profile_failed_line(std::string_view name, std::string_view error, bool multi) {
    std::string text = "[-] profile '" + std::string(name) + "' found no data-plane endpoint: " +
                       std::string(error);
    if (multi) text += "; trying next profile";
    return text;
}

std::string wg_testing_forced_line(const SocketAddr& peer, std::string_view name) {
    return "[*] testing forced peer " + addr(peer) + " with hemeranoize profile '" +
           std::string(name) + "'";
}

std::string wg_forced_profile_passed_line(std::string_view name, std::chrono::milliseconds rtt) {
    return "[+] profile '" + std::string(name) + "' passed handshake + data-plane (rtt " + dur(rtt) +
           ")";
}

std::string wg_forced_profile_failed_line(std::string_view name, std::string_view error) {
    return "[-] profile '" + std::string(name) + "' failed on forced peer: " + std::string(error);
}

std::string wg_forced_exhausted_line(const SocketAddr& peer) {
    return "[-] forced peer " + addr(peer) +
           " failed with every hemeranoize profile; retrying shortly";
}

// run_gool
std::string gool_blacklist_outer_line(const SocketAddr& peer, std::uint32_t fails) {
    return "[-] outer endpoint " + addr(peer) + " failed " + num(fails) +
           " times in a row; blacklisting and rescanning";
}

std::string gool_blacklist_inner_line(const SocketAddr& peer, std::uint32_t fails) {
    return "[-] inner endpoint " + addr(peer) + " failed " + num(fails) +
           " times in a row; blacklisting and rescanning";
}

std::string gool_pinned_exhausted_line(std::uint32_t fails) {
    return "[-] the endpoints you chose failed " + num(fails) +
           " times in a row; still retrying them, drop --wiw-outer/--wiw-inner to let the scan "
           "pick instead";
}

// run_mim
std::string mim_outer_rescan_line(const SocketAddr& peer, std::uint32_t fails) {
    return "[-] outer edge " + addr(peer) + " failed " + num(fails) + " times in a row; rescanning";
}

std::string mim_inner_another_line(const SocketAddr& peer, std::uint32_t fails) {
    return "[-] inner edge " + addr(peer) +
           " failed " + num(fails) + " times in a row; trying another";
}

namespace {

// ---- request builders for the flows ----------------------------------------------------------

[[nodiscard]] FlowRequest verify_masque_request(
    const SocketAddr& peer, const std::optional<std::vector<std::uint8_t>>& ech) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::VerifyMasquePeer;
    request.peer = peer;
    request.ech = ech;
    request.timeout = QUICK_VERIFY_TIMEOUT;
    return request;
}

[[nodiscard]] FlowRequest hunt_masque_request(const std::pair<std::string, IpScan>& scan) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::HuntMasquePeer;
    request.mode_str = scan.first;
    request.ip = scan.second;
    return request;
}

// verify_endpoint on a probe path: the keepalive is Rust's None on every check that does not run
// a tunnel.
[[nodiscard]] FlowRequest verify_wg_request(const SocketAddr& peer, const HemeraNoizeConfig& noise,
                                            std::chrono::seconds timeout) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::VerifyWgEndpoint;
    request.peer = peer;
    request.noise = noise;
    request.timeout = timeout;
    return request;
}

[[nodiscard]] FlowRequest hunt_wg_endpoint_request(const std::pair<std::string, IpScan>& scan,
                                                  const HemeraNoizeConfig& noise,
                                                  const std::vector<SocketAddr>& excluded) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::HuntWgEndpoint;
    request.mode_str = scan.first;
    request.ip = scan.second;
    request.noise = noise;
    request.excluded = excluded;
    return request;
}

[[nodiscard]] FlowRequest hunt_wg_peers_request(const std::pair<std::string, IpScan>& scan,
                                               std::size_t want,
                                               const std::vector<IpAddress>& avoid) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::HuntWgPeers;
    request.mode_str = scan.first;
    request.ip = scan.second;
    request.want = want;
    request.avoid = avoid;
    request.excluded = wg_excluded_for(avoid);
    return request;
}

[[nodiscard]] FlowRequest save_lastconn_request(std::string path, const SocketAddr& peer,
                                               std::string profile, std::string carrier) {
    FlowRequest request;
    request.kind = FlowRequest::Kind::SaveLastconn;
    request.path = std::move(path);
    request.peer_text = addr(peer);
    request.profile = std::move(profile);
    request.carrier = std::move(carrier);
    return request;
}

// The ProbeResult the selected-gateway line wants, from a hunt reply.
[[nodiscard]] ProbeResult probe_of(const SocketAddr& peer, std::chrono::milliseconds rtt) {
    ProbeResult result;
    result.ip = peer.ip;
    result.port = peer.port;
    result.rtt = rtt;
    return result;
}

// Marks a flow step as sleeping and remembers which phase wakes it.
[[nodiscard]] FlowStep sleep_step(int& phase, std::chrono::seconds delay, int wake_phase) {
    phase = wake_phase;
    FlowRequest request = sleep_request(delay);
    FlowStep step;
    step.request = request;
    return step;
}

} // namespace

// Extra phase numbers for the flows: the pre-loop stages (assigned endpoint, cached ring) are
// entered only from begin(), but their continuations re-enter begin() once their verify replies, so
// the phase marks which stages have already run. Nothing new happens in the Rust that way; it is
// how its straight-line pre-loop code maps onto begin()/resume().
constexpr int MA_ASSIGNED_DONE = 21; // the assigned-endpoint verify is over
constexpr int MA_STAGES_DONE = 22;   // assigned and cached stages are both over
constexpr int WG_ASSIGNED_DONE = 23;
constexpr int WG_STAGES_DONE = 24;

// ---- MasqueFlow -------------------------------------------------------------------------------

MasqueFlow::MasqueFlow(Config config) : config_(std::move(config)) {}

FlowStep MasqueFlow::stopped() {
    cancelled_ = true;
    done_ = true;
    return FlowStep{};
}

FlowStep MasqueFlow::sleep_then(std::chrono::seconds delay, int phase) {
    return sleep_step(phase_, delay, phase);
}

FlowStep MasqueFlow::begin() {
    if (config_.cancel.is_cancelled()) return stopped();

    forced_ = raw(config_.settings, PEER_ENV);

    // HEMERA_TEAM_ENDPOINT, parsed and verified before anything else, unless a pin was given.
    if (phase_ == PH_NONE && !forced_.has_value()) {
        if (const auto value = raw(config_.settings, TEAM_ENDPOINT_ENV)) {
            if (const auto parsed = ::hemera::core::parse_socket_addr(*value)) {
                assigned_ = *parsed;
                FlowStep step;
                note_info(step.notes, verifying_assigned_line(*assigned_));
                phase_ = MA_ASSIGNED;
                pending_ = verify_masque_request(*assigned_, config_.ech);
                step.request = pending_;
                return step;
            }
        }
    }

    // The lastconn ring, when nothing answered already.
    if ((phase_ == PH_NONE || phase_ == MA_ASSIGNED_DONE) && !forced_.has_value() &&
        !quick_peer_.has_value() && config_.cached.has_value()) {
        ring_ = ring_peers(*config_.cached, masque_carrier(config_.settings));
        if (!ring_.empty() && want_quick_reconnect(config_.settings, *config_.cached, config_.prompt)) {
            ring_index_ = 0;
            FlowStep step;
            note_info(step.notes, verifying_cached_line(ring_[0]));
            phase_ = MA_RING;
            pending_ = verify_masque_request(ring_[0], config_.ech);
            step.request = pending_;
            return step;
        }
    }

    if (!scan_settings_.has_value()) {
        if (forced_.has_value() || quick_peer_.has_value()) {
            scan_settings_ = scan_settings_from_env(config_.settings);
        } else {
            scan_settings_ = std::make_pair(select_scan_mode_str(config_.settings, "", config_.prompt),
                                            select_ip_version(config_.settings, config_.prompt));
        }
    }
    return loop_top();
}

FlowStep MasqueFlow::loop_top() {
    if (config_.cancel.is_cancelled()) return stopped();

    if (quick_peer_.has_value()) {
        const SocketAddr peer = *quick_peer_;
        quick_peer_.reset();
        return use_peer(peer);
    }

    if (last_good_peer_.has_value()) {
        FlowStep step;
        note_info(step.notes, retrying_last_good_line(*last_good_peer_));
        phase_ = MA_LASTGOOD;
        pending_ = verify_masque_request(*last_good_peer_, config_.ech);
        step.request = pending_;
        return step;
    }

    return forced_or_hunt();
}

FlowStep MasqueFlow::forced_or_hunt() {
    if (config_.cancel.is_cancelled()) return stopped();

    if (forced_.has_value()) {
        const auto parsed = parse_forced_peer(*forced_);
        if (!parsed.has_value()) {
            fatal_ = parsed.error();
            done_ = true;
            return FlowStep{};
        }
        FlowStep step;
        note_info(step.notes, using_forced_peer_line(*parsed));
        return merge_into(std::move(step), use_peer(*parsed));
    }

    FlowStep step;
    note_info(step.notes, std::string(HUNT_MASQUE_LINE));
    phase_ = MA_HUNT;
    pending_ = hunt_masque_request(*scan_settings_);
    step.request = pending_;
    return step;
}

FlowStep MasqueFlow::use_peer(const SocketAddr& peer) {
    FlowStep step;
    note_info(step.notes, using_edge_line(peer));

    if (!forced_.has_value()) {
        // lastconn::save, then the bookkeeping the Rust runs after it, then the tunnel.
        phase_ = MA_SAVE;
        pending_ = save_lastconn_request(config_.lastconn_path, peer,
                                         saved_lastconn_profile(config_.settings),
                                         std::string(masque_carrier(config_.settings)));
        step.request = pending_;
        last_good_peer_ = peer;
        return step;
    }

    last_good_peer_ = peer;
    phase_ = MA_TUNNEL;
    pending_ = FlowRequest{};
    pending_.kind = FlowRequest::Kind::RunTunnel;
    pending_.shape = config_.gool_inner.has_value() ? RunShape::GoolTunnel : RunShape::MasqueTunnel;
    pending_.peer = peer;
    pending_.ech = config_.ech;
    pending_.timeout = masque_startup_timeout(config_.settings);
    pending_.gool_inner_path = config_.gool_inner.value_or(std::string());
    step.request = pending_;
    return step;
}

FlowStep MasqueFlow::resume(const FlowReply& reply) {
    if (config_.cancel.is_cancelled()) return stopped();

    switch (phase_) {
        case MA_ASSIGNED: {
            FlowStep step;
            if (reply.ok) {
                note_info(step.notes, assigned_works_line(*assigned_));
                quick_peer_ = assigned_;
            } else {
                note_warn(step.notes, assigned_failed_line(*assigned_));
            }
            // The cached stage follows, exactly as the Rust's straight-line pre-loop code does.
            phase_ = MA_ASSIGNED_DONE;
            return merge_into(std::move(step), begin());
        }
        case MA_RING: {
            FlowStep step;
            const SocketAddr peer = ring_[ring_index_];
            if (reply.ok) {
                note_info(step.notes, cached_works_line(peer));
                quick_peer_ = peer;
                phase_ = MA_STAGES_DONE;
                return merge_into(std::move(step), begin());
            }
            note_warn(step.notes, cached_dead_line(peer));
            ++ring_index_;
            if (ring_index_ < ring_.size()) {
                note_info(step.notes, verifying_cached_line(ring_[ring_index_]));
                phase_ = MA_RING;
                pending_ = verify_masque_request(ring_[ring_index_], config_.ech);
                step.request = pending_;
                return step;
            }
            note_warn(step.notes, std::string(NO_REMEMBERED_GATEWAY));
            phase_ = MA_STAGES_DONE;
            return merge_into(std::move(step), begin());
        }
        case MA_LASTGOOD: {
            FlowStep step;
            if (reply.ok) {
                return merge_into(std::move(step), use_peer(*last_good_peer_));
            }
            note_warn(step.notes, last_good_dead_line(*last_good_peer_));
            return merge_into(std::move(step), forced_or_hunt());
        }
        case MA_HUNT: {
            if (!reply.ok) {
                FlowStep step;
                note_warn(step.notes, no_usable_masque_line(reply.error.display()));
                return merge_into(std::move(step),
                                  sleep_then(masque_reconnect_delay(config_.settings), MA_SLEEP_RETRY));
            }
            FlowStep step;
            note_info(step.notes, masque_selected_line(probe_of(reply.peer, reply.rtt)));
            return merge_into(std::move(step), use_peer(reply.peer));
        }
        case MA_SLEEP_RETRY:
            return loop_top();
        case MA_SAVE: {
            FlowRequest tunnel;
            tunnel.kind = FlowRequest::Kind::RunTunnel;
            tunnel.shape =
                config_.gool_inner.has_value() ? RunShape::GoolTunnel : RunShape::MasqueTunnel;
            tunnel.peer = *last_good_peer_;
            tunnel.ech = config_.ech;
            tunnel.timeout = masque_startup_timeout(config_.settings);
            tunnel.gool_inner_path = config_.gool_inner.value_or(std::string());
            phase_ = MA_TUNNEL;
            pending_ = tunnel;
            FlowStep step;
            step.request = pending_;
            return step;
        }
        case MA_TUNNEL: {
            FlowStep step;
            if (reply.ok) {
                note_warn(step.notes, tunnel_closed_line("MASQUE tunnel"));
            } else {
                note_warn(step.notes, tunnel_ended_line("MASQUE tunnel", reply.error.display()));
            }
            return merge_into(std::move(step),
                              sleep_then(masque_reconnect_delay(config_.settings), MA_SLEEP_END));
        }
        case MA_SLEEP_END:
            return loop_top();
        default:
            break;
    }
    return loop_top();
}

// ---- WireguardFlow ----------------------------------------------------------------------------

WireguardFlow::WireguardFlow(Config config) : config_(std::move(config)) {}

FlowStep WireguardFlow::stopped() {
    cancelled_ = true;
    done_ = true;
    return FlowStep{};
}

FlowStep WireguardFlow::begin(TimePoint now) {
    if (config_.cancel.is_cancelled()) return stopped();

    FlowStep step;

    if (phase_ == PH_NONE) {
        // wg_profile_candidates writes the primary-profile line before anything else.
        candidates_ = wg_profile_candidates(config_.settings, step.notes);

        forced_ = raw(config_.settings, WG_PEER_ENV);
        if (!forced_.has_value()) forced_ = raw(config_.settings, PEER_ENV);

        // identity.ipv4.parse::<Ipv4Addr>() up front; a bad address stops the run.
        const auto local = ::hemera::core::parse_address(config_.identity.ipv4);
        if (!local.has_value() || !local->v4) {
            fatal_ = Error::other(std::string(INVALID_IPV4));
            done_ = true;
            return step;
        }

        if (!forced_.has_value()) {
            if (const auto value = raw(config_.settings, TEAM_ENDPOINT_ENV)) {
                if (const auto parsed = ::hemera::core::parse_socket_addr(*value)) {
                    assigned_ = *parsed;
                    profile_index_ = 0;
                    note_info(step.notes, verifying_assigned_line(*assigned_));
                    phase_ = WG_ASSIGNED;
                    pending_ = verify_wg_request(*assigned_, candidates_[0].second,
                                                 ASSIGNED_VERIFY_TIMEOUT);
                    step.request = pending_;
                    return step;
                }
            }
        }
    }

    if ((phase_ == PH_NONE || phase_ == WG_ASSIGNED_DONE) && !forced_.has_value() &&
        !quick_.has_value() && config_.cached.has_value()) {
        ring_ = ring_peers(*config_.cached, std::string(::hemera::core::CARRIER_WIREGUARD));
        if (!ring_.empty() &&
            want_quick_reconnect(config_.settings, *config_.cached, config_.prompt)) {
            cached_profile_ = hemeranoize::from_profile(config_.cached->profile);
            ring_index_ = 0;
            note_info(step.notes, wg_cached_verifying_line(ring_[0]));
            phase_ = WG_RING;
            pending_ = verify_wg_request(ring_[0], cached_profile_, CACHED_VERIFY_TIMEOUT);
            step.request = pending_;
            return step;
        }
    }

    if (!scan_settings_.has_value()) {
        if (forced_.has_value() || quick_.has_value()) {
            scan_settings_ = scan_settings_from_env(config_.settings);
        } else {
            scan_settings_ = std::make_pair(select_scan_mode_str(config_.settings, "", config_.prompt),
                                            select_ip_version(config_.settings, config_.prompt));
        }
    }
    return merge_into(std::move(step), loop_top(now));
}

// The (peer, profile, profile_name) pick of run_wireguard's loop body: a consumed quick answer,
// else a retry of the last known-good endpoint, else the forced peer or the hunt.
FlowStep WireguardFlow::loop_top(TimePoint now) {
    if (config_.cancel.is_cancelled()) return stopped();

    // endpoint_cooldowns.retain(|_, until| *until > now)
    std::erase_if(endpoint_cooldowns_,
                  [&](const std::pair<SocketAddr, TimePoint>& entry) { return entry.second <= now; });

    FlowStep step;
    if (consecutive_fails_ >= MAX_CONSECUTIVE_FAILS) {
        if (last_good_.has_value()) {
            const auto cooldown = wg_endpoint_cooldown(config_.settings);
            const SocketAddr peer = last_good_->peer;
            endpoint_cooldowns_.emplace_back(peer,
                                             now + std::chrono::duration_cast<TimePoint::duration>(
                                                       cooldown));
            note_warn(step.notes, wg_cooling_down_line(peer, consecutive_fails_, cooldown));
            last_good_.reset();
        }
        consecutive_fails_ = 0;
    }

    if (quick_.has_value()) {
        const LastGood chosen = *quick_;
        quick_.reset();
        return merge_into(std::move(step), use_peer(chosen));
    }

    if (last_good_.has_value()) {
        note_info(step.notes, wg_retrying_last_good_line(last_good_->peer));
        phase_ = WG_LASTGOOD;
        pending_ = verify_wg_request(last_good_->peer, last_good_->profile, LAST_GOOD_VERIFY_TIMEOUT);
        step.request = pending_;
        return step;
    }

    return merge_into(std::move(step), forced_or_hunt());
}

FlowStep WireguardFlow::forced_or_hunt() {
    if (config_.cancel.is_cancelled()) return stopped();

    if (forced_.has_value()) {
        const auto parsed = parse_forced_peer(*forced_);
        if (!parsed.has_value()) {
            fatal_ = parsed.error();
            done_ = true;
            return FlowStep{};
        }
        FlowStep step;
        note_info(step.notes, using_forced_peer_line(*parsed));
        profile_index_ = 0;
        phase_ = WG_FORCED;
        note_info(step.notes, wg_testing_forced_line(*parsed, candidates_[0].first));
        pending_ = verify_wg_request(*parsed, candidates_[0].second, FORCED_VERIFY_TIMEOUT);
        step.request = pending_;
        return step;
    }

    // hunt_wg_peer: one HuntWgEndpoint per profile, in order.
    FlowStep step;
    profile_index_ = 0;
    phase_ = WG_HUNT;
    note_info(step.notes, wg_hunt_profile_line(candidates_[0].first));
    pending_ = hunt_wg_endpoint_request(*scan_settings_, candidates_[0].second, cooldowns());
    step.request = pending_;
    return step;
}

FlowStep WireguardFlow::use_peer(LastGood chosen) {
    FlowStep step;
    note_info(step.notes, using_edge_line(chosen.peer));

    const bool is_same = last_good_.has_value() && last_good_->peer == chosen.peer;
    if (!is_same) consecutive_fails_ = 0;
    last_good_ = chosen;

    if (!forced_.has_value()) {
        phase_ = WG_SAVE;
        pending_ = save_lastconn_request(config_.lastconn_path, chosen.peer, chosen.name,
                                         std::string(::hemera::core::CARRIER_WIREGUARD));
        step.request = pending_;
        return step;
    }

    phase_ = WG_TUNNEL;
    pending_ = FlowRequest{};
    pending_.kind = FlowRequest::Kind::RunTunnel;
    pending_.shape = RunShape::WireguardTunnel;
    pending_.peer = chosen.peer;
    pending_.noise = chosen.profile;
    pending_.timeout = wg_tunnel_validate_timeout(config_.settings);
    pending_.keepalive = wg_keepalive_secs(config_.settings);
    step.request = pending_;
    return step;
}

FlowStep WireguardFlow::resume(const FlowReply& reply, TimePoint now) {
    if (config_.cancel.is_cancelled()) return stopped();

    switch (phase_) {
        case WG_ASSIGNED: {
            FlowStep step;
            const auto& [name, profile] = candidates_[profile_index_];
            if (reply.ok) {
                note_info(step.notes, wg_assigned_works_line(*assigned_, name, reply.rtt));
                quick_ = LastGood{*assigned_, profile, name};
                phase_ = WG_ASSIGNED_DONE;
                return merge_into(std::move(step), begin(now));
            }
            note_debug(step.notes, wg_assigned_failed_line(*assigned_, name, reply.error.display()));
            ++profile_index_;
            if (profile_index_ < candidates_.size()) {
                phase_ = WG_ASSIGNED;
                pending_ = verify_wg_request(*assigned_, candidates_[profile_index_].second,
                                             ASSIGNED_VERIFY_TIMEOUT);
                step.request = pending_;
                return step;
            }
            note_warn(step.notes, wg_assigned_gave_up_line(*assigned_));
            phase_ = WG_ASSIGNED_DONE;
            return merge_into(std::move(step), begin(now));
        }
        case WG_RING: {
            FlowStep step;
            const SocketAddr peer = ring_[ring_index_];
            if (reply.ok) {
                note_info(step.notes, wg_cached_works_line(peer, reply.rtt));
                quick_ = LastGood{peer, cached_profile_, config_.cached->profile};
                phase_ = WG_STAGES_DONE;
                return merge_into(std::move(step), begin(now));
            }
            note_warn(step.notes, wg_cached_dead_line(peer, reply.error.display()));
            ++ring_index_;
            if (ring_index_ < ring_.size()) {
                note_info(step.notes, wg_cached_verifying_line(ring_[ring_index_]));
                phase_ = WG_RING;
                pending_ = verify_wg_request(ring_[ring_index_], cached_profile_,
                                             CACHED_VERIFY_TIMEOUT);
                step.request = pending_;
                return step;
            }
            note_warn(step.notes, std::string(WG_NO_REMEMBERED));
            phase_ = WG_STAGES_DONE;
            return merge_into(std::move(step), begin(now));
        }
        case WG_LASTGOOD: {
            FlowStep step;
            if (reply.ok) {
                return merge_into(std::move(step), use_peer(*last_good_));
            }
            note_warn(step.notes, wg_last_good_dead_line(last_good_->peer, reply.error.display()));
            return merge_into(std::move(step), forced_or_hunt());
        }
        case WG_FORCED: {
            FlowStep step;
            const auto& [name, profile] = candidates_[profile_index_];
            const SocketAddr peer = pending_.peer;
            if (reply.ok) {
                note_info(step.notes, wg_forced_profile_passed_line(name, reply.rtt));
                return merge_into(std::move(step), use_peer(LastGood{peer, profile, name}));
            }
            note_warn(step.notes, wg_forced_profile_failed_line(name, reply.error.display()));
            ++profile_index_;
            if (profile_index_ < candidates_.size()) {
                note_info(step.notes, wg_testing_forced_line(peer, candidates_[profile_index_].first));
                phase_ = WG_FORCED;
                pending_ = verify_wg_request(peer, candidates_[profile_index_].second,
                                             FORCED_VERIFY_TIMEOUT);
                pending_.peer = peer;
                step.request = pending_;
                return step;
            }
            note_warn(step.notes, wg_forced_exhausted_line(peer));
            phase_ = WG_SLEEP_RETRY;
            step.request = sleep_request(wg_reconnect_delay(config_.settings));
            return step;
        }
        case WG_HUNT: {
            FlowStep step;
            const std::string& name = candidates_[profile_index_].first;
            if (reply.ok) {
                note_info(step.notes, wg_hunt_selected_line(reply.peer, reply.profile_name));
                return merge_into(std::move(step),
                                  use_peer(LastGood{reply.peer, reply.profile, reply.profile_name}));
            }
            note_warn(step.notes, wg_hunt_profile_failed_line(name, reply.error.display(),
                                                              candidates_.size() > 1));
            ++profile_index_;
            if (profile_index_ < candidates_.size()) {
                note_info(step.notes, wg_hunt_profile_line(candidates_[profile_index_].first));
                phase_ = WG_HUNT;
                pending_ = hunt_wg_endpoint_request(*scan_settings_,
                                                    candidates_[profile_index_].second, cooldowns());
                step.request = pending_;
                return step;
            }
            // hunt_wg_peer's own error after every profile has failed: NoCleanEndpoint.
            note_warn(step.notes,
                      no_usable_wireguard_line(Error::no_clean_endpoint().display()));
            phase_ = WG_SLEEP_RETRY;
            step.request = sleep_request(wg_reconnect_delay(config_.settings));
            return step;
        }
        case WG_SLEEP_RETRY:
        case WG_SLEEP_END:
            return loop_top(now);
        case WG_SAVE: {
            FlowStep step;
            phase_ = WG_TUNNEL;
            pending_ = FlowRequest{};
            pending_.kind = FlowRequest::Kind::RunTunnel;
            pending_.shape = RunShape::WireguardTunnel;
            pending_.peer = last_good_->peer;
            pending_.noise = last_good_->profile;
            pending_.timeout = wg_tunnel_validate_timeout(config_.settings);
            pending_.keepalive = wg_keepalive_secs(config_.settings);
            step.request = pending_;
            return step;
        }
        case WG_TUNNEL: {
            FlowStep step;
            if (reply.ok) {
                note_warn(step.notes, tunnel_closed_line("WireGuard tunnel"));
            } else {
                note_warn(step.notes,
                          tunnel_ended_line("WireGuard tunnel", reply.error.display()));
            }
            ++consecutive_fails_;
            phase_ = WG_SLEEP_END;
            step.request = sleep_request(wg_reconnect_delay(config_.settings));
            return step;
        }
        default:
            break;
    }
    return loop_top(now);
}

const std::optional<SocketAddr>& WireguardFlow::current_peer() const {
    // LastGood carries a bare SocketAddr and the declaration hands back an optional reference, so
    // the snapshot goes into a static the reference can honestly point at.
    static thread_local std::optional<SocketAddr> value;
    if (last_good_.has_value()) {
        value = last_good_->peer;
    } else {
        value.reset();
    }
    return value;
}

std::vector<SocketAddr> WireguardFlow::cooldowns() const {
    std::vector<SocketAddr> peers;
    peers.reserve(endpoint_cooldowns_.size());
    for (const auto& [peer, until] : endpoint_cooldowns_) {
        (void)until;
        peers.push_back(peer);
    }
    return peers;
}

// ---- GoolFlow ---------------------------------------------------------------------------------

GoolFlow::GoolFlow(Config config) : config_(std::move(config)) {}

FlowStep GoolFlow::stopped() {
    cancelled_ = true;
    done_ = true;
    return FlowStep{};
}

FlowStep GoolFlow::begin() {
    if (config_.cancel.is_cancelled()) return stopped();

    FlowStep step;
    if (phase_ == PH_NONE) {
        // run_gool's first line is the pin read; a nonsense endpoint stops the run.
        const auto pinned = wiw_endpoints_with_fallback(config_.settings);
        if (!pinned.has_value()) {
            fatal_ = pinned.error();
            done_ = true;
            return step;
        }
        pinned_ = *pinned;
        if (pinned_.outer.has_value() && pinned_.inner.has_value()) {
            note_info(step.notes,
                      pinned_pair_line("warp-in-warp", *pinned_.outer, *pinned_.inner));
        } else if (pinned_.outer.has_value()) {
            note_info(step.notes, gool_pinned_outer_line(*pinned_.outer));
        } else if (pinned_.inner.has_value()) {
            note_info(step.notes, gool_pinned_inner_line(*pinned_.inner));
        }
        outer_peer_ = pinned_.outer;
        inner_peer_ = pinned_.inner;
    }
    return merge_into(std::move(step), loop_top());
}

// The loop body of run_gool: the blacklist pass, then the pair it already has, then the hunt for
// whatever the pair is missing.
FlowStep GoolFlow::loop_top() {
    if (config_.cancel.is_cancelled()) return stopped();

    FlowStep step;
    if (consecutive_fails_ >= MAX_CONSECUTIVE_FAILS) {
        bool rescanning = false;
        if (!pinned_.outer.has_value() && outer_peer_.has_value()) {
            note_warn(step.notes, gool_blacklist_outer_line(*outer_peer_, consecutive_fails_));
            outer_peer_.reset();
            rescanning = true;
        }
        if (!pinned_.inner.has_value() && inner_peer_.has_value()) {
            note_warn(step.notes, gool_blacklist_inner_line(*inner_peer_, consecutive_fails_));
            inner_peer_.reset();
            rescanning = true;
        }
        if (!rescanning) {
            note_warn(step.notes, gool_pinned_exhausted_line(consecutive_fails_));
        }
        consecutive_fails_ = 0;
    }

    if (outer_peer_.has_value() && inner_peer_.has_value()) {
        return merge_into(std::move(step), use_pair(*outer_peer_, *inner_peer_));
    }

    // usize::from(known_outer.is_none()) + usize::from(known_inner.is_none())
    const std::size_t wanted = (outer_peer_.has_value() ? 0u : 1u) +
                               (inner_peer_.has_value() ? 0u : 1u);
    // The HashSet of the other hop's addresses, de-duplicated like the Rust's collect.
    std::vector<IpAddress> avoid;
    if (outer_peer_.has_value()) avoid.push_back(outer_peer_->ip);
    if (inner_peer_.has_value() && !contains(avoid, inner_peer_->ip)) {
        avoid.push_back(inner_peer_->ip);
    }

    if (!scan_settings_.has_value()) {
        scan_settings_ = std::make_pair(
            select_scan_mode_str(config_.settings, WIW_MANUAL_TIP, config_.prompt),
            select_ip_version(config_.settings, config_.prompt));
    }

    // select_wg_peers' own three leading lines, in the Rust's order.
    note_info(step.notes, wg_hunting_line(wanted));
    if (!avoid.empty()) note_info(step.notes, wg_avoid_line(avoid.size()));

    phase_ = GO_HUNT;
    pending_ = hunt_wg_peers_request(*scan_settings_, wanted, avoid);
    // hemeranoize_config() runs while select_wg_peers builds its probe, after the avoid line.
    pending_.noise = hemeranoize_config(config_.settings, step.notes);
    step.request = pending_;
    return step;
}

// "[+] using cloudflare edge {outer} (outer) and {inner} (inner)", then the tunnel.
FlowStep GoolFlow::use_pair(const SocketAddr& outer, const SocketAddr& inner) {
    FlowStep step;
    note_info(step.notes, using_edge_pair_line(outer, inner));
    outer_peer_ = outer;
    inner_peer_ = inner;

    phase_ = GO_TUNNEL;
    pending_ = FlowRequest{};
    pending_.kind = FlowRequest::Kind::RunTunnel;
    pending_.shape = RunShape::WarpInWarp;
    pending_.peer = outer;
    pending_.inner_peer = inner;
    step.request = pending_;
    return step;
}

FlowStep GoolFlow::resume(const FlowReply& reply) {
    if (config_.cancel.is_cancelled()) return stopped();

    switch (phase_) {
        case GO_HUNT: {
            FlowStep step;
            if (!reply.ok) {
                // select_wg_peers failed whole: the identity's keys, its ipv4, or the prober.
                note_warn(step.notes, no_usable_warp_line(reply.error.display()));
                return merge_into(std::move(step),
                                  sleep_step(phase_, wg_reconnect_delay(config_.settings),
                                             GO_SLEEP));
            }

            // select_wg_peers' post-filter, with the per-pick line it logs after the empty check.
            std::vector<WgProbeResult> selected;
            for (const auto& result : reply.results) {
                if (selected.size() >= pending_.want) break;
                if (contains(pending_.avoid, result.ip)) continue;
                selected.push_back(result);
            }
            if (selected.empty()) {
                note_warn(step.notes,
                          no_usable_warp_line(Error::no_clean_endpoint().display()));
                return merge_into(std::move(step),
                                  sleep_step(phase_, wg_reconnect_delay(config_.settings),
                                             GO_SLEEP));
            }
            for (const auto& result : selected) note_info(step.notes, wg_selected_line(result));

            std::vector<SocketAddr> found;
            found.reserve(selected.size());
            for (const auto& result : selected) found.push_back(SocketAddr{result.ip, result.port});
            if (verified_scan_selected(config_.settings, scan_settings_)) spread_hops(found);

            // outer = known_outer.or_else(next); inner = known_inner.or_else(next).
            std::size_t next = 0;
            std::optional<SocketAddr> outer = outer_peer_;
            std::optional<SocketAddr> inner = inner_peer_;
            if (!outer.has_value() && next < found.size()) outer = found[next++];
            if (!inner.has_value() && next < found.size()) inner = found[next++];

            if (!outer.has_value() || !inner.has_value()) {
                note_warn(step.notes, std::string(GOOL_ONE_EDGE));
                outer_peer_ = pinned_.outer;
                inner_peer_ = pinned_.inner;
                return merge_into(std::move(step),
                                  sleep_step(phase_, wg_reconnect_delay(config_.settings),
                                             GO_SLEEP));
            }
            return merge_into(std::move(step), use_pair(*outer, *inner));
        }
        case GO_TUNNEL: {
            FlowStep step;
            if (reply.ok) {
                note_warn(step.notes, tunnel_closed_line("gool tunnel"));
            } else {
                note_warn(step.notes, tunnel_ended_line("gool tunnel", reply.error.display()));
            }
            ++consecutive_fails_;
            return merge_into(std::move(step),
                              sleep_step(phase_, wg_reconnect_delay(config_.settings), GO_SLEEP));
        }
        case GO_SLEEP:
            return loop_top();
        default:
            break;
    }
    return loop_top();
}

// ---- MimFlow ----------------------------------------------------------------------------------

MimFlow::MimFlow(Config config) : config_(std::move(config)) {}

FlowStep MimFlow::stopped() {
    cancelled_ = true;
    done_ = true;
    return FlowStep{};
}

FlowStep MimFlow::begin() {
    if (config_.cancel.is_cancelled()) return stopped();

    FlowStep step;
    if (phase_ == PH_NONE) {
        const auto pinned = mim_endpoints_of(config_.settings);
        if (!pinned.has_value()) {
            fatal_ = pinned.error();
            done_ = true;
            return step;
        }
        pinned_ = *pinned;
        if (pinned_.outer.has_value() && pinned_.inner.has_value()) {
            note_info(step.notes,
                      pinned_pair_line("masque-in-masque", *pinned_.outer, *pinned_.inner));
        } else if (pinned_.outer.has_value()) {
            note_info(step.notes, mim_pinned_outer_line(*pinned_.outer));
        } else if (pinned_.inner.has_value()) {
            note_info(step.notes, mim_pinned_inner_line(*pinned_.inner));
        }
        outer_peer_ = pinned_.outer;
        inner_peer_ = pinned_.inner;
    }
    return merge_into(std::move(step), loop_top());
}

FlowStep MimFlow::loop_top() {
    if (config_.cancel.is_cancelled()) return stopped();

    FlowStep step;
    if (consecutive_fails_ >= MAX_CONSECUTIVE_FAILS) {
        // run_mim's two takes; the second one only speaks when the inner edge was given by hand
        // and the outer one failed twice, which is the pairing the Rust keeps.
        if (!pinned_.outer.has_value() && outer_peer_.has_value()) {
            note_warn(step.notes, mim_outer_rescan_line(*outer_peer_, consecutive_fails_));
            outer_peer_.reset();
        }
        if (!pinned_.inner.has_value() && inner_peer_.has_value()) {
            note_warn(step.notes, mim_inner_another_line(*inner_peer_, consecutive_fails_));
            inner_peer_.reset();
        }
        consecutive_fails_ = 0;
    }

    if (outer_peer_.has_value()) {
        return merge_into(std::move(step), after_outer(*outer_peer_));
    }

    if (!scan_settings_.has_value()) {
        scan_settings_ = std::make_pair(
            select_scan_mode_str(config_.settings, MIM_MANUAL_TIP, config_.prompt),
            select_ip_version(config_.settings, config_.prompt));
    }

    // hunt_masque_peer's leading line; the engine owns the probe it describes.
    note_info(step.notes, std::string(HUNT_MASQUE_LINE));
    phase_ = MI_HUNT;
    pending_ = hunt_masque_request(*scan_settings_);
    step.request = pending_;
    return step;
}

// Everything run_mim does once the outer edge is known: the candidate list, the empty refusal,
// and the tunnel request.
FlowStep MimFlow::after_outer(const SocketAddr& outer) {
    FlowStep step;
    std::vector<SocketAddr> candidates;
    if (inner_peer_.has_value()) {
        candidates.push_back(*inner_peer_);
    } else {
        candidates = inner_masque_candidates(
            outer, MIM_INNER_TRIES,
            verified_scan_selected(config_.settings, scan_settings_), config_.random);
    }

    if (candidates.empty()) {
        // "no second masque edge is known for the inner hop" ends run_mim in the Rust.
        fatal_ = Error::other(std::string(NO_SECOND_MASQUE_EDGE));
        done_ = true;
        return step;
    }

    candidates_ = std::move(candidates);
    outer_peer_ = outer;

    phase_ = MI_TUNNEL;
    pending_ = FlowRequest{};
    pending_.kind = FlowRequest::Kind::RunTunnel;
    pending_.shape = RunShape::MasqueInMasque;
    pending_.peer = outer;
    pending_.candidates = candidates_;
    pending_.ech = config_.ech;
    pending_.timeout = masque_startup_timeout(config_.settings);
    step.request = pending_;
    return step;
}

FlowStep MimFlow::resume(const FlowReply& reply) {
    if (config_.cancel.is_cancelled()) return stopped();

    switch (phase_) {
        case MI_HUNT: {
            if (!reply.ok) {
                FlowStep step;
                note_warn(step.notes, no_usable_masque_line(reply.error.display()));
                return merge_into(std::move(step),
                                  sleep_step(phase_, masque_reconnect_delay(config_.settings),
                                             MI_SLEEP));
            }
            // hunt_masque_peer's selected line, which the engine measured but does not own.
            FlowStep step;
            note_info(step.notes, masque_selected_line(probe_of(reply.peer, reply.rtt)));
            return merge_into(std::move(step), after_outer(reply.peer));
        }
        case MI_TUNNEL: {
            FlowStep step;
            if (reply.ok) {
                note_warn(step.notes, tunnel_closed_line("masque-in-masque tunnel"));
            } else {
                note_warn(step.notes,
                          tunnel_ended_line("masque-in-masque tunnel", reply.error.display()));
            }
            ++consecutive_fails_;
            return merge_into(std::move(step),
                              sleep_step(phase_, masque_reconnect_delay(config_.settings),
                                         MI_SLEEP));
        }
        case MI_SLEEP:
            return loop_top();
        default:
            break;
    }
    return loop_top();
}

} // namespace hemera::core::coreflow
