#pragma once

// Port of the orchestrator of aether/src/lib.rs (pinned commit 6175b67): the argument and
// environment resolution that turns a command line into a run configuration, the start-up sequence
// and its ordering constraints, the four reconnect loops and everything they decide -- what is
// retried, in what order, with which timeout, mark and profile -- the cancellation wiring, and
// every error string and log line lib.rs produces.
//
// lib.rs is an async programme: it spawns tokio tasks, races them with tokio::select! and sleeps
// between attempts. This port keeps every decision and drops the runtime. The four loops
// (run_masque, run_wireguard, run_gool, run_mim) become synchronous state machines that emit a
// FlowRequest naming the one piece of work the engine owes them, and answer with a FlowReply; the
// engine -- which owns the sockets, the netstack, the TUN device and the tasks -- executes the
// request and calls resume(). Everything lib.rs decides between two pieces of I/O is here and is
// testable without a network.
//
// WHAT IS NOT HERE, because it needs a socket, a terminal, a task or the netstack. Each is a named
// seam the engine supplies; none is faked:
//   * BindListener      -- socks::bind_listener for the socks5 and http proxy availability checks.
//   * PromptLine        -- prompt_line: stdin().is_terminal(), the write to stdout and the read.
//   * ListDir           -- std::fs::read_dir for enrolled_teams.
//   * EchTransport      -- dns::fetch_ech_config's resolver.
//   * AccountSeams      -- account::{provision_wg, provision_team, refresh_profile,
//                          ensure_masque_enrolled, enable_warp} and socks::set_gateway_proxy.
//   * zerotrust::Hooks  -- the Access HTTP exchange and the login-code prompt.
//   * FlowRequest       -- the hunts, the quick verifies, the tunnel runs and the sleeps.
//   * SignalInstaller   -- main.rs's Ctrl-C handler; lib.rs itself installs none.
//   * install_netstack_panic_guard's body -- it filters smoltcp panics, and this core has no
//     smoltcp; the hook is kept so the ordering is right and the engine can install its own.
//   * tor and psiphon -- removed from this product. Their modes, their two reverse-carrier error
//     strings, their two protocol-menu entries and the AETHER_UPSTREAM / AETHER_MASQUE_HTTP2
//     mutations they make are not ported. Nothing else was dropped.
//
// SECURITY. No note, error string or log line here ever carries a certificate, a private key, an
// access token or an ECH key. The two PEM blocks and the WireGuard scalars travel only inside
// request structs the engine reads, and the ECH key is logged as its byte length alone, exactly as
// lib.rs does. Nothing here opens, reads or writes aether-masque.toml; identity.hpp owns the
// account file and quarantines a damaged one.

#include "account.hpp"
#include "aethernoize.hpp"
#include "dns.hpp"
#include "identity.hpp"
#include "lastconn.hpp"
#include "localapi.hpp"
#include "masque_h2.hpp"
#include "noize.hpp"
#include "prober.hpp"
#include "quic.hpp"
#include "settings.hpp"
#include "tls.hpp"
#include "wireguard.hpp"
#include "zerotrust.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aether::core::coreflow {

using AetherNoizeConfig = ::aether::core::aethernoize::AetherNoizeConfig;
// dns.hpp, tls.hpp, identity.hpp, lastconn.hpp, stats.hpp and consts.hpp all declare into
// aether::core itself rather than a namespace of their own, so the names they own are aliased
// here one by one instead of by a namespace.
using EchTransport = ::aether::core::EchTransport;
using IpAddress = ::aether::core::IpAddress;
using IpScan = ::aether::core::prober::IpScan;
using LastConnection = ::aether::core::LastConnection;
using NoizeConfig = ::aether::core::noize::NoizeConfig;
using ProbeResult = ::aether::core::prober::ProbeResult;
using Random = ::aether::core::prober::Random;
using ScanMode = ::aether::core::prober::ScanMode;
using SocketAddr = ::aether::core::SocketAddr;
using TimePoint = ::aether::core::prober::time_point;
using WgProbeResult = ::aether::core::prober::WgProbeResult;

// ---- constants of lib.rs -------------------------------------------------------------------

inline constexpr std::size_t TUNNEL_MTU = 1280;
inline constexpr std::size_t INNER_MTU = 1200;
inline constexpr std::size_t H2_TUNNEL_MTU = 1500;

inline constexpr std::string_view DEFAULT_CONFIG = "aether.toml";
inline constexpr std::uint16_t WG_EXAMPLE_PORT = 2408;

// quic::MAX_DATAGRAM_SIZE - TUNNEL_MTU, the room a MASQUE datagram capsule and its headers take.
inline constexpr std::size_t MASQUE_DATAGRAM_OVERHEAD = quic::MAX_DATAGRAM_SIZE - TUNNEL_MTU;
inline constexpr std::uint16_t MASQUE_INNER_PORT = 443;
inline constexpr std::size_t MIM_INNER_TRIES = 6;
inline constexpr std::uint32_t GOOL_INNER_ATTEMPTS = 2;
// The three reconnect loops each carry their own copy of this constant in the Rust.
inline constexpr std::uint32_t MAX_CONSECUTIVE_FAILS = 2;

// env!("CARGO_PKG_VERSION") of the pinned core.
inline constexpr std::string_view CORE_VERSION = "2.3.0";
inline constexpr std::string_view DEFAULT_SOCKS_LISTEN = "127.0.0.1:1819";

// The fixed verification budgets lib.rs hard-codes at each call site.
inline constexpr std::chrono::seconds QUICK_VERIFY_TIMEOUT{5};    // quick_verify_masque_peer
inline constexpr std::chrono::seconds ASSIGNED_VERIFY_TIMEOUT{8}; // the organization's endpoint
inline constexpr std::chrono::seconds CACHED_VERIFY_TIMEOUT{6};   // a lastconn ring entry
inline constexpr std::chrono::seconds LAST_GOOD_VERIFY_TIMEOUT{6};
inline constexpr std::chrono::seconds FORCED_VERIFY_TIMEOUT{10};
// mim_inner_startup: masque_startup_timeout().min(12s).
inline constexpr std::chrono::seconds MIM_INNER_STARTUP_CAP{12};

// The keepalives establish_wg's three call sites pass.
inline constexpr std::uint16_t WIW_OUTER_KEEPALIVE = 5;
inline constexpr std::uint16_t WIW_INNER_KEEPALIVE = 20;
inline constexpr std::uint16_t GOOL_INNER_KEEPALIVE = 25;

// establish_masque's `label` at each call site, which is also what its error strings carry.
inline constexpr std::string_view MASQUE_LABEL = "masque";
inline constexpr std::string_view OUTER_LABEL = "outer";
inline constexpr std::string_view INNER_LABEL = "inner";

// The names join_outcome is called with.
inline constexpr std::string_view OUTER_MASQUE_TUNNEL = "outer masque tunnel";
inline constexpr std::string_view INNER_MASQUE_TUNNEL = "inner masque tunnel";
inline constexpr std::string_view OUTER_WIREGUARD_TUNNEL = "outer wireguard tunnel";
inline constexpr std::string_view INNER_WIREGUARD_TUNNEL = "inner wireguard tunnel";
inline constexpr std::string_view SOCKS5_SERVER = "socks5 server";

// The task names guard_tasks() and explicit_aborts() speak in.
inline constexpr std::string_view SOCKS_TASK = "socks";
inline constexpr std::string_view HTTP_TASK = "http";
inline constexpr std::string_view OUTER_TASK = "outer";
inline constexpr std::string_view INNER_TASK = "inner";

// The settings keys lib.rs reads. Every read goes through Settings; none through std::getenv.
inline constexpr std::string_view LOG_LEVEL_ENV = "AETHER_LOG_LEVEL";
inline constexpr std::string_view CONFIG_ENV = "AETHER_CONFIG";
inline constexpr std::string_view WG_CONFIG_ENV = "AETHER_WG_CONFIG";
inline constexpr std::string_view MASQUE_CONFIG_ENV = "AETHER_MASQUE_CONFIG";
inline constexpr std::string_view SOCKS_ENV = "AETHER_SOCKS";
inline constexpr std::string_view HTTP_PROXY_ENV = "AETHER_HTTP_PROXY";
inline constexpr std::string_view PROTOCOL_ENV = "AETHER_PROTOCOL";
inline constexpr std::string_view PEER_ENV = "AETHER_PEER";
inline constexpr std::string_view WG_PEER_ENV = "AETHER_WG_PEER";
inline constexpr std::string_view REGISTER_ENV = "AETHER_REGISTER";
inline constexpr std::string_view SCAN_ENV = "AETHER_SCAN";
inline constexpr std::string_view IP_ENV = "AETHER_IP";
inline constexpr std::string_view NOIZE_ENV = "AETHER_NOIZE";
inline constexpr std::string_view MTU_ENV = "AETHER_MASQUE_MTU";
inline constexpr std::string_view REPROVISION_ENV = "AETHER_REPROVISION";
inline constexpr std::string_view TEAM_ENDPOINT_ENV = "AETHER_TEAM_ENDPOINT";
inline constexpr std::string_view GATEWAY_ENV = "AETHER_GATEWAY";
inline constexpr std::string_view QUICK_RECONNECT_ENV = "AETHER_QUICK_RECONNECT";
inline constexpr std::string_view GOOL_MODE_ENV = "AETHER_GOOL_MODE";
inline constexpr std::string_view GOOL_INNER_ENV = "AETHER_GOOL_INNER";
inline constexpr std::string_view NO_PROFILE_RETRY_ENV = "AETHER_WG_NO_PROFILE_RETRY";
inline constexpr std::string_view ECH_ENV = "AETHER_ECH";
inline constexpr std::string_view WIW_LIST_ENV = "AETHER_WIW_PEERS";
inline constexpr std::string_view WIW_OUTER_ENV = "AETHER_WIW_OUTER_PEER";
inline constexpr std::string_view WIW_INNER_ENV = "AETHER_WIW_INNER_PEER";
inline constexpr std::string_view MIM_LIST_ENV = "AETHER_MIM_PEERS";
inline constexpr std::string_view MIM_OUTER_ENV = "AETHER_MIM_OUTER_PEER";
inline constexpr std::string_view MIM_INNER_ENV = "AETHER_MIM_INNER_PEER";
inline constexpr std::string_view MASQUE_RECONNECT_ENV = "AETHER_MASQUE_RECONNECT_SECS";
inline constexpr std::string_view MASQUE_STARTUP_ENV = "AETHER_MASQUE_STARTUP_SECS";
inline constexpr std::string_view WG_RECONNECT_ENV = "AETHER_WG_RECONNECT_SECS";
inline constexpr std::string_view WG_COOLDOWN_ENV = "AETHER_WG_ENDPOINT_COOLDOWN_SECS";
inline constexpr std::string_view WG_VALIDATE_ENV = "AETHER_WG_VALIDATE_SECS";
inline constexpr std::string_view WG_KEEPALIVE_ENV = "AETHER_WG_KEEPALIVE";
inline constexpr std::string_view MASQUE_HTTP2_ENV = "AETHER_MASQUE_HTTP2";
inline constexpr std::string_view TEAM_ENV = "AETHER_TEAM";
inline constexpr std::string_view ACCESS_EMAIL_ENV = "AETHER_ACCESS_EMAIL";

// ---- log lines ------------------------------------------------------------------------------

// The level a Rust log macro used, carried with the text so a ported line cannot silently change
// level on its way to the logger. lib.rs uses all four.
enum class Level { Debug, Info, Warn, Error };

struct Note {
    Level level = Level::Info;
    std::string text;

    [[nodiscard]] bool operator==(const Note&) const = default;
};

using Notes = std::vector<Note>;

void note_debug(Notes& notes, std::string text);
void note_info(Notes& notes, std::string text);
void note_warn(Notes& notes, std::string text);
void note_error(Notes& notes, std::string text);

// Just the texts, in order, which is what a test compares.
[[nodiscard]] std::vector<std::string> texts(const Notes& notes);
[[nodiscard]] bool has_text(const Notes& notes, std::string_view needle);

// ---- errors ---------------------------------------------------------------------------------

// error.rs's AetherError. Every `{e}` in a lib.rs log line prints Display, which is the variant's
// own prefix and the message together, so the port keeps the two apart and never logs one for the
// other.
enum class ErrorKind {
    Io,
    Quic,
    H3,
    Tls,
    Ech,
    Masque,
    NoCleanEndpoint,
    Capsule,
    Api,
    IdentityRefused,
    Cancelled,
    Other,
};

struct Error {
    ErrorKind kind = ErrorKind::Other;
    std::string message;

    // Rust's #[error("...")] Display for the variant.
    [[nodiscard]] std::string display() const;

    [[nodiscard]] static Error other(std::string message);
    [[nodiscard]] static Error no_clean_endpoint();
    [[nodiscard]] static Error identity_refused(std::string reason);
};

// "prober: no clean endpoint found", the whole Display of the variant lib.rs's hunts fail with.
inline constexpr std::string_view NO_CLEAN_ENDPOINT = "prober: no clean endpoint found";
// The two literal errors lib.rs raises when a two-hop run has nowhere to go.
inline constexpr std::string_view NO_INNER_MASQUE_EDGE =
    "no inner masque edge answered through the outer tunnel";
inline constexpr std::string_view NO_SECOND_MASQUE_EDGE =
    "no second masque edge is known for the inner hop";
inline constexpr std::string_view NO_WG_ENDPOINT_TO_TRY = "no wireguard endpoint to try";
// The three places lib.rs writes this on its own.
inline constexpr std::string_view INVALID_IPV4 = "invalid ipv4";

// ---- seams ----------------------------------------------------------------------------------

// prompt_line: nothing when stdin is no terminal, else the prompt written to stdout and the line
// read back, trimmed. The terminal is the engine's.
using PromptLine = std::function<std::optional<std::string>(std::string_view prompt)>;

// std::fs::read_dir's entry names, empty when the directory cannot be read.
using ListDir = std::function<std::vector<std::string>(const std::string& dir)>;

// socks::bind_listener. lib.rs drops the listener straight away in run_with: the bind is only an
// availability check, so the seam returns nothing but the verdict.
using BindListener =
    std::function<std::expected<void, std::string>(std::string_view what, const SocketAddr& listen)>;

// main.rs's Ctrl-C / SIGTERM handler. lib.rs installs no signal handler of its own; the port keeps
// the wiring here so a library build can stop a run the way the binary does.
using SignalInstaller = std::function<void(const localapi::Cancel& cancel)>;

using Cancel = ::aether::core::localapi::Cancel;

// Installs `installer` so a signal raises `cancel`. A missing installer means nothing is wired,
// which is what a test wants.
void wire_signals(const Cancel& cancel, const SignalInstaller& installer);

// Settings has no remove, and lib.rs calls std::env::remove_var in four places.
void unset(Settings& settings, std::string_view key);

// ---- small readers of lib.rs ----------------------------------------------------------------

// env_value: the value trimmed, and nothing when it is absent or trims to empty.
[[nodiscard]] std::optional<std::string> env_value(const Settings& settings, std::string_view key);

// Rust's `str::parse::<u64>()` / `::<usize>()` with no trimming: an optional leading '+', then one
// or more digits, and nothing else. A value that overflows is no value, as in the Rust.
[[nodiscard]] std::optional<std::uint64_t> parse_u64_strict(std::string_view text);

// parse_local_v4: the text before the first '/', parsed as an IPv4 address, else 0.0.0.0.
[[nodiscard]] IpAddress parse_local_v4(std::string_view text);

// scan_keyword: the five words that mean "let the scan pick".
[[nodiscard]] bool scan_keyword(std::string_view value);
// wiw_scan_requested: AETHER_WIW_PEERS says one of those words.
[[nodiscard]] bool wiw_scan_requested(const Settings& settings);

// masque_tunnel_mtu: AETHER_MASQUE_MTU trimmed and inside 576..=1500, else 1500 on the HTTP/2
// carrier and 1280 on QUIC.
[[nodiscard]] std::size_t masque_tunnel_mtu(const Settings& settings);
// masque_carrier: the lastconn carrier the session's gateways are filed under.
[[nodiscard]] std::string_view masque_carrier(const Settings& settings);

// derive_sibling_path: "-{suffix}" inserted before the extension of the file part of `base`.
[[nodiscard]] std::string derive_sibling_path(std::string_view base, std::string_view suffix);
[[nodiscard]] std::string lastconn_path(std::string_view config_path);

// team_scope: the normalized team name of AETHER_TEAM, nothing when there is none.
[[nodiscard]] std::optional<std::string> team_scope(const Settings& settings);

[[nodiscard]] std::string warp_config_path(const Settings& settings, std::string_view base);
[[nodiscard]] std::string masque_config_path(const Settings& settings, std::string_view base);

// keep_saved_identity: a refused identity is replaced unless AETHER_REPROVISION is exactly one of
// "0", "off" or "false".
[[nodiscard]] bool keep_saved_identity(const Settings& settings);

// gool_classic: AETHER_GOOL_MODE is exactly "wiw", "wg" or "classic", or any of the three
// warp-in-warp endpoint settings names a hop.
[[nodiscard]] bool gool_classic(const Settings& settings);

// The three profile readings, each with its own default, and the log line each writes.
[[nodiscard]] std::string noize_profile(const Settings& settings);        // or "firewall"
[[nodiscard]] std::string aethernoize_profile(const Settings& settings);  // or "balanced"
[[nodiscard]] std::string wg_primary_profile(const Settings& settings);   // or "balanced"
[[nodiscard]] NoizeConfig noize_config(const Settings& settings, Notes& notes);
[[nodiscard]] AetherNoizeConfig aethernoize_config(const Settings& settings, Notes& notes);
[[nodiscard]] std::string noize_profile_line(std::string_view profile);
[[nodiscard]] std::string aethernoize_profile_line(std::string_view profile);
[[nodiscard]] std::string wg_primary_profile_line(std::string_view profile);

// wg_profile_candidates: the primary profile, then balanced/aggressive/light/off unless
// AETHER_WG_NO_PROFILE_RETRY is set, case-insensitively de-duplicated.
[[nodiscard]] std::vector<std::pair<std::string, AetherNoizeConfig>> wg_profile_candidates(
    const Settings& settings, Notes& notes);

// base_config: AETHER_CONFIG as it stands, or DEFAULT_CONFIG.
[[nodiscard]] std::string base_config_path(const Settings& settings);
// AETHER_SOCKS parsed as an address and a port, or 127.0.0.1:1819.
[[nodiscard]] SocketAddr socks_listen(const Settings& settings);

struct HttpProxyListen {
    std::optional<SocketAddr> listen;
    // The warn line an unparsable value produces, which is the only way this is not silent.
    std::optional<std::string> warning;
};
[[nodiscard]] HttpProxyListen http_proxy_listen(const Settings& settings);
[[nodiscard]] std::string unparsable_http_proxy_warning(std::string_view trimmed);

// log_default_filter: "info,aether={level}", the level AETHER_LOG_LEVEL names when it is one of the
// five words env_logger takes, else "info".
[[nodiscard]] std::string log_level_of(const Settings& settings);
[[nodiscard]] std::string log_default_filter(const Settings& settings);
[[nodiscard]] std::string version_line();

// The six second-valued knobs. Each parses the raw value strictly, wants it above zero, caps it at
// a day and falls back to its own default.
[[nodiscard]] std::chrono::seconds env_secs(const Settings& settings, std::string_view key,
                                           std::uint64_t fallback);
[[nodiscard]] std::chrono::seconds masque_reconnect_delay(const Settings& settings);   // 2
[[nodiscard]] std::chrono::seconds masque_startup_timeout(const Settings& settings);   // 30
[[nodiscard]] std::chrono::seconds mim_inner_startup(const Settings& settings);        // min(.,12)
[[nodiscard]] std::chrono::seconds wg_reconnect_delay(const Settings& settings);       // 2
[[nodiscard]] std::chrono::seconds wg_endpoint_cooldown(const Settings& settings);     // 300
[[nodiscard]] std::chrono::seconds wg_tunnel_validate_timeout(const Settings& settings); // 10
// AETHER_WG_KEEPALIVE as u16, above zero, no cap, default 5.
[[nodiscard]] std::uint16_t wg_keepalive_secs(const Settings& settings);

// ---- the two-hop endpoints ------------------------------------------------------------------

struct WiwEndpoints {
    std::optional<SocketAddr> outer;
    std::optional<SocketAddr> inner;

    [[nodiscard]] bool is_empty() const { return !outer.has_value() && !inner.has_value(); }
    // Refuses a pair that names one edge twice, with the address in the message.
    [[nodiscard]] std::expected<WiwEndpoints, Error> checked() const;

    [[nodiscard]] bool operator==(const WiwEndpoints&) const = default;
};

[[nodiscard]] std::string same_edge_error(const IpAddress& ip);
[[nodiscard]] std::string endpoint_no_port_error(std::string_view text, const IpAddress& address);
[[nodiscard]] std::string endpoint_nonsense_error(std::string_view text);
inline constexpr std::string_view NO_ENDPOINT_GIVEN =
    "no endpoint was given; expected one or two addresses";
[[nodiscard]] std::string too_many_endpoints_error(std::size_t found);
[[nodiscard]] std::string bad_peer_address_error(std::string_view raw);

// parse_endpoint: an address and a port together. A bare address is refused with the shape wanted
// spelled out; anything else is refused with an example to copy.
[[nodiscard]] std::expected<SocketAddr, Error> parse_endpoint(std::string_view raw);
// parse_endpoint_list: one or two endpoints separated by ',', ';' or a space.
[[nodiscard]] std::expected<std::vector<SocketAddr>, Error> parse_endpoint_list(std::string_view raw);

[[nodiscard]] std::expected<WiwEndpoints, Error> nested_endpoints_of(const Settings& settings,
                                                                    std::string_view list_key,
                                                                    std::string_view outer_key,
                                                                    std::string_view inner_key);
[[nodiscard]] std::expected<WiwEndpoints, Error> wiw_endpoints_of(const Settings& settings);
[[nodiscard]] std::expected<WiwEndpoints, Error> mim_endpoints_of(const Settings& settings);
// The classic-gool reading: the warp-in-warp settings first, then AETHER_WG_PEER, then AETHER_PEER.
[[nodiscard]] std::expected<WiwEndpoints, Error> wiw_endpoints_with_fallback(const Settings& settings);

// ---- protocols ------------------------------------------------------------------------------

enum class Protocol { Masque, WireGuard, WarpInWarp, MasqueInMasque };

[[nodiscard]] Protocol protocol_parse(std::string_view raw);
[[nodiscard]] std::string_view protocol_label(Protocol protocol);

// The two warn lines run_with writes when a pin does not apply to the protocol chosen.
[[nodiscard]] std::string ignored_wiw_warning(Protocol protocol);
[[nodiscard]] std::string ignored_mim_warning(Protocol protocol);

// ---- --register -----------------------------------------------------------------------------

struct RegisterSet {
    bool wireguard = false;
    bool wireguard_inner = false;
    bool masque = false;
    bool masque_inner = false;

    [[nodiscard]] bool operator==(const RegisterSet&) const = default;
};

[[nodiscard]] std::string register_bad_value_error(std::string_view other);
[[nodiscard]] std::expected<RegisterSet, Error> register_set_parse(std::string_view value);
// AETHER_REGISTER, trimmed and non-empty, as the set it names. An unparsable value is an error, so
// `--register everything` stops the core rather than registering nothing.
[[nodiscard]] std::expected<std::optional<RegisterSet>, Error> register_request(const Settings& settings);

// One identity --register makes sure of, in the order lib.rs walks them.
struct RegistrationTarget {
    std::string label;
    std::string path;
    bool over_masque = false;

    [[nodiscard]] bool operator==(const RegistrationTarget&) const = default;
};

[[nodiscard]] std::vector<RegistrationTarget> register_plan(const RegisterSet& wanted,
                                                           const Settings& settings,
                                                           std::string_view base_config);
[[nodiscard]] std::string identity_ready_line(std::string_view label, const Identity& identity);
[[nodiscard]] std::string identities_ready_line(const std::vector<std::string>& ready);

// ---- prompts --------------------------------------------------------------------------------

inline constexpr std::string_view SCAN_MODE_PROMPT =
    "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough "
    " (deep, best ping)\n  [4] verified  (measured edges only, never a guessed neighbour; on gool "
    "and\n                 mim it keeps the two hops in different ranges, which is what\n        "
    "         moves the exit address)\n  [5] ironclad  (real tunnel + real HTTP check per "
    "candidate, guaranteed working)\nChoose [1-5] (default 2): ";

inline constexpr std::string_view MIM_MANUAL_TIP =
    "\n(tip: you can skip this scan and give the two masque hops yourself:\n        aether --mim "
    "--mim-outer <ip:port> --mim-inner <ip:port>\n      the port is required, and naming just the "
    "outer one lets aether pick\n      the inner edge for you)\n";

inline constexpr std::string_view WIW_MANUAL_TIP =
    "\n(tip: you can skip this scan and give the two gool hops yourself:\n        aether --gool "
    "--wiw-outer <ip:port> --wiw-inner <ip:port>\n      the port is required, and naming just one "
    "of the two lets the scan\n      find the other)\n";

inline constexpr std::string_view GOOL_PROMPT =
    "\nWhich gool?\n  [1] gool over masque: wireguard carried inside a masque tunnel, for a "
    "foreign exit address (default)\n  [2] classic gool: wireguard carried inside wireguard, a "
    "plain warp exit\nChoose [1-2] (default 1): ";

inline constexpr std::string_view MASQUE_TRANSPORT_PROMPT =
    "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP "
    "networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or "
    "throttled)\nChoose [1-2] (default 1): ";

inline constexpr std::string_view IP_VERSION_PROMPT =
    "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ";

inline constexpr std::string_view TEAM_ENROL_PROMPT_BLANK =
    "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com (blank to cancel): ";
inline constexpr std::string_view TEAM_EMAIL_PROMPT =
    "Email address for the one-time login code (blank to cancel): ";

// The scan-mode prompt with a manual-pin tip in front of it, which is what select_scan_mode_str
// shows on the two-hop protocols.
[[nodiscard]] std::string scan_mode_prompt(std::string_view tip);
// The protocol menu. With tor and psiphon gone from this product the base four entries are
// followed straight by the Zero Trust one, numbered 5.
[[nodiscard]] std::string protocol_prompt(const std::optional<std::string>& team);
[[nodiscard]] std::string team_enrol_prompt(const std::vector<std::string>& known);
[[nodiscard]] std::string quick_reconnect_prompt(const LastConnection& cached);

// select_scan_mode_str: AETHER_SCAN as it stands when the key is there at all, else the answer read
// off the prompt, mapped to a profile name.
[[nodiscard]] std::string select_scan_mode_str(const Settings& settings, std::string_view tip,
                                              const PromptLine& prompt);
[[nodiscard]] ScanMode select_scan_mode(const Settings& settings, const PromptLine& prompt);
[[nodiscard]] IpScan select_ip_version(const Settings& settings, const PromptLine& prompt);
// scan_settings_from_env: the pair a run reads when it is not going to ask.
[[nodiscard]] std::pair<std::string, IpScan> scan_settings_from_env(const Settings& settings);
using ScanSettings = std::optional<std::pair<std::string, IpScan>>;
// verified_scan_selected: the cached scan settings, or AETHER_SCAN, name the verified mode.
[[nodiscard]] bool verified_scan_selected(const Settings& settings, const ScanSettings& cached);

// select_gool: answer "2" writes AETHER_GOOL_MODE=classic. Either way the protocol is WarpInWarp.
[[nodiscard]] Protocol select_gool(Settings& settings, const PromptLine& prompt);
// select_masque_transport: skipped when AETHER_MASQUE_HTTP2 or AETHER_PEER is set at all; answer
// "2" writes AETHER_MASQUE_HTTP2=1.
void select_masque_transport(Settings& settings, const PromptLine& prompt, Notes& notes);
// select_protocol, the whole loop: the menu, the Zero Trust enrolment on answer 5, and the answer
// that ends it.
[[nodiscard]] Protocol select_protocol(Settings& settings, std::string_view base_config,
                                      const PromptLine& prompt, const zerotrust::Hooks& hooks,
                                      const ListDir& list_dir, Notes& notes);

// ---- zero trust enrolment -------------------------------------------------------------------

struct TeamDeps {
    // prompt_line, for the team name and the email address.
    PromptLine prompt;
    zerotrust::Hooks hooks;
    ListDir list_dir;
};

// enrolled_teams: the "{stem}-team-{name}.toml" siblings of `base`, without the empty name and the
// "-secondary" and "-lastconn" derivatives, de-duplicated and sorted. A directory that cannot be
// read yields nothing.
[[nodiscard]] std::vector<std::string> enrolled_teams_from_names(std::string_view base,
                                                                const std::vector<std::string>& names);
[[nodiscard]] std::vector<std::string> enrolled_teams(std::string_view base, const ListDir& list_dir);

// enrol_zero_trust. Writes AETHER_TEAM and AETHER_ACCESS_EMAIL into `settings` and removes them
// again on every failure path, exactly as the Rust writes and removes the environment. Never fails:
// a refusal is a note and a return to personal WARP.
void enrol_zero_trust(Settings& settings, std::string_view base_config, const TeamDeps& team,
                      Notes& notes);

// ---- the account layer lib.rs drives --------------------------------------------------------

// The round trips. Each is a network exchange the engine owns; the decisions around them are here.
struct AccountSeams {
    std::function<std::expected<Identity, Error>(std::string_view model, std::string_view locale)>
        provision_wg;
    std::function<std::expected<Identity, Error>(std::string_view model, std::string_view locale,
                                                const zerotrust::TeamSettings& team)>
        provision_team;
    std::function<Identity(Identity identity)> refresh_profile;
    std::function<std::expected<account::MasqueEnrollment, Error>(const Identity& identity)>
        ensure_masque_enrolled;
    // account::enable_warp. `access_token` is key material: the engine sends it, nothing logs it.
    std::function<std::expected<void, Error>(std::string_view device_id,
                                            std::string_view access_token)>
        enable_warp;
    std::function<void(std::string_view gateway_proxy)> set_gateway_proxy;
};

// What a MASQUE enrolment round trip answered with. A refusal is its own outcome because
// load_or_enrol_masque turns it into a marked identity rather than an error.
struct EnrolOutcome {
    enum class Kind { Enrolled, Refused, Failed };

    Kind kind = Kind::Failed;
    account::MasqueEnrollment enrollment;
    std::string reason; // Refused: the reason inside IdentityRefused. Failed: the Error's Display.
    Error error;        // Failed only.
};

[[nodiscard]] std::string enrolling_team_line(const zerotrust::TeamSettings& team);
[[nodiscard]] std::string gateway_proxy_debug_line(std::string_view gateway_proxy);
[[nodiscard]] std::string assigned_endpoint_line(std::string_view peer);
// adopt_team_profile: refresh, then the gateway proxy, then the endpoint the organization assigned.
// Writes AETHER_TEAM_ENDPOINT when the assigned address and port parse.
[[nodiscard]] Identity adopt_team_profile(Settings& settings, Identity identity,
                                         const AccountSeams& seams, Notes& notes);
[[nodiscard]] std::expected<Identity, Error> provision_account(const Settings& settings,
                                                              const AccountSeams& seams,
                                                              Notes& notes);
[[nodiscard]] std::expected<Identity, Error> load_or_provision_warp(const Settings& settings,
                                                                   const std::string& config_path,
                                                                   const AccountSeams& seams,
                                                                   Notes& notes);
[[nodiscard]] std::expected<Identity, Error> load_or_enrol_masque(const Settings& settings,
                                                                 const std::string& config_path,
                                                                 const AccountSeams& seams,
                                                                 Notes& notes);
[[nodiscard]] std::expected<Identity, Error> load_or_provision_masque(const Settings& settings,
                                                                     const std::string& config_path,
                                                                     const AccountSeams& seams,
                                                                     Notes& notes);
// --register: the identities it names, in order, the line each writes, and the summary line
// behind them. The ready labels come back as well so the caller can see what was registered.
[[nodiscard]] std::expected<std::vector<std::string>, Error> register_identities(
    const Settings& settings, const RegisterSet& wanted, std::string_view base_config,
    const AccountSeams& seams, Notes& notes);

// The identity-file log lines, which are the only place a path is named next to an account.
[[nodiscard]] std::string loaded_warp_identity_line(std::string_view config_path);
[[nodiscard]] std::string loaded_masque_identity_line(std::string_view config_path);
[[nodiscard]] std::string no_warp_identity_line();
[[nodiscard]] std::string no_masque_identity_line();
[[nodiscard]] std::string saved_warp_identity_line(std::string_view config_path);
[[nodiscard]] std::string saved_masque_identity_line(std::string_view config_path);
[[nodiscard]] std::string replace_refused_warp_line();
[[nodiscard]] std::string replace_refused_masque_line();
[[nodiscard]] std::string needs_certificate_line();
[[nodiscard]] std::string saved_identity_refused_line(std::string_view reason);
[[nodiscard]] std::string warp_enabled_line();
[[nodiscard]] std::string warp_enable_failed_line(std::string_view error);

// ---- ECH ------------------------------------------------------------------------------------

// resolve_ech. The key the WARP API took is offered without a second lookup and is logged as its
// byte length alone; otherwise tls::ech_key decides, over `transport`. With no key the note says
// the server name goes out in the clear.
[[nodiscard]] std::expected<std::optional<std::vector<std::uint8_t>>, Error> resolve_ech(
    const Settings& settings, const EchTransport& transport, Notes& notes);
[[nodiscard]] std::string ech_from_api_line(std::size_t bytes);
inline constexpr std::string_view ECH_OFF_LINE = "[+] ECH off; the server name goes out in cleartext";

// ---- start-up -------------------------------------------------------------------------------

struct StartupHooks {
    PromptLine prompt;
    BindListener bind_listener;
    // install_netstack_panic_guard. The body is smoltcp's and is not ported; the ordering is.
    std::function<void()> install_netstack_guard;
    // stats::spawn_reporter.
    std::function<void()> spawn_stats_reporter;
    TeamDeps team;
};

struct Startup {
    enum class Kind {
        Exit,     // --version or --help: print and stop, which is cli::Parsed::Done
        Register, // --register: make the identities and stop
        Run,      // carry on into the dispatch
    };

    Kind kind = Kind::Run;
    CliOutcome cli = CliOutcome::Run;
    std::string log_filter;
    std::string banner;         // "Aether v{version}"
    std::string sysprofile;     // sysprofile::summary
    std::string base_config;
    std::optional<RegisterSet> register_set;
    SocketAddr listen;
    std::optional<SocketAddr> http_proxy;
    WiwEndpoints pinned_wiw;
    WiwEndpoints pinned_mim;
    Protocol protocol = Protocol::Masque;
    bool classic_gool = false;
    Notes notes;
};

// run_with, up to its dispatch, in the Rust's exact order: the arguments, the log filter, the
// banner, the machine profile, the egress mark, the stats reporter, the netstack guard, the two
// option checks, the API's ECH stash cleared, the base config, --register short-circuiting before
// any listener is bound, the two listener availability checks, the two pin readings and the
// protocol resolution with its two ignored-pin warnings. `settings` is written by the prompts.
[[nodiscard]] std::expected<Startup, Error> startup(const std::vector<std::string>& args,
                                                   Settings& settings,
                                                   const StartupHooks& hooks);

// ---- the dispatch ---------------------------------------------------------------------------

enum class RunKind { Masque, WireGuard, GoolOverMasque, ClassicGool, Mim };

struct RunPlan {
    RunKind kind = RunKind::Masque;
    std::string primary_path;
    // ClassicGool and Mim: the second hop's identity file.
    std::string secondary_path;
    // GoolOverMasque: where the wireguard identity carried inside the masque tunnel lives.
    std::string gool_inner_path;
    // Masque, WireGuard and GoolOverMasque keep a last-connection file.
    std::optional<std::string> lastconn;
    // Masque, GoolOverMasque and Mim start an EchSession that outlives the run.
    bool starts_ech_session = false;
    // Masque, GoolOverMasque and Mim ask the transport question first.
    bool asks_masque_transport = false;
};

[[nodiscard]] RunPlan run_plan(const Settings& settings, Protocol protocol, bool classic_gool,
                              std::string_view base_config);
[[nodiscard]] std::string identity_ready_line(const Identity& identity);
[[nodiscard]] std::string gool_plan_line(const Identity& identity, std::string_view inner_path);
[[nodiscard]] std::string pair_ready_line(const Identity& outer, const Identity& inner);

// ---- budgets, ranges and inner-hop candidates ----------------------------------------------

// mim_inner_budget: (datagram, mtu) for an inner hop carried by an outer link of `outer_mtu`.
[[nodiscard]] std::pair<std::size_t, std::size_t> mim_inner_budget(std::size_t outer_mtu,
                                                                  const SocketAddr& inner_peer,
                                                                  bool h2);
// edge_network: the first three octets of a v4 address, nothing for v6.
[[nodiscard]] std::optional<std::array<std::uint8_t, 3>> edge_network(const IpAddress& ip);
// spread_hops: puts the first address in a different /24 second, so the two hops are not neighbours.
void spread_hops(std::vector<SocketAddr>& found);
// masque_verified_ladder: the measured gateways, those outside the outer range first, then the rest,
// then the alternate ports; the outer address itself never appears.
[[nodiscard]] std::vector<SocketAddr> masque_verified_ladder(const SocketAddr& outer,
                                                            std::size_t count);
// sibling_candidates: guessed neighbours of `outer` on the MASQUE port, shuffled.
[[nodiscard]] std::vector<SocketAddr> sibling_candidates(const SocketAddr& outer, std::size_t count,
                                                        const Random& rng);
// inner_masque_candidates: the verified ladder first when `verified`, then siblings up to `count`.
[[nodiscard]] std::vector<SocketAddr> inner_masque_candidates(const SocketAddr& outer,
                                                             std::size_t count, bool verified,
                                                             const Random& rng);

// ---- the hunts ------------------------------------------------------------------------------

inline constexpr std::string_view HUNT_MASQUE_DEEP_LINE =
    "[*] hunting for a working MASQUE gateway (deep connect-ip verification)";
inline constexpr std::string_view HUNT_MASQUE_LINE =
    "[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)";

[[nodiscard]] std::string masque_selected_line(const ProbeResult& best);
[[nodiscard]] std::string using_forced_peer_line(const SocketAddr& peer);
[[nodiscard]] std::string selected_protocol_line(Protocol protocol);
[[nodiscard]] std::string using_edge_line(const SocketAddr& peer);
[[nodiscard]] std::string using_edge_pair_line(const SocketAddr& outer, const SocketAddr& inner);

// The MASQUE probe lib.rs builds. cert_pem and key_pem are key material: the engine reads them,
// nothing logs them.
struct MasqueProbeParams {
    std::string sni;
    std::string authority;
    std::string path;
    std::string cert_pem;
    std::string key_pem;
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    NoizeConfig noise;
    std::vector<std::uint16_t> ports;
    IpScan ip = IpScan::V4;
    IpAddress local_ipv4;
};

// hunt_masque_peer's probe, which offers the session's ECH key, and select_peer's, which does not.
[[nodiscard]] MasqueProbeParams masque_probe_for(const Settings& settings, const Identity& identity,
                                                const std::optional<std::vector<std::uint8_t>>& ech,
                                                IpScan ip, Notes& notes);

// The WireGuard probe lib.rs builds. Both scalars are key material.
struct WgProbeParams {
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 32> peer_public_key{};
    std::array<std::uint8_t, 3> client_id{};
    IpAddress local_ipv4;
    AetherNoizeConfig noise;
    std::vector<std::uint16_t> ports;
    IpScan ip = IpScan::V4;
    std::vector<SocketAddr> excluded;
};

[[nodiscard]] std::expected<WgProbeParams, Error> wg_probe_for(const Settings& settings,
                                                              const Identity& identity,
                                                              const AetherNoizeConfig& noise,
                                                              IpScan ip,
                                                              std::vector<SocketAddr> excluded,
                                                              Notes& notes);
[[nodiscard]] std::string wg_hunting_line(std::size_t want);
[[nodiscard]] std::string wg_avoid_line(std::size_t avoid);
[[nodiscard]] std::string wg_selected_line(const WgProbeResult& picked);
// select_wg_peers' excluded set: every avoid address on every WireGuard port.
[[nodiscard]] std::vector<SocketAddr> wg_excluded_for(const std::vector<IpAddress>& avoid);
// select_wg_peers' post-filter: drop the avoided addresses, take `want`, and fail with
// NoCleanEndpoint when nothing is left.
[[nodiscard]] std::expected<std::vector<SocketAddr>, Error> pick_wg_peers(
    const std::vector<WgProbeResult>& found, const std::vector<IpAddress>& avoid, std::size_t want);

// select_peer's forced-peer reading: AETHER_PEER on the two MASQUE protocols, AETHER_WG_PEER then
// AETHER_PEER on the two WireGuard ones. The raw value, as lib.rs takes it.
[[nodiscard]] std::optional<std::string> forced_peer_for(const Settings& settings, Protocol protocol);
[[nodiscard]] std::expected<SocketAddr, Error> parse_forced_peer(std::string_view raw);

// ---- the quick checks -----------------------------------------------------------------------

// quick_verify_masque_peer on the QUIC carrier.
[[nodiscard]] quic::VerifyParams quick_verify_quic_params(const Settings& settings,
                                                         const Identity& identity,
                                                         const SocketAddr& peer,
                                                         const std::optional<std::vector<std::uint8_t>>& ech,
                                                         Notes& notes);
// The same check on the HTTP/2 carrier: quiet, pinned, on the h2 peer.
[[nodiscard]] masque_h2::H2TunnelConfig quick_verify_h2_config(const Settings& settings,
                                                              const Identity& identity,
                                                              const SocketAddr& peer,
                                                              const std::optional<std::vector<std::uint8_t>>& ech,
                                                              Notes& notes);
// want_quick_reconnect: AETHER_QUICK_RECONNECT's eight exact words, else the prompt, where anything
// but "n" or "no" says yes.
[[nodiscard]] bool want_quick_reconnect(const Settings& settings, const LastConnection& cached,
                                       const PromptLine& prompt);

// The lastconn ring as addresses, in the order usable_peers gives them.
[[nodiscard]] std::vector<SocketAddr> ring_peers(const LastConnection& cached,
                                                std::string_view carrier);

// ---- establishing a hop ---------------------------------------------------------------------

// establish_masque's two configurations and the line each writes.
struct MasqueHopParams {
    bool h2 = false;
    std::string label;
    std::size_t mtu = TUNNEL_MTU;
    std::size_t datagram = quic::MAX_DATAGRAM_SIZE;
    bool version_bait = true;
    std::chrono::seconds startup{30};
    masque_h2::H2TunnelConfig h2_config;
    quic::TunnelConfig quic_config;
    // The "[+] [{label}] MASQUE transport: ..." line, at the level lib.rs writes it.
    std::string transport_line;
};

[[nodiscard]] MasqueHopParams establish_masque_params(const Settings& settings,
                                                     const Identity& identity,
                                                     const SocketAddr& peer,
                                                     const std::optional<std::vector<std::uint8_t>>& ech,
                                                     bool h2, std::size_t mtu, std::size_t datagram,
                                                     bool version_bait, std::chrono::seconds startup,
                                                     std::string_view label, Notes& notes);
[[nodiscard]] std::string masque_transport_h2_line(std::string_view label, const SocketAddr& peer,
                                                  std::size_t mtu);
[[nodiscard]] std::string masque_transport_h3_line(std::string_view label, const SocketAddr& peer,
                                                  std::size_t mtu, std::size_t datagram_budget);

// The four ways establish_masque's startup wait can end.
enum class StartupVerdict {
    Ready,
    ExitedBeforeValidation,
    FailedBeforeValidation,
    JoinError,
    TimedOut,
};
[[nodiscard]] std::string startup_verdict_error(std::string_view label, StartupVerdict verdict,
                                               std::string_view detail,
                                               std::chrono::milliseconds startup);

// run_masque_tunnel's dial address: the h2 peer on the HTTP/2 carrier, the peer itself on QUIC.
[[nodiscard]] SocketAddr masque_dial_peer(const Settings& settings, const SocketAddr& peer);
[[nodiscard]] std::string tunnel_exited_error(std::string_view error);
[[nodiscard]] std::string tunnel_join_error(std::string_view error);

// establish_wg's whole argument set, resolved.
struct WgEstablish {
    std::string label;
    std::size_t mtu = TUNNEL_MTU;
    bool obfuscate = true;
    std::uint16_t keepalive = WIW_OUTER_KEEPALIVE;
    AetherNoizeConfig profile;
    std::chrono::seconds validate_timeout{10};
    // Key material: the engine reads these, nothing logs them.
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 32> peer_public_key{};
    std::array<std::uint8_t, 3> client_id{};
    IpAddress local_ipv4;
};

[[nodiscard]] std::expected<WgEstablish, Error> establish_wg_params(const Settings& settings,
                                                                   const Identity& identity,
                                                                   std::size_t mtu, bool obfuscate,
                                                                   std::uint16_t keepalive,
                                                                   std::string_view label,
                                                                   Notes& notes);
[[nodiscard]] std::string wg_validating_line(std::string_view label, const SocketAddr& peer);
[[nodiscard]] std::string wg_validated_line(std::string_view label);
[[nodiscard]] std::string wg_validation_error(std::string_view label, std::string_view error);
[[nodiscard]] std::string wg_tunnel_closed_line(std::string_view label);
[[nodiscard]] std::string wg_tunnel_exited_line(std::string_view label, std::string_view error);
[[nodiscard]] std::string wg_tunnel_exited_error(std::string_view label, std::string_view error);

// run_wireguard_tunnel, the single-hop one, whose lines carry no label.
[[nodiscard]] std::string wg_tunnel_validating_line(const SocketAddr& peer);
[[nodiscard]] std::string wg_tunnel_validation_error(std::string_view error);
[[nodiscard]] std::string wg_tunnel_run_exited_error(std::string_view error);
inline constexpr std::string_view WG_TUNNEL_VALIDATED_LINE =
    "[+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5";

// The three establish_wg call sites of run_warp_in_warp and run_gool_tunnel.
[[nodiscard]] std::expected<WgEstablish, Error> wiw_outer_establish(const Settings& settings,
                                                                   const Identity& primary,
                                                                   Notes& notes);
[[nodiscard]] std::expected<WgEstablish, Error> wiw_inner_establish(const Settings& settings,
                                                                   const Identity& secondary,
                                                                   Notes& notes);
[[nodiscard]] std::expected<WgEstablish, Error> gool_inner_establish(const Settings& settings,
                                                                    const Identity& inner_identity,
                                                                    Notes& notes);

// ---- masque-in-masque ------------------------------------------------------------------------

[[nodiscard]] std::string mim_establishing_line(const SocketAddr& peer);
[[nodiscard]] std::string mim_too_small_warning(std::size_t outer_mtu);
[[nodiscard]] std::string mim_trying_line(const SocketAddr& inner_peer, const SocketAddr& forwarder);
[[nodiscard]] std::string mim_inner_ok_line(const SocketAddr& inner_peer);
[[nodiscard]] std::string mim_inner_fail_line(const SocketAddr& inner_peer, std::string_view error);
[[nodiscard]] std::string mim_ready_line(const SocketAddr& outer, const SocketAddr& inner_peer);

// One inner candidate's whole plan: its budget, whether the outer link is too small for it, and
// which forwarder carries it.
struct MimAttempt {
    SocketAddr inner_peer;
    std::size_t datagram = 0;
    std::size_t mtu = 0;
    // The warn line run_masque_in_masque writes when a QUIC datagram will not fit the outer link.
    bool warn_too_small = false;
    // "tcp" on the HTTP/2 carrier, "udp" on QUIC.
    std::string forwarder_kind;
};

// The inner candidates run_masque_in_masque walks: those whose address is not the outer one.
[[nodiscard]] std::vector<MimAttempt> mim_inner_plan(std::size_t outer_mtu, bool h2,
                                                    const SocketAddr& outer,
                                                    const std::vector<SocketAddr>& inner_peers);

// ---- classic warp-in-warp -------------------------------------------------------------------

[[nodiscard]] std::expected<void, Error> warp_in_warp_precheck(const SocketAddr& outer,
                                                              const SocketAddr& inner_peer);
[[nodiscard]] std::string wiw_outer_line(const SocketAddr& peer);
[[nodiscard]] std::string wiw_forwarder_line(const SocketAddr& inner_peer,
                                            const SocketAddr& forwarder);
inline constexpr std::string_view WIW_INNER_LINE =
    "[*] establishing inner WARP tunnel (warp-in-warp)...";

// ---- gool over masque -----------------------------------------------------------------------

// gool_inner_peers: AETHER_GOOL_INNER alone when it is set, else the identity's assigned endpoint
// and the WireGuard v4 seeds, each on port 2408, de-duplicated.
[[nodiscard]] std::expected<std::vector<SocketAddr>, Error> gool_inner_peers(const Settings& settings,
                                                                            const Identity& identity);
// One attempt at one inner candidate, in the order run_gool_tunnel makes them.
struct GoolAttempt {
    SocketAddr inner_peer;
    std::uint32_t attempt = 1;
};
[[nodiscard]] std::vector<GoolAttempt> gool_attempt_plan(const std::vector<SocketAddr>& candidates);

[[nodiscard]] std::string gool_attempt_line(const SocketAddr& inner_peer,
                                           const SocketAddr& forwarder);
[[nodiscard]] std::string gool_attempt_fail_line(const SocketAddr& inner_peer, std::uint32_t attempt,
                                                std::string_view error);
[[nodiscard]] std::string gool_ready_line(const SocketAddr& peer, const SocketAddr& inner_peer);
// Whether the identity's assigned_endpoint should be replaced by the inner address that worked.
[[nodiscard]] bool gool_remembers(const Settings& settings, const Identity& inner_identity,
                                 const IpAddress& inner_ip);
[[nodiscard]] std::string gool_remember_line(const IpAddress& inner_ip);
[[nodiscard]] std::string gool_identity_loaded_line(std::string_view inner_path);
[[nodiscard]] std::string gool_identity_saved_line(std::string_view inner_path,
                                                  const Identity& identity);
inline constexpr std::string_view GOOL_REGISTERING_LINE =
    "[*] registering the gool wireguard identity through the masque tunnel";
[[nodiscard]] std::string gool_enable_warp_warn(std::string_view error);

// The pinned-hop lines run_gool and run_mim write. The outer-only wordings differ, which is easy to
// lose: gool scans for the inner one, mim chooses it.
[[nodiscard]] std::string pinned_pair_line(std::string_view what, const SocketAddr& outer,
                                          const SocketAddr& inner);
[[nodiscard]] std::string gool_pinned_outer_line(const SocketAddr& outer);
[[nodiscard]] std::string gool_pinned_inner_line(const SocketAddr& inner);
[[nodiscard]] std::string mim_pinned_outer_line(const SocketAddr& outer);
[[nodiscard]] std::string mim_pinned_inner_line(const SocketAddr& inner);

// ---- the reconnect loops --------------------------------------------------------------------

// The four loops of lib.rs, as state machines. Each emits one FlowRequest at a time; the engine
// does the work and calls resume() with the answer. A step with no request is the end: `fatal()`
// carries the error the loop would have returned, `cancelled()` says the run was stopped.
//
// Cancellation. lib.rs has none inside these loops: Ctrl-C kills the process. This is a library, so
// every step checks the shared Cancel flag first and stops the loop when it is raised, which is the
// only behaviour the port adds. Nothing else is invented.

// Which run_* a RunTunnel request names.
enum class RunShape { MasqueTunnel, WireguardTunnel, MasqueInMasque, WarpInWarp, GoolTunnel };

// Which of a run_*'s select arms finished first.
enum class Winner { Outer, Inner, Socks, Policy };

struct FlowRequest {
    enum class Kind {
        Sleep,             // wait `delay`, then resume with an empty reply
        SaveLastconn,      // write the last-connection file, then resume with an empty reply
        VerifyMasquePeer,  // quick_verify_masque_peer(peer, ech)
        VerifyWgEndpoint,  // wireguard::verify_endpoint(peer, noise, timeout, keepalive)
        HuntMasquePeer,    // hunt_masque_peer(mode_str, ip)
        HuntWgEndpoint,    // hunt_wg_peer_with_profile(mode_str, ip, noise, excluded)
        HuntWgPeers,       // select_wg_peers(mode_str, ip, want, avoid)
        RunTunnel,         // the run_* for `shape`
    };

    Kind kind = Kind::Sleep;

    std::chrono::seconds delay{0};

    // SaveLastconn
    std::string path;
    std::string peer_text;
    std::string profile;
    std::string carrier;

    // Verify, Hunt and RunTunnel
    SocketAddr peer;
    std::optional<SocketAddr> inner_peer;
    std::vector<SocketAddr> candidates;
    std::vector<SocketAddr> excluded;
    std::vector<IpAddress> avoid;
    std::size_t want = 0;
    std::string mode_str;
    IpScan ip = IpScan::V4;
    AetherNoizeConfig noise;
    std::string profile_name;
    std::chrono::seconds timeout{0};
    // Nothing is Rust's `None` keepalive, which the checks that only probe pass.
    std::optional<std::uint16_t> keepalive;
    RunShape shape = RunShape::MasqueTunnel;
    std::optional<std::vector<std::uint8_t>> ech;
    // GoolTunnel: where the WireGuard identity carried inside the MASQUE tunnel lives. The
    // flow owns it (MasqueFlow::Config::gool_inner); the engine only reads it.
    std::string gool_inner_path;
};

struct FlowReply {
    // Verify*: the check passed. RunTunnel: the tunnel returned Ok(()). Hunt*: an endpoint came back.
    bool ok = false;
    // The failure when !ok. Its Display is what lib.rs interpolates into its warn lines.
    Error error;
    SocketAddr peer;
    std::vector<SocketAddr> peers;
    // HuntWgPeers: the raw results, which the flow filters and takes from, as select_wg_peers does.
    std::vector<WgProbeResult> results;
    std::chrono::milliseconds rtt{0};
    // HuntWgEndpoint: the profile that found the endpoint, which the loop then keeps.
    AetherNoizeConfig profile;
    std::string profile_name;
};

struct FlowStep {
    Notes notes;
    // Nothing when the loop is over: see fatal() and cancelled().
    std::optional<FlowRequest> request;
};

// The tasks a run_* pushes into its TaskGuard, in push order, which is the order the guard's drop
// aborts them. `http` says whether an http proxy listener was bound at all.
[[nodiscard]] std::vector<std::string_view> guard_tasks(RunShape shape, bool http);
// The tasks a run_* aborts by hand once its select picks a winner, in order. The guard's drop
// follows. A MasqueTunnel or WireguardTunnel that ends on the exit-policy arm returns early and
// aborts nothing by hand.
[[nodiscard]] std::vector<std::string_view> explicit_aborts(RunShape shape, Winner winner);

// join_outcome: the error text a finished task turns into.
struct JoinOutcome {
    enum class Kind { Completed, Failed, Cancelled, Panicked };

    Kind kind = Kind::Completed;
    // Failed: the tunnel's own error. Panicked: the join error's text.
    std::string error;
};
[[nodiscard]] std::string join_outcome(std::string_view what, const JoinOutcome& outcome);

// TaskGuard: the abort handles a run_* collects, aborted in push order when it is dropped. Move
// only, as the Rust is; a moved-from guard holds nothing.
class TaskGuard {
public:
    using Abort = std::function<void()>;

    TaskGuard() = default;
    ~TaskGuard();
    TaskGuard(TaskGuard&& other) noexcept;
    TaskGuard& operator=(TaskGuard&& other) noexcept;
    TaskGuard(const TaskGuard&) = delete;
    TaskGuard& operator=(const TaskGuard&) = delete;

    void push(Abort handle);
    // Drains and aborts, which is what the destructor does.
    void abort_all();
    [[nodiscard]] std::size_t size() const { return handles_.size(); }

private:
    std::vector<Abort> handles_;
};

// What every flow reads.
struct FlowConfig {
    const Settings& settings;
    PromptLine prompt;
    Cancel cancel;
};

// run_masque, with gool_inner set for the gool-over-masque protocol.
class MasqueFlow {
public:
    struct Config {
        const Settings& settings;
        PromptLine prompt;
        Cancel cancel;
        Identity identity;
        SocketAddr listen;
        std::string lastconn_path;
        // lastconn::load_last_connection(lastconn_path), which the engine reads once.
        std::optional<LastConnection> cached;
        // tls::session_ech(): the key every handshake of the session offers.
        std::optional<std::vector<std::uint8_t>> ech;
        // Some(path) makes the run gool over masque rather than a plain MASQUE tunnel.
        std::optional<std::string> gool_inner;
    };

    explicit MasqueFlow(Config config);

    [[nodiscard]] FlowStep begin();
    [[nodiscard]] FlowStep resume(const FlowReply& reply);

    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] bool cancelled() const { return cancelled_; }
    [[nodiscard]] const std::optional<Error>& fatal() const { return fatal_; }
    // The endpoint the loop is on, once it has chosen one.
    [[nodiscard]] const std::optional<SocketAddr>& current_peer() const { return last_good_peer_; }
    // The config this flow was built with: the engine's ExecContext reads identity, listen and ech
    // off it, the way lib.rs reaches them through its own frame.
    [[nodiscard]] const Config& config() const { return config_; }

private:
    FlowStep stopped();
    FlowStep loop_top();
    FlowStep forced_or_hunt();
    FlowStep use_peer(const SocketAddr& peer);
    FlowStep sleep_then(std::chrono::seconds delay, int phase);

    Config config_;
    std::optional<std::string> forced_;
    std::optional<SocketAddr> quick_peer_;
    std::vector<SocketAddr> ring_;
    std::size_t ring_index_ = 0;
    std::optional<SocketAddr> assigned_;
    ScanSettings scan_settings_;
    std::optional<SocketAddr> last_good_peer_;
    FlowRequest pending_;
    int phase_ = 0;
    bool done_ = false;
    bool cancelled_ = false;
    std::optional<Error> fatal_;
};

// run_wireguard. Time is injected: the endpoint cooldowns are the only arithmetic in lib.rs that
// reads a clock, and this way it is testable without waiting.
class WireguardFlow {
public:
    struct Config {
        const Settings& settings;
        PromptLine prompt;
        Cancel cancel;
        Identity identity;
        SocketAddr listen;
        std::string lastconn_path;
        std::optional<LastConnection> cached;
    };

    explicit WireguardFlow(Config config);

    [[nodiscard]] FlowStep begin(TimePoint now);
    [[nodiscard]] FlowStep resume(const FlowReply& reply, TimePoint now);

    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] bool cancelled() const { return cancelled_; }
    [[nodiscard]] const std::optional<Error>& fatal() const { return fatal_; }
    [[nodiscard]] const std::optional<SocketAddr>& current_peer() const;
    // The endpoints currently excluded, which is what the hunt is asked to leave out.
    [[nodiscard]] std::vector<SocketAddr> cooldowns() const;
    // The config this flow was built with, for the engine's ExecContext (see MasqueFlow::config).
    [[nodiscard]] const Config& config() const { return config_; }

private:
    struct LastGood {
        SocketAddr peer;
        AetherNoizeConfig profile;
        std::string name;
    };

    FlowStep stopped();
    FlowStep loop_top(TimePoint now);
    FlowStep forced_or_hunt();
    FlowStep use_peer(LastGood chosen);

    Config config_;
    std::vector<std::pair<std::string, AetherNoizeConfig>> candidates_;
    std::optional<std::string> forced_;
    std::optional<LastGood> quick_;
    std::optional<LastGood> last_good_;
    std::vector<SocketAddr> ring_;
    std::size_t ring_index_ = 0;
    std::size_t profile_index_ = 0;
    std::optional<SocketAddr> assigned_;
    ScanSettings scan_settings_;
    std::uint32_t consecutive_fails_ = 0;
    std::vector<std::pair<SocketAddr, TimePoint>> endpoint_cooldowns_;
    AetherNoizeConfig cached_profile_;
    FlowRequest pending_;
    int phase_ = 0;
    bool done_ = false;
    bool cancelled_ = false;
    std::optional<Error> fatal_;
};

// run_gool: the classic warp-in-warp loop.
class GoolFlow {
public:
    struct Config {
        const Settings& settings;
        PromptLine prompt;
        Cancel cancel;
        Identity primary;
        Identity secondary;
        SocketAddr listen;
    };

    explicit GoolFlow(Config config);

    [[nodiscard]] FlowStep begin();
    [[nodiscard]] FlowStep resume(const FlowReply& reply);

    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] bool cancelled() const { return cancelled_; }
    [[nodiscard]] const std::optional<Error>& fatal() const { return fatal_; }
    [[nodiscard]] const std::optional<SocketAddr>& current_peer() const { return outer_peer_; }
    [[nodiscard]] const std::optional<SocketAddr>& current_inner_peer() const { return inner_peer_; }
    // The config this flow was built with, for the engine's ExecContext (see MasqueFlow::config).
    [[nodiscard]] const Config& config() const { return config_; }

private:
    FlowStep stopped();
    FlowStep loop_top();
    FlowStep use_pair(const SocketAddr& outer, const SocketAddr& inner);

    Config config_;
    WiwEndpoints pinned_;
    std::optional<SocketAddr> outer_peer_;
    std::optional<SocketAddr> inner_peer_;
    std::uint32_t consecutive_fails_ = 0;
    ScanSettings scan_settings_;
    FlowRequest pending_;
    int phase_ = 0;
    bool done_ = false;
    bool cancelled_ = false;
    std::optional<Error> fatal_;
};

// run_mim: the masque-in-masque loop.
class MimFlow {
public:
    struct Config {
        const Settings& settings;
        PromptLine prompt;
        Cancel cancel;
        Identity primary;
        Identity secondary;
        SocketAddr listen;
        // sibling_candidates' shuffle and the v6 segment draws.
        Random random;
        std::optional<std::vector<std::uint8_t>> ech;
    };

    explicit MimFlow(Config config);

    [[nodiscard]] FlowStep begin();
    [[nodiscard]] FlowStep resume(const FlowReply& reply);

    [[nodiscard]] bool done() const { return done_; }
    [[nodiscard]] bool cancelled() const { return cancelled_; }
    [[nodiscard]] const std::optional<Error>& fatal() const { return fatal_; }
    [[nodiscard]] const std::optional<SocketAddr>& current_peer() const { return outer_peer_; }
    [[nodiscard]] const std::vector<SocketAddr>& current_candidates() const { return candidates_; }
    // The config this flow was built with, for the engine's ExecContext (see MasqueFlow::config).
    [[nodiscard]] const Config& config() const { return config_; }

private:
    FlowStep stopped();
    FlowStep loop_top();
    FlowStep after_outer(const SocketAddr& outer);

    Config config_;
    WiwEndpoints pinned_;
    std::optional<SocketAddr> outer_peer_;
    std::optional<SocketAddr> inner_peer_;
    std::vector<SocketAddr> candidates_;
    std::uint32_t consecutive_fails_ = 0;
    ScanSettings scan_settings_;
    FlowRequest pending_;
    int phase_ = 0;
    bool done_ = false;
    bool cancelled_ = false;
    std::optional<Error> fatal_;
};

// ---- the reconnect warn lines ---------------------------------------------------------------

[[nodiscard]] std::string tunnel_closed_line(std::string_view what);
[[nodiscard]] std::string tunnel_ended_line(std::string_view what, std::string_view error);
[[nodiscard]] std::string no_usable_masque_line(std::string_view error);
[[nodiscard]] std::string no_usable_warp_line(std::string_view error);
[[nodiscard]] std::string no_usable_wireguard_line(std::string_view error);

// run_masque
[[nodiscard]] std::string verifying_assigned_line(const SocketAddr& assigned);
[[nodiscard]] std::string assigned_works_line(const SocketAddr& assigned);
[[nodiscard]] std::string assigned_failed_line(const SocketAddr& assigned);
[[nodiscard]] std::string verifying_cached_line(const SocketAddr& peer);
[[nodiscard]] std::string cached_works_line(const SocketAddr& peer);
[[nodiscard]] std::string cached_dead_line(const SocketAddr& peer);
inline constexpr std::string_view NO_REMEMBERED_GATEWAY =
    "[-] no remembered gateway answers; scanning fresh";
[[nodiscard]] std::string retrying_last_good_line(const SocketAddr& peer);
[[nodiscard]] std::string last_good_dead_line(const SocketAddr& peer);
[[nodiscard]] std::string saved_lastconn_profile(const Settings& settings);

// run_wireguard
[[nodiscard]] std::string wg_assigned_works_line(const SocketAddr& assigned, std::string_view name,
                                                std::chrono::milliseconds rtt);
[[nodiscard]] std::string wg_assigned_failed_line(const SocketAddr& assigned, std::string_view name,
                                                 std::string_view error);
[[nodiscard]] std::string wg_assigned_gave_up_line(const SocketAddr& assigned);
[[nodiscard]] std::string wg_cached_verifying_line(const SocketAddr& peer);
[[nodiscard]] std::string wg_cached_works_line(const SocketAddr& peer, std::chrono::milliseconds rtt);
[[nodiscard]] std::string wg_cached_dead_line(const SocketAddr& peer, std::string_view error);
inline constexpr std::string_view WG_NO_REMEMBERED =
    "[-] no remembered endpoint answers; scanning fresh";
[[nodiscard]] std::string wg_retrying_last_good_line(const SocketAddr& peer);
[[nodiscard]] std::string wg_last_good_dead_line(const SocketAddr& peer, std::string_view error);
[[nodiscard]] std::string wg_cooling_down_line(const SocketAddr& peer, std::uint32_t fails,
                                              std::chrono::seconds cooldown);
[[nodiscard]] std::string wg_hunt_profile_line(std::string_view name);
[[nodiscard]] std::string wg_hunt_selected_line(const SocketAddr& peer, std::string_view name);
[[nodiscard]] std::string wg_hunt_profile_failed_line(std::string_view name, std::string_view error,
                                                     bool multi);
[[nodiscard]] std::string wg_testing_forced_line(const SocketAddr& peer, std::string_view name);
[[nodiscard]] std::string wg_forced_profile_passed_line(std::string_view name,
                                                       std::chrono::milliseconds rtt);
[[nodiscard]] std::string wg_forced_profile_failed_line(std::string_view name,
                                                       std::string_view error);
[[nodiscard]] std::string wg_forced_exhausted_line(const SocketAddr& peer);

// run_gool
[[nodiscard]] std::string gool_blacklist_outer_line(const SocketAddr& peer, std::uint32_t fails);
[[nodiscard]] std::string gool_blacklist_inner_line(const SocketAddr& peer, std::uint32_t fails);
[[nodiscard]] std::string gool_pinned_exhausted_line(std::uint32_t fails);
inline constexpr std::string_view GOOL_ONE_EDGE =
    "[-] the scan only turned up one edge, so warp-in-warp would use it twice; rescanning";

// run_mim
[[nodiscard]] std::string mim_outer_rescan_line(const SocketAddr& peer, std::uint32_t fails);
[[nodiscard]] std::string mim_inner_another_line(const SocketAddr& peer, std::uint32_t fails);

} // namespace aether::core::coreflow
