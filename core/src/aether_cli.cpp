// aether-core.exe: the native core's console entry point, the counterpart of aether/src/main.rs
// (pinned commit 6175b67). main.rs is three lines: it hands `env::args().skip(1)` to aether::run(),
// which is lib.rs::run_with, and prints the Err with Rust's default Termination (`Error: {e:?}`) and
// exits 1 when run() returns one. Everything that produces output here is what lib.rs::run_with and
// its port, coreflow::startup and the four run_* flows, decide; this file only supplies the seams
// lib.rs got from tokio and its own sockets -- the argument vector, the logger sink, the Ctrl-C
// handler, the listener availability check, the prompts -- and drives the flow state machines to
// their requests.
//
// NO FAKE TUNNEL. The live driver the FlowRequests name -- the hunts, the quick verifies, the socks
// accept loop, the netstack pump and the QUIC/WireGuard tunnel runs -- does not exist yet: no
// concrete localapi::Engine is implemented and account.cpp/prober.cpp/zerotrust.cpp are decision-only
// (their sockets are the seams coreflow.hpp lists). Every call site below that the Rust makes into
// the network is reached exactly where the Rust reaches it, and the seam that answers it carries a
// `// NOT WIRED:` marker naming the symbol that must fill it. A run therefore stops at the first
// unwired capability with an honest `[-]`/`Error:` line and exit 1; it never prints success.
//
// SECURITY. Secrets travel only through the environment (settings_from_environment) and the Settings
// map; none is ever moved to argv, printed, or logged. The five keys the GUI passes --
// AETHER_MASQUE_HTTP2, AETHER_ACCESS_EMAIL, AETHER_ACCESS_CLIENT_ID, AETHER_ACCESS_CLIENT_SECRET,
// AETHER_ACCESS_TOKEN -- are read by that map and stop there. ECH and account key material is named
// by byte length alone (coreflow owns those lines). aether-masque.toml is never opened here.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// windows.h's min/max macros break BoringSSL's span.h (std::numeric_limits<>::max()); the core's
// other translation units already rely on NOMINMAX, so the console entry point sets it too.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include "coreflow.hpp"
#include "access_http.hpp"
#include "account_live.hpp"
#include "ech_transport.hpp"
#include "settings.hpp"
#include "localapi.hpp"
#include "lastconn.hpp"
#include "stats.hpp"
#include "inproc_core.hpp"
#include "dns.hpp"
#include "prober.hpp"
#include "zerotrust.hpp"
#include "transport.hpp"
#include "netstack.hpp"
#include "netpacket.hpp"
#include "socks.hpp"
#include "sniff.hpp"
#include "wg_live.hpp"
#include "egress.hpp"
#include "exitloc.hpp"
#include "routing.hpp"
#include "upstream.hpp"
#include "quic.hpp"
#include "masque_h2.hpp"
#include "sysprofile.hpp"
#include "identity.hpp"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <expected>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <io.h>
#include <asio.hpp>

namespace {

namespace cf = aether::core::coreflow;
namespace localapi = aether::core::localapi;

using aether::core::CliOutcome;
using aether::core::Identity;
using aether::core::LastConnection;
using aether::core::Settings;
using aether::core::SocketAddr;
using aether::core::load_last_connection;
using aether::core::save_last_connection;
using aether::core::settings_from_environment;
using aether::core::trim;

using cf::Cancel;
using cf::Error;
using cf::ErrorKind;
using cf::FlowReply;
using cf::FlowRequest;
using cf::FlowStep;
using cf::Level;
using cf::Note;
using cf::Notes;

// ---- the console --------------------------------------------------------------------------------

// The GUI spawns the core with stdout and stderr merged onto one pipe (process.cpp:447-448) and
// reads it line by line, so every line is flushed as it is written. lib.rs logs through env_logger,
// whose default sink is stderr with `format_timestamp_millis()` (lib.rs:88-91); the marker text
// ([+]/[-]/[*]) is part of the message and is what process.cpp matches, so the timestamp/level
// prefix here mirrors env_logger's default shape rather than the raw line.

[[nodiscard]] const char* level_tag(Level level) {
    switch (level) {
        case Level::Debug: return "DEBUG";
        case Level::Warn: return "WARN";
        case Level::Error: return "ERROR";
        case Level::Info: break;
    }
    return "INFO";
}

// env_logger's `[YYYY-MM-DDTHH:MM:SS.mmm+HH:MM LEVEL target] message`. The log target the core's
// own lines carry is the crate name, "aether".
[[nodiscard]] std::string stamp() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    TIME_ZONE_INFORMATION tz{};
    const DWORD kind = GetTimeZoneInformation(&tz);
    // windows.h stores the offset westward in minutes; env_logger prints it eastward.
    const LONG east =
        -(kind == TIME_ZONE_ID_DAYLIGHT ? tz.Bias + tz.DaylightBias : tz.Bias + tz.StandardBias);
    const char sign = east < 0 ? '-' : '+';
    const LONG absolute = east < 0 ? -east : east;
    char text[48];
    std::snprintf(text, sizeof text, "%04u-%02u-%02uT%02u:%02u:%02u.%03u%c%02u:%02u",
                  now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
                  now.wMilliseconds, sign, static_cast<unsigned>(absolute / 60),
                  static_cast<unsigned>(absolute % 60));
    return text;
}

std::function<void(std::string_view)> g_inproc_log_sink = nullptr;
std::function<void(const std::string&)> g_inproc_state_sink = nullptr;

void emit(Level level, std::string_view text) {
    std::string line = "[" + stamp() + " " + level_tag(level) + " aether] " + std::string(text);
    if (g_inproc_log_sink) {
        g_inproc_log_sink(line);
    }
    std::fprintf(stderr, "%s\n", line.c_str());
    std::fflush(stderr);
}

void emit(const Note& entry) { emit(entry.level, entry.text); }
void emit_all(const Notes& notes) { for (const Note& entry : notes) emit(entry); }

// lib.rs:82-91's env_logger filter on the aether target: info unless AETHER_LOG_LEVEL lowers it, so
// log::debug!/trace! texts reach the pipe only when the level allows -- the same gate note_level
// applies to the transport notes (coreflow.cpp:487-495's log_level_of is the filter's source).
[[nodiscard]] bool log_at(const Settings& settings, std::string_view wanted) {
    const std::string have = cf::log_level_of(settings);
    if (have == "trace") return true;
    if (have == "debug") return wanted == "debug";
    return false;
}

// The version/help/prompt path is stdout (cli.rs prints USAGE with print!, lib.rs's prompts with
// print! then flush), kept flushed so a piped GUI reader sees the line the moment it is written.
void out_raw(std::string_view text) {
    std::fwrite(text.data(), 1, text.size(), stdout);
    std::fflush(stdout);
}

void out_line(std::string_view text) {
    if (g_inproc_log_sink) {
        g_inproc_log_sink(text);
    }
    out_raw(text);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

// ---- argv (main.rs: `env::args().skip(1)`) ------------------------------------------------------

[[nodiscard]] std::string to_utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), size,
                            nullptr, nullptr) == 0) {
        return {};
    }
    return out;
}

// The Unicode command line, decoded to UTF-8 and with the program name dropped -- Rust's lossy
// `env::args()` read of the same wide vector. Flag values (config paths, peer addresses) keep their
// bytes; no secret is ever passed this way because the caller only puts secrets in the environment.
[[nodiscard]] std::vector<std::string> command_line_args() {
    std::vector<std::string> args;
    int count = 0;
    LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wide == nullptr) return args;
    args.reserve(count > 0 ? static_cast<size_t>(count) - 1 : 0);
    for (int index = 1; index < count; ++index) args.push_back(to_utf8(std::wstring(wide[index])));
    LocalFree(wide);
    return args;
}

// ---- Ctrl-C / SIGTERM (the seam coreflow.hpp:27 names SignalInstaller) -------------------------

// lib.rs installs no signal handler of its own (coreflow.hpp:259): Ctrl-C simply ends the Rust
// process. This is a native binary the GUI supervises, so a stop is turned into the cooperative
// Cancel every flow checks, letting the run release the wintun adapter and the netstack state
// before it exits. The handler cancels the master flag; the copies in every FlowConfig share it.

const Cancel* g_cancel = nullptr;

BOOL WINAPI console_ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT ||
        type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        if (g_cancel != nullptr) g_cancel->cancel();
        return TRUE;
    }
    return FALSE;
}

void install_console_signals(const Cancel& cancel) {
    g_cancel = &cancel;
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
}

// ---- the startup seams --------------------------------------------------------------------------

// prompt_line (lib.rs): nothing when stdin is no terminal; otherwise the prompt goes to stdout and
// the line read back is trimmed. The GUI gives the core a piped stdin, so this answers nothing and
// the run takes the non-interactive branch, exactly as the Rust does.
cf::PromptLine make_prompt() {
    return [](std::string_view prompt) -> std::optional<std::string> {
        if (_isatty(_fileno(stdin)) == 0) return std::nullopt;
        out_raw(prompt);
        std::string line;
        if (!std::getline(std::cin, line)) return std::nullopt;
        return std::string(trim(line));
    };
}

[[nodiscard]] int fill_address(const SocketAddr& listen, sockaddr_storage& storage) {
    std::memset(&storage, 0, sizeof storage);
    if (listen.ip.v4) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(storage);
        v4.sin_family = AF_INET;
        v4.sin_port = htons(listen.port);
        std::memcpy(&v4.sin_addr.s_addr, listen.ip.bytes.data() + 12, 4);
        return sizeof sockaddr_in;
    }
    auto& v6 = reinterpret_cast<sockaddr_in6&>(storage);
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons(listen.port);
    std::memcpy(&v6.sin6_addr, listen.ip.bytes.data(), 16);
    return sizeof sockaddr_in6;
}

// socks::bind_listener / bind_http_proxy (lib.rs:120-121): the bind is only an availability probe,
// and lib.rs drops the listener straight away. So this binds, listens once, and closes -- a port
// already held is the Io error startup turns into a fatal stop, the way `?` does in the Rust.
cf::BindListener make_bind_listener() {
    return [](std::string_view what, const SocketAddr& listen) -> std::expected<void, std::string> {
        const int family = listen.ip.v4 ? AF_INET : AF_INET6;
        const SOCKET socket = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (socket == INVALID_SOCKET) {
            return std::unexpected(std::string(what) + ": socket failed (" +
                                   std::to_string(WSAGetLastError()) + ")");
        }
        sockaddr_storage storage{};
        const int length = fill_address(listen, storage);
        bool open = ::bind(socket, reinterpret_cast<const sockaddr*>(&storage), length) == 0 &&
                    ::listen(socket, 1) == 0;
        const int failed = WSAGetLastError();
        closesocket(socket);
        if (!open) {
            return std::unexpected(std::string(what) + " could not bind " + listen.to_string() +
                                   " (" + std::to_string(failed) + ")");
        }
        return {};
    };
}

// std::fs::read_dir for enrolled_teams (coreflow.hpp:251): the entry names, nothing on failure.
cf::ListDir make_list_dir() {
    return [](const std::string& dir) -> std::vector<std::string> {
        std::vector<std::string> names;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (ec) break;
            names.push_back(entry.path().filename().string());
        }
        return names;
    };
}

// The Access HTTP exchange (AccessRequest in, AccessResponse out) over https_runtime::send:
// method, redirects and a per-host cookie jar per the request's own flags.
auto zerotrust_hooks_http(const Settings& settings) {
    // One client (one cookie jar) for the whole hooks object, like reqwest's Client: the email
    // flow's resend/submit round trips share it through the same std::function.
    return aether::core::access_http(settings);
}

// zerotrust::Hooks.code_prompt: the terminal read. The engine prints the banner and answers what
// its stdin does; off a terminal there is nothing to read, which is what a pipe means in the Rust.
auto zerotrust_hooks_code_prompt() {
    return [](const aether::core::zerotrust::CodePromptAsk& ask)
               -> aether::core::zerotrust::CodePromptReply {
        using aether::core::zerotrust::CodePromptReply;
        using aether::core::zerotrust::CodeRead;
        if (_isatty(_fileno(stdin)) == 0) return {}; // Closed: no code is coming
        out_raw(ask.banner);
        if (ask.interactive) {
            // A terminal waits for the person: no deadline, one blocking line.
            std::string line;
            if (!std::getline(std::cin, line)) return {};
            CodePromptReply reply;
            reply.read = CodeRead::Line;
            reply.line = std::move(line);
            return reply;
        }
        // A pipe waits CODE_WAIT_SECS and then says so.
        const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input == NULL || input == INVALID_HANDLE_VALUE) return {};
        if (WaitForSingleObject(input, static_cast<DWORD>(ask.wait_secs * 1000)) != WAIT_OBJECT_0) {
            CodePromptReply reply;
            reply.read = CodeRead::TimedOut;
            return reply;
        }
        std::string line;
        if (!std::getline(std::cin, line)) return {};
        CodePromptReply reply;
        reply.read = CodeRead::Line;
        reply.line = std::move(line);
        return reply;
    };
}

aether::core::zerotrust::Hooks make_team_hooks(const Settings& settings) {
    aether::core::zerotrust::Hooks hooks;
    hooks.http = zerotrust_hooks_http(settings);
    hooks.code_prompt = zerotrust_hooks_code_prompt();
    hooks.interactive = _isatty(_fileno(stdin)) != 0;
    return hooks;
}

// ---- the networked capabilities the exe still owes ----------------------------------------------

// NOT WIRED (1-6), now wired through account_live.cpp over https_runtime::send:
//   1. AccountSeams.provision_wg           -> account_live::provision_wg
//   2. AccountSeams.provision_team         -> account_live::provision_team
//   3. AccountSeams.refresh_profile        -> account_live::refresh_profile
//   4. AccountSeams.ensure_masque_enrolled -> account_live::ensure_masque_enrolled
//   5. AccountSeams.enable_warp            -> account_live::enable_warp
//   6. AccountSeams.set_gateway_proxy      -> socks::set_gateway_proxy
// make_ech_transport is defined below; the account calls need it for --ech=auto lookups.
cf::EchTransport make_ech_transport(const Settings& settings);

[[nodiscard]] cf::Error to_flow_error(const aether::core::account::LiveError& error) {
    using aether::core::account::LiveKind;
    switch (error.kind) {
        case LiveKind::IdentityRefused:
            return cf::Error::identity_refused(error.message);
        case LiveKind::Ech:
            return cf::Error{cf::ErrorKind::Ech, error.message};
        case LiveKind::Tls:
            return cf::Error{cf::ErrorKind::Tls, error.message};
        case LiveKind::Api:
            break;
    }
    return cf::Error{cf::ErrorKind::Api, error.message};
}

cf::AccountSeams make_account_seams(const Settings& settings) {
    namespace live = aether::core::account;
    live::LiveEnv env;
    env.settings = &settings;
    env.ech_transport = make_ech_transport(settings);
    env.team_hooks = make_team_hooks(settings);
    env.info = [](const std::string& line) { emit(Level::Info, line); };
    env.warn = [](const std::string& line) { emit(Level::Warn, line); };
    env.debug = [](const std::string& line) { emit(Level::Debug, line); };

    cf::AccountSeams seams;
    // provision_wg's jwt is None here: coreflow's seam carries no token, and lib.rs threads
    // --jwt through provision_account, which this port does not take.
    seams.provision_wg = [env](std::string_view model, std::string_view locale)
        -> std::expected<Identity, cf::Error> {
        auto provisioned = live::provision_wg(model, locale, std::nullopt, env);
        if (!provisioned.has_value()) return std::unexpected(to_flow_error(provisioned.error()));
        return *provisioned;
    };
    seams.provision_team = [env](std::string_view model, std::string_view locale,
                                 const aether::core::zerotrust::TeamSettings& team)
        -> std::expected<Identity, cf::Error> {
        auto provisioned = live::provision_team(model, locale, team, env);
        if (!provisioned.has_value()) return std::unexpected(to_flow_error(provisioned.error()));
        return *provisioned;
    };
    seams.refresh_profile = [env](Identity identity) {
        return live::refresh_profile(std::move(identity), env);
    };
    seams.ensure_masque_enrolled = [env](const Identity& identity)
        -> std::expected<aether::core::account::MasqueEnrollment, cf::Error> {
        auto enrolled = live::ensure_masque_enrolled(identity, env);
        if (!enrolled.has_value()) return std::unexpected(to_flow_error(enrolled.error()));
        return *enrolled;
    };
    seams.enable_warp = [env](std::string_view device_id, std::string_view access_token)
        -> std::expected<void, cf::Error> {
        auto enabled = live::enable_warp(device_id, access_token, env);
        if (!enabled.has_value()) return std::unexpected(to_flow_error(enabled.error()));
        return {};
    };
    seams.set_gateway_proxy = [](std::string_view gateway_proxy) {
        (void)aether::core::socks::set_gateway_proxy(gateway_proxy);
    };
    return seams;
}

// NOT WIRED (7), now wired: dns::fetch_ech_config's resolver over a real socket -- UDP/TCP
// straight at the resolver, DoH through https_runtime::send.
cf::EchTransport make_ech_transport(const Settings& settings) {
    return aether::core::default_ech_transport(settings);
}

// THE WOVEN LIST (11-16), all executing:
//   11. HuntMasquePeer   -> both carriers; ironclad runs tunnelping::masque_http_ping (throwaway
//                          Hop + real HTTP probe, ranked by its round trip).
//   12. HuntWgEndpoint   -> verify_endpoint_keep_session + WgHunt.
//       HuntWgPeers      -> select_wg_peers: one hunt for `want`, avoid filter in flow.
//                          ironclad runs tunnelping::wg_http_ping_established the same way.
//   13. VerifyMasquePeer -> both carriers.  14. VerifyWgEndpoint -> wg_live verify.
//   15. RunTunnel        -> MasqueTunnel (both carriers), WireguardTunnel (wg_live::run_tunnel),
//                          MasqueInMasque, WarpInWarp and GoolTunnel (two Hop composers above).
//   16. (folded into 15.)
// Nothing on this list refuses anymore; Exec::Refused below is now unreachable, kept as the
// honest answer for any future Kind the flow learns before the engine does.

enum class Exec {
    Ran,     // the request was carried out; resume the flow with the reply.
    Refused, // the capability is not wired; stop the run honestly.
};

// Defined with the fatal-error reporting below; forward declared so the flow loops can use it.
[[nodiscard]] int fail(const Error& error);

// The Rust sleeps between reconnect attempts with tokio::time::sleep; here the same wait, sliced so
// a Ctrl-C (the shared Cancel flag) is felt promptly. An empty reply follows, as Sleep requests.
void interruptible_sleep(std::chrono::seconds delay, const Cancel& cancel) {
    const auto finish = std::chrono::steady_clock::now() + delay;
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < finish) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// The same wait for a sub-second budget: the pump's sleeps are milliseconds, and every one of them
// still has to answer a Ctrl-C promptly, so the slice stays 50 ms.
void interruptible_sleep_ms(std::chrono::milliseconds delay, const Cancel& cancel) {
    const auto finish = std::chrono::steady_clock::now() + delay;
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < finish) {
        std::this_thread::sleep_for(std::chrono::milliseconds(
            delay < std::chrono::milliseconds(50) ? delay : std::chrono::milliseconds(50)));
    }
}

[[nodiscard]] std::string request_kind_name(FlowRequest::Kind kind) {
    switch (kind) {
        case FlowRequest::Kind::Sleep: return "Sleep";
        case FlowRequest::Kind::SaveLastconn: return "SaveLastconn";
        case FlowRequest::Kind::VerifyMasquePeer: return "VerifyMasquePeer";
        case FlowRequest::Kind::VerifyWgEndpoint: return "VerifyWgEndpoint";
        case FlowRequest::Kind::HuntMasquePeer: return "HuntMasquePeer";
        case FlowRequest::Kind::HuntWgEndpoint: return "HuntWgEndpoint";
        case FlowRequest::Kind::HuntWgPeers: return "HuntWgPeers";
        case FlowRequest::Kind::RunTunnel: return "RunTunnel";
    }
    return "Unknown";
}

// ---- the live executor -------------------------------------------------------------------------

namespace tr = aether::core::transport;
namespace pr = aether::core::prober;
namespace ns = aether::core::netstack;
namespace netpacket = aether::core::netpacket;
namespace sk = aether::core::socks;
namespace up = aether::core::upstream;
namespace rt = aether::core::routing;
namespace quic = aether::core::quic;
namespace carrier_h2 = aether::core::masque_h2;
namespace sysprofile = aether::core::sysprofile;

using aether::core::IpAddress;

// What a FlowRequest does not name: which identity the call runs on, which ECH key the session
// offers, and where the proxy listens. lib.rs keeps both in the frame it is running, so the choice
// is visible at the call site -- quick_verify_masque_peer(&identity, peer, tls::session_ech()) at
// lib.rs:1371/1388/1419, hunt_masque_peer(&identity, ...) at :1441 and :2062 (run_mim hunts on the
// OUTER identity), run_masque_tunnel(&identity, peer, ...) at :1471, and run_masque_in_masque at
// :1887/:1925 takes primary for the outer hop and secondary for the inner one. Every run_* arm of
// run_dispatch builds one of these next to its flow Config, so the same mapping holds here.
struct ExecContext {
    const Settings& settings;
    // The identity the flow's own handshakes run on: run_masque's `identity`, run_mim's `primary`,
    // run_wireguard's and run_gool's `primary`. Key material stays in memory; never on a log.
    const Identity& primary;
    // The second hop's identity, where the protocol has one (run_mim's inner MASQUE hop,
    // run_gool's inner WireGuard hop). Null when the flow has only one.
    const Identity* secondary = nullptr;
    // socks::bind_listener's address, the `listen` every run_* hands its tunnel.
    SocketAddr listen{};
    // tls::session_ech(): the key the session's handshakes offer. HuntMasquePeer carries no ech of
    // its own (lib.rs:1268 reads tls::session_ech() inside hunt_masque_peer), so the probes take this
    // one when the request does not name a key.
    std::optional<std::vector<std::uint8_t>> ech;
    const Cancel& cancel;
};

// The key this handshake offers: the request's when the flow named one, else the session's.
[[nodiscard]] const std::optional<std::vector<std::uint8_t>>& ech_for(const FlowRequest& request,
                                                                      const ExecContext& ctx) {
    return request.ech.has_value() ? request.ech : ctx.ech;
}

// prober.rs::host_has_ipv6: bind [::]:0 and connect() a datagram socket at the v6 edge. A UDP
// connect sends nothing; it is the route lookup that answers, which is exactly what the Rust's
// `sock.connect(..).await.is_ok()` measures.
[[nodiscard]] bool host_has_ipv6() {
    const SOCKET socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) return false;

    sockaddr_in6 wildcard{};
    wildcard.sin6_family = AF_INET6;
    wildcard.sin6_addr = in6addr_any;
    wildcard.sin6_port = 0;
    bool reachable =
        ::bind(socket, reinterpret_cast<sockaddr*>(&wildcard), sizeof wildcard) == 0;

    if (reachable) {
        sockaddr_in6 target{};
        target.sin6_family = AF_INET6;
        target.sin6_port = htons(443);
        // 2606:4700:d0::a29f:c001, the same address prober.rs:261 uses.
        static constexpr std::uint8_t edge[16] = {0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x0d,
                                                  0x00, 0x00, 0x00, 0x00, 0xa2, 0x9f, 0xc0, 0x01};
        std::memcpy(&target.sin6_addr, edge, sizeof edge);
        reachable = ::connect(socket, reinterpret_cast<sockaddr*>(&target), sizeof target) == 0;
    }
    closesocket(socket);
    return reachable;
}

// transport's Observer hands over everything quic.rs writes with log::info!, log_or_debug (info for
// a tunnel, which is what establish_masque always builds: quic.quiet is false) and log::debug!/trace!.
// env_logger's filter is info unless AETHER_LOG_LEVEL says otherwise (lib.rs:82-91), so the debug and
// trace texts must not reach the pipe the GUI reads: the texts quic.rs prints at info or warn are
// listed, and every other note is dropped.
[[nodiscard]] std::optional<Level> note_level(std::string_view line) {
    static constexpr std::string_view info_lines[] = {
        "ech config injected (",                            // quic.rs:330
        "quic handshake established; alpn=",                // quic.rs:458 (log_or_debug)
        "connect-ip request sent on stream ",               // quic.rs:468
        "[*] validating masque data-plane before exposing socks5", // quic.rs:474
        "[+] masque tunnel validated (end-to-end data confirmed); exposing socks5", // quic.rs:505
        "connect-ip status: ",                              // quic.rs:608
        "edge assigned ",                                   // quic.rs:657
        "received ",                                        // quic.rs:668 route advertisements
        "peer closed: ",                                    // quic.rs:551
        "local closed: ",                                   // quic.rs:562
        "migrated to local ",                               // quic.rs:779
        "[h2] ",                                            // masque_h2.rs log_or_debug lines
        "[+] dialling out through the ",                   // upstream.rs: from_value announce
        "[-] the upstream proxy setting was ignored: ",    // upstream.rs: from_value ignore
    };
    static constexpr std::string_view warn_lines[] = {
        "ech_required: retrying handshake with server retry_configs", // quic.rs:524
        "migration failed: ",                                         // quic.rs:412
    };
    for (const std::string_view prefix : info_lines) {
        if (line.starts_with(prefix)) return Level::Info;
    }
    for (const std::string_view prefix : warn_lines) {
        if (line.starts_with(prefix)) return Level::Warn;
    }
    return std::nullopt; // the debug!/trace! texts (quic.rs:389/400/404/433/436/494/673/712/718/722)
}

// The tunnel's Observer: quic.rs's run() lines, at the level that run writes them.
// TEMP-DIAG (QUIC silence chase): pass everything at Debug so recv/write errors surface.
class TunnelObserver : public tr::Observer {
public:
    void on_note(std::string_view line) override { emit(Level::Debug, line); }
    // tls.rs's announce_once: the verification mode, once per process, at info.
    void on_verification(std::string_view line) override { emit(Level::Info, line); }
};

// quic.rs's inbound_tx: the datagram the netstack reads as its tunnel traffic. Rust's channel is
// bounded, and the pump that owns the stack drains it every turn, so the queue here is unbounded and
// never reports Full -- nothing is dropped that the Rust would have kept.
class StackInbound : public tr::InboundSink {
public:
    explicit StackInbound(ns::NetStack& stack) : stack_(stack) {}
    tr::Room try_send(std::span<const std::uint8_t> ip_packet) override {
        stack_.submit_inbound(std::vector<std::uint8_t>(ip_packet.begin(), ip_packet.end()));
        return tr::Room::Accepted;
    }

private:
    ns::NetStack& stack_;
};

// establish_masque's addr_rx bridge task (lib.rs:1514-1524): the capsule's assignment goes into the
// stack for its family, and a failure is the warn line the bridge logs.
class StackAssigned : public tr::AddressSink {
public:
    explicit StackAssigned(ns::NetStack& stack) : stack_(stack) {}
    tr::Room try_send(const quic::AssignedAddr& assigned) override {
        const netpacket::TunnelAddr address{assigned.ip, assigned.prefix};
        if (assigned.ip.v4) {
            stack_.set_addrs(address, std::nullopt);
        } else {
            stack_.set_addrs(std::nullopt, address);
        }
        return tr::Room::Accepted;
    }

private:
    ns::NetStack& stack_;
};

// netstack.rs's flush_tx destination: the tunnel's outbound channel, quic.rs's outbound_rx.
class TunnelOutbound : public ns::PacketSink {
public:
    explicit TunnelOutbound(tr::Session& session) : session_(session) {}
    ns::SendOutcome try_send(std::span<const std::uint8_t> packet) override {
        switch (session_.send_ip_packet(packet)) {
            case tr::Room::Accepted: return ns::SendOutcome::Ok;
            case tr::Room::Full: return ns::SendOutcome::Full;
            case tr::Room::Closed: return ns::SendOutcome::Closed;
        }
        return ns::SendOutcome::Closed;
    }

private:
    tr::Session& session_;
};

// One check's answer. lib.rs:1299 quick_verify_masque_peer returns a plain bool -- a failed check is
// never an error to the flow -- and prober.rs::verify_one keeps the error for its trace! line, which
// sits under the log filter. `error` is kept here for the same reason: nothing prints it by default.
struct CheckOutcome {
    bool ok = false;
    std::chrono::milliseconds rtt{0};
    std::string error;
};

// bind_via_upstream's attach step for a socket the engine already bound (upstream.rs:618): the
// proxy is read silently -- the "[+] dialling out ..." announce belongs to the memoized
// configured() read, so a second announce here would print the line twice -- and the guard is
// the caller's to hold beside the socket, because the detour only lives while it does. No proxy
// configured, an unparseable one, or a local peer all answer an empty guard: the direct path,
// not an error. Only a failed ASSOCIATE is one.
[[nodiscard]] std::expected<up::DetourGuard, std::string> attach_upstream(const Settings& settings,
                                                                         const SocketAddr& local,
                                                                         const SocketAddr& peer) {
    const auto raw = settings.get("AETHER_UPSTREAM");
    if (!raw) return up::DetourGuard{};
    auto proxy = up::Upstream::parse(*raw);
    if (!proxy) return up::DetourGuard{}; // ignored, as from_value would ignore it
    auto attached = up::attach_detour(*proxy, local, peer, local.ip.v4);
    if (!attached) return std::unexpected(attached.error());
    if (attached->id() != 0) {
        emit(Level::Info, "[+] " + peer.to_string() + " is reached through the upstream relay at " +
                              attached->relay().to_string());
    }
    return std::move(*attached);
}

// quic.rs::verify_masque, on one throwaway transport::Session. The socket is bound to the peer's
// wildcard (bind_addr_for) and connected to upstream::relay_target, exactly as :811-820 does it, so
// --upstream applies to every check as it does in the Rust.
[[nodiscard]] CheckOutcome verify_quic(const Settings& settings, const quic::VerifyParams& params,
                                      const Cancel& cancel) {
    CheckOutcome outcome;
    const auto io = tr::WinUdp::open_for_peer(params.peer, settings);
    if (!io.has_value()) {
        outcome.error = "io: " + io.error();
        return outcome;
    }
    // upstream.rs:618: the detour is attached before relay_target is read, so the connect below
    // and every flush after it go through the shim when a proxy is on.
    auto detour = attach_upstream(settings, (*io)->local(), params.peer);
    if (!detour.has_value()) {
        outcome.error = "io: " + detour.error();
        return outcome;
    }
    // verify_masque's sock.connect(relay_target(local, peer)) (quic.rs:819).
    const SocketAddr target = up::relay_target((*io)->local(), params.peer);
    if (const auto connected = (*io)->connect_to(target); !connected.has_value()) {
        outcome.error = "io: " + connected.error();
        return outcome;
    }

    tr::Session::Seams seams;
    seams.io = io->get();
    // The same table the Rust's flush reads on every write (upstream.rs::relay_target).
    seams.relay = [](const SocketAddr& local, const SocketAddr& intended) {
        return up::relay_target(local, intended);
    };

    // A check writes nothing at info: verify_masque's own lines are all trace!/debug! (quic.rs:884,
    // 888, 984), so no Observer is attached and the session prints nothing.
    const auto start = std::chrono::steady_clock::now();
    auto opened = tr::Session::open(tr::Session::Setup::for_verify(params), settings,
                                    std::move(seams), start);
    if (!opened.has_value()) {
        outcome.error = "other: " + opened.error();
        return outcome;
    }
    tr::Session& session = **opened;

    const auto deadline = start + params.timeout;
    for (;;) {
        if (cancel.is_cancelled()) {
            outcome.error = "cancelled";
            return outcome;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            // quic.rs:864-866: the one error a verify returns on its own budget, in AetherError's
            // words. The caller only reads `ok`, which stays false.
            outcome.error = "other: verify timeout";
            return outcome;
        }
        const auto tick = session.tick(now);
        if (tick.error.has_value()) {
            outcome.error = *tick.error;
            return outcome;
        }
        if (session.ready()) {
            outcome.ok = true;
            outcome.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
            return outcome;
        }
        if (tick.closed) {
            outcome.error = session.error().has_value() ? *session.error() : session.close().text();
            return outcome;
        }
        auto delay = tick.delay.value_or(std::chrono::milliseconds(20));
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (delay > remaining) delay = remaining < std::chrono::milliseconds(0)
                                            ? std::chrono::milliseconds(0)
                                            : remaining;
        interruptible_sleep_ms(delay, cancel);
    }
}

// masque_h2::verify_h2_with on one throwaway handshake: the H2 arm of verify_one
// (prober.rs:414-438) and of quick_verify_masque_peer (lib.rs:1317-1334). Same contract as
// verify_quic: a failed check is never an error to the flow.
[[nodiscard]] CheckOutcome verify_h2(const Settings& settings,
                                     const carrier_h2::H2TunnelConfig& cfg,
                                     std::chrono::milliseconds timeout, const Cancel& cancel) {
    CheckOutcome outcome;
    // masque_h2.rs::dial: the proxy's stream when one is on, the direct connect when not.
    const carrier_h2::DialSocket dial = [&settings](const SocketAddr& peer) {
        return carrier_h2::dial(peer, settings);
    };
    const auto start = std::chrono::steady_clock::now();
    auto proven = carrier_h2::verify_h2_with(cfg, timeout, settings, dial);
    if (!proven.has_value()) {
        outcome.error = "other: " + proven.error();
        return outcome;
    }
    outcome.ok = true;
    outcome.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    (void)cancel;
    return outcome;
}

// The hunt's shared cursor: which candidate is next, and whether the loop has already picked.
struct HuntShared {
    std::mutex mutex;
    std::size_t next = 0;
    bool stop = false;
    // The workers still probing. When this reaches zero the candidate stream has run dry, which is
    // prober.rs:330's `None => break`.
    std::atomic<std::size_t> live{0};
};

// prober.rs's hunt logs carry their own markers, and the Rust prints every one of them at info or
// warn (prober.rs:317/319/322/333/344/357/359/362/371), so "[+]" is info and "[-]" is warn here.
void emit_hunt_logs(const std::vector<std::string>& logs) {
    for (const std::string& line : logs) {
        emit(line.starts_with("[-]") ? Level::Warn : Level::Info, line);
    }
}

// tunnelping.rs::masque_http_ping, defined with the tunnel runtime below: a throwaway Hop on
// either carrier plus the real HTTP probe through it. The round trip is the data-plane proof,
// which is what the ironclad hunt ranks by.
struct MasquePing {
    SocketAddr peer;
    std::string sni;
    std::string authority;
    std::string path;
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    std::optional<std::vector<std::uint8_t>> ech;
    pr::NoizeConfig noize;
    IpAddress local_ipv4;
};

[[nodiscard]] std::expected<std::chrono::milliseconds, std::string> masque_http_ping(
    const MasquePing& ping, const Settings& settings, const Identity& identity,
    std::chrono::milliseconds timeout, const Cancel& cancel);

// tunnelping.rs::wg_http_ping_established: the same probe through a verified WireGuard session
// on a throwaway Hop. The session is consumed: the tunnel runs on it until the probe answers.
[[nodiscard]] std::expected<std::chrono::milliseconds, std::string> wg_http_ping(
    ::aether::core::wg_live::LiveSession session,
    const aether::core::aethernoize::AetherNoizeConfig& noise, const Settings& settings,
    const Identity& identity, std::chrono::milliseconds timeout, const Cancel& cancel);

class Hop;
class TunnelObserver;

// verify_endpoint_keep_session with the engine's own seams, defined with the tunnel runtime
// below; the hunts need it first for the ironclad arm.
[[nodiscard]] std::expected<::aether::core::wg_live::LiveSession, std::string>
wg_verify_keep_session(const Identity& identity, const SocketAddr& peer,
                       const ::aether::core::aethernoize::AetherNoizeConfig& noise,
                       std::chrono::milliseconds timeout, std::uint16_t keepalive,
                       const Settings& settings, const Cancel& cancel);

// Shared WireGuard seams + establish_masque's Hop, both defined below and needed by the
// ironclad pings before their definitions.
[[nodiscard]] ::aether::core::wg_live::RunEnv wg_run_env(const Settings& settings,
                                                        const Cancel& cancel);
[[nodiscard]] std::expected<cf::StartupVerdict, std::string> start_masque_hop(
    Hop& hop, const cf::MasqueHopParams& params, const Settings& settings,
    const Identity& identity, const rt::RuleSet& routes, TunnelObserver& observer,
    const Cancel& cancel);

// hunt_masque_peer (lib.rs:1253) and prober.rs::hunt_best_gateway (:266): the candidate list, the
// bounded-concurrency probe stream, and the budget/quiet-after-first/target state machine. Each probe
// is quic.rs::verify_masque on its own session, which is what verify_one's non-ironclad, non-h2 arm
// runs (prober.rs:440-459).
void hunt_masque(const ExecContext& ctx, const FlowRequest& request, FlowReply& reply) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;

    const pr::ScanMode mode = pr::scan_mode_parse(request.mode_str);
    pr::Strategy st = pr::scan_strategy(mode);
    st.concurrency = sysprofile::cap_concurrency(settings, st.concurrency);

    // prober.rs:271-279: a v6 scan on a host without a v6 route falls back, or stops.
    const pr::EffectiveIp effective = pr::effective_ip(request.ip, host_has_ipv6());
    if (!effective.log.empty()) emit(Level::Warn, effective.log);
    if (!effective.ok) {
        reply.ok = false;
        reply.error = Error::no_clean_endpoint();
        return;
    }

    // lib.rs:1262-1273's MasqueProbe: the identity's certificate and key (lengths only, never text),
    // the session's ECH key (:1268 tls::session_ech()), the noize config and the MASQUE port list.
    Notes notes;
    const cf::MasqueProbeParams probe =
        cf::masque_probe_for(settings, ctx.primary, ech_for(request, ctx), effective.ip, notes);
    emit_all(notes);

    const pr::Random random = pr::default_random();
    const std::vector<pr::Candidate> candidates = pr::build_candidates(
        st, probe.ports, effective.ip, pr::zero_trust_mode(settings), random);

    emit(Level::Info, pr::scan_line(pr::scan_mode_label(mode), effective.ip, candidates.size(),
                                    probe.ports, st.concurrency, st.per_probe_timeout,
                                    st.overall_deadline));

    const auto start = std::chrono::steady_clock::now();
    pr::MasqueHunt hunt(st, start);
    HuntShared shared;
    // verify_one's carrier arm (prober.rs:414-459): the H2 check on the HTTP/2 carrier, the QUIC
    // check otherwise -- never an H3 fallback for --h2, which would be invisible to it.
    const bool h2 = carrier_h2::enabled(settings);

    // The probe stream: verify_one's body for one candidate. prober.rs:295-300 builds every probe
    // future up front and pulls `concurrency` of them at a time through buffer_unordered; the same
    // budget of workers takes candidates off a shared cursor.
    auto worker = [&] {
        ++shared.live;
        struct Decrement {
            HuntShared& shared;
            ~Decrement() { --shared.live; }
        } decrement{shared};
        for (;;) {
            if (cancel.is_cancelled()) return;
            std::size_t index = 0;
            {
                const std::lock_guard<std::mutex> lock(shared.mutex);
                if (shared.stop || shared.next >= candidates.size()) return;
                index = shared.next++;
            }
            const pr::Candidate& candidate = candidates[index];
            const SocketAddr peer{candidate.first, candidate.second};

            // verify_one's ironclad arm (prober.rs:385-411): the whole candidate proves itself
            // through a throwaway tunnel and a real HTTP round trip, on either carrier.
            if (mode == pr::ScanMode::Ironclad) {
                MasquePing ping;
                ping.peer = peer;
                ping.sni = probe.sni;
                ping.authority = probe.authority;
                ping.path = probe.path;
                ping.cert_pem.assign(probe.cert_pem.begin(), probe.cert_pem.end());
                ping.key_pem.assign(probe.key_pem.begin(), probe.key_pem.end());
                ping.ech = probe.ech_config_list;
                ping.noize = probe.noise;
                ping.local_ipv4 = probe.local_ipv4;
                auto proven = masque_http_ping(ping, settings, ctx.primary,
                                               pr::IRONCLAD_TCPING_TIMEOUT, cancel);
                if (!proven.has_value()) continue; // a log::trace!, under the filter
                const pr::ProbeResult result{candidate.first, candidate.second, *proven};
                emit(Level::Info, pr::ironclad_verified_line(result));
                const std::lock_guard<std::mutex> lock(shared.mutex);
                if (shared.stop) return;
                const pr::HuntStep step = hunt.on_result(result, std::chrono::steady_clock::now());
                emit_hunt_logs(step.logs);
                if (step.done || step.early_exit) shared.stop = true;
                continue;
            }

            // prober.rs:440-451: the probe's own params, cloned off the probe but for this peer
            // and the strategy's per-probe budget. noize_config() is NOT re-read here -- the Rust
            // clones probe.noize, so the profile line stays a single one per scan. The H2 arm
            // (prober.rs:414-438) dials the candidate as-is, quiet and pinned.
            CheckOutcome check;
            if (h2) {
                carrier_h2::H2TunnelConfig h2cfg;
                h2cfg.peer = peer;
                h2cfg.sni = probe.sni;
                h2cfg.authority = probe.authority;
                h2cfg.path = probe.path;
                h2cfg.cert_pem.assign(probe.cert_pem.begin(), probe.cert_pem.end());
                h2cfg.key_pem.assign(probe.key_pem.begin(), probe.key_pem.end());
                h2cfg.local_ipv4 = probe.local_ipv4;
                h2cfg.quiet = true;
                h2cfg.pin_endpoint = true;
                h2cfg.expected_pins = carrier_h2::default_expected_pins();
                h2cfg.ech_config_list = probe.ech_config_list;
                check = verify_h2(settings, h2cfg, st.per_probe_timeout, cancel);
            } else {
                quic::VerifyParams params;
                params.peer = peer;
                params.sni = probe.sni;
                params.authority = probe.authority;
                params.path = probe.path;
                params.cert_pem.assign(probe.cert_pem.begin(), probe.cert_pem.end());
                params.key_pem.assign(probe.key_pem.begin(), probe.key_pem.end());
                params.ech_config_list = probe.ech_config_list;
                params.noize = probe.noise;
                params.timeout = st.per_probe_timeout;
                params.local_ipv4 = probe.local_ipv4;
                check = verify_quic(settings, params, cancel);
            }
            if (!check.ok) continue; // prober.rs:434/456 is a log::trace!, under the filter

            const pr::ProbeResult result{candidate.first, candidate.second, check.rtt};
            const std::lock_guard<std::mutex> lock(shared.mutex);
            if (shared.stop) return;
            const pr::HuntStep step = hunt.on_result(result, std::chrono::steady_clock::now());
            emit_hunt_logs(step.logs);
            if (step.done || step.early_exit) shared.stop = true;
        }
    };

    const std::size_t threads =
        std::min<std::size_t>(st.concurrency == 0 ? 1 : st.concurrency, candidates.size());
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (std::size_t index = 0; index < threads; ++index) pool.emplace_back(worker);

    // The select loop's other arm: tokio::time::sleep(remaining) on min(quiet_until, deadline).
    bool finished = false;
    while (!cancel.is_cancelled()) {
        bool stop = false;
        {
            const std::lock_guard<std::mutex> lock(shared.mutex);
            stop = shared.stop || hunt.done();
        }
        if (stop) break;
        // The stream ran dry: every worker has taken its last candidate.
        if (shared.live.load() == 0) break;

        const auto now = std::chrono::steady_clock::now();
        if (now >= hunt.next_wake()) {
            const std::lock_guard<std::mutex> lock(shared.mutex);
            const pr::HuntStep step = hunt.on_timeout(now);
            emit_hunt_logs(step.logs);
            if (step.done) {
                shared.stop = true;
                finished = true;
                break;
            }
        }
        interruptible_sleep_ms(std::chrono::milliseconds(10), cancel);
    }

    if (cancel.is_cancelled()) shared.stop = true;
    for (std::thread& thread : pool) thread.join();

    // The stream running dry is Rust's `None => break` (prober.rs:330): finalise once, if the budgets
    // have not already done it.
    if (!hunt.done() && !finished) {
        const std::lock_guard<std::mutex> lock(shared.mutex);
        emit_hunt_logs(hunt.on_exhausted().logs);
    }

    if (const std::optional<pr::ProbeResult> best = hunt.result(); best.has_value()) {
        reply.ok = true;
        reply.peer = SocketAddr{best->ip, best->port};
        reply.rtt = best->rtt;
        return;
    }
    reply.ok = false;
    reply.error = Error::no_clean_endpoint();
}

// wireguard::verify_endpoint_keep_session on one throwaway socket, driven the way
// verify_quic drives a MASQUE check: open through the upstream relay table, handshake plus the
// data-plane confirmation wg_live runs inside, and answer ok/rtt. A failed check is never an
// error to the flow -- the caller only reads `ok`, like lib.rs:1299 does for MASQUE.
[[nodiscard]] CheckOutcome verify_wg(const Settings& settings, const SocketAddr& peer,
                                     const ::aether::core::aethernoize::AetherNoizeConfig& noise,
                                     std::chrono::milliseconds timeout,
                                     std::optional<std::uint16_t> keepalive,
                                     const ::aether::core::Identity& identity,
                                     const Cancel& cancel) {
    namespace wgl = ::aether::core::wg_live;
    namespace tr = ::aether::core::transport;
    namespace up = ::aether::core::upstream;
    CheckOutcome outcome;
    const auto local = aether::core::parse_address(identity.ipv4);
    if (!local.has_value() || !local->v4) {
        outcome.error = "other: invalid ipv4";
        return outcome;
    }
    wgl::VerifyParams params;
    params.peer = peer;
    params.private_key = identity.wg_private_key;
    params.peer_public = identity.wg_peer_public_key;
    params.client_id = identity.client_id;
    params.local_ipv4 = *local;
    params.noise = noise;
    params.timeout = timeout.count() > 0 ? timeout : std::chrono::milliseconds(10000);
    params.keepalive = keepalive;
    params.settings = &settings;

    wgl::VerifyEnv env;
    env.now = wgl::monotonic_clock();
    env.sleep = wgl::thread_sleep();
    // UdpIo::receive is non-blocking, so the wait is the sleep arm: rest the slice out, then
    // let drive_verify attempt the recv. Cancel cuts the sleep short.
    env.wait = [&cancel](std::chrono::milliseconds d) {
        interruptible_sleep_ms(d, cancel);
        return !cancel.is_cancelled();
    };
    env.random = wgl::boringssl_random();
    env.note = [](wgl::Level, std::string_view) {}; // trace!/debug! only, under the filter

    wgl::OpenSeams seams_open;
    seams_open.settings = &settings;
    seams_open.make_io = [&settings](const SocketAddr& p, const Settings& s)
        -> std::expected<std::unique_ptr<tr::UdpIo>, std::string> {
        auto io = tr::WinUdp::open_for_peer(p, s);
        if (!io.has_value()) return std::unexpected(io.error());
        return std::move(*io);
    };
    seams_open.relay = [](const SocketAddr& local_addr, const SocketAddr& intended) {
        return up::relay_target(local_addr, intended);
    };
    seams_open.connect = [](tr::UdpIo& io, const SocketAddr& target) -> std::expected<void, std::string> {
        if (auto* udp = dynamic_cast<tr::WinUdp*>(&io)) return udp->connect_to(target);
        return {};
    };

    const auto start = std::chrono::steady_clock::now();
    wgl::VerifyJob job{params, env, seams_open};
    auto result = wgl::verify_endpoint_keep_session(std::move(job), cancel);
    if (!result.has_value()) {
        outcome.error = "other: " + result.error().display();
        return outcome;
    }
    outcome.ok = true;
    outcome.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return outcome;
}

// hunt_wg_peer (lib.rs:2188 + wg_prober.rs::hunt_wg_endpoints): the candidate list, the
// bounded-concurrency probe stream, and the budget/quiet-after-first/target state machine. Each
// probe is verify_one_wg's non-ironclad arm -- verify_endpoint_keep_session on its own socket.
void hunt_wg(const ExecContext& ctx, const FlowRequest& request, FlowReply& reply,
             const ::aether::core::aethernoize::AetherNoizeConfig& noise, std::size_t want) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;

    const pr::WgScanMode mode = pr::wg_scan_mode_parse(request.mode_str);
    pr::WgStrategy st = pr::wg_scan_strategy(mode);
    st.concurrency = sysprofile::cap_concurrency(settings, st.concurrency);

    const pr::EffectiveIp effective = pr::effective_ip(request.ip, host_has_ipv6());
    if (!effective.log.empty()) emit(Level::Warn, effective.log);
    if (!effective.ok) {
        reply.ok = false;
        reply.error = Error::no_clean_endpoint();
        return;
    }

    // wg_prober.rs::build_wg_candidates sources: anchors + sampled pool. Zero-trust runs prefer
    // the zt prefixes, the way the MASQUE scan prefers its own zt CIDRs.
    const bool zt = pr::zero_trust_mode(settings);
    pr::WgCandidateSources sources;
    sources.anchors_v4.assign(std::begin(aether::core::wireguard::wg_seeds_v4),
                              std::end(aether::core::wireguard::wg_seeds_v4));
    sources.anchors_v6.assign(std::begin(aether::core::wireguard::wg_seeds_v6),
                              std::end(aether::core::wireguard::wg_seeds_v6));
    if (zt) {
        sources.prefixes_v4.assign(std::begin(aether::core::wireguard::wg_zt_prefixes_v4),
                                   std::end(aether::core::wireguard::wg_zt_prefixes_v4));
        sources.prefixes_v6.assign(std::begin(aether::core::wireguard::wg_zt_prefixes_v6),
                                   std::end(aether::core::wireguard::wg_zt_prefixes_v6));
    } else {
        sources.prefixes_v4.assign(std::begin(aether::core::wireguard::wg_prefixes_v4),
                                   std::end(aether::core::wireguard::wg_prefixes_v4));
        sources.prefixes_v6.assign(std::begin(aether::core::wireguard::wg_prefixes_v6),
                                   std::end(aether::core::wireguard::wg_prefixes_v6));
    }
    sources.embed_v4.assign(std::begin(aether::core::wireguard::wg_prefixes_v4),
                            std::end(aether::core::wireguard::wg_prefixes_v4));

    std::vector<std::uint16_t> ports(std::begin(aether::core::wireguard::wg_ports),
                                     std::end(aether::core::wireguard::wg_ports));
    std::vector<pr::Candidate> excluded;
    excluded.reserve(request.excluded.size());
    for (const SocketAddr& peer : request.excluded) excluded.emplace_back(peer.ip, peer.port);

    const pr::Random random = pr::default_random();
    const std::vector<pr::Candidate> candidates =
        pr::build_wg_candidates(st, ports, effective.ip, excluded, sources, random);

    emit(Level::Info, pr::wg_scan_line(pr::wg_scan_mode_label(mode), effective.ip, candidates.size(),
                                       ports, st.concurrency, st.per_probe_timeout,
                                       st.overall_deadline));

    const auto start = std::chrono::steady_clock::now();
    pr::WgHunt hunt(st, want == 0 ? 1 : want, start);
    HuntShared shared;

    auto worker = [&] {
        ++shared.live;
        struct Decrement {
            HuntShared& shared;
            ~Decrement() { --shared.live; }
        } decrement{shared};
        for (;;) {
            if (cancel.is_cancelled()) return;
            std::size_t index = 0;
            {
                const std::lock_guard<std::mutex> lock(shared.mutex);
                if (shared.stop || shared.next >= candidates.size()) return;
                index = shared.next++;
            }
            const pr::Candidate& candidate = candidates[index];
            const SocketAddr peer{candidate.first, candidate.second};

            // verify_one_wg's ironclad arm (wg_prober.rs:282-338): the handshake first, then the
            // real HTTP round trip through the verified session. The rtt the hunt ranks by is
            // the HTTP one.
            if (mode == pr::WgScanMode::Ironclad) {
                auto kept = wg_verify_keep_session(
                    ctx.primary, peer, noise, st.per_probe_timeout,
                    aether::core::wireguard::default_persistent_keepalive, settings, cancel);
                if (!kept.has_value()) continue; // a log::trace!, under the filter
                auto proven = wg_http_ping(std::move(*kept), noise, settings, ctx.primary,
                                           pr::WG_IRONCLAD_TCPING_TIMEOUT, cancel);
                if (!proven.has_value()) continue;
                const pr::WgProbeResult result{candidate.first, candidate.second, *proven};
                emit(Level::Info, pr::wg_ironclad_verified_line(result));
                const std::lock_guard<std::mutex> lock(shared.mutex);
                if (shared.stop) return;
                const pr::WgHuntStep step = hunt.on_result(result, std::chrono::steady_clock::now());
                emit_hunt_logs(step.logs);
                if (step.done || step.early_exit) shared.stop = true;
                continue;
            }

            const CheckOutcome check =
                verify_wg(settings, peer, noise, st.per_probe_timeout,
                          std::nullopt, ctx.primary, cancel);
            if (!check.ok) continue; // wg_prober.rs:305 is a log::trace!, under the filter

            const pr::WgProbeResult result{candidate.first, candidate.second, check.rtt};
            const std::lock_guard<std::mutex> lock(shared.mutex);
            if (shared.stop) return;
            const pr::WgHuntStep step = hunt.on_result(result, std::chrono::steady_clock::now());
            emit_hunt_logs(step.logs);
            if (step.done || step.early_exit) shared.stop = true;
        }
    };

    const std::size_t threads =
        std::min<std::size_t>(st.concurrency == 0 ? 1 : st.concurrency, candidates.size());
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (std::size_t index = 0; index < threads; ++index) pool.emplace_back(worker);

    bool finished = false;
    while (!cancel.is_cancelled()) {
        bool stop = false;
        {
            const std::lock_guard<std::mutex> lock(shared.mutex);
            stop = shared.stop || hunt.done();
        }
        if (stop) break;
        if (shared.live.load() == 0) break;

        const auto now = std::chrono::steady_clock::now();
        if (now >= hunt.next_wake()) {
            const std::lock_guard<std::mutex> lock(shared.mutex);
            const pr::WgHuntStep step = hunt.on_timeout(now);
            emit_hunt_logs(step.logs);
            if (step.done) {
                shared.stop = true;
                finished = true;
                break;
            }
        }
        interruptible_sleep_ms(std::chrono::milliseconds(10), cancel);
    }

    if (cancel.is_cancelled()) shared.stop = true;
    for (std::thread& thread : pool) thread.join();

    if (!hunt.done() && !finished) {
        const std::lock_guard<std::mutex> lock(shared.mutex);
        emit_hunt_logs(hunt.on_exhausted().logs);
    }

    const std::vector<pr::WgProbeResult> picked = hunt.result();
    if (picked.empty()) {
        reply.ok = false;
        reply.error = Error::no_clean_endpoint();
        return;
    }
    reply.ok = true;
    reply.peer = SocketAddr{picked.front().ip, picked.front().port};
    reply.rtt = picked.front().rtt;
    reply.profile = noise;
    reply.results.assign(picked.begin(), picked.end());
    reply.peers.clear();
    for (const auto& pr : picked) reply.peers.push_back(SocketAddr{pr.ip, pr.port});
}

// ---- the tunnel runtime -----------------------------------------------------------------------

// Everything run_tunnel composes lives here. The rule for the whole section is the rule the rest of
// the tree follows: nothing below re-decides a protocol question. transport.cpp, masque_h2_runtime
// .cpp, wg_live.cpp and netstack.cpp are the port's carriers and packet engine; the proxy
// listeners below are this file's own. This section only supplies what tokio gave them -- threads, one mutex around the
// stack the Rust held in an Arc, the channel pairs Rust's mpsc::channel calls built, and the socket
// the pump owns.
namespace eg = aether::core::egress;
namespace wgl = aether::core::wg_live;
namespace xloc = aether::core::exitloc;

// The queue between the packet engine and a carrier: netstack's flush_tx writes its end and the
// carrier's outbound_rx reads the other. The Rust's `mpsc::channel(sysprofile::channel_capacity())`.
class StackQueue {
public:
    explicit StackQueue(std::size_t capacity) {
        auto pair = ns::Channel<std::vector<std::uint8_t>>::bounded(capacity == 0 ? 1 : capacity);
        tx_ = std::move(pair.first);
        rx_ = std::move(pair.second);
    }

    // flush_tx's try_send: nothing blocks, a full queue is the Rust's Full (the packet is dropped and
    // counted by the stack, never by this queue).
    [[nodiscard]] ns::SendOutcome push(std::span<const std::uint8_t> packet) {
        return tx_.try_send(std::vector<std::uint8_t>(packet.begin(), packet.end()));
    }
    // outbound_rx.recv() at a carrier's pace: nothing when the queue is empty.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> pull() { return rx_.recv(); }
    // Rust's `while let Some(p) = rx.recv()` ending: every sender dropped and the queue drained.
    [[nodiscard]] bool ended() const { return rx_.at_end(); }
    // The send task's end, which is what makes `ended()` answer for the reader's side.
    void close() { tx_ = ns::Sender<std::vector<std::uint8_t>>{}; }

private:
    ns::Sender<std::vector<std::uint8_t>> tx_;
    ns::Receiver<std::vector<std::uint8_t>> rx_;
};

class Hop;

// netstack's PacketSink for a stream carrier: flush_tx's outbound channel. It takes NO lock
// itself: its only caller is NetStack::tick, which always runs as tick_stack below with the hop
// mutex already held -- taking it again would be a recursive lock of a non-recursive mutex,
// which is what killed the first packet of every working tunnel (the forwarder's, first).
// The carrier side reads through WgOutbound/H2Outbound, which lock normally; pump and carrier
// stay apart through the one mutex, just never twice on one turn.
class QueueSink final : public ns::PacketSink {
public:
    explicit QueueSink(Hop& hop) : hop_(hop) {}
    ns::SendOutcome try_send(std::span<const std::uint8_t> packet) override;

private:
    Hop& hop_;
};

// quic.rs's inbound_tx / addr_tx for one hop, both through the hop's mutex.
class LockedInbound final : public tr::InboundSink {
public:
    explicit LockedInbound(Hop& hop) : hop_(hop) {}
    tr::Room try_send(std::span<const std::uint8_t> ip_packet) override;

private:
    Hop& hop_;
};

class LockedAssigned final : public tr::AddressSink {
public:
    explicit LockedAssigned(Hop& hop) : hop_(hop) {}
    tr::Room try_send(const quic::AssignedAddr& assigned) override;

private:
    Hop& hop_;
};

// masque_h2.rs's ctrl_rx, and the same queue wg_live and transport are driven from.
class ControlQueue final : public carrier_h2::ControlQueue {
public:
    void push(quic::Control control) {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (gone_) return;
        queue_.push_back(control);
    }
    void shutdown() {
        const std::lock_guard<std::mutex> lock(mutex_);
        gone_ = true;
        queue_.clear();
    }
    [[nodiscard]] std::optional<quic::Control> try_recv() override {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        const quic::Control front = queue_.front();
        queue_.pop_front();
        return front;
    }
    [[nodiscard]] bool gone() const override {
        const std::lock_guard<std::mutex> lock(mutex_);
        return gone_ && queue_.empty();
    }

private:
    mutable std::mutex mutex_;
    std::deque<quic::Control> queue_;
    bool gone_ = false;
};

// One hop: the packet engine, the two data-plane queues, the carrier's threads and the answers the
// reconnect loop reads (ready, finished, error). Rust builds exactly this shape inside
// establish_masque -- netstack::spawn + quic::channels() + the addr bridge task + the ready oneshot
// + the tunnel task -- and hands it back as MasqueHop { stack, exit, _ctrl, _guard }.
class Hop {
public:
    Hop(const Settings& settings, std::size_t mtu)
        : queue_(sysprofile::channel_capacity(settings)),
          sink_(*this),
          inbound_(*this),
          assigned_(*this),
          mtu_(mtu) {}

    Hop(const Hop&) = delete;
    Hop& operator=(const Hop&) = delete;

    // netstack::spawn, with the sink and the two channels wired. `identity` names the addresses the
    // stack starts with (Rust's &identity.ipv4 / &identity.ipv6); the edge may reassign them later
    // through the capsule bridge.
    [[nodiscard]] std::expected<void, std::string> open(const Settings& settings,
                                                        const Identity& identity,
                                                        const rt::RuleSet& routes) {
        ns::NetStack::Config config = ns::NetStack::Config::from_settings(
            settings, identity.ipv4, identity.ipv6, mtu_);
        config.outbound = &sink_;
        config.routes = &routes;
        auto spawned = ns::NetStack::spawn(config, std::chrono::steady_clock::now());
        if (!spawned.has_value()) return std::unexpected(spawned.error());
        stack_ = std::move(*spawned);
        return {};
    }

    ~Hop() {
        stop_.set();
        control_.shutdown();
        join_carriers();
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            queue_.close();
        }
    }

    // ---- the pump thread's side -------------------------------------------------------------

    // The stack's lock. Every call into the stack, its app-side handles and StackQueue takes it,
    // because netstack.hpp's channels are unsynchronised deques and the Rust's are mpsc.
    std::mutex& mutex() { return mutex_; }
    ns::NetStack* stack() { return stack_.get(); }
    StackQueue& queue() { return queue_; }

    // One turn of the Rust's netstack run loop.
    void tick_stack() {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!stack_) return;
        last_tick_ = stack_->tick(std::chrono::steady_clock::now()).delay.value_or(
            std::chrono::milliseconds(20));
    }
    [[nodiscard]] std::chrono::milliseconds last_tick_delay() const { return last_tick_; }

    tr::InboundSink* inbound_sink() { return &inbound_; }
    tr::AddressSink* address_sink() { return &assigned_; }
    carrier_h2::ControlQueue* h2_control() { return &control_; }
    void control(quic::Control c) { control_.push(c); }

    // ---- the run's answers --------------------------------------------------------------------

    void set_ready() {
        const std::lock_guard<std::mutex> lock(ready_mutex_);
        if (ready_) return;
        ready_ = true;
        ready_cv_.notify_all();
    }
    [[nodiscard]] bool ready() const {
        const std::lock_guard<std::mutex> lock(ready_mutex_);
        return ready_;
    }
    // establish_masque's ready_rx: Ok(()) on the signal, the tunnel task's own answer otherwise.
    // `startup` is the Rust's tokio::time::timeout budget; the verdict is coreflow's enum, so the
    // flow's error line is the Rust's wording.
    [[nodiscard]] cf::StartupVerdict wait_ready(std::chrono::seconds startup, const Cancel& cancel) {
        const auto deadline = std::chrono::steady_clock::now() + startup;
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(ready_mutex_);
                ready_cv_.wait_for(lock, std::chrono::milliseconds(50), [this] {
                    return ready_ || finished_;
                });
                if (ready_) return cf::StartupVerdict::Ready;
                if (finished_) {
                    ready_ = false;
                    return error_.has_value() ? cf::StartupVerdict::FailedBeforeValidation
                                              : cf::StartupVerdict::ExitedBeforeValidation;
                }
            }
            if (cancel.is_cancelled()) return cf::StartupVerdict::TimedOut;
            if (std::chrono::steady_clock::now() >= deadline) return cf::StartupVerdict::TimedOut;
        }
    }

    // The tunnel task's return: Ok(()) is nothing, Err(e) the text. First answer wins, as Rust's
    // select is first-past.
    void finish(std::optional<std::string> error) {
        const std::lock_guard<std::mutex> lock(ready_mutex_);
        if (finished_) return;
        finished_ = true;
        error_ = std::move(error);
        ready_cv_.notify_all();
    }
    [[nodiscard]] bool finished() const {
        const std::lock_guard<std::mutex> lock(ready_mutex_);
        return finished_;
    }
    [[nodiscard]] std::optional<std::string> error() const {
        const std::lock_guard<std::mutex> lock(ready_mutex_);
        return error_;
    }

    // Rust's TaskGuard: the run's stop flag every thread on this hop races against, and the joins the
    // guard's drop stands for.
    eg::Stop& stop() { return stop_; }
    void add_thread(std::thread thread) { threads_.push_back(std::move(thread)); }
    void join_carriers() {
        for (std::thread& thread : threads_) {
            if (thread.joinable()) thread.join();
        }
        threads_.clear();
    }

private:
    StackQueue queue_;
    QueueSink sink_;
    LockedInbound inbound_;
    LockedAssigned assigned_;
    ControlQueue control_;
    std::unique_ptr<ns::NetStack> stack_;
    std::mutex mutex_;
    std::chrono::milliseconds last_tick_{2000};
    const std::size_t mtu_;
    mutable std::mutex ready_mutex_;
    std::condition_variable ready_cv_;
    bool ready_ = false;
    bool finished_ = false;
    std::optional<std::string> error_;
    eg::Stop stop_;
    std::vector<std::thread> threads_;
};

ns::SendOutcome QueueSink::try_send(std::span<const std::uint8_t> packet) {
    // Called from NetStack::tick with hop_.mutex() already held by tick_stack; see the class.
    return hop_.queue().push(packet);
}

tr::Room LockedInbound::try_send(std::span<const std::uint8_t> ip_packet) {
    const std::lock_guard<std::mutex> lock(hop_.mutex());
    if (ns::NetStack* stack = hop_.stack(); stack != nullptr) {
        stack->submit_inbound(std::vector<std::uint8_t>(ip_packet.begin(), ip_packet.end()));
    }
    return tr::Room::Accepted;
}

tr::Room LockedAssigned::try_send(const quic::AssignedAddr& assigned) {
    const std::lock_guard<std::mutex> lock(hop_.mutex());
    ns::NetStack* stack = hop_.stack();
    if (stack == nullptr) return tr::Room::Closed;
    const netpacket::TunnelAddr address{assigned.ip, assigned.prefix};
    if (assigned.ip.v4) stack->set_addrs(address, std::nullopt);
    else stack->set_addrs(std::nullopt, address);
    return tr::Room::Accepted;
}

// The H2 carrier's outbound_rx (masque_h2.rs:392): the queue's reader, `gone` the sender's drop.
class H2Outbound final : public carrier_h2::OutboundSource {
public:
    explicit H2Outbound(Hop& hop) : hop_(hop) {}
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> try_recv() override {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        return hop_.queue().pull();
    }
    [[nodiscard]] bool gone() const override {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        return hop_.queue().ended();
    }

private:
    Hop& hop_;
};

// The WireGuard carrier's outbound_rx (wireguard.rs:235): the same queue, read with a budget the
// loop hands in. The wait is answered by polling the queue outside the lock never, inside it always:
// a blocking hold here would stall the pump thread that fills it.
class WgOutbound final : public wgl::OutboundSource {
public:
    explicit WgOutbound(Hop& hop) : hop_(hop) {}
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> try_recv(
        std::chrono::milliseconds budget) override {
        const auto finish = std::chrono::steady_clock::now() + budget;
        for (;;) {
            {
                const std::lock_guard<std::mutex> lock(hop_.mutex());
                if (std::optional<std::vector<std::uint8_t>> packet = hop_.queue().pull()) {
                    return packet;
                }
            }
            if (hop_.stop().asked()) return std::nullopt;
            if (budget.count() <= 0 || std::chrono::steady_clock::now() >= finish) {
                return std::nullopt;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    [[nodiscard]] bool closed() const override {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        return hop_.queue().ended();
    }

private:
    Hop& hop_;
};

// Every thread of the Rust's netstack run loop is one pump here: the stack ticked on its own thread
// while the carrier runs on another, exactly as smoltcp's run() task and the quic::run task sit
// beside each other in tokio.
void pump_hop(Hop& hop, const Cancel& cancel) {
    while (!hop.stop().asked() && !hop.finished() && !cancel.is_cancelled()) {
        hop.tick_stack();
        interruptible_sleep_ms(hop.last_tick_delay(), cancel);
    }
}

// ---- the QUIC carrier (quic.rs::run on transport::Session) ------------------------------------

// One tunnel's session, driven the way verify_quic drives a check, but for the whole run: the same
// tick order, the same relay table, and the two extra turns the tunnel has -- the ready signal that
// lets socks5 be exposed, and the control queue that closes it.
void run_quic_hop(Hop& hop, quic::TunnelConfig tunnel, const Settings& settings,
                  const Cancel& cancel, TunnelObserver& observer) {
    auto io = tr::WinUdp::open_for_peer(tunnel.peer, settings);
    if (!io.has_value()) {
        hop.finish("io: " + io.error());
        return;
    }
    // upstream.rs:618, as in verify_quic above. The guard lives beside the socket for the whole
    // run; dropping it would forget the detour and send the tunnel direct mid-run.
    auto detour = attach_upstream(settings, (*io)->local(), tunnel.peer);
    if (!detour.has_value()) {
        hop.finish("io: " + detour.error());
        return;
    }
    tr::Session::Seams seams;
    seams.io = io->get();
    seams.relay = [](const SocketAddr& local, const SocketAddr& intended) {
        return up::relay_target(local, intended);
    };
    seams.inbound = hop.inbound_sink();
    seams.assigned = hop.address_sink();
    seams.observer = &observer;
    seams.make_io = [&settings](const SocketAddr& bind) {
        return tr::WinUdp::open(bind, settings);
    };

    const auto start = std::chrono::steady_clock::now();
    auto opened = tr::Session::open(tr::Session::Setup::for_tunnel(tunnel), settings,
                                   std::move(seams), start);
    if (!opened.has_value()) {
        hop.finish("other: " + opened.error());
        return;
    }
    tr::Session& session = **opened;

    bool closing = false;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (cancel.is_cancelled()) break;
        if (hop.stop().asked() && !closing) {
            // quic.rs's ctrl_rx arm: the run's answer to a stop is the "bye" application close, and
            // the flush that puts it on the wire happens on the turns after it.
            session.control(quic::Control::Close);
            closing = true;
        }
        const auto tick = session.tick(now);
        if (tick.error.has_value()) {
            hop.finish(*tick.error);
            break;
        }
        if (tick.closed) {
            hop.finish(session.error()); // Nothing is Ok(()) -- the close is the Rust's Ok(()).
            break;
        }
        if (session.ready() && !hop.ready()) hop.set_ready();
        interruptible_sleep_ms(tick.delay.value_or(std::chrono::milliseconds(20)), cancel);
        if (closing) break; // one turn after the close went out is all the flush needs
    }
    if (!hop.finished()) hop.finish(std::nullopt);
    hop.stop().set();
}

// ---- the HTTP/2 carrier (masque_h2.rs::run on masque_h2::run_with) -----------------------------

void run_h2_hop(Hop& hop, const carrier_h2::H2TunnelConfig cfg, const Settings& settings,
               const Cancel& cancel, carrier_h2::OutboundSource& outbound,
               tr::Observer& observer) {
    // masque_h2.rs::dial, as in verify_h2 above. The observer carries the announce lines.
    const carrier_h2::DialSocket dial = [&settings, &observer](const SocketAddr& peer) {
        return carrier_h2::dial(peer, settings, std::nullopt, &observer);
    };
    carrier_h2::TunnelSeams seams;
    seams.inbound = hop.inbound_sink();
    seams.assigned = hop.address_sink();
    seams.observer = &observer;
    seams.outbound = &outbound;
    seams.control = hop.h2_control();
    seams.ready = [&hop] { hop.set_ready(); };

    auto result = carrier_h2::run_with(cfg, settings, dial, seams);
    if (result.has_value()) hop.finish(std::nullopt);
    else hop.finish(result.error());
    hop.stop().set();
    (void)cancel;
}

// ---- the proxy listeners ----------------------------------------------------------------------

// socks.rs's bind_listener: bind the address exactly as it is given, listen with tokio's backlog,
// and accept in a loop. Rust's accept is awaited inside a select beside the run's stop, so the wait
// here is sliced and each slice re-reads the stop -- the only difference the port needs, and one that
// changes no decision.
class AcceptListener {
public:
    ~AcceptListener() {
        if (handle_ != INVALID_SOCKET) closesocket(handle_);
    }
    AcceptListener(const AcceptListener&) = delete;
    AcceptListener& operator=(const AcceptListener&) = delete;

    [[nodiscard]] static std::expected<std::unique_ptr<AcceptListener>, std::string>
    bind(std::string_view kind, const SocketAddr& listen) {
        auto self = std::unique_ptr<AcceptListener>(new AcceptListener());
        const int family = listen.ip.v4 ? AF_INET : AF_INET6;
        self->handle_ = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (self->handle_ == INVALID_SOCKET) {
            return std::unexpected(std::string(kind) + ": socket failed (" +
                                   std::to_string(WSAGetLastError()) + ")");
        }
        sockaddr_storage storage{};
        const int length = fill_address(listen, storage);
        if (::bind(self->handle_, reinterpret_cast<const sockaddr*>(&storage), length) != 0 ||
            ::listen(self->handle_, 128) != 0) {
            const int failed = WSAGetLastError();
            return std::unexpected(std::string(kind) + " could not bind " + listen.to_string() +
                                   " (" + std::to_string(failed) + ")");
        }
        self->local_ = listen;
        return self;
    }

    [[nodiscard]] const SocketAddr& local() const { return local_; }

    // accept(), or nothing when the stop was asked or the slice ran out. An accept error is the
    // Rust's `Err(e) => accept_backoff`: the caller pauses by the code and keeps going until the
    // backoff says the listener cannot.
    std::expected<std::optional<SOCKET>, int> accept(eg::Stop& stop) {
        fd_set read;
        FD_ZERO(&read);
        FD_SET(handle_, &read);
        timeval slice{};
        slice.tv_usec = 50'000;
        const int ready = ::select(0, &read, nullptr, nullptr, &slice);
        if (ready == 0) return std::optional<SOCKET>{}; // nothing yet, or the stop was asked
        if (ready == SOCKET_ERROR) return WSAGetLastError();
        sockaddr_storage peer{};
        int length = sizeof peer;
        const SOCKET client = ::accept(handle_, reinterpret_cast<sockaddr*>(&peer), &length);
        if (client == INVALID_SOCKET) return WSAGetLastError();
        u_long blocking = 1;
        ::ioctlsocket(client, FIONBIO, &blocking);
        return std::optional<SOCKET>{client};
    }

private:
    AcceptListener() = default;

    SOCKET handle_ = INVALID_SOCKET;
    SocketAddr local_{};
};

// The hop's app-side handles, wrapped in the one lock the stack and its channels live behind.
class StackTcp final : public eg::ByteStream {
public:
    StackTcp(Hop& hop, ns::TcpSender sender, ns::Receiver<std::vector<std::uint8_t>> from_stack)
        : hop_(hop), sender_(std::move(sender)), from_stack_(std::move(from_stack)) {}

    [[nodiscard]] eg::ReadAttempt read(std::uint8_t* out, std::size_t len, eg::Millis wait,
                                       eg::Stop& stop) override {
        const auto finish = std::chrono::steady_clock::now() + wait;
        for (;;) {
            {
                const std::lock_guard<std::mutex> lock(hop_.mutex());
                if (std::optional<std::vector<std::uint8_t>> chunk = from_stack_.recv()) {
                    if (chunk->empty()) return eg::ReadAttempt{eg::ReadAttempt::Kind::Bytes, 0, {}};
                    const std::size_t taken = std::min(len, chunk->size());
                    std::memcpy(out, chunk->data(), taken);
                    if (taken < chunk->size()) {
                        leftovers_.insert(leftovers_.end(), chunk->begin() +
                                                               static_cast<std::ptrdiff_t>(taken),
                                          chunk->end());
                    }
                    return eg::ReadAttempt{eg::ReadAttempt::Kind::Bytes, taken, {}};
                }
                if (!leftovers_.empty()) {
                    const std::size_t taken = std::min(len, leftovers_.size());
                    std::memcpy(out, leftovers_.data(), taken);
                    leftovers_.erase(leftovers_.begin(),
                                     leftovers_.begin() + static_cast<std::ptrdiff_t>(taken));
                    return eg::ReadAttempt{eg::ReadAttempt::Kind::Bytes, taken, {}};
                }
                if (from_stack_.at_end()) return eg::ReadAttempt{eg::ReadAttempt::Kind::End, 0, {}};
            }
            if (stop.asked()) return eg::ReadAttempt{eg::ReadAttempt::Kind::Timeout, 0, {}};
            if (wait.count() > 0 && std::chrono::steady_clock::now() >= finish) {
                return eg::ReadAttempt{eg::ReadAttempt::Kind::Timeout, 0, {}};
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    [[nodiscard]] std::expected<void, std::string> write(std::span<const std::uint8_t> bytes,
                                                         eg::Stop& stop) override {
        // TcpSender::send awaits room; here that await is the retry, and a Full is not an error.
        std::vector<std::uint8_t> payload(bytes.begin(), bytes.end());
        for (;;) {
            ns::SendOutcome outcome;
            {
                const std::lock_guard<std::mutex> lock(hop_.mutex());
                outcome = sender_.send(payload);
            }
            switch (outcome) {
                case ns::SendOutcome::Ok: return {};
                case ns::SendOutcome::Closed: return std::unexpected(std::string(eg::STOPPED));
                case ns::SendOutcome::Full: break;
            }
            if (stop.asked()) return std::unexpected(std::string(eg::STOPPED));
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    [[nodiscard]] std::expected<void, std::string> shutdown_write() override {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        sender_.close();
        return {};
    }

private:
    Hop& hop_;
    ns::TcpSender sender_;
    ns::Receiver<std::vector<std::uint8_t>> from_stack_;
    std::vector<std::uint8_t> leftovers_;
};

// The same for one UDP association inside the tunnel.
class StackUdp final {
public:
    StackUdp(Hop& hop, ns::UdpSender sender, ns::Receiver<ns::UdpInbound> from_stack)
        : hop_(hop), sender_(std::move(sender)), from_stack_(std::move(from_stack)) {}

    [[nodiscard]] bool send_to(const SocketAddr& dst, std::span<const std::uint8_t> data) {
        for (;;) {
            ns::SendOutcome outcome;
            {
                const std::lock_guard<std::mutex> lock(hop_.mutex());
                outcome = sender_.send_to(dst, std::vector<std::uint8_t>(data.begin(), data.end()));
            }
            if (outcome == ns::SendOutcome::Ok) return true;
            if (outcome == ns::SendOutcome::Closed) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // The next datagram off the stack, nothing while the queue is empty, false once the channel has
    // ended (Rust's recv() answering None).
    [[nodiscard]] std::optional<ns::UdpInbound> recv(eg::Stop& stop, eg::Millis wait) {
        const auto finish = std::chrono::steady_clock::now() + wait;
        for (;;) {
            {
                const std::lock_guard<std::mutex> lock(hop_.mutex());
                if (std::optional<ns::UdpInbound> arrived = from_stack_.recv()) return arrived;
                if (from_stack_.at_end()) return std::nullopt;
            }
            if (stop.asked()) return std::nullopt;
            if (std::chrono::steady_clock::now() >= finish) return std::nullopt;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    void close() {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        sender_.close();
    }

    // Whether the stack's half of the association is gone (Rust's recv() answering None).
    [[nodiscard]] bool ended() {
        const std::lock_guard<std::mutex> lock(hop_.mutex());
        return from_stack_.at_end();
    }

private:
    Hop& hop_;
    ns::UdpSender sender_;
    ns::Receiver<ns::UdpInbound> from_stack_;
};

// What the listeners need besides the hop: the route table the Rust keeps in its OnceLock, the two
// budgets socks.rs arms, the address the bound reply carries and the log sink.
struct ProxyOptions {
    const Settings& settings;
    const rt::RuleSet& routes;
    SocketAddr socks_listen{};
    std::optional<SocketAddr> http_listen;
};

// stack.open_tcp(dst) and the ticket, driven to its answer. Rust awaits the oneshot; here the ticket
// is filled by the pump thread's ticks, so this waits on it. `budget` is socks.rs's
// tokio::time::timeout around that await -- DIRECT_CONNECT_TIMEOUT_MS on the direct path's twin, and
// the connect timeout here.
[[nodiscard]] std::expected<std::unique_ptr<StackTcp>, std::string> stack_dial(
    Hop& hop, const SocketAddr& dst, std::optional<eg::Millis> budget) {
    ns::ConnectTicket ticket;
    {
        const std::lock_guard<std::mutex> lock(hop.mutex());
        auto opened = hop.stack()->open_tcp(dst, std::chrono::steady_clock::now());
        if (!opened.has_value()) return std::unexpected(opened.error());
        ticket = std::move(*opened);
    }
    const auto finish = std::chrono::steady_clock::now() + budget.value_or(std::chrono::milliseconds(0));
    for (;;) {
        {
            const std::lock_guard<std::mutex> lock(hop.mutex());
            if (ticket.ready()) {
                auto answer = ticket.take();
                if (!answer.has_value()) return std::unexpected("connect: no answer");
                std::expected<ns::TcpConn, std::string>& conn = *answer;
                if (!conn.has_value()) return std::unexpected(conn.error());
                auto split = std::move(*conn).into_split();
                return std::make_unique<StackTcp>(hop, std::move(split.first),
                                                  std::move(split.second));
            }
            if (ticket.abandoned()) return std::unexpected("connect: abandoned");
        }
        if (hop.stop().asked()) return std::unexpected(std::string(eg::STOPPED));
        if (budget.has_value() && std::chrono::steady_clock::now() >= finish) {
            return std::unexpected(std::string(eg::TIMED_OUT) + "connect timed out");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

// ---- the client bodies (socks.rs's handshake, relay and udp associate) ---------------------------

// accept_backoff's two groups on the codes a Windows accept answers with: a paused or interrupted
// call tries again at once, resource exhaustion waits the Rust's 100 ms, and anything else is the end
// of the listener (socks.rs:291-300's match, on the io::ErrorKind the same raw codes carry).
[[nodiscard]] std::optional<eg::Millis> accept_pause(int code, bool& fatal) {
    switch (code) {
        case WSAEWOULDBLOCK:
        case WSAEINTR: return std::chrono::milliseconds(0);
        case WSAEMFILE:
        case WSAENOBUFS: return std::chrono::milliseconds(100);
        default: fatal = true; return std::nullopt;
    }
}

// One exact read: Rust's read_exact, whose await is bounded by the handshake budget and cut short by
// the run's stop. The four outcomes stay four because the Rust branches on all of them.
[[nodiscard]] bool read_exact(eg::ByteStream& in, std::uint8_t* out, std::size_t len,
                              eg::Millis budget, eg::Stop& stop) {
    std::size_t got = 0;
    const auto finish = std::chrono::steady_clock::now() + budget;
    while (got < len) {
        const auto left = std::chrono::duration_cast<eg::Millis>(finish - std::chrono::steady_clock::now());
        const eg::Millis slice = left < std::chrono::milliseconds(50) ? (left.count() < 0
                                                                            ? std::chrono::milliseconds(0)
                                                                            : left)
                                                                     : std::chrono::milliseconds(50);
        const auto attempt = in.read(out + got, len - got, slice, stop);
        switch (attempt.kind) {
            case eg::ReadAttempt::Kind::Bytes: got += attempt.count; break;
            case eg::ReadAttempt::Kind::End: return false;
            case eg::ReadAttempt::Kind::Timeout:
                if (stop.asked()) return false;
                if (std::chrono::steady_clock::now() >= finish) return false;
                break;
            case eg::ReadAttempt::Kind::Failure: return false;
        }
        if (stop.asked()) return false;
    }
    return got == len;
}

[[nodiscard]] bool write_all(eg::ByteStream& out, std::span<const std::uint8_t> bytes,
                             eg::Stop& stop) {
    return out.write(bytes, stop).has_value();
}

// A text answer on a stream: the http arm's status lines are literals, and egress's ByteStream only
// takes bytes.
[[nodiscard]] bool write_text(eg::ByteStream& out, std::string_view text, eg::Stop& stop) {
    return out.write(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                                   text.size()),
                     stop)
        .has_value();
}

// socks.rs's enable_keepalive: the netstack's own idle, and the interval a quarter of it clamped to
// the five-to-thirty-second band the Rust's Windows arm keeps. The retries the Rust adds are gated to
// the Unix targets, so on Windows there is nothing to set and nothing is invented. A failure is the
// Rust's debug line and no more.
void enable_keepalive(eg::Socket& socket, const Settings& settings) {
    const eg::Millis idle = ns::TcpLimits::from_settings(settings).keepalive;
    eg::Millis interval = std::chrono::duration_cast<eg::Millis>(idle / 4);
    if (interval < std::chrono::seconds(5)) interval = std::chrono::seconds(5);
    if (interval > std::chrono::seconds(30)) interval = std::chrono::seconds(30);
    if (const auto applied = socket.apply_keepalive(idle, interval); !applied.has_value()) {
        emit(Level::Debug, "could not enable keep-alive on a connection: " + applied.error());
    }
}

// The tunnel's own DNS, one datagram association per name: A first, then AAAA, on each resolver in
// socks::resolver_addresses' order, inside the Rust's five-second window (socks.rs's
// dns_resolve / resolve_preferring_v4). The association is opened and closed around the two
// questions, which is what makes a stale answer unable to cross into the next name.
[[nodiscard]] std::optional<IpAddress> tunnel_resolve(Hop& hop, const Settings& settings,
                                                      std::string_view name, eg::Stop& stop) {
    const std::vector<sk::Endpoint> resolvers = sk::resolver_addresses(settings);
    for (const std::uint16_t qtype : {sk::QTYPE_A, sk::QTYPE_AAAA}) {
        ns::UdpConn conn;
        {
            const std::lock_guard<std::mutex> lock(hop.mutex());
            auto opened = hop.stack()->open_udp(std::chrono::steady_clock::now());
            if (!opened.has_value()) return std::nullopt;
            conn = std::move(*opened);
        }
        auto split = [&] {
            const std::lock_guard<std::mutex> lock(hop.mutex());
            return conn.into_split();
        }();
        StackUdp udp(hop, std::move(split.first), std::move(split.second));
        const auto [query, id] = sk::new_dns_query(name, qtype);
        for (const sk::Endpoint& server : resolvers) {
            const SocketAddr dst{server.address, server.port};
            if (!udp.send_to(dst, query)) continue;
            const auto finish = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
            while (!stop.asked() && std::chrono::steady_clock::now() < finish) {
                const auto left = std::chrono::duration_cast<eg::Millis>(
                    finish - std::chrono::steady_clock::now());
                std::optional<ns::UdpInbound> arrived = udp.recv(stop, left);
                if (!arrived.has_value()) break;
                if (!aether::core::response_matches(arrived->data, id, name, qtype)) continue;
                if (const auto ip = sk::parse_dns_answer(arrived->data, qtype)) return ip;
                break; // the Rust takes no record / no such name as "try the next qtype"
            }
        }
        udp.close();
    }
    return std::nullopt;
}

// The address a client asked for, however the request spelled it: an address stays itself, a name
// goes through the tunnel's DNS. Rust's resolve(): a name that parses as an address needs no lookup.
[[nodiscard]] std::optional<IpAddress> target_address(Hop& hop, const ProxyOptions& options,
                                                      const sk::Target& target, eg::Stop& stop) {
    if (target.is_ip()) return target.ip();
    if (const auto literal = aether::core::parse_address(target.domain())) return *literal;
    return tunnel_resolve(hop, options.settings, target.domain(), stop);
}

// Asio IOCP-backed asynchronous duplex relay between two native Windows sockets.
// Avoids 50ms polling loops and eliminates thread-per-direction overhead.
void relay_sockets_asio(SOCKET raw1, SOCKET raw2, eg::Stop& stop, eg::Millis linger) {
    asio::io_context io;
    asio::ip::tcp::socket sock1(io);
    asio::ip::tcp::socket sock2(io);

    asio::error_code ec;
    sock1.assign(asio::ip::tcp::v4(), raw1, ec);
    if (ec) return;
    sock2.assign(asio::ip::tcp::v4(), raw2, ec);
    if (ec) {
        sock1.release(ec);
        return;
    }

    struct ReleaseOnExit {
        asio::ip::tcp::socket& s1;
        asio::ip::tcp::socket& s2;
        ~ReleaseOnExit() {
            asio::error_code ec_rel;
            (void)s1.release(ec_rel);
            (void)s2.release(ec_rel);
        }
    } releaser{sock1, sock2};

    struct BridgeContext {
        std::array<std::uint8_t, sk::RELAY_CHUNK> buf1{};
        std::array<std::uint8_t, sk::RELAY_CHUNK> buf2{};
        std::atomic<bool> cancelled{false};
    };
    auto ctx = std::make_shared<BridgeContext>();

    auto stop_timer = std::make_shared<asio::steady_timer>(io);
    std::function<void(const asio::error_code&)> check_stop;
    check_stop = [&sock1, &sock2, &stop, ctx, stop_timer, &check_stop](const asio::error_code& timer_ec) {
        if (timer_ec || ctx->cancelled.load(std::memory_order_relaxed)) return;
        if (stop.asked()) {
            ctx->cancelled.store(true, std::memory_order_relaxed);
            asio::error_code c_ec;
            sock1.cancel(c_ec);
            sock2.cancel(c_ec);
            return;
        }
        stop_timer->expires_after(asio::chrono::milliseconds(50));
        stop_timer->async_wait(check_stop);
    };
    stop_timer->expires_after(asio::chrono::milliseconds(50));
    stop_timer->async_wait(check_stop);

    std::function<void()> pump_1_to_2;
    pump_1_to_2 = [&sock1, &sock2, ctx, &pump_1_to_2]() {
        if (ctx->cancelled.load(std::memory_order_relaxed)) return;
        sock1.async_read_some(asio::buffer(ctx->buf1),
            [&sock1, &sock2, ctx, &pump_1_to_2](const asio::error_code& r_ec, std::size_t n) {
                if (ctx->cancelled.load(std::memory_order_relaxed)) return;
                if (!r_ec && n > 0) {
                    asio::async_write(sock2, asio::buffer(ctx->buf1.data(), n),
                        [&sock1, &sock2, ctx, &pump_1_to_2](const asio::error_code& w_ec, std::size_t /*written*/) {
                            if (w_ec || ctx->cancelled.load(std::memory_order_relaxed)) {
                                ctx->cancelled.store(true, std::memory_order_relaxed);
                                asio::error_code c_ec;
                                sock1.cancel(c_ec);
                                sock2.cancel(c_ec);
                                return;
                            }
                            pump_1_to_2();
                        });
                } else {
                    asio::error_code shut_ec;
                    sock2.shutdown(asio::ip::tcp::socket::shutdown_send, shut_ec);
                }
            });
    };

    auto linger_timer = std::make_shared<asio::steady_timer>(io);
    std::function<void()> pump_2_to_1;
    pump_2_to_1 = [&sock1, &sock2, ctx, linger, linger_timer, &pump_2_to_1]() {
        if (ctx->cancelled.load(std::memory_order_relaxed)) return;
        sock2.async_read_some(asio::buffer(ctx->buf2),
            [&sock1, &sock2, ctx, linger, linger_timer, &pump_2_to_1](const asio::error_code& r_ec, std::size_t n) {
                if (ctx->cancelled.load(std::memory_order_relaxed)) return;
                if (!r_ec && n > 0) {
                    asio::async_write(sock1, asio::buffer(ctx->buf2.data(), n),
                        [&sock1, &sock2, ctx, &pump_2_to_1](const asio::error_code& w_ec, std::size_t /*written*/) {
                            if (w_ec || ctx->cancelled.load(std::memory_order_relaxed)) {
                                ctx->cancelled.store(true, std::memory_order_relaxed);
                                asio::error_code c_ec;
                                sock1.cancel(c_ec);
                                sock2.cancel(c_ec);
                                return;
                            }
                            pump_2_to_1();
                        });
                } else {
                    asio::error_code shut_ec;
                    sock1.shutdown(asio::ip::tcp::socket::shutdown_send, shut_ec);
                    if (linger.count() > 0) {
                        linger_timer->expires_after(asio::chrono::milliseconds(linger.count()));
                        linger_timer->async_wait([&sock1, &sock2, ctx](const asio::error_code& t_ec) {
                            if (!t_ec) {
                                ctx->cancelled.store(true, std::memory_order_relaxed);
                                asio::error_code c_ec;
                                sock1.cancel(c_ec);
                                sock2.cancel(c_ec);
                            }
                        });
                    }
                }
            });
    };

    pump_1_to_2();
    pump_2_to_1();

    io.run();
    stop.set();
}

// socks.rs's relay_tunneled: both directions, each on its own thread, the half-close linger behind
// the tunnel's last byte. A stop asked by the caller or the death of either half ends both, which is
// the Rust's select over the two copy loops.
void relay_pair(eg::ByteStream& client, eg::ByteStream& tunnel, eg::Stop& stop,
                eg::Millis linger) {
    auto* client_sock = dynamic_cast<eg::Socket*>(&client);
    auto* tunnel_sock = dynamic_cast<eg::Socket*>(&tunnel);
    if (client_sock != nullptr && tunnel_sock != nullptr) {
        relay_sockets_asio(static_cast<SOCKET>(client_sock->handle()),
                           static_cast<SOCKET>(tunnel_sock->handle()),
                           stop, linger);
        return;
    }

    auto client_to_tunnel = [&] {
        std::vector<std::uint8_t> buffer(sk::RELAY_CHUNK);
        for (;;) {
            const auto attempt = client.read(buffer.data(), buffer.size(),
                                             std::chrono::milliseconds(50), stop);
            if (attempt.kind == eg::ReadAttempt::Kind::Bytes && attempt.count > 0) {
                if (!tunnel.write(std::span<const std::uint8_t>(buffer.data(), attempt.count), stop)
                        .has_value()) {
                    break;
                }
                continue;
            }
            if (attempt.kind == eg::ReadAttempt::Kind::End) {
                (void)tunnel.shutdown_write(); // Rust's `let _ = sender.shutdown().await`
                break;
            }
            if (attempt.kind == eg::ReadAttempt::Kind::Failure) break;
            if (stop.asked()) break;
        }
    };
    auto tunnel_to_client = [&] {
        std::vector<std::uint8_t> buffer(sk::RELAY_CHUNK);
        for (;;) {
            const auto attempt = tunnel.read(buffer.data(), buffer.size(),
                                             std::chrono::milliseconds(50), stop);
            if (attempt.kind == eg::ReadAttempt::Kind::Bytes && attempt.count > 0) {
                if (!client.write(std::span<const std::uint8_t>(buffer.data(), attempt.count), stop)
                        .has_value()) {
                    break;
                }
                continue;
            }
            if (attempt.kind == eg::ReadAttempt::Kind::End) {
                // The write half goes, then the linger waits for the client's own EOF, which is
                // Rust's half_close_linger around the remaining read.
                (void)client.shutdown_write();
                const auto finish = std::chrono::steady_clock::now() + linger;
                while (!stop.asked() && std::chrono::steady_clock::now() < finish) {
                    const auto last = client.read(buffer.data(), buffer.size(),
                                                  std::chrono::milliseconds(50), stop);
                    if (last.kind == eg::ReadAttempt::Kind::End) break;
                    if (last.kind == eg::ReadAttempt::Kind::Failure) break;
                    if (last.kind == eg::ReadAttempt::Kind::Bytes && last.count > 0) {
                        // Still writing what the client sends after our half closed: Rust keeps the
                        // client's bytes flowing to the closed tunnel until its own EOF.
                        (void)tunnel.write(std::span<const std::uint8_t>(buffer.data(), last.count),
                                           stop);
                    }
                }
                break;
            }
            if (attempt.kind == eg::ReadAttempt::Kind::Failure) break;
            if (stop.asked()) break;
        }
        stop.set();
    };
    std::thread first(client_to_tunnel);
    std::thread second(tunnel_to_client);
    first.join();
    second.join();
}

// socks.rs's connect_direct, defined below with the rest of the direct path: the loopback rule on
// the answer, the system's resolver on a name, and the connect inside DIRECT_CONNECT_TIMEOUT_MS.
[[nodiscard]] std::expected<std::unique_ptr<eg::Socket>, std::string>
connect_direct(std::string_view host, std::uint16_t port, const SocketAddr& client,
               const ProxyOptions& options, eg::Stop& stop);

// socks.rs's open_through_gateway, defined with the rest of the gateway path: the tunnel dials the
// gateway, asks it for a CONNECT to the authority, and keeps the bytes after the status head.
[[nodiscard]] std::expected<std::pair<std::unique_ptr<StackTcp>, std::vector<std::uint8_t>>,
                            std::string>
stack_open_through_gateway(Hop& hop, const sk::Endpoint& proxy, std::string_view authority,
                           std::uint16_t port, eg::Stop& stop);

// The direct path's twin: this machine's own socket to the target, no tunnel between them. Rust's
// handle_direct / connect_direct, including the loopback rule, the DENIED/GENERAL reply split and
// the replay of the bytes the sniff already read.
void serve_direct_and_relay(ProxyOptions& options, eg::Socket& client, const sk::Target& target,
                            std::uint16_t port, std::vector<std::uint8_t> head, bool replied,
                            eg::Stop& stop) {
    const std::string host = target.is_ip() ? sk::address_text(target.ip())
                                            : std::string(target.domain());
    auto connected = connect_direct(host, port, client.peer(), options, stop);
    if (!connected.has_value()) {
        const std::string failure = connected.error();
        // handle_direct's Ok(Err(error)) arm: the loopback rule inside connect_direct answers
        // PermissionDenied, and only that answer becomes REP_NOT_ALLOWED.
        emit(Level::Debug, "[route] direct connect to " + host + ":" + std::to_string(port) +
                               " failed: " + failure);
        if (!replied) {
            (void)write_all(client,
                            sk::build_reply(eg::is_denied(failure) ? sk::REP_NOT_ALLOWED
                                                                    : sk::REP_GENERAL),
                            stop);
        }
        return;
    }
    eg::Socket& upstream = **connected;
    if (!head.empty() && !write_all(upstream, std::span<const std::uint8_t>(head), stop)) return;
    if (!replied) (void)write_all(client, sk::build_reply(sk::REP_OK), stop);
    const eg::Millis linger = std::chrono::seconds(sk::half_close_linger_secs(options.settings));
    relay_pair(client, upstream, stop, linger);
}

// A sockaddr as the core's address: the family decides where the bytes go, exactly as fill_address
// puts them the other way.
[[nodiscard]] SocketAddr socket_addr_of(const sockaddr_storage& storage) {
    SocketAddr out{};
    if (storage.ss_family == AF_INET) {
        const auto& v4 = reinterpret_cast<const sockaddr_in&>(storage);
        out.ip.v4 = true;
        std::memcpy(out.ip.bytes.data() + 12, &v4.sin_addr.s_addr, 4);
        out.port = ntohs(v4.sin_port);
        return out;
    }
    const auto& v6 = reinterpret_cast<const sockaddr_in6&>(storage);
    out.ip.v4 = false;
    std::memcpy(out.ip.bytes.data(), &v6.sin6_addr, 16);
    out.port = ntohs(v6.sin6_port);
    return out;
}

void serve_udp_associate(Hop& hop, ProxyOptions& options, eg::Stop& stop, eg::Socket& client,
                         SocketAddr peer, const sk::Request& request);
void serve_http_client(Hop& hop, ProxyOptions& options, eg::Stop& run_stop, SOCKET raw);

// The socks5 request, read to the last byte its ATYP needs, then parsed by the codec that owns the
// grammar. Nothing here decides anything the codec does not already decide.
[[nodiscard]] std::expected<sk::Request, std::string> read_request(eg::ByteStream& in,
                                                                   eg::Stop& stop) {
    std::uint8_t head[5]{};
    if (!read_exact(in, head, 5, eg::Millis(std::chrono::milliseconds(sk::HANDSHAKE_TIMEOUT_MS)),
                    stop)) {
        return std::unexpected(std::string("the client did not send its request in time"));
    }
    std::size_t tail = 0;
    // The tail arithmetic lives in socks.hpp under test; see request_tail_bytes.
    if (auto counted = sk::request_tail_bytes(head[3], head[4]); !counted.has_value()) {
        return std::unexpected(std::string("bad atyp ") + std::to_string(head[3]) +
                               " after command " + std::to_string(head[1]));
    } else {
        tail = *counted;
    }
    std::vector<std::uint8_t> buffer(5 + tail);
    std::memcpy(buffer.data(), head, 5);
    if (!read_exact(in, buffer.data() + 5, tail,
                    eg::Millis(std::chrono::milliseconds(sk::HANDSHAKE_TIMEOUT_MS)), stop)) {
        return std::unexpected(std::string("the client did not send its request in time"));
    }
    auto request = sk::parse_request(buffer);
    if (!request.has_value()) return std::unexpected(request.error());
    return *request;
}

// socks.rs's handle_client, from the greeting to the relay. The handshake accepts whatever the client
// offered and answers [0x05, 0x00] -- no method list is checked, because the Rust checks none -- and
// the connect arm keeps the sniff/reply order of handle_connect: a target that is an address with
// domain rules to match gets the bound reply first and its own first bytes read for a name, the route
// verdict then decides between the block answer, the direct path and the tunnel, and the tunnel's own
// arm goes through the gateway when one is set and the port wants it.
void serve_socks_client(Hop& hop, ProxyOptions& options, eg::Stop& run_stop, SOCKET raw,
                        SocketAddr peer) {
    const Settings& settings = options.settings;
    const eg::Millis handshake = std::chrono::milliseconds(sk::HANDSHAKE_TIMEOUT_MS);
    const eg::Millis linger = std::chrono::seconds(sk::half_close_linger_secs(settings));
    auto adopted = eg::Socket::adopt(raw);
    if (!adopted.has_value()) {
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + adopted.error());
        return;
    }
    eg::Socket& client = **adopted;
    eg::Stop stop;
    stop.parent(&run_stop);

    std::uint8_t prefix[2]{};
    if (!read_exact(client, prefix, 2, handshake, stop)) {
        emit(Level::Debug,
             "socks client " + peer.to_string() +
                 " ended: the client did not finish the socks5 handshake in time");
        return;
    }
    if (prefix[0] != sk::VER) {
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: bad greeting version");
        return;
    }
    std::vector<std::uint8_t> methods(prefix[1]);
    if (!methods.empty() && !read_exact(client, methods.data(), methods.size(), handshake, stop)) {
        emit(Level::Debug,
             "socks client " + peer.to_string() +
                 " ended: the client did not finish the socks5 handshake in time");
        return;
    }
    std::vector<std::uint8_t> greeting_bytes(2 + methods.size());
    greeting_bytes[0] = prefix[0];
    greeting_bytes[1] = prefix[1];
    std::memcpy(greeting_bytes.data() + 2, methods.data(), methods.size());
    const auto greeting = sk::parse_greeting(greeting_bytes);
    if (!greeting.has_value()) {
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + greeting.error());
        return;
    }
    if (!write_all(client, sk::build_method_selection(), stop)) return;

    const std::expected<sk::Request, std::string> request = read_request(client, stop);
    if (!request.has_value()) {
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + request.error());
        return;
    }

    if (request->command == sk::CMD_UDP_ASSOCIATE) {
        serve_udp_associate(hop, options, stop, client, peer, *request);
        return;
    }
    if (request->command != sk::CMD_CONNECT) {
        (void)write_all(client, sk::build_reply(sk::REP_NOT_SUPPORTED), stop);
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: unsupported socks command");
        return;
    }

    // handle_connect's sniff arm: only an address target, only with sniffing on and domain rules to
    // match against, and it answers first because the reply has to go out before the reading starts.
    std::vector<std::uint8_t> head;
    bool replied = false;
    std::optional<std::string> named;
    if (request->target.is_ip() && sk::sniff_enabled(settings) && options.routes.has_domain_rules()) {
        if (!write_all(client, sk::build_reply(sk::REP_OK), stop)) return;
        replied = true;
        std::vector<std::uint8_t> peek(aether::core::PEEK_BUDGET);
        const auto attempt = client.read(peek.data(), peek.size(),
                                         std::chrono::milliseconds(sk::sniff_window_ms(settings)),
                                         stop);
        if (attempt.kind == eg::ReadAttempt::Kind::Timeout) {
            head.clear(); // Err(_elapsed) => Some(Vec::new())
        } else if (attempt.kind == eg::ReadAttempt::Kind::End ||
                   attempt.kind == eg::ReadAttempt::Kind::Failure) {
            return; // None => return Ok(())
        } else {
            peek.resize(attempt.count);
            head = peek;
        }
        if (head.empty()) {
            // socks.rs:716 is log::trace!, invisible under the default filter; log_at is the filter.
            if (log_at(settings, "trace")) {
                emit(Level::Debug, "[route] " + request->target.text() + ":" +
                                       std::to_string(request->port) +
                                       " sent nothing to read a name from");
            }
        } else {
            named = aether::core::sniff_hostname(std::span<const std::uint8_t>(head));
            if (named.has_value() && log_at(settings, "debug")) {
                emit(Level::Debug, "[route] " + request->target.text() + ":" +
                                       std::to_string(request->port) + " announced itself as " +
                                       *named);
            }
        }
    }

    const rt::Action action = sk::decide_route(options.routes, request->target, named,
                                               request->port);
    if (action == rt::Action::Block) {
        emit(Level::Debug, "[route] block tcp " + request->target.text() + ":" +
                               std::to_string(request->port));
        if (!replied) (void)write_all(client, sk::build_reply(sk::REP_NOT_ALLOWED), stop);
        return;
    }
    if (action == rt::Action::Direct) {
        emit(Level::Debug, "[route] direct tcp " + request->target.text() + ":" +
                               std::to_string(request->port));
        serve_direct_and_relay(options, client, request->target, request->port, std::move(head),
                               replied, stop);
        return;
    }

    // The tunnel arm: the gateway first when one is set for this port, and under its failure the
    // plain dial -- the two are Rust's `match via_gateway`, and the gateway's failure retires it.
    std::optional<std::vector<std::uint8_t>> leftover;
    std::unique_ptr<StackTcp> tunnel;
    if (const std::optional<sk::Endpoint> gateway = sk::gateway_proxy();
        gateway.has_value() && sk::should_use_gateway(request->port)) {
        const std::string authority = request->target.is_ip()
                                          ? sk::address_text(request->target.ip())
                                          : std::string(request->target.domain());
        auto through = stack_open_through_gateway(hop, *gateway, authority, request->port, stop);
        if (through.has_value()) {
            leftover = std::move(through->second);
            tunnel = std::move(through->first);
        } else {
            if (const std::optional<std::string> line = sk::retire_gateway(through.error());
                line.has_value()) {
                emit(Level::Debug, *line);
            }
        }
    }
    if (!tunnel) {
        const std::optional<IpAddress> address = target_address(hop, options, request->target, stop);
        if (!address.has_value()) {
            (void)write_all(client, sk::build_reply(sk::REP_GENERAL), stop);
            emit(Level::Debug, "socks client " + peer.to_string() + " ended: no A or AAAA record for " +
                                   request->target.text());
            return;
        }
        const SocketAddr dst{*address, request->port};
        auto dialed = stack_dial(hop, dst, std::chrono::milliseconds(
                                              ns::TcpLimits::from_settings(settings).connect));
        if (!dialed.has_value()) {
            (void)write_all(client, sk::build_reply(sk::REP_GENERAL), stop);
            emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + dialed.error());
            return;
        }
        tunnel = std::move(*dialed);
        if (!leftover.has_value()) leftover = std::vector<std::uint8_t>{};
    }

    if (!replied && !write_all(client, sk::build_reply(sk::REP_OK), stop)) return;
    if (!head.empty() && !write_all(*tunnel, std::span<const std::uint8_t>(head), stop)) return;
    if (leftover.has_value() && !leftover->empty() &&
        !write_all(client, std::span<const std::uint8_t>(*leftover), stop)) {
        return;
    }
    relay_pair(client, *tunnel, stop, linger);
}

// socks.rs's handle_udp_associate, arm for arm: the relay is bound on the listener's own address,
// the reply carries what it got, one direct socket sits on 0.0.0.0:0 for the whole association, the
// first datagram's source latches the client (and every later one is checked against it, with the
// Rust's first-and-every-64th warning), and the loop's four arms are the four reads the Rust selects
// over -- the client's datagrams, the tunnel's answers, the direct socket's answers and the control
// connection's own end. Any one of them closing the loop is the association over; `sender.close()`
// is the last thing it does.
void serve_udp_associate(Hop& hop, ProxyOptions& options, eg::Stop& stop, eg::Socket& client,
                         SocketAddr peer, const sk::Request& request) {
    const SocketAddr bind{options.socks_listen.ip, 0};
    auto bound = eg::udp_bind(bind);
    if (!bound.has_value()) {
        (void)write_all(client, sk::build_reply(sk::REP_GENERAL), stop);
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + bound.error());
        return;
    }
    eg::DatagramSocket& relay = **bound;
    const SocketAddr relay_addr = relay.local();
    if (!write_all(client, sk::build_bound_reply({relay_addr.ip, relay_addr.port}), stop)) return;

    ns::UdpConn conn;
    {
        const std::lock_guard<std::mutex> lock(hop.mutex());
        auto opened = hop.stack()->open_udp(std::chrono::steady_clock::now());
        if (!opened.has_value()) {
            (void)write_all(client, sk::build_reply(sk::REP_GENERAL), stop);
            emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + opened.error());
            return;
        }
        conn = std::move(*opened);
    }
    auto split = [&] {
        const std::lock_guard<std::mutex> lock(hop.mutex());
        return conn.into_split();
    }();
    StackUdp tunnel(hop, std::move(split.first), std::move(split.second));

    IpAddress any;
    any.v4 = true;
    auto direct = eg::udp_bind(SocketAddr{any, 0});
    if (!direct.has_value()) {
        (void)write_all(client, sk::build_reply(sk::REP_GENERAL), stop);
        emit(Level::Debug, "socks client " + peer.to_string() + " ended: " + direct.error());
        return;
    }
    eg::DatagramSocket& direct_relay = **direct;

    const sk::Endpoint control{peer.ip, peer.port};
    const IpAddress expected = sk::expected_udp_source(control, request.target);

    // The latch is shared by the three arms, so it is the one thing here the Rust's single task does
    // not need and this port does.
    std::mutex latch_mutex;
    std::optional<sk::Endpoint> latched;
    std::uint64_t refused = 0;
    auto answer_client = [&](const SocketAddr& from, std::span<const std::uint8_t> data) {
        std::optional<sk::Endpoint> target;
        {
            const std::lock_guard<std::mutex> lock(latch_mutex);
            target = latched;
        }
        if (!target.has_value()) return;
        (void)relay.send_to(SocketAddr{target->address, target->port},
                            sk::build_udp_reply({from.ip, from.port}, data), stop);
    };

    // from_stack.recv(): the tunnel's answers, framed with the far end's address.
    std::thread tunnel_side([&] {
        while (!stop.asked() && !hop.finished()) {
            const std::optional<ns::UdpInbound> arrived =
                tunnel.recv(stop, std::chrono::milliseconds(50));
            if (!arrived.has_value()) {
                if (tunnel.ended()) break; // Rust's `None => break`
                continue;
            }
            answer_client(arrived->from, arrived->data);
        }
        stop.set();
    });

    // direct_relay.recv_from(): the direct arm's answers. Rust's arm is `Err(_) => continue`, so a
    // failed read does not end the association.
    std::thread direct_side([&] {
        std::vector<std::uint8_t> buffer(65535);
        while (!stop.asked() && !hop.finished()) {
            auto back = direct_relay.recv_from(std::chrono::milliseconds(50), stop);
            if (!back.has_value()) continue;
            if (!back->has_value()) continue;
            const eg::Datagram& packet = back->value();
            answer_client(packet.from, packet.data);
        }
    });

    // relay.recv_from(): the client's datagrams, and the control read that ends it all. Rust selects
    // over the four reads; here the control read is its own thread because a blocking read cannot be
    // one arm of a loop that is waiting on something else.
    std::atomic<bool> control_closed{false};
    std::thread control_side([&] {
        std::vector<std::uint8_t> ctrl(256);
        while (!stop.asked() && !hop.finished()) {
            const auto watched =
                client.read(ctrl.data(), ctrl.size(), std::chrono::milliseconds(50), stop);
            if (watched.kind == eg::ReadAttempt::Kind::End ||
                watched.kind == eg::ReadAttempt::Kind::Failure) {
                control_closed = true;
                stop.set();
                return;
            }
        }
    });

    {
        while (!stop.asked() && !hop.finished() && !control_closed) {
            auto arrived = relay.recv_from(std::chrono::milliseconds(50), stop);
            if (!arrived.has_value()) break; // Err(_) => break
            if (!arrived->has_value()) continue;
            const eg::Datagram& packet = arrived->value();
            const sk::Endpoint from{packet.from.ip, packet.from.port};
            {
                const std::lock_guard<std::mutex> lock(latch_mutex);
                if (!sk::udp_source_allowed(expected, latched, from)) {
                    refused += 1;
                    if (refused == 1 || refused % 64 == 0) {
                        emit(Level::Warn,
                             "[-] udp relay " + relay_addr.to_string() +
                                 " dropped a datagram from " + from.text() +
                                 "; this association only serves " + sk::address_text(expected) +
                                 " (refused=" + std::to_string(refused) + ")");
                    }
                    continue;
                }
                if (!latched.has_value()) {
                    emit(Level::Debug, "udp relay " + relay_addr.to_string() +
                                           " latched to client " + from.text());
                    latched = from;
                }
            }
            const auto framed = sk::parse_udp_request(packet.data);
            if (!framed.has_value()) continue;
            const rt::Action action =
                sk::decide_route(options.routes, framed->target, std::nullopt, framed->port);
            if (action == rt::Action::Block) {
                emit(Level::Debug, "[route] block udp " + framed->target.text() + ":" +
                                       std::to_string(framed->port));
                continue;
            }
            if (action == rt::Action::Direct) {
                std::optional<SocketAddr> outside;
                if (framed->target.is_ip()) {
                    outside = SocketAddr{framed->target.ip(), framed->port};
                } else {
                    auto found = aether::core::parse_address(framed->target.domain());
                    if (found.has_value()) outside = SocketAddr{*found, framed->port};
                    else {
                        auto named = eg::lookup(framed->target.domain(), framed->port);
                        if (named.has_value() && !named->empty()) outside = named->front();
                    }
                }
                if (outside.has_value() && !sk::direct_target_allowed(peer.ip, outside->ip)) {
                    emit(Level::Debug, "[route] direct udp to " + outside->to_string() +
                                           " refused: only local clients may reach this machine's "
                                           "own loopback");
                } else if (outside.has_value()) {
                    emit(Level::Debug, "[route] direct udp " + framed->target.text() + ":" +
                                           std::to_string(framed->port));
                    (void)direct_relay.send_to(*outside, framed->payload, stop);
                } else {
                    emit(Level::Debug,
                         "[route] direct udp " + framed->target.text() + " did not resolve");
                }
                continue;
            }
            const std::optional<IpAddress> address =
                target_address(hop, options, framed->target, stop);
            if (!address.has_value()) continue;
            if (!tunnel.send_to(SocketAddr{*address, framed->port}, framed->payload)) break;
        }
    }

    stop.set();
    tunnel_side.join();
    direct_side.join();
    control_side.join();
    tunnel.close();
}

// socks.rs's connect_direct: tokio's own resolver on the host (an address literal answers itself),
// the loopback rule on every candidate, then the first connect that succeeds inside
// DIRECT_CONNECT_TIMEOUT_MS -- the budget is one deadline for the whole attempt, because the Rust
// wraps this call in the timeout rather than each connect. A candidate this machine's loopback or
// the wildcard only answers a client that is itself on loopback, which is the rule that stops the
// proxy being a reflector, and its answer is the PermissionDenied the caller replies NOT_ALLOWED to.
[[nodiscard]] std::expected<std::unique_ptr<eg::Socket>, std::string>
connect_direct(std::string_view host, std::uint16_t port, const SocketAddr& client,
               const ProxyOptions& options, eg::Stop& stop) {
    const auto finish =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(sk::DIRECT_CONNECT_TIMEOUT_MS);
    auto found = eg::lookup(host, port);
    if (!found.has_value()) return std::unexpected(found.error());
    std::optional<std::string> last_error;
    for (const SocketAddr& address : *found) {
        if (!sk::direct_target_allowed(client.ip, address.ip)) {
            last_error = std::string(eg::DENIED) + address.to_string() +
                         " is this machine's own loopback, which only local clients may reach";
            continue;
        }
        const auto left =
            std::chrono::duration_cast<eg::Millis>(finish - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            // handle_direct's Err(_elapsed) arm, which replies REP_GENERAL.
            return std::unexpected(std::string(eg::TIMED_OUT) + "direct connect to " +
                                   std::string(host) + ":" + std::to_string(port) + " timed out");
        }
        auto connected = eg::tcp_connect(address, left, stop);
        if (connected.has_value()) {
            // connect_direct's own two calls on the winner: nodelay, then the keepalive.
            (void)(*connected)->set_nodelay();
            enable_keepalive(**connected, options.settings);
            return connected;
        }
        last_error = connected.error();
    }
    return std::unexpected(last_error.has_value()
                               ? *last_error
                               : std::string(host) + " did not resolve to any address");
}

// String::from_utf8_lossy (the socks.rs/http.rs call sites print byte heads that may not be UTF-8):
// valid stretches pass through, each invalid stretch becomes one U+FFFD. The split mirrors the std's
// valid_up_to/error_len -- the Unicode maximal-subpart rule: a failed sequence consumes the in-range
// bytes its lead claimed before the failure (1 when the lead itself is out of range), and a sequence
// cut short by the end of input consumes the rest, as one replacement.
struct Utf8Scan {
    std::size_t take;  // bytes to consume
    bool valid;        // true: complete sequence to copy; false: one U+FFFD's worth
};

[[nodiscard]] Utf8Scan utf8_scan(std::span<const std::uint8_t> bytes, std::size_t at) {
    const std::size_t count = bytes.size();
    const auto cont = [&](std::size_t index) {
        return index < count && bytes[index] >= 0x80 && bytes[index] <= 0xBF;
    };
    const std::uint8_t lead = bytes[at];
    if (lead < 0x80) return {1, true};
    if (lead >= 0xC2 && lead <= 0xDF)
        return cont(at + 1) ? Utf8Scan{2, true} : Utf8Scan{1, false};
    if (lead >= 0xE0 && lead <= 0xEF) {
        // E0 keeps b1 >= 0xA0 (no overlongs), ED keeps b1 <= 0x9F (no surrogates).
        const std::uint8_t low = lead == 0xE0 ? 0xA0 : 0x80;
        const std::uint8_t high = lead == 0xED ? 0x9F : 0xBF;
        const bool first = at + 1 < count && bytes[at + 1] >= low && bytes[at + 1] <= high;
        if (!first) return {1, false};
        return cont(at + 2) ? Utf8Scan{3, true} : Utf8Scan{2, false};
    }
    if (lead >= 0xF0 && lead <= 0xF4) {
        // F0 keeps b1 >= 0x90 (no overlongs), F4 keeps b1 <= 0x8F (<= U+10FFFF).
        const std::uint8_t low = lead == 0xF0 ? 0x90 : 0x80;
        const std::uint8_t high = lead == 0xF4 ? 0x8F : 0xBF;
        const bool first = at + 1 < count && bytes[at + 1] >= low && bytes[at + 1] <= high;
        if (!first) return {1, false};
        if (!cont(at + 2)) return {2, false};
        return cont(at + 3) ? Utf8Scan{4, true} : Utf8Scan{3, false};
    }
    return {1, false}; // stray continuation, 0xC0/0xC1, 0xF5..0xFF
}

[[nodiscard]] std::string utf8_lossy(std::span<const std::uint8_t> bytes) {
    std::string out;
    std::size_t index = 0;
    while (index < bytes.size()) {
        const Utf8Scan scan = utf8_scan(bytes, index);
        if (scan.valid) {
            for (std::size_t offset = 0; offset < scan.take; ++offset)
                out.push_back(static_cast<char>(bytes[index + offset]));
        } else {
            out.append("\xEF\xBF\xBD");
        }
        index += scan.take;
    }
    return out;
}

// socks.rs's open_through_gateway: the tunnel dials the gateway itself, asks it for a CONNECT to the
// authority, and keeps whatever came after the status head as the channel's first bytes. Every answer
// here is the Rust's own text, because the caller's arms (`retire_gateway` on any failure, the plain
// tunnel dial under it) read nothing else.
[[nodiscard]] std::expected<std::pair<std::unique_ptr<StackTcp>, std::vector<std::uint8_t>>,
                           std::string>
stack_open_through_gateway(Hop& hop, const sk::Endpoint& proxy, std::string_view authority,
                           std::uint16_t port, eg::Stop& stop) {
    const SocketAddr gateway{proxy.address, proxy.port};
    const std::optional<eg::Millis> probe =
        std::chrono::milliseconds(sk::GATEWAY_PROBE_TIMEOUT_MS);
    auto dialed = stack_dial(hop, gateway, probe);
    if (!dialed.has_value()) {
        return std::unexpected("gateway " + gateway.to_string() + " did not accept a connection");
    }
    StackTcp& tunnel = **dialed;
    if (!write_all(tunnel, sk::build_proxy_connect(authority, port), stop)) {
        return std::unexpected("gateway " + gateway.to_string() + " did not take the connect");
    }
    std::vector<std::uint8_t> head;
    std::vector<std::uint8_t> chunk(sk::RELAY_CHUNK);
    for (;;) {
        const eg::ReadAttempt attempt = tunnel.read(chunk.data(), chunk.size(),
                                                    std::chrono::milliseconds(
                                                        sk::GATEWAY_PROBE_TIMEOUT_MS),
                                                    stop);
        if (attempt.kind == eg::ReadAttempt::Kind::Timeout) {
            return std::unexpected("gateway " + gateway.to_string() + " did not answer in time");
        }
        if (attempt.kind == eg::ReadAttempt::Kind::End) {
            return std::unexpected("gateway " + gateway.to_string() + " closed the connection");
        }
        if (attempt.kind == eg::ReadAttempt::Kind::Failure) {
            return std::unexpected(attempt.error);
        }
        head.insert(head.end(), chunk.begin(),
                    chunk.begin() + static_cast<std::ptrdiff_t>(attempt.count));
        if (const auto at = sk::find_head_end(std::span<const std::uint8_t>(head));
            at.has_value()) {
            const auto accepted = sk::proxy_connect_succeeded(std::span<const std::uint8_t>(head));
            if (!accepted.has_value()) {
                return std::unexpected("gateway " + gateway.to_string() +
                                       " sent a malformed response");
            }
            if (!*accepted) {
                std::string text = utf8_lossy(std::span<const std::uint8_t>(head.data(), *at));
                const std::size_t line_end = text.find('\n');
                if (line_end != std::string::npos) text.resize(line_end);
                text = aether::core::trim(text);
                return std::unexpected("gateway refused " + std::string(authority) + ":" +
                                       std::to_string(port) + " (" +
                                       (text.empty() ? std::string("no status") : text) + ")");
            }
            std::vector<std::uint8_t> leftover(head.begin() + static_cast<std::ptrdiff_t>(*at),
                                               head.end());
            return std::make_pair(std::move(*dialed), std::move(leftover));
        }
        if (head.size() > sk::GATEWAY_HEAD_LIMIT) {
            return std::unexpected("gateway " + gateway.to_string() +
                                   " sent an oversized response head");
        }
    }
}

// socks.rs's read_head: the bytes up to and including the blank line, and whatever the same read
// already carried past it. The search starts three bytes before what is buffered, which is how a
// CRLF split across two reads is still found, and the limit is checked after the buffer grows, so an
// oversized head is the Rust's "http request head too large".
[[nodiscard]] std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>,
                           std::string>
read_head(eg::Socket& client, eg::Stop& stop) {
    std::vector<std::uint8_t> head;
    std::vector<std::uint8_t> chunk(sk::RELAY_CHUNK);
    const auto finish = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(sk::HANDSHAKE_TIMEOUT_MS);
    for (;;) {
        const auto left =
            std::chrono::duration_cast<eg::Millis>(finish - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            return std::unexpected(
                "the client did not send a request head in time");
        }
        const auto attempt = client.read(chunk.data(), chunk.size(),
                                         left < std::chrono::milliseconds(50) ? left
                                                                              : std::chrono::milliseconds(50),
                                         stop);
        if (attempt.kind == eg::ReadAttempt::Kind::Failure) {
            return std::unexpected(attempt.error);
        }
        if (attempt.kind == eg::ReadAttempt::Kind::End) {
            return std::unexpected("the http client closed before sending a request");
        }
        if (attempt.kind == eg::ReadAttempt::Kind::Timeout) {
            if (stop.asked()) return std::unexpected(std::string(eg::STOPPED));
            continue;
        }
        if (attempt.count == 0) continue;
        const std::size_t search_from = head.size() >= 3 ? head.size() - 3 : 0;
        head.insert(head.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(attempt.count));
        const auto ended = sk::find_head_end(std::span<const std::uint8_t>(head));
        if (ended.has_value() && *ended >= search_from + 4) {
            std::vector<std::uint8_t> early(head.begin() + static_cast<std::ptrdiff_t>(*ended),
                                            head.end());
            head.erase(head.begin() + static_cast<std::ptrdiff_t>(*ended), head.end());
            return std::make_pair(std::move(head), std::move(early));
        }
        if (head.size() > sk::HTTP_HEAD_LIMIT) {
            return std::unexpected("http request head too large");
        }
    }
}

// The preamble Rust builds for a plain request: the codec's origin-form first line, which carries its
// own CRLF, then everything the head held after the first line.
[[nodiscard]] std::vector<std::uint8_t> http_preamble(const std::vector<std::uint8_t>& head,
                                                      const sk::HttpRequestLine& request) {
    if (!request.rewritten.has_value()) return {};
    const std::string text = utf8_lossy(std::span<const std::uint8_t>(head));
    const std::size_t line_end = text.find("\r\n");
    const std::string rest = line_end == std::string::npos
                                 ? std::string()
                                 : text.substr(line_end + 2);
    const std::string rewritten = *request.rewritten + rest;
    return std::vector<std::uint8_t>(rewritten.begin(), rewritten.end());
}

// socks.rs's handle_http_client: read_head under the handshake budget, the first line's verdict, the
// three route arms and the reply order the Rust keeps (the 200 for a CONNECT, then the gateway's
// leftover bytes to the client, then the preamble, then whatever arrived early, then the relay).
void serve_http_client(Hop& hop, ProxyOptions& options, eg::Stop& run_stop, SOCKET raw) {
    static constexpr std::string_view bad_request =
        "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
    static constexpr std::string_view forbidden =
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
    static constexpr std::string_view bad_gateway =
        "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
    static constexpr std::string_view established =
        "HTTP/1.1 200 Connection established\r\n\r\n";

    auto adopted = eg::Socket::adopt(raw);
    if (!adopted.has_value()) {
        emit(Level::Debug, "http proxy client ended: " + adopted.error());
        return;
    }
    eg::Socket& client = **adopted;
    const SocketAddr peer = client.peer();
    eg::Stop stop;
    stop.parent(&run_stop);

    const auto read = read_head(client, stop);
    if (!read.has_value()) {
        emit(Level::Debug, "http proxy client " + peer.to_string() + " ended: " + read.error());
        return;
    }
    const std::vector<std::uint8_t>& head = read->first;
    const std::vector<std::uint8_t>& early = read->second;
    const std::string text = utf8_lossy(std::span<const std::uint8_t>(head));
    const std::string_view first_line = std::string_view(text).substr(0, text.find('\n'));

    const auto request = sk::parse_request_line(first_line);
    if (!request.has_value()) {
        (void)write_text(client, bad_request, stop);
        emit(Level::Debug, "http proxy client " + peer.to_string() +
                               " ended: unsupported http proxy request: " +
                               std::string(first_line));
        return;
    }

    const sk::Target target = [&, authority = std::string(request->authority)] {
        if (const auto ip = aether::core::parse_address(authority)) {
            return sk::Target::from_ip(*ip);
        }
        return sk::Target::from_domain(authority);
    }();

    const eg::Millis linger = std::chrono::seconds(sk::half_close_linger_secs(options.settings));
    const rt::Action action =
        sk::decide_route(options.routes, target, std::nullopt, request->port);
    if (action == rt::Action::Block) {
        emit(Level::Debug, "[route] block http " + request->authority + ":" +
                               std::to_string(request->port));
        (void)write_text(client, forbidden, stop);
        return;
    }
    if (action == rt::Action::Direct) {
        // relay_http_direct: the connect's own answer decides between the 403 and the 502.
        emit(Level::Debug, "[route] direct http " + request->authority + ":" +
                               std::to_string(request->port));
        auto connected = connect_direct(request->authority, request->port, peer, options, stop);
        if (!connected.has_value()) {
            (void)write_text(client, eg::is_denied(connected.error()) ? forbidden : bad_gateway,
                             stop);
            emit(Level::Debug, "http proxy client " + peer.to_string() +
                                   " ended: " + connected.error());
            return;
        }
        eg::Socket& upstream = **connected;
        const std::vector<std::uint8_t> preamble = http_preamble(head, *request);
        if (preamble.empty()) {
            (void)write_text(client, established, stop);
        } else if (!write_all(upstream, std::span<const std::uint8_t>(preamble), stop)) {
            return;
        }
        if (!early.empty() &&
            !write_all(upstream, std::span<const std::uint8_t>(early), stop)) {
            return;
        }
        relay_pair(client, upstream, stop, linger);
        return;
    }

    // open_tunneled: the gateway first when one is set and the port wants it, and the plain tunnel
    // dial under it -- including the Rust's fallback, a gateway that fails is retired and the same
    // target is dialled through the tunnel itself.
    std::optional<std::vector<std::uint8_t>> leftover;
    std::unique_ptr<StackTcp> tunnel;
    auto via_gateway = [&, settings = &options.settings] {
        if (!sk::should_use_gateway(request->port)) return std::optional<sk::Endpoint>{};
        return sk::gateway_proxy();
    };
    const std::optional<sk::Endpoint> gateway = via_gateway();
    if (gateway.has_value()) {
        auto through = stack_open_through_gateway(hop, *gateway, request->authority,
                                                 request->port, stop);
        if (through.has_value()) {
            leftover = std::move(through->second);
            tunnel = std::move(through->first);
        } else {
            if (const std::optional<std::string> line =
                    sk::retire_gateway(through.error()); line.has_value()) {
                emit(Level::Debug, *line);
            }
        }
    }
    if (!tunnel) {
        const std::optional<IpAddress> address = target_address(hop, options, target, stop);
        if (!address.has_value()) {
            (void)write_text(client, bad_gateway, stop);
            emit(Level::Debug, "http proxy client " + peer.to_string() +
                                   " ended: " + request->authority + " did not resolve");
            return;
        }
        const SocketAddr dst{*address, request->port};
        auto dialed = stack_dial(hop, dst, std::chrono::milliseconds(
                                             ns::TcpLimits::from_settings(options.settings)
                                                 .connect));
        if (!dialed.has_value()) {
            (void)write_text(client, bad_gateway, stop);
            emit(Level::Debug, "http proxy client " + peer.to_string() +
                                   " ended: " + dialed.error());
            return;
        }
        tunnel = std::move(*dialed);
        leftover = std::vector<std::uint8_t>{};
    }

    const std::vector<std::uint8_t> preamble = http_preamble(head, *request);
    if (preamble.empty() && !write_text(client, established, stop)) return;
    if (leftover.has_value() && !leftover->empty() &&
        !write_all(client, std::span<const std::uint8_t>(*leftover), stop)) {
        return;
    }
    if (!preamble.empty() &&
        !write_all(*tunnel, std::span<const std::uint8_t>(preamble), stop)) {
        return;
    }
    if (!early.empty() && !write_all(*tunnel, std::span<const std::uint8_t>(early), stop)) return;
    relay_pair(client, *tunnel, stop, linger);
}

// The listener itself: Rust's serve(), the listening line, the world-reachable warning, the accept
// loop with accept_backoff and one thread per client up to client_limit(). `http` switches the body
// from the SOCKS5 handshake to the CONNECT listener, which is the only difference between the two
// (the same relay, the same route rules and the same limits answer both).
void serve_proxy(Hop& hop, ProxyOptions& options, const SocketAddr& listen, std::string_view kind,
                 bool http, const Cancel& cancel) {
    auto listener = AcceptListener::bind(kind, listen);
    if (!listener.has_value()) {
        emit(Level::Error, "[-] " + std::string(kind) + ": " + listener.error());
        hop.finish("other: " + listener.error());
        return;
    }
    emit(Level::Info, std::string(kind) == "socks5"
                          ? "[+] socks5 server listening on " + listen.to_string()
                          : "[+] " + std::string(kind) + " listening on " + listen.to_string());
    if (std::string(kind) == "socks5" && g_inproc_state_sink) {
        g_inproc_state_sink("Connected");
    }
    if (sk::is_unspecified(listen.ip)) {
        emit(Level::Warn, "[-] warning: " + std::string(kind) + " is bound to " +
                              listen.to_string() + ", reachable from the network");
    }
    eg::Stop& run_stop = hop.stop();
    const std::size_t limit =
        sk::client_limit_for(options.settings, sysprofile::tuning(options.settings).tier);
    std::atomic<std::size_t> active_clients{0};
    std::mutex shutdown_mutex;
    std::condition_variable shutdown_cv;

    // Asio thread pool: bounds OS threads, eliminates thread exhaustion
    const std::size_t pool_threads = std::clamp(
        static_cast<std::size_t>(std::thread::hardware_concurrency() * 4),
        std::size_t{8}, limit);
    asio::thread_pool pool(pool_threads);

    bool fatal = false;
    while (!run_stop.asked() && !cancel.is_cancelled() && !fatal) {
        const auto accepted = (*listener)->accept(run_stop);
        if (!accepted.has_value()) {
            bool stop_now = false;
            const std::optional<eg::Millis> pause = accept_pause(accepted.error(), stop_now);
            if (stop_now) {
                emit(Level::Error, "[-] " + std::string(kind) + " accept failed (" +
                                       std::to_string(accepted.error()) + ")");
                fatal = true;
                break;
            }
            if (pause.has_value() && pause->count() > 0) {
                interruptible_sleep_ms(*pause, cancel);
            }
            continue;
        }
        if (!accepted->has_value()) continue; // the slice ran out; the stop decides whether to go on
        const SOCKET raw = **accepted;
        sockaddr_storage storage{};
        int length = sizeof storage;
        SocketAddr peer{};
        if (::getpeername(raw, reinterpret_cast<sockaddr*>(&storage), &length) == 0) {
            peer = socket_addr_of(storage);
        }
        if (active_clients.load(std::memory_order_relaxed) >= limit) {
            emit(Level::Warn, "[-] " + std::string(kind) + ": at the client limit, dropping " +
                                  peer.to_string());
            closesocket(raw);
            continue;
        }
        active_clients.fetch_add(1, std::memory_order_relaxed);
        asio::post(pool, [&hop, &options, &run_stop, raw, peer, http, &cancel, &active_clients,
                          &shutdown_mutex, &shutdown_cv] {
            if (http) serve_http_client(hop, options, run_stop, raw);
            else serve_socks_client(hop, options, run_stop, raw, peer);

            if (active_clients.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                std::lock_guard<std::mutex> lock(shutdown_mutex);
                shutdown_cv.notify_all();
            }
        });
    }
    run_stop.set();
    pool.stop();
    pool.join();
    {
        std::unique_lock<std::mutex> lock(shutdown_mutex);
        shutdown_cv.wait(lock, [&] { return active_clients.load(std::memory_order_acquire) == 0; });
    }
}

// run_masque_tunnel (lib.rs:1612): establish_masque on the QUIC carrier, the netstack pump,
// the socks5 + http listeners, then block until the tunnel ends. Mirrors the Rust's select over
// the tunnel exit (the exit-policy guard pends when no policy is set, the socks task never ends
// first on its own): the first of tunnel-finish / cancel wins, the listeners are stopped after.
// Other shapes refuse honestly -- no fallback, no fake success.
// ---- the ironclad probe (tunnelping.rs::http_probe through a throwaway Hop) -------------------

// http_probe on an established Hop: the probe host out of the tunnel's DNS, a TCP dial, the
// GET from http_probe_request(), and bytes until should_stop, inside HTTP_PROBE_DEADLINE.
// The verdict is http_probe_passed: a 204 on the first status line.
[[nodiscard]] std::expected<void, std::string> ironclad_http_probe(Hop& hop,
                                                                   const Settings& settings,
                                                                   eg::Stop& stop) {
    const std::uint16_t port = pr::http_probe_port(settings);
    const std::string host(pr::HTTP_PROBE_HOST);
    const auto start = std::chrono::steady_clock::now();
    const auto finish = start + pr::HTTP_PROBE_DEADLINE;
    const std::optional<IpAddress> ip = tunnel_resolve(hop, settings, host, stop);
    if (!ip.has_value() || stop.asked()) {
        return std::unexpected("ironclad http probe: " + host + " did not resolve");
    }
    auto dialed = stack_dial(hop, SocketAddr{*ip, port},
                             std::chrono::duration_cast<eg::Millis>(pr::HTTP_PROBE_DEADLINE));
    if (!dialed.has_value()) return std::unexpected(dialed.error());
    StackTcp& conn = **dialed;
    const std::string request = pr::http_probe_request();
    if (!write_all(conn,
                   std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(
                                                     request.data()),
                                                 request.size()),
                   stop)) {
        return std::unexpected("ironclad http probe: write failed");
    }
    std::string body;
    std::vector<std::uint8_t> chunk(2048);
    bool timed_out = false;
    for (;;) {
        const auto left =
            std::chrono::duration_cast<eg::Millis>(finish - std::chrono::steady_clock::now());
        if (left.count() <= 0 || stop.asked()) {
            timed_out = true;
            break;
        }
        const auto attempt = conn.read(chunk.data(), chunk.size(),
                                       std::min(left, eg::Millis(50)), stop);
        if (attempt.kind == eg::ReadAttempt::Kind::Bytes && attempt.count > 0) {
            body += sk::utf8_lossy(std::span<const std::uint8_t>(chunk.data(), attempt.count));
            if (pr::http_probe_should_stop(body)) break;
            continue;
        }
        if (attempt.kind == eg::ReadAttempt::Kind::End) break;
        if (attempt.kind == eg::ReadAttempt::Kind::Failure) {
            timed_out = true;
            break;
        }
        // Timeout slices just mean nothing arrived yet; the overall deadline above decides.
    }
    if (timed_out) return std::unexpected("http probe response timeout");
    if (!pr::http_probe_passed(body)) {
        return std::unexpected("unexpected http probe response: " + pr::first_status_line(body));
    }
    return {};
}

std::expected<std::chrono::milliseconds, std::string> masque_http_ping(
    const MasquePing& ping, const Settings& settings, const Identity& identity,
    std::chrono::milliseconds timeout, const Cancel& cancel) {
    // tunnelping.rs::masque_http_ping: the stack starts on the probe's own addresses, the tunnel
    // runs quiet on either carrier, and the probe goes through once the data plane is validated.
    const bool h2 = carrier_h2::enabled(settings);
    Identity creds = identity;
    creds.cert_pem.assign(ping.cert_pem.begin(), ping.cert_pem.end());
    creds.key_pem.assign(ping.key_pem.begin(), ping.key_pem.end());
    creds.ipv4 = pr::render_ip(ping.local_ipv4);
    creds.ipv6.clear();
    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    Hop hop(settings, pr::PING_MTU);
    TunnelObserver observer;
    Notes notes;
    const std::chrono::seconds startup =
        std::max<std::chrono::seconds>(std::chrono::duration_cast<std::chrono::seconds>(timeout),
                                       std::chrono::seconds(1));
    cf::MasqueHopParams params = cf::establish_masque_params(
        settings, creds, h2 ? carrier_h2::h2_peer(settings, ping.peer) : ping.peer, ping.ech, h2,
        pr::PING_MTU, quic::MAX_DATAGRAM_SIZE, true, startup, "ironclad", notes);
    // The scan already logged the obfuscation profile with the probe; the establish would log it
    // a second time per candidate, so that one line stays out.
    notes.erase(std::remove_if(notes.begin(), notes.end(),
                               [](const Note& note) {
                                   return note.text.starts_with("[+] obfuscation profile: ") ||
                                          note.text.starts_with("[+] aethernoize profile: ");
                               }),
                notes.end());
    emit_all(notes);
    params.quic_config.noize = ping.noize;
    auto ready = start_masque_hop(hop, params, settings, creds, routes, observer, cancel);
    const auto started = std::chrono::steady_clock::now();
    if (!ready.has_value() || *ready != cf::StartupVerdict::Ready) {
        const std::string detail =
            !ready.has_value()
                ? ready.error()
                : cf::startup_verdict_error("ironclad", *ready, hop.error().value_or(std::string()),
                                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                                startup));
        hop.stop().set();
        hop.join_carriers();
        return std::unexpected(detail);
    }
    auto probed = ironclad_http_probe(hop, settings, hop.stop());
    hop.stop().set();
    hop.join_carriers();
    if (cancel.is_cancelled()) return std::unexpected(std::string("cancelled"));
    if (!probed.has_value()) return std::unexpected(probed.error());
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                started);
}

std::expected<std::chrono::milliseconds, std::string> wg_http_ping(
    ::aether::core::wg_live::LiveSession session,
    const aether::core::aethernoize::AetherNoizeConfig& noise, const Settings& settings,
    const Identity& identity, std::chrono::milliseconds timeout, const Cancel& cancel) {
    // tunnelping.rs::wg_http_ping_established: the verified session carries a throwaway Hop (on
    // the identity's IPv4 and the loopback IPv6, as the Rust's WgPingParams does) while the
    // probe goes through it. The whole attempt is bounded by `timeout`.
    (void)timeout;
    Identity addrs = identity;
    addrs.ipv6 = "::1";
    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);
    Hop hop(settings, pr::PING_MTU);
    if (auto opened = hop.open(settings, addrs, routes); !opened.has_value()) {
        return std::unexpected(opened.error());
    }
    WgOutbound outbound(hop);
    wgl::DataPlane plane;
    plane.inbound = hop.inbound_sink();
    plane.outbound = &outbound;
    const IpAddress local =
        aether::core::parse_address(identity.ipv4).value_or(IpAddress{});
    wgl::Tunnel tunnel =
        wgl::tunnel_from_session(std::move(session), noise, plane, wg_run_env(settings, cancel),
                                 local);
    hop.add_thread(std::thread([&hop, &cancel] { pump_hop(hop, cancel); }));
    hop.add_thread(std::thread([&hop, &tunnel, &cancel] {
        auto done = wgl::run_tunnel(tunnel, cancel);
        if (!done.has_value()) hop.finish(done.error().display());
        else hop.finish(std::nullopt);
        hop.stop().set();
    }));
    const auto started = std::chrono::steady_clock::now();
    auto probed = ironclad_http_probe(hop, settings, hop.stop());
    hop.stop().set();
    hop.join_carriers();
    if (cancel.is_cancelled()) return std::unexpected(std::string("cancelled"));
    if (!probed.has_value()) return std::unexpected(probed.error());
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                started);
}

// ---- the exit-location guard (exitloc.rs: report / settle / watch) ----------------------------

// read_trace through the tunnel: the trace host out of the tunnel's DNS, a TCP open on port 80,
// the GET from trace_request(), and bytes until trace_answered() or the 8 KiB cap, all inside
// LOOKUP_TIMEOUT. The round trip rides along for parse_exit.
[[nodiscard]] std::expected<std::pair<std::string, std::chrono::milliseconds>, std::string>
exit_trace(Hop& hop, const Settings& settings, eg::Stop& stop) {
    const auto start = std::chrono::steady_clock::now();
    const auto finish = start + xloc::LOOKUP_TIMEOUT;
    const std::optional<IpAddress> ip =
        tunnel_resolve(hop, settings, std::string(xloc::TRACE_HOST), stop);
    if (!ip.has_value() || stop.asked()) {
        return std::unexpected("the trace answer carried no location");
    }
    auto dialed = stack_dial(hop, SocketAddr{*ip, xloc::TRACE_PORT},
                             std::chrono::duration_cast<eg::Millis>(xloc::LOOKUP_TIMEOUT));
    if (!dialed.has_value()) return std::unexpected(dialed.error());
    StackTcp& conn = **dialed;
    const std::string request = xloc::trace_request();
    if (!write_all(conn, std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t*>(request.data()),
                                request.size()),
                   stop)) {
        return std::unexpected("the trace answer carried no location");
    }
    std::string body;
    std::vector<std::uint8_t> chunk(2048);
    for (;;) {
        const auto left = std::chrono::duration_cast<eg::Millis>(
            finish - std::chrono::steady_clock::now());
        if (left.count() <= 0 || stop.asked()) break;
        const auto attempt =
            conn.read(chunk.data(), chunk.size(), std::min(left, eg::Millis(50)), stop);
        if (attempt.kind == eg::ReadAttempt::Kind::Bytes && attempt.count > 0) {
            body += sk::utf8_lossy(std::span<const std::uint8_t>(chunk.data(), attempt.count));
            if (body.size() > xloc::TRACE_BUFFER_LIMIT || xloc::trace_answered(body)) {
                break;
            }
            continue;
        }
        if (attempt.kind == eg::ReadAttempt::Kind::End) break;
        if (attempt.kind == eg::ReadAttempt::Kind::Failure) break;
    }
    const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    if (std::chrono::steady_clock::now() >= finish && !xloc::trace_answered(body)) {
        return std::unexpected(std::string(xloc::TIMEOUT_MESSAGE));
    }
    return std::pair{std::move(body), rtt};
}

void emit_exit_line(const xloc::LogLine& line) {
    emit(line.level == xloc::Level::Warn     ? Level::Warn
         : line.level == xloc::Level::Debug ? Level::Debug
                                            : Level::Info,
         line.text);
}

// report (exitloc.rs:152): the exit line at info, the failure at debug. Nothing on a stop.
[[nodiscard]] std::optional<xloc::Exit> exit_report(Hop& hop, const Settings& settings,
                                                    std::string_view what, eg::Stop& stop) {
    auto traced = exit_trace(hop, settings, stop);
    if (!traced.has_value()) {
        emit_exit_line(xloc::probe_failure_line(what, traced.error()));
        return std::nullopt;
    }
    xloc::Exit exit = xloc::parse_exit(traced->first, traced->second);
    emit(Level::Info, xloc::report_line(what, exit));
    return exit;
}

// settle (exitloc.rs:225): no policy fires one background report and carries on; a policy reads
// the exit now and stops the run when it cannot be honoured.
[[nodiscard]] std::expected<void, std::string> exit_settle(Hop& hop, const Settings& settings,
                                                           const std::optional<xloc::Policy>& policy,
                                                           std::string_view what) {
    if (!policy.has_value()) {
        const std::string label(what);
        hop.add_thread(std::thread([&hop, settings, label] {
            eg::Stop& stop = hop.stop();
            (void)exit_report(hop, settings, label, stop);
        }));
        return {};
    }
    auto exit = exit_report(hop, settings, what, hop.stop());
    if (!exit.has_value()) {
        return std::unexpected(
            "the exit location could not be read, so the policy cannot be honoured");
    }
    const xloc::Verdict verdict = xloc::settle(policy, exit);
    if (verdict.log.has_value()) emit_exit_line(*verdict.log);
    if (verdict.error.has_value()) return std::unexpected(*verdict.error);
    return {};
}

// watch (exitloc.rs:253): every interval another lookup; a moved exit finishes the hop so the
// run reconnects, a quiet check only logs.
void exit_watch(Hop& hop, const Settings& settings, xloc::Policy policy, const Cancel& cancel) {
    hop.add_thread(std::thread([&hop, settings, policy = std::move(policy), &cancel] {
        eg::Stop& stop = hop.stop();
        for (;;) {
            interruptible_sleep_ms(
                std::chrono::duration_cast<std::chrono::milliseconds>(policy.interval()), cancel);
            if (stop.asked() || hop.finished() || cancel.is_cancelled()) return;
            auto traced = exit_trace(hop, settings, stop);
            xloc::WatchStep step;
            if (!traced.has_value()) {
                step = xloc::watch_step(policy, std::unexpected(traced.error()));
            } else if (auto loc = xloc::lookup_from(traced->first); loc.has_value()) {
                step = xloc::watch_step(policy, *loc);
            } else {
                step = xloc::watch_step(policy, std::unexpected(loc.error()));
            }
            emit_exit_line(step.log);
            if (step.reconnect.has_value()) {
                hop.finish(step.reconnect);
                return;
            }
        }
    }));
}

// verify_endpoint_keep_session with the engine's own seams (WinUdp + relay table), for callers
// that keep the session -- run_wireguard_tunnel and the two-hop establishes. The error is the
// display text, which is what every log line and reply interpolates.
[[nodiscard]] std::expected<wgl::LiveSession, std::string> wg_verify_keep_session(
    const Identity& identity, const SocketAddr& peer,
    const ::aether::core::aethernoize::AetherNoizeConfig& noise,
    std::chrono::milliseconds timeout, std::uint16_t keepalive, const Settings& settings,
    const Cancel& cancel) {
    wgl::VerifyParams params;
    params.peer = peer;
    params.private_key = identity.wg_private_key;
    params.peer_public = identity.wg_peer_public_key;
    params.client_id = identity.client_id;
    if (const auto local = aether::core::parse_address(identity.ipv4);
        local.has_value() && local->v4) {
        params.local_ipv4 = *local;
    } else {
        return std::unexpected(std::string("invalid ipv4"));
    }
    params.noise = noise;
    params.timeout = timeout.count() > 0 ? timeout : std::chrono::milliseconds(10000);
    params.keepalive = keepalive;
    params.settings = &settings;

    wgl::VerifyEnv env;
    env.now = wgl::monotonic_clock();
    env.sleep = wgl::thread_sleep();
    env.wait = [&cancel](std::chrono::milliseconds d) {
        interruptible_sleep_ms(d, cancel);
        return !cancel.is_cancelled();
    };
    env.random = wgl::boringssl_random();
    // The verify's own lines (the handshake trace, the timer retransmits): trace and debug ride
    // log_at like every other debug!/trace! text, so --log-level debug shows the verify breathing
    // instead of a silent ten seconds.
    env.note = [&settings](wgl::Level level, std::string_view line) {
        if (level == wgl::Level::Trace || level == wgl::Level::Debug) {
            if (!log_at(settings, "debug")) return;
            emit(Level::Debug, line);
            return;
        }
        emit(level == wgl::Level::Error   ? Level::Error
             : level == wgl::Level::Warn ? Level::Warn
                                         : Level::Info,
             line);
    };

    wgl::OpenSeams open;
    open.settings = &settings;
    open.make_io = [&settings](const SocketAddr& p, const Settings& s)
        -> std::expected<std::unique_ptr<tr::UdpIo>, std::string> {
        auto io = tr::WinUdp::open_for_peer(p, s);
        if (!io.has_value()) return std::unexpected(io.error());
        return std::move(*io);
    };
    open.relay = [](const SocketAddr& local_addr, const SocketAddr& intended) {
        return up::relay_target(local_addr, intended);
    };
    open.connect = [](tr::UdpIo& io, const SocketAddr& target) -> std::expected<void, std::string> {
        if (auto* udp = dynamic_cast<tr::WinUdp*>(&io)) return udp->connect_to(target);
        return {};
    };

    wgl::VerifyJob job{params, env, open};
    auto session = wgl::verify_endpoint_keep_session(std::move(job), cancel);
    if (!session.has_value()) return std::unexpected(session.error().display());
    return std::move(*session);
}

// ---- the two-hop forwarders (lib.rs:1834, 2689) --------------------------------------------

// spawn_udp_forwarder (lib.rs:2689): a 127.0.0.1:0 socket whose datagrams ride the outer
// tunnel to `remote`, and whose answers go back to the last sender -- the Rust's inner_peer
// mutex read. Heap-held: the relay threads outlive any move of the handle, so only the pointer
// travels. Stops and joins on destruction.
class UdpForwarder {
public:
    static std::expected<std::unique_ptr<UdpForwarder>, std::string> open(
        Hop& outer, const SocketAddr& remote, const Cancel& cancel) {
        auto self = std::unique_ptr<UdpForwarder>(new UdpForwarder());
        self->sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (self->sock_ == INVALID_SOCKET) {
            return std::unexpected("udp forwarder: socket failed (" +
                                    std::to_string(WSAGetLastError()) + ")");
        }
        sockaddr_in loop{};
        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        loop.sin_port = 0;
        if (::bind(self->sock_, reinterpret_cast<sockaddr*>(&loop), sizeof loop) != 0) {
            const int code = WSAGetLastError();
            closesocket(self->sock_);
            return std::unexpected("udp forwarder: bind failed (" + std::to_string(code) + ")");
        }
        sockaddr_in bound{};
        int len = sizeof bound;
        if (getsockname(self->sock_, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
            const int code = WSAGetLastError();
            closesocket(self->sock_);
            return std::unexpected("udp forwarder: getsockname failed (" + std::to_string(code) +
                                    ")");
        }
        self->local_.ip.v4 = true;
        std::memcpy(self->local_.ip.bytes.data() + 12, &bound.sin_addr.s_addr, 4);
        self->local_.port = ntohs(bound.sin_port);
        u_long nonblock = 1;
        ::ioctlsocket(self->sock_, FIONBIO, &nonblock);

        {
            const std::lock_guard<std::mutex> lock(outer.mutex());
            auto opened = outer.stack()->open_udp(std::chrono::steady_clock::now());
            if (!opened.has_value()) {
                closesocket(self->sock_);
                return std::unexpected(opened.error());
            }
            auto split = std::move(*opened).into_split();
            self->udp_.emplace(outer, std::move(split.first), std::move(split.second));
        }

        UdpForwarder* raw = self.get();
        // Up: loopback datagrams into the tunnel, remembering who sent them.
        self->up_ = std::thread([raw, remote, &cancel] {
            std::vector<std::uint8_t> buffer(65536);
            while (!raw->stop_.load() && !cancel.is_cancelled()) {
                fd_set read;
                FD_ZERO(&read);
                FD_SET(raw->sock_, &read);
                timeval slice{};
                slice.tv_usec = 50'000;
                if (::select(0, &read, nullptr, nullptr, &slice) <= 0) continue;
                sockaddr_storage sender{};
                int sender_len = sizeof sender;
                const int got = recvfrom(raw->sock_, reinterpret_cast<char*>(buffer.data()),
                                         static_cast<int>(buffer.size()), 0,
                                         reinterpret_cast<sockaddr*>(&sender), &sender_len);
                if (got <= 0) continue;
                {
                    const std::lock_guard<std::mutex> lock(raw->peer_mutex_);
                    raw->peer_.emplace();
                    std::memcpy(&raw->peer_->storage, &sender,
                                static_cast<std::size_t>(sender_len));
                    raw->peer_->length = sender_len;
                }
                (void)raw->udp_->send_to(remote, std::span<const std::uint8_t>(
                                                     buffer.data(),
                                                     static_cast<std::size_t>(got)));
            }
        });
        // Down: tunnel datagrams back to the last sender -- a follower, not a migration.
        self->down_ = std::thread([raw, &cancel] {
            eg::Stop idle;
            while (!raw->stop_.load() && !cancel.is_cancelled()) {
                std::optional<ns::UdpInbound> arrived =
                    raw->udp_->recv(idle, std::chrono::milliseconds(50));
                if (!arrived.has_value()) continue;
                sockaddr_storage sender{};
                int sender_len = 0;
                {
                    const std::lock_guard<std::mutex> lock(raw->peer_mutex_);
                    if (!raw->peer_.has_value()) continue;
                    sender = raw->peer_->storage;
                    sender_len = raw->peer_->length;
                }
                (void)::sendto(raw->sock_, reinterpret_cast<const char*>(arrived->data.data()),
                                static_cast<int>(arrived->data.size()), 0,
                                reinterpret_cast<sockaddr*>(&sender), sender_len);
            }
        });
        return self;
    }

    UdpForwarder(const UdpForwarder&) = delete;
    UdpForwarder& operator=(const UdpForwarder&) = delete;

    ~UdpForwarder() {
        stop_.store(true);
        if (up_.joinable()) up_.join();
        if (down_.joinable()) down_.join();
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
    }

    [[nodiscard]] const SocketAddr& local() const { return local_; }

private:
    UdpForwarder() = default;

    struct PeerAddr {
        sockaddr_storage storage{};
        int length = 0;
    };

    SOCKET sock_ = INVALID_SOCKET;
    SocketAddr local_{};
    std::optional<StackUdp> udp_;
    std::thread up_;
    std::thread down_;
    std::atomic<bool> stop_{false};
    std::mutex peer_mutex_;
    std::optional<PeerAddr> peer_;
};

// spawn_tcp_forwarder (lib.rs:1834): a 127.0.0.1:0 listener; every accepted client is relayed
// into the outer tunnel addressed at `remote`, which is stack.open_tcp plus relay_tunneled.
// Same heap-held lifetime as the UDP one.
class TcpForwarder {
public:
    static std::expected<std::unique_ptr<TcpForwarder>, std::string> open(
        Hop& outer, const ProxyOptions& outer_options, const SocketAddr& remote,
        const Cancel& cancel) {
        auto self = std::unique_ptr<TcpForwarder>(new TcpForwarder());
        self->listener_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (self->listener_ == INVALID_SOCKET) {
            return std::unexpected("tcp forwarder: socket failed (" +
                                    std::to_string(WSAGetLastError()) + ")");
        }
        sockaddr_in loop{};
        loop.sin_family = AF_INET;
        loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        loop.sin_port = 0;
        if (::bind(self->listener_, reinterpret_cast<sockaddr*>(&loop), sizeof loop) != 0 ||
            ::listen(self->listener_, 16) != 0) {
            const int code = WSAGetLastError();
            closesocket(self->listener_);
            return std::unexpected("tcp forwarder: bind failed (" + std::to_string(code) + ")");
        }
        sockaddr_in bound{};
        int len = sizeof bound;
        if (getsockname(self->listener_, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
            const int code = WSAGetLastError();
            closesocket(self->listener_);
            return std::unexpected("tcp forwarder: getsockname failed (" + std::to_string(code) +
                                    ")");
        }
        self->local_.ip.v4 = true;
        std::memcpy(self->local_.ip.bytes.data() + 12, &bound.sin_addr.s_addr, 4);
        self->local_.port = ntohs(bound.sin_port);
        u_long nonblock = 1;
        ::ioctlsocket(self->listener_, FIONBIO, &nonblock);

        TcpForwarder* raw = self.get();
        self->accept_ = std::thread([raw, &outer, &outer_options, remote, &cancel] {
            const eg::Millis linger =
                std::chrono::seconds(sk::half_close_linger_secs(outer_options.settings));
            while (!raw->stop_.load() && !cancel.is_cancelled()) {
                fd_set read;
                FD_ZERO(&read);
                FD_SET(raw->listener_, &read);
                timeval slice{};
                slice.tv_usec = 50'000;
                if (::select(0, &read, nullptr, nullptr, &slice) <= 0) continue;
                sockaddr_storage from{};
                int from_len = sizeof from;
                const SOCKET client = ::accept(raw->listener_, reinterpret_cast<sockaddr*>(&from),
                                               &from_len);
                if (client == INVALID_SOCKET) continue;
                // One relay per client, on its own thread: the accept loop never waits for one.
                std::thread([&outer, &outer_options, remote, client, linger, &cancel] {
                    auto adopted = eg::Socket::adopt(client);
                    if (!adopted.has_value()) {
                        closesocket(client);
                        return;
                    }
                    eg::Socket& downstream = **adopted;
                    eg::Stop stop;
                    auto upstream = stack_dial(outer, remote, std::nullopt);
                    if (!upstream.has_value()) return;
                    relay_pair(downstream, **upstream, stop, linger);
                }).detach();
            }
        });
        return self;
    }

    TcpForwarder(const TcpForwarder&) = delete;
    TcpForwarder& operator=(const TcpForwarder&) = delete;

    ~TcpForwarder() {
        stop_.store(true);
        if (accept_.joinable()) accept_.join();
        if (listener_ != INVALID_SOCKET) closesocket(listener_);
    }

    [[nodiscard]] const SocketAddr& local() const { return local_; }

private:
    TcpForwarder() = default;

    SOCKET listener_ = INVALID_SOCKET;
    SocketAddr local_{};
    std::thread accept_;
    std::atomic<bool> stop_{false};
};
// ---- shared WireGuard seams (one definition, every establish uses it) ----------------------

// The note sink for wg_live::run_tunnel: trace/debug stay under the filter, the rest ride emit.
[[nodiscard]] wgl::Note wg_note_sink() {
    return [](wgl::Level level, std::string_view line) {
        if (level == wgl::Level::Trace || level == wgl::Level::Debug) return;
        emit(level == wgl::Level::Error   ? Level::Error
             : level == wgl::Level::Warn ? Level::Warn
                                         : Level::Info,
             line);
    };
}

[[nodiscard]] wgl::RunEnv wg_run_env(const Settings& settings, const Cancel& cancel) {
    wgl::RunEnv env;
    env.now = wgl::monotonic_clock();
    env.sleep = wgl::thread_sleep();
    env.wait = [&cancel](std::chrono::milliseconds d) {
        interruptible_sleep_ms(d, cancel);
        return !cancel.is_cancelled();
    };
    env.random = wgl::boringssl_random();
    env.note = wg_note_sink();
    env.settings = &settings;
    return env;
}

[[nodiscard]] wgl::OpenSeams wg_open_seams(const Settings& settings) {
    wgl::OpenSeams open;
    open.settings = &settings;
    open.make_io = [&settings](const SocketAddr& peer, const Settings& s)
        -> std::expected<std::unique_ptr<tr::UdpIo>, std::string> {
        auto io = tr::WinUdp::open_for_peer(peer, s);
        if (!io.has_value()) return std::unexpected(io.error());
        return std::move(*io);
    };
    open.relay = [](const SocketAddr& local, const SocketAddr& intended) {
        return up::relay_target(local, intended);
    };
    open.connect = [](tr::UdpIo& io, const SocketAddr& target) -> std::expected<void, std::string> {
        if (auto* udp = dynamic_cast<tr::WinUdp*>(&io)) return udp->connect_to(target);
        return {};
    };
    return open;
}

// establish_masque's Hop on one carrier: open the stack, start the pump + carrier, wait for
// ready. The transport line is the caller's (it is logged before the wait in the Rust too).
[[nodiscard]] std::expected<cf::StartupVerdict, std::string> start_masque_hop(
    Hop& hop, const cf::MasqueHopParams& params, const Settings& settings,
    const Identity& identity, const rt::RuleSet& routes, TunnelObserver& observer,
    const Cancel& cancel) {
    if (auto opened = hop.open(settings, identity, routes); !opened.has_value()) {
        return std::unexpected(opened.error());
    }
    hop.add_thread(std::thread([&hop, &cancel] { pump_hop(hop, cancel); }));
    if (params.h2) {
        carrier_h2::H2TunnelConfig h2cfg = params.h2_config;
        hop.add_thread(std::thread([&hop, h2cfg, &settings, &cancel, &observer]() mutable {
            H2Outbound outbound(hop);
            run_h2_hop(hop, h2cfg, settings, cancel, outbound, observer);
        }));
    } else {
        quic::TunnelConfig tunnel = params.quic_config;
        hop.add_thread(std::thread([&hop, tunnel, &settings, &cancel, &observer]() mutable {
            run_quic_hop(hop, std::move(tunnel), settings, cancel, observer);
        }));
    }
    return hop.wait_ready(params.startup, cancel);
}

// (handshake + data plane) before anything is exposed, then the established session carries
// the netstack pump and the socks5 + http listeners until the tunnel ends. Mirrors the Rust's
// select over the tunnel run: the first of tunnel-finish / cancel wins.
[[nodiscard]] Exec run_wg_tunnel(const FlowRequest& request, FlowReply& reply,
                                 const ExecContext& ctx) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;
    const SocketAddr peer = request.peer;

    emit(Level::Info, cf::wg_tunnel_validating_line(peer));
    const auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(request.timeout);
    auto session = wg_verify_keep_session(
        ctx.primary, peer, request.noise, timeout,
        request.keepalive.value_or(aether::core::wireguard::default_persistent_keepalive),
        settings, cancel);
    if (!session.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(cf::wg_tunnel_validation_error(session.error()));
        return Exec::Ran;
    }
    emit(Level::Info, std::string(cf::WG_TUNNEL_VALIDATED_LINE));

    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    Hop hop(settings, cf::TUNNEL_MTU);
    if (auto opened = hop.open(settings, ctx.primary, routes); !opened.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(opened.error());
        return Exec::Ran;
    }

    const cf::HttpProxyListen http = cf::http_proxy_listen(settings);
    if (http.warning.has_value()) emit(Level::Warn, *http.warning);
    ProxyOptions options{settings, routes, ctx.listen, http.listen};

    WgOutbound outbound(hop);
    wgl::DataPlane plane;
    plane.inbound = hop.inbound_sink();
    plane.outbound = &outbound;
    wgl::RunEnv run_env = wg_run_env(settings, cancel);
    const IpAddress wg_local = aether::core::parse_address(ctx.primary.ipv4).value_or(IpAddress{});
    wgl::Tunnel tunnel =
        wgl::tunnel_from_session(std::move(*session), request.noise, plane, run_env, wg_local);

    hop.add_thread(std::thread([&hop, &cancel] { pump_hop(hop, cancel); }));
    hop.add_thread(std::thread([&hop, &tunnel, &cancel] {
        auto done = wgl::run_tunnel(tunnel, cancel);
        if (!done.has_value()) hop.finish(done.error().display());
        else hop.finish(std::nullopt);
        hop.stop().set();
    }));

    const std::optional<xloc::Policy> wg_policy = xloc::Policy::from_env(settings);
    if (auto settled = exit_settle(hop, settings, wg_policy, "wireguard"); !settled.has_value()) {
        hop.stop().set();
        hop.join_carriers();
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(cf::wg_tunnel_validation_error(settled.error()));
        return Exec::Ran;
    }

    hop.add_thread(std::thread(
        [&hop, &options, &cancel] { serve_proxy(hop, options, options.socks_listen, "socks5", false, cancel); }));
    if (options.http_listen.has_value()) {
        const SocketAddr http_listen = *options.http_listen;
        hop.add_thread(std::thread([&hop, &options, &cancel, http_listen] {
            serve_proxy(hop, options, http_listen, "http proxy", true, cancel);
        }));
    }
    if (wg_policy.has_value()) exit_watch(hop, settings, *wg_policy, cancel);

    while (!hop.finished() && !cancel.is_cancelled() && !hop.stop().asked()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    hop.stop().set();
    hop.join_carriers();
    reply = FlowReply{};
    if (cancel.is_cancelled()) {
        reply.ok = false;
        reply.error = Error{ErrorKind::Cancelled, std::string()};
        return Exec::Ran;
    }
    if (const auto err = hop.error(); err.has_value()) {
        reply.ok = false;
        reply.error = Error::other(cf::wg_tunnel_run_exited_error(*err));
    } else {
        reply.ok = true;
    }
    return Exec::Ran;
}

// run_masque_tunnel (lib.rs:1612): establish_masque on either carrier, the netstack pump,
// the socks5 + http listeners, then block until the tunnel ends. Mirrors the Rust's select over
// the tunnel exit (the exit-policy guard pends when no policy is set, the socks task never ends
// first on its own): the first of tunnel-finish / cancel wins, the listeners are stopped after.
[[nodiscard]] Exec run_masque_tunnel(const FlowRequest& request, FlowReply& reply,
                                     const ExecContext& ctx) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;
    const bool h2 = carrier_h2::enabled(settings);
    Notes notes;
    const SocketAddr dial = cf::masque_dial_peer(settings, request.peer);
    const std::size_t mtu = cf::masque_tunnel_mtu(settings);
    const std::chrono::seconds startup =
        request.timeout.count() > 0 ? request.timeout : cf::masque_startup_timeout(settings);
    cf::MasqueHopParams params = cf::establish_masque_params(
        settings, ctx.primary, dial, ech_for(request, ctx), h2, mtu,
        quic::MAX_DATAGRAM_SIZE, !h2, startup, "masque", notes);
    emit_all(notes);
    emit(Level::Info, params.transport_line);

    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    Hop hop(settings, mtu);
    TunnelObserver observer;
    auto ready = start_masque_hop(hop, params, settings, ctx.primary, routes, observer, cancel);
    if (!ready.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(ready.error());
        return Exec::Ran;
    }

    const cf::StartupVerdict verdict = *ready;
    if (verdict != cf::StartupVerdict::Ready) {
        hop.stop().set();
        hop.join_carriers();
        reply = FlowReply{};
        reply.ok = false;
        const std::string detail = hop.error().value_or(std::string());
        reply.error = Error::other(cf::startup_verdict_error(
            "masque", verdict, detail,
            std::chrono::duration_cast<std::chrono::milliseconds>(startup)));
        return Exec::Ran;
    }

    const cf::HttpProxyListen http = cf::http_proxy_listen(settings);
    if (http.warning.has_value()) emit(Level::Warn, *http.warning);
    ProxyOptions options{settings, routes, ctx.listen, http.listen};

    const std::optional<xloc::Policy> policy = xloc::Policy::from_env(settings);
    if (auto settled = exit_settle(hop, settings, policy, "masque"); !settled.has_value()) {
        hop.stop().set();
        hop.join_carriers();
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(std::move(settled.error()));
        return Exec::Ran;
    }

    hop.add_thread(std::thread(
        [&hop, &options, &cancel] { serve_proxy(hop, options, options.socks_listen, "socks5", false, cancel); }));
    if (options.http_listen.has_value()) {
        const SocketAddr http_listen = *options.http_listen;
        hop.add_thread(std::thread([&hop, &options, &cancel, http_listen] {
            serve_proxy(hop, options, http_listen, "http proxy", true, cancel);
        }));
    }
    if (policy.has_value()) exit_watch(hop, settings, *policy, cancel);

    while (!hop.finished() && !cancel.is_cancelled() && !hop.stop().asked()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    hop.stop().set();
    hop.join_carriers();
    reply = FlowReply{};
    if (cancel.is_cancelled()) {
        reply.ok = false;
        reply.error = Error{ErrorKind::Cancelled, std::string()};
        return Exec::Ran;
    }
    if (const auto err = hop.error(); err.has_value()) {
        reply.ok = false;
        reply.error = Error::other(cf::tunnel_exited_error(*err));
    } else {
        reply.ok = true;
    }
    return Exec::Ran;
}

// establish_wg's Hop (lib.rs:2605): the session is already validated by the caller, so this
// opens the stack and starts the pump + wg_live run thread with no ready wait.
[[nodiscard]] std::expected<std::unique_ptr<Hop>, std::string> start_wg_hop(
    wgl::LiveSession session, const cf::WgEstablish& est, const Identity& identity,
    const Settings& settings, const rt::RuleSet& routes, const Cancel& cancel) {
    auto hop = std::make_unique<Hop>(settings, est.mtu);
    if (auto opened = hop->open(settings, identity, routes); !opened.has_value()) {
        return std::unexpected(opened.error());
    }
    auto outbound = std::make_unique<WgOutbound>(*hop);
    wgl::DataPlane plane;
    plane.inbound = hop->inbound_sink();
    plane.outbound = outbound.get();
    wgl::Tunnel tunnel = wgl::tunnel_from_session(std::move(session), est.profile, plane,
                                                  wg_run_env(settings, cancel), est.local_ipv4);
    Hop* raw = hop.get();
    hop->add_thread(std::thread([raw, &cancel] { pump_hop(*raw, cancel); }));
    hop->add_thread(std::thread([raw, held = std::move(outbound), tunnel = std::move(tunnel),
                                 &cancel]() mutable {
        auto done = wgl::run_tunnel(tunnel, cancel);
        if (!done.has_value()) raw->finish(done.error().display());
        else raw->finish(std::nullopt);
        raw->stop().set();
    }));
    return hop;
}

// run_warp_in_warp (lib.rs:2738): the outer WARP hop, a loopback UDP forwarder for the inner
// edge, the inner WARP hop through it, then the listeners on the inner hop. Like MIM, the end
// is always a reconnect.
[[nodiscard]] Exec run_wiw_tunnel(const FlowRequest& request, FlowReply& reply,
                                  const ExecContext& ctx) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;
    if (ctx.secondary == nullptr || !request.inner_peer.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other("warp-in-warp needs two endpoints");
        return Exec::Ran;
    }
    const SocketAddr outer_peer = request.peer;
    const SocketAddr inner_peer = *request.inner_peer;
    if (auto prechecked = cf::warp_in_warp_precheck(outer_peer, inner_peer);
        !prechecked.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = prechecked.error();
        return Exec::Ran;
    }

    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    emit(Level::Info, cf::wiw_outer_line(outer_peer));
    Notes notes;
    auto outer_est = cf::wiw_outer_establish(settings, ctx.primary, notes);
    emit_all(notes);
    if (!outer_est.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = outer_est.error();
        return Exec::Ran;
    }
    auto outer_session = wg_verify_keep_session(
        ctx.primary, outer_peer, outer_est->profile,
        std::chrono::duration_cast<std::chrono::milliseconds>(outer_est->validate_timeout),
        outer_est->keepalive, settings, cancel);
    if (!outer_session.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(cf::wg_validation_error("outer", outer_session.error()));
        return Exec::Ran;
    }
    emit(Level::Info, cf::wg_validated_line("outer"));
    auto outer = start_wg_hop(std::move(*outer_session), *outer_est, ctx.primary, settings,
                              routes, cancel);
    if (!outer.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(outer.error());
        return Exec::Ran;
    }

    auto fwd = UdpForwarder::open(**outer, inner_peer, cancel);
    if (!fwd.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(fwd.error());
        return Exec::Ran;
    }
    emit(Level::Info, cf::wiw_forwarder_line(inner_peer, (*fwd)->local()));

    emit(Level::Info, std::string(cf::WIW_INNER_LINE));
    auto inner_est = cf::wiw_inner_establish(settings, *ctx.secondary, notes);
    emit_all(notes);
    if (!inner_est.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = inner_est.error();
        return Exec::Ran;
    }
    auto inner_session = wg_verify_keep_session(
        *ctx.secondary, (*fwd)->local(), inner_est->profile,
        std::chrono::duration_cast<std::chrono::milliseconds>(inner_est->validate_timeout),
        inner_est->keepalive, settings, cancel);
    if (!inner_session.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(cf::wg_validation_error("inner", inner_session.error()));
        return Exec::Ran;
    }
    emit(Level::Info, cf::wg_validated_line("inner"));
    auto inner = start_wg_hop(std::move(*inner_session), *inner_est, *ctx.secondary, settings,
                              routes, cancel);
    if (!inner.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(inner.error());
        return Exec::Ran;
    }

    const std::optional<xloc::Policy> policy = xloc::Policy::from_env(settings);
    if (auto settled = exit_settle(**inner, settings, policy, "warp-in-warp");
        !settled.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(std::move(settled.error()));
        return Exec::Ran;
    }

    const cf::HttpProxyListen http = cf::http_proxy_listen(settings);
    if (http.warning.has_value()) emit(Level::Warn, *http.warning);
    ProxyOptions options{settings, routes, ctx.listen, http.listen};
    Hop& inner_ref = **inner;
    (*inner)->add_thread(std::thread([&inner_ref, &options, &cancel] {
        serve_proxy(inner_ref, options, options.socks_listen, "socks5", false, cancel);
    }));
    if (options.http_listen.has_value()) {
        const SocketAddr http_listen = *options.http_listen;
        (*inner)->add_thread(std::thread([&inner_ref, &options, &cancel, http_listen] {
            serve_proxy(inner_ref, options, http_listen, "http proxy", true, cancel);
        }));
    }
    if (policy.has_value()) exit_watch(**inner, settings, *policy, cancel);

    while (!(*outer)->finished() && !(*inner)->finished() && !cancel.is_cancelled() &&
           !(*outer)->stop().asked() && !(*inner)->stop().asked()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    (*outer)->stop().set();
    (*inner)->stop().set();
    (*outer)->join_carriers();
    (*inner)->join_carriers();
    if (cancel.is_cancelled()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error{ErrorKind::Cancelled, std::string()};
        return Exec::Ran;
    }
    cf::JoinOutcome outcome;
    std::string what;
    if ((*outer)->finished()) {
        what = "outer wireguard tunnel";
        if (const auto err = (*outer)->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    } else {
        what = "inner wireguard tunnel";
        if (const auto err = (*inner)->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    }
    reply = FlowReply{};
    reply.ok = false;
    reply.error = Error::other(cf::join_outcome(what, outcome));
    return Exec::Ran;
}

// run_masque_in_masque (lib.rs:1875): the outer MASQUE hop, then one inner hop per candidate
// through a loopback forwarder until one answers, then the listeners on the inner hop. The end
// is always a reconnect: join_outcome names whichever hop stopped first.
[[nodiscard]] Exec run_mim_tunnel(const FlowRequest& request, FlowReply& reply,
                                  const ExecContext& ctx) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;
    if (ctx.secondary == nullptr) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other("masque-in-masque needs two identities");
        return Exec::Ran;
    }
    const SocketAddr outer_peer = request.peer;
    const bool h2 = carrier_h2::enabled(settings);
    const std::size_t outer_mtu = cf::masque_tunnel_mtu(settings);
    emit(Level::Info, cf::mim_establishing_line(outer_peer));

    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    auto outer = std::make_unique<Hop>(settings, outer_mtu);
    TunnelObserver outer_observer;
    Notes notes;
    cf::MasqueHopParams outer_params = cf::establish_masque_params(
        settings, ctx.primary, outer_peer, ech_for(request, ctx), h2, outer_mtu,
        quic::MAX_DATAGRAM_SIZE, true, cf::masque_startup_timeout(settings), "outer", notes);
    emit_all(notes);
    emit(Level::Info, outer_params.transport_line);
    auto outer_ready =
        start_masque_hop(*outer, outer_params, settings, ctx.primary, routes, outer_observer, cancel);
    if (!outer_ready.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(outer_ready.error());
        return Exec::Ran;
    }
    if (*outer_ready != cf::StartupVerdict::Ready) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(cf::startup_verdict_error(
            "outer", *outer_ready, outer->error().value_or(std::string()),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                cf::masque_startup_timeout(settings))));
        return Exec::Ran;
    }

    const std::vector<cf::MimAttempt> plan =
        cf::mim_inner_plan(outer_mtu, h2, outer_peer, request.candidates);
    std::unique_ptr<Hop> inner;
    std::unique_ptr<UdpForwarder> udp_fwd;
    std::unique_ptr<TcpForwarder> tcp_fwd;
    SocketAddr inner_peer{};
    bool chosen = false;
    const ProxyOptions outer_options{settings, routes, ctx.listen, std::nullopt};
    for (const cf::MimAttempt& attempt : plan) {
        if (cancel.is_cancelled()) {
            reply = FlowReply{};
            reply.ok = false;
            reply.error = Error{ErrorKind::Cancelled, std::string()};
            return Exec::Ran;
        }
        if (attempt.warn_too_small) emit(Level::Warn, cf::mim_too_small_warning(outer_mtu));
        SocketAddr forwarder;
        if (h2) {
            auto opened = TcpForwarder::open(*outer, outer_options, attempt.inner_peer, cancel);
            if (!opened.has_value()) {
                reply = FlowReply{};
                reply.ok = false;
                reply.error = Error::other(opened.error());
                return Exec::Ran;
            }
            tcp_fwd = std::move(*opened);
            forwarder = tcp_fwd->local();
        } else {
            auto opened = UdpForwarder::open(*outer, attempt.inner_peer, cancel);
            if (!opened.has_value()) {
                reply = FlowReply{};
                reply.ok = false;
                reply.error = Error::other(opened.error());
                return Exec::Ran;
            }
            udp_fwd = std::move(*opened);
            forwarder = udp_fwd->local();
        }
        emit(Level::Info, cf::mim_trying_line(attempt.inner_peer, forwarder));

        inner = std::make_unique<Hop>(settings, attempt.mtu);
        TunnelObserver inner_observer;
        Notes inner_notes;
        cf::MasqueHopParams inner_params = cf::establish_masque_params(
            settings, *ctx.secondary, forwarder, std::nullopt, h2, attempt.mtu, attempt.datagram,
            false, cf::mim_inner_startup(settings), "inner", inner_notes);
        emit_all(inner_notes);
        emit(Level::Info, inner_params.transport_line);
        auto inner_ready = start_masque_hop(*inner, inner_params, settings, *ctx.secondary,
                                            routes, inner_observer, cancel);
        if (inner_ready.has_value() && *inner_ready == cf::StartupVerdict::Ready) {
            inner_peer = attempt.inner_peer;
            chosen = true;
            emit(Level::Info, cf::mim_inner_ok_line(inner_peer));
            break;
        }
        const std::string detail =
            !inner_ready.has_value()
                ? inner_ready.error()
                : (*inner_ready == cf::StartupVerdict::FailedBeforeValidation &&
                           inner->error().has_value()
                     ? *inner->error()
                     : cf::startup_verdict_error(
                           "inner", *inner_ready, inner->error().value_or(std::string()),
                           std::chrono::duration_cast<std::chrono::milliseconds>(
                               cf::mim_inner_startup(settings))));
        emit(Level::Info, cf::mim_inner_fail_line(attempt.inner_peer, detail));
        inner.reset();
    }
    if (!chosen) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(std::string(cf::NO_INNER_MASQUE_EDGE));
        return Exec::Ran;
    }

    const std::optional<xloc::Policy> policy = xloc::Policy::from_env(settings);
    if (auto settled = exit_settle(*inner, settings, policy, "masque-in-masque");
        !settled.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(std::move(settled.error()));
        return Exec::Ran;
    }

    const cf::HttpProxyListen http = cf::http_proxy_listen(settings);
    if (http.warning.has_value()) emit(Level::Warn, *http.warning);
    ProxyOptions options{settings, routes, ctx.listen, http.listen};
    Hop& inner_ref = *inner;
    inner->add_thread(std::thread([&inner_ref, &options, &cancel] {
        serve_proxy(inner_ref, options, options.socks_listen, "socks5", false, cancel);
    }));
    if (options.http_listen.has_value()) {
        const SocketAddr http_listen = *options.http_listen;
        inner->add_thread(std::thread([&inner_ref, &options, &cancel, http_listen] {
            serve_proxy(inner_ref, options, http_listen, "http proxy", true, cancel);
        }));
    }
    if (policy.has_value()) exit_watch(*inner, settings, *policy, cancel);
    emit(Level::Info, cf::mim_ready_line(outer_peer, inner_peer));

    while (!outer->finished() && !inner->finished() && !cancel.is_cancelled() &&
           !outer->stop().asked() && !inner->stop().asked()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    outer->stop().set();
    inner->stop().set();
    outer->join_carriers();
    inner->join_carriers();
    // join_outcome, always an error: the run below reconnects either way.
    cf::JoinOutcome outcome;
    std::string what;
    if (cancel.is_cancelled()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error{ErrorKind::Cancelled, std::string()};
        return Exec::Ran;
    }
    if (outer->finished()) {
        what = "outer masque tunnel";
        if (const auto err = outer->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    } else {
        what = "inner masque tunnel";
        if (const auto err = inner->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    }
    reply = FlowReply{};
    reply.ok = false;
    reply.error = Error::other(cf::join_outcome(what, outcome));
    return Exec::Ran;
}

// run_gool_tunnel (lib.rs:2886): the outer MASQUE hop, the inner WireGuard identity loaded
// or registered through the tunnel, one inner hop per candidate through a loopback forwarder,
// then the listeners on the inner hop. Like MIM, the end is always a reconnect.
[[nodiscard]] Exec run_gool_tunnel(const FlowRequest& request, FlowReply& reply,
                                   const ExecContext& ctx, std::string_view inner_path) {
    const Settings& settings = ctx.settings;
    const Cancel& cancel = ctx.cancel;
    const SocketAddr outer_peer = request.peer;
    const bool h2 = carrier_h2::enabled(settings);
    const std::size_t outer_mtu = cf::masque_tunnel_mtu(settings);

    std::vector<std::string> route_notes;
    const rt::RuleSet routes = rt::RuleSet::from_env(settings, route_notes);
    for (const std::string& line : route_notes) emit(Level::Warn, line);

    auto outer = std::make_unique<Hop>(settings, outer_mtu);
    TunnelObserver outer_observer;
    Notes notes;
    cf::MasqueHopParams outer_params = cf::establish_masque_params(
        settings, ctx.primary, cf::masque_dial_peer(settings, outer_peer), ech_for(request, ctx),
        h2, outer_mtu, quic::MAX_DATAGRAM_SIZE, true, cf::masque_startup_timeout(settings),
        "outer", notes);
    emit_all(notes);
    emit(Level::Info, outer_params.transport_line);
    auto outer_ready = start_masque_hop(*outer, outer_params, settings, ctx.primary, routes,
                                        outer_observer, cancel);
    if (!outer_ready.has_value() || *outer_ready != cf::StartupVerdict::Ready) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(
            !outer_ready.has_value()
                ? outer_ready.error()
                : cf::startup_verdict_error(
                      "outer", *outer_ready, outer->error().value_or(std::string()),
                      std::chrono::duration_cast<std::chrono::milliseconds>(
                          cf::masque_startup_timeout(settings))));
        return Exec::Ran;
    }

    // gool_inner_identity: the file when it is there, else a registration through the tunnel.
    Identity inner_identity;
    {
        auto loaded = ::aether::core::load_identity(std::string(inner_path));
        if (!loaded.has_value()) {
            reply = FlowReply{};
            reply.ok = false;
            reply.error = Error::other(loaded.error());
            return Exec::Ran;
        }
        if (loaded->has_value()) {
            inner_identity = std::move(**loaded);
            emit(Level::Info, cf::gool_identity_loaded_line(inner_path));
        } else {
            // A loopback SOCKS5 listener serving the outer stack, on an ephemeral port, so the
            // registration below dials the WARP API through the masque tunnel.
            SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                reply = FlowReply{};
                reply.ok = false;
                reply.error = Error::other("gool listener: socket failed");
                return Exec::Ran;
            }
            sockaddr_in loop{};
            loop.sin_family = AF_INET;
            loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            loop.sin_port = 0;
            std::optional<SocketAddr> through;
            if (::bind(listener, reinterpret_cast<sockaddr*>(&loop), sizeof loop) == 0 &&
                ::listen(listener, 16) == 0) {
                sockaddr_in bound{};
                int len = sizeof bound;
                if (getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &len) == 0) {
                    SocketAddr addr;
                    addr.ip.v4 = true;
                    std::memcpy(addr.ip.bytes.data() + 12, &bound.sin_addr.s_addr, 4);
                    addr.port = ntohs(bound.sin_port);
                    through = addr;
                }
            }
            if (!through.has_value()) {
                const int code = WSAGetLastError();
                closesocket(listener);
                reply = FlowReply{};
                reply.ok = false;
                reply.error =
                    Error::other("gool listener: bind failed (" + std::to_string(code) + ")");
                return Exec::Ran;
            }
            u_long nonblock = 1;
            ::ioctlsocket(listener, FIONBIO, &nonblock);
            ProxyOptions temp_options{settings, routes, *through, std::nullopt};
            std::atomic<bool> temp_stop{false};
            std::mutex clients_mutex;
            std::vector<std::thread> clients;
            std::thread temp([&, listener] {
                while (!temp_stop.load() && !cancel.is_cancelled() &&
                       !outer->stop().asked()) {
                    fd_set read;
                    FD_ZERO(&read);
                    FD_SET(listener, &read);
                    timeval slice{};
                    slice.tv_usec = 50'000;
                    if (::select(0, &read, nullptr, nullptr, &slice) <= 0) continue;
                    const SOCKET raw = ::accept(listener, nullptr, nullptr);
                    if (raw == INVALID_SOCKET) continue;
                    u_long nb = 1;
                    ::ioctlsocket(raw, FIONBIO, &nb);
                    const SocketAddr nobody{};
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    clients.emplace_back([&, raw] {
                        serve_socks_client(*outer, temp_options, outer->stop(), raw, nobody);
                    });
                }
            });
            emit(Level::Info, std::string(cf::GOOL_REGISTERING_LINE));
            Settings through_settings = settings;
            through_settings.set("AETHER_UPSTREAM", "socks5h://" + through->to_string());
            aether::core::account::LiveEnv live_env;
            live_env.settings = &through_settings;
            live_env.ech_transport = make_ech_transport(through_settings);
            live_env.team_hooks = make_team_hooks(through_settings);
            live_env.info = [](const std::string& line) { emit(Level::Info, line); };
            live_env.warn = [](const std::string& line) { emit(Level::Warn, line); };
            live_env.debug = [](const std::string& line) { emit(Level::Debug, line); };
            auto registered = aether::core::account::provision_wg(
                ::aether::core::DEFAULT_MODEL, ::aether::core::DEFAULT_LOCALE, std::nullopt,
                live_env);
            temp_stop.store(true);
            if (temp.joinable()) temp.join();
            for (std::thread& client : clients) {
                if (client.joinable()) client.join();
            }
            closesocket(listener);
            if (!registered.has_value()) {
                reply = FlowReply{};
                reply.ok = false;
                reply.error = to_flow_error(registered.error());
                return Exec::Ran;
            }
            inner_identity = std::move(*registered);
            if (auto enabled = aether::core::account::enable_warp(inner_identity.device_id,
                                                                  inner_identity.access_token,
                                                                  live_env);
                !enabled.has_value()) {
                emit(Level::Warn, cf::gool_enable_warp_warn(
                                      to_flow_error(enabled.error()).display()));
            }
            if (auto saved = ::aether::core::save_identity(std::string(inner_path), inner_identity);
                !saved.has_value()) {
                reply = FlowReply{};
                reply.ok = false;
                reply.error = Error::other(saved.error());
                return Exec::Ran;
            }
            emit(Level::Info, cf::gool_identity_saved_line(inner_path, inner_identity));
        }
    }

    auto candidates = cf::gool_inner_peers(settings, inner_identity);
    if (!candidates.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = candidates.error();
        return Exec::Ran;
    }
    const std::vector<cf::GoolAttempt> plan = cf::gool_attempt_plan(*candidates);

    auto inner_est = cf::gool_inner_establish(settings, inner_identity, notes);
    emit_all(notes);
    if (!inner_est.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = inner_est.error();
        return Exec::Ran;
    }

    std::unique_ptr<Hop> inner;
    std::unique_ptr<UdpForwarder> fwd;
    SocketAddr inner_peer{};
    SocketAddr last_peer{};
    std::string last_error = "no wireguard endpoint to try";
    for (const cf::GoolAttempt& attempt : plan) {
        if (cancel.is_cancelled()) {
            reply = FlowReply{};
            reply.ok = false;
            reply.error = Error{ErrorKind::Cancelled, std::string()};
            return Exec::Ran;
        }
        if (attempt.inner_peer != last_peer || fwd == nullptr) {
            auto opened = UdpForwarder::open(*outer, attempt.inner_peer, cancel);
            if (!opened.has_value()) {
                last_error = opened.error();
                continue; // the next candidate gets its own forwarder
            }
            fwd = std::move(*opened);
            last_peer = attempt.inner_peer;
        }
        emit(Level::Info, cf::gool_attempt_line(attempt.inner_peer, fwd->local()));
        auto session = wg_verify_keep_session(
            inner_identity, fwd->local(), inner_est->profile,
            std::chrono::duration_cast<std::chrono::milliseconds>(inner_est->validate_timeout),
            inner_est->keepalive, settings, cancel);
        if (!session.has_value()) {
            last_error = session.error();
            emit(Level::Warn,
                 cf::gool_attempt_fail_line(attempt.inner_peer, attempt.attempt, last_error));
            continue;
        }
        auto hop = start_wg_hop(std::move(*session), *inner_est, inner_identity, settings, routes,
                                cancel);
        if (!hop.has_value()) {
            last_error = hop.error();
            emit(Level::Warn,
                 cf::gool_attempt_fail_line(attempt.inner_peer, attempt.attempt, last_error));
            continue;
        }
        inner = std::move(*hop);
        inner_peer = attempt.inner_peer;
        break;
    }
    if (inner == nullptr) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(last_error);
        return Exec::Ran;
    }

    if (cf::gool_remembers(settings, inner_identity, inner_peer.ip)) {
        Identity remembered = inner_identity;
        remembered.assigned_endpoint = sk::address_text(inner_peer.ip);
        if (auto saved = ::aether::core::save_identity(std::string(inner_path), remembered);
            saved.has_value()) {
            emit(Level::Info, cf::gool_remember_line(inner_peer.ip));
        }
    }

    const std::optional<xloc::Policy> policy = xloc::Policy::from_env(settings);
    if (auto settled = exit_settle(*inner, settings, policy, "gool"); !settled.has_value()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error::other(std::move(settled.error()));
        return Exec::Ran;
    }

    const cf::HttpProxyListen http = cf::http_proxy_listen(settings);
    if (http.warning.has_value()) emit(Level::Warn, *http.warning);
    ProxyOptions options{settings, routes, ctx.listen, http.listen};
    Hop& inner_ref = *inner;
    inner->add_thread(std::thread([&inner_ref, &options, &cancel] {
        serve_proxy(inner_ref, options, options.socks_listen, "socks5", false, cancel);
    }));
    if (options.http_listen.has_value()) {
        const SocketAddr http_listen = *options.http_listen;
        inner->add_thread(std::thread([&inner_ref, &options, &cancel, http_listen] {
            serve_proxy(inner_ref, options, http_listen, "http proxy", true, cancel);
        }));
    }
    if (policy.has_value()) exit_watch(*inner, settings, *policy, cancel);
    emit(Level::Info, cf::gool_ready_line(outer_peer, inner_peer));

    while (!outer->finished() && !inner->finished() && !cancel.is_cancelled() &&
           !outer->stop().asked() && !inner->stop().asked()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    outer->stop().set();
    inner->stop().set();
    outer->join_carriers();
    inner->join_carriers();
    if (cancel.is_cancelled()) {
        reply = FlowReply{};
        reply.ok = false;
        reply.error = Error{ErrorKind::Cancelled, std::string()};
        return Exec::Ran;
    }
    cf::JoinOutcome outcome;
    std::string what;
    if (outer->finished()) {
        what = "outer masque tunnel";
        if (const auto err = outer->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    } else {
        what = "inner wireguard tunnel";
        if (const auto err = inner->error()) outcome = {cf::JoinOutcome::Kind::Failed, *err};
    }
    reply = FlowReply{};
    reply.ok = false;
    reply.error = Error::other(cf::join_outcome(what, outcome));
    return Exec::Ran;
}

[[nodiscard]] Exec run_tunnel(const FlowRequest& request, FlowReply& reply, const ExecContext& ctx) {
    switch (request.shape) {
        case cf::RunShape::MasqueTunnel:
            return run_masque_tunnel(request, reply, ctx);
        case cf::RunShape::WireguardTunnel:
            return run_wg_tunnel(request, reply, ctx);
        case cf::RunShape::MasqueInMasque:
            return run_mim_tunnel(request, reply, ctx);
        case cf::RunShape::WarpInWarp:
            return run_wiw_tunnel(request, reply, ctx);
        case cf::RunShape::GoolTunnel:
            return run_gool_tunnel(request, reply, ctx, request.gool_inner_path);
    }
    return Exec::Refused;
}

[[nodiscard]] Exec execute(const FlowRequest& request, FlowReply& reply, const ExecContext& ctx) {
    const Cancel& cancel = ctx.cancel;
    switch (request.kind) {
        case FlowRequest::Kind::Sleep:
            interruptible_sleep(request.delay, cancel);
            reply = FlowReply{};
            return Exec::Ran;
        case FlowRequest::Kind::SaveLastconn: {
            // lastconn.cpp owns the file; this is real filesystem work, so it is wired. A failed
            // write is only a warn line, which is how lib.rs treats it (the run carries on).
            const auto saved = save_last_connection(
                request.path, request.peer_text, request.profile, request.carrier);
            if (!saved.has_value()) emit(Level::Warn, "[-] lastconn: " + saved.error());
            reply = FlowReply{};
            return Exec::Ran;
        }
        case FlowRequest::Kind::VerifyMasquePeer: {
            // lib.rs:1299 quick_verify_masque_peer: the answer is a bool, and the flow's warn line
            // for a failed check is coreflow's own. The budget is the request's, which is the Rust's
            // hard-coded from_secs(5) (QUICK_VERIFY_TIMEOUT). H2 runs its own check
            // (lib.rs:1317-1334) -- never a QUIC fallback, which would be invisible to --h2.
            if (carrier_h2::enabled(ctx.settings)) {
                Notes notes;
                const carrier_h2::H2TunnelConfig cfg = cf::quick_verify_h2_config(
                    ctx.settings, ctx.primary, request.peer, ech_for(request, ctx), notes);
                emit_all(notes);
                const CheckOutcome check = verify_h2(
                    ctx.settings, cfg,
                    std::chrono::duration_cast<std::chrono::milliseconds>(request.timeout),
                    cancel);
                reply = FlowReply{};
                reply.ok = check.ok;
                reply.rtt = check.rtt;
                if (!check.ok) reply.error = Error::other(check.error);
                return Exec::Ran;
            }
            Notes notes;
            const quic::VerifyParams params = cf::quick_verify_quic_params(
                ctx.settings, ctx.primary, request.peer, ech_for(request, ctx), notes);
            emit_all(notes); // noize_config's profile line, which the Rust writes on the way
            const CheckOutcome check = verify_quic(ctx.settings, params, cancel);
            reply = FlowReply{};
            reply.ok = check.ok;
            reply.rtt = check.rtt;
            if (!check.ok) reply.error = Error::other(check.error);
            return Exec::Ran;
        }
        case FlowRequest::Kind::HuntMasquePeer: {
            reply = FlowReply{};
            hunt_masque(ctx, request, reply);
            return Exec::Ran;
        }
        case FlowRequest::Kind::RunTunnel:
            return run_tunnel(request, reply, ctx);
        case FlowRequest::Kind::VerifyWgEndpoint: {
            // wireguard::verify_endpoint on one throwaway session: the answer is a bool to the
            // flow, and the flow's own lines name the profile. The budget is the request's.
            const CheckOutcome check = verify_wg(
                ctx.settings, request.peer, request.noise,
                std::chrono::duration_cast<std::chrono::milliseconds>(request.timeout),
                request.keepalive, ctx.primary, cancel);
            reply = FlowReply{};
            reply.ok = check.ok;
            reply.rtt = check.rtt;
            if (!check.ok) reply.error = Error::other(check.error);
            return Exec::Ran;
        }
        case FlowRequest::Kind::HuntWgEndpoint: {
            reply = FlowReply{};
            hunt_wg(ctx, request, reply, request.noise, 1);
            if (reply.ok) {
                reply.profile = request.noise;
                reply.profile_name = request.profile_name;
            }
            return Exec::Ran;
        }
        case FlowRequest::Kind::HuntWgPeers: {
            // select_wg_peers (lib.rs:1134): one hunt for `want` endpoints, the avoid filter and
            // the per-pick lines here, the take(want) in the flow's own post-filter.
            reply = FlowReply{};
            hunt_wg(ctx, request, reply, request.noise,
                    request.want == 0 ? 1 : request.want);
            if (!reply.ok) return Exec::Ran;
            for (const auto& pick : reply.results) {
                emit(Level::Info, cf::wg_selected_line(pick));
            }
            return Exec::Ran;
        }
    }
    return Exec::Refused;
}

// The stop the executor owes: name the request that cannot be carried out, exit 1. No success is
// printed. Unreachable for every Kind the flow knows today (THE WOVEN LIST above); kept for any
// future Kind the flow learns before the engine does.
[[nodiscard]] int unwired(const FlowRequest& request) {
    emit(Level::Error, "[-] aether-core: tunnel executor not wired for FlowRequest::Kind::" +
                           request_kind_name(request.kind) +
                           " -- see core/src/aether_cli.cpp THE WOVEN LIST");
    return 1;
}

// ---- the flow loop ------------------------------------------------------------------------------

// lib.rs's run_masque / run_gool / run_mim become synchronous state machines (coreflow.hpp). The
// engine's whole job is: print what each step decided, carry out the one request, answer it, repeat.
// The context is what execute() reads for identity / listen / ECH -- built from flow.config() by the
// caller, so the references land on the flow that owns them.
template <class Flow>
[[nodiscard]] int drive(Flow& flow, const ExecContext& ctx) {
    FlowStep step = flow.begin();
    emit_all(step.notes);
    while (step.request.has_value()) {
        if (ctx.cancel.is_cancelled()) break;
        FlowReply reply;
        if (execute(*step.request, reply, ctx) == Exec::Refused) return unwired(*step.request);
        step = flow.resume(reply);
        emit_all(step.notes);
    }
    if (ctx.cancel.is_cancelled() || flow.cancelled()) return 0;
    if (flow.fatal().has_value()) return fail(*flow.fatal());
    return 0;
}

// run_wireguard reads a clock for its endpoint cooldowns, so its loop passes `now` to each call.
[[nodiscard]] int drive_wireguard(cf::WireguardFlow& flow, const ExecContext& ctx) {
    const auto now = std::chrono::steady_clock::now();
    FlowStep step = flow.begin(now);
    emit_all(step.notes);
    while (step.request.has_value()) {
        if (ctx.cancel.is_cancelled()) break;
        FlowReply reply;
        if (execute(*step.request, reply, ctx) == Exec::Refused) return unwired(*step.request);
        step = flow.resume(reply, now);
        emit_all(step.notes);
    }
    if (ctx.cancel.is_cancelled() || flow.cancelled()) return 0;
    if (flow.fatal().has_value()) return fail(*flow.fatal());
    return 0;
}

// ---- reporting a fatal error --------------------------------------------------------------------

// main.rs returns run()'s Result, so Rust's default Termination writes `Error: {e:?}` (the AetherError
// Debug: Variant("message")) to stderr and exits 1. error.rs's #[derive(Error, Debug)] gives string
// variants the shape `Variant("text")` and the unit variants just `Variant`. Io/Quic/H3 wrap a foreign
// error whose Debug this port cannot reproduce, so their payload is shown as its own message.
[[nodiscard]] std::string quote(std::string_view text) {
    std::string out = "\"";
    for (const unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char escape[8];
                    std::snprintf(escape, sizeof escape, "\\u{%x}", c);
                    out += escape;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += "\"";
    return out;
}

[[nodiscard]] std::string fatal_line(const Error& error) {
    switch (error.kind) {
        case ErrorKind::NoCleanEndpoint: return "Error: NoCleanEndpoint";
        case ErrorKind::Cancelled: return "Error: Cancelled";
        case ErrorKind::Quic: return "Error: Quic(" + quote(error.message) + ")";
        case ErrorKind::H3: return "Error: H3(" + quote(error.message) + ")";
        case ErrorKind::Io: return "Error: Io(" + quote(error.message) + ")";
        case ErrorKind::Tls: return "Error: Tls(" + quote(error.message) + ")";
        case ErrorKind::Ech: return "Error: Ech(" + quote(error.message) + ")";
        case ErrorKind::Masque: return "Error: Masque(" + quote(error.message) + ")";
        case ErrorKind::Capsule: return "Error: Capsule(" + quote(error.message) + ")";
        case ErrorKind::Api: return "Error: Api(" + quote(error.message) + ")";
        case ErrorKind::IdentityRefused: return "Error: IdentityRefused(" + quote(error.message) + ")";
        case ErrorKind::Other: break;
    }
    return "Error: Other(" + quote(error.message) + ")";
}

[[nodiscard]] int fail(const Error& error) {
    std::fprintf(stderr, "%s\n", fatal_line(error).c_str());
    std::fflush(stderr);
    return 1;
}

// ---- the dispatch (lib.rs:232-305) --------------------------------------------------------------

// The four run_* are chosen by RunPlan. Every protocol first needs an identity, which needs the
// account seams (NOT WIRED 1-6); that stop is reached before any socket opens.
[[nodiscard]] int run_dispatch(Settings& settings, const cf::Startup& started,
                              const cf::RunPlan& plan, cf::StartupHooks& hooks, Cancel& cancel) {
    const cf::AccountSeams seams = make_account_seams(settings);
    const cf::EchTransport ech_transport = make_ech_transport(settings);
    cf::Notes notes;

    if (plan.asks_masque_transport) cf::select_masque_transport(settings, hooks.prompt, notes);
    emit_all(notes);
    notes.clear();

    switch (plan.kind) {
        case cf::RunKind::Masque:
        case cf::RunKind::GoolOverMasque: {
            auto identity = cf::load_or_provision_masque(settings, plan.primary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!identity.has_value()) return fail(identity.error());
            emit(Level::Info, plan.kind == cf::RunKind::Masque
                                  ? cf::identity_ready_line(*identity)
                                  : cf::gool_plan_line(*identity, plan.gool_inner_path));

            auto ech = cf::resolve_ech(settings, ech_transport, notes);
            emit_all(notes);
            notes.clear();
            if (!ech.has_value()) return fail(ech.error());

            std::optional<LastConnection> cached;
            if (plan.lastconn.has_value()) cached = load_last_connection(*plan.lastconn);

            const std::optional<std::string> gool_inner = plan.kind == cf::RunKind::GoolOverMasque
                                                              ? std::optional<std::string>(plan.gool_inner_path)
                                                              : std::nullopt;
            cf::MasqueFlow::Config config{settings,
                                          hooks.prompt,
                                          cancel,
                                          std::move(*identity),
                                          started.listen,
                                          plan.lastconn.value_or(std::string()),
                                          cached,
                                          std::move(*ech),
                                          gool_inner};
            cf::MasqueFlow flow(std::move(config));
            const ExecContext ctx{settings, flow.config().identity, nullptr, flow.config().listen,
                                  flow.config().ech, cancel};
            return drive(flow, ctx);
        }
        case cf::RunKind::WireGuard: {
            auto identity = cf::load_or_provision_warp(settings, plan.primary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!identity.has_value()) return fail(identity.error());
            emit(Level::Info, cf::identity_ready_line(*identity));

            std::optional<LastConnection> cached;
            if (plan.lastconn.has_value()) cached = load_last_connection(*plan.lastconn);

            cf::WireguardFlow::Config config{settings,
                                             hooks.prompt,
                                             cancel,
                                             std::move(*identity),
                                             started.listen,
                                             plan.lastconn.value_or(std::string()),
                                             cached};
            cf::WireguardFlow flow(std::move(config));
            const ExecContext ctx{settings, flow.config().identity, nullptr, flow.config().listen,
                                  std::nullopt, cancel};
            return drive_wireguard(flow, ctx);
        }
        case cf::RunKind::ClassicGool: {
            auto primary = cf::load_or_provision_warp(settings, plan.primary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!primary.has_value()) return fail(primary.error());
            auto secondary = cf::load_or_provision_warp(settings, plan.secondary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!secondary.has_value()) return fail(secondary.error());
            emit(Level::Info, cf::pair_ready_line(*primary, *secondary));

            cf::GoolFlow::Config config{settings,
                                        hooks.prompt,
                                        cancel,
                                        std::move(*primary),
                                        std::move(*secondary),
                                        started.listen};
            cf::GoolFlow flow(std::move(config));
            const ExecContext ctx{settings, flow.config().primary, &flow.config().secondary,
                                  flow.config().listen, std::nullopt, cancel};
            return drive(flow, ctx);
        }
        case cf::RunKind::Mim: {
            auto primary = cf::load_or_provision_masque(settings, plan.primary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!primary.has_value()) return fail(primary.error());
            auto secondary = cf::load_or_provision_masque(settings, plan.secondary_path, seams, notes);
            emit_all(notes);
            notes.clear();
            if (!secondary.has_value()) return fail(secondary.error());
            emit(Level::Info, cf::pair_ready_line(*primary, *secondary));

            auto ech = cf::resolve_ech(settings, ech_transport, notes);
            emit_all(notes);
            notes.clear();
            if (!ech.has_value()) return fail(ech.error());

            cf::MimFlow::Config config{settings,
                                       hooks.prompt,
                                       cancel,
                                       std::move(*primary),
                                       std::move(*secondary),
                                       started.listen,
                                       aether::core::prober::default_random(),
                                       std::move(*ech)};
            cf::MimFlow flow(std::move(config));
            const ExecContext ctx{settings, flow.config().primary, &flow.config().secondary,
                                  flow.config().listen, flow.config().ech, cancel};
            return drive(flow, ctx);
        }
    }
    return 0;
}

// ---- crash report -------------------------------------------------------------------------------
//
// A silent death is undebuggable, and this binary has died silently before: install an
// unhandled-exception filter and a terminate handler that print the fault before the process
// goes. Raw module-relative addresses (RVA) only -- resolving names needs symbols the Release
// binary does not ship, and an RVA maps straight onto dumpbin /DIA output for whoever holds the
// matching binary. The filter returns EXECUTE_HANDLER so the process still exits with the
// exception's own code; the terminate handler aborts, as terminate would.

void crash_print_rva(const char* what, const void* addr) {
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "[FATAL] aether %s at %p (no module list)\n", what, addr);
        std::fflush(stderr);
        return;
    }
    MODULEENTRY32 entry{};
    entry.dwSize = sizeof entry;
    const auto here = reinterpret_cast<std::uintptr_t>(addr);
    if (Module32First(snapshot, &entry) != FALSE) {
        do {
            const auto base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            if (here >= base && here < base + entry.modBaseSize) {
                std::fprintf(stderr, "[FATAL] aether %s at %ls+0x%zx\n", what, entry.szModule,
                             here - base);
                std::fflush(stderr);
                CloseHandle(snapshot);
                return;
            }
        } while (Module32Next(snapshot, &entry) != FALSE);
    }
    CloseHandle(snapshot);
    std::fprintf(stderr, "[FATAL] aether %s at %p (outside all modules)\n", what, addr);
    std::fflush(stderr);
}

LONG WINAPI crash_filter(EXCEPTION_POINTERS* info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    std::fprintf(stderr, "[FATAL] aether crashed: exception 0x%08lx\n",
                 static_cast<unsigned long>(code));
    std::fflush(stderr);
    crash_print_rva("fault", info->ExceptionRecord->ExceptionAddress);
    void* frames[16]{};
    const WORD taken = CaptureStackBackTrace(0, 16, frames, nullptr);
    for (WORD i = 0; i < taken; ++i) {
        char slot[32]{};
        std::snprintf(slot, sizeof slot, "stack#%u", static_cast<unsigned>(i));
        crash_print_rva(slot, frames[i]);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void crash_terminated() {
    std::fprintf(stderr, "[FATAL] aether terminated: uncaught exception\n");
    std::fflush(stderr);
    void* frames[16]{};
    const WORD taken = CaptureStackBackTrace(0, 16, frames, nullptr);
    for (WORD i = 0; i < taken; ++i) {
        char slot[32]{};
        std::snprintf(slot, sizeof slot, "stack#%u", static_cast<unsigned>(i));
        crash_print_rva(slot, frames[i]);
    }
    std::abort();
}

void install_crash_report() {
    // The vectored handler runs before the unhandled filter and -- unlike it -- also sees
    // fail-fast exceptions (0xC0000409, the /GS cookie), which never reach the filter. It only
    // reports: execution continues the search, so the exit code stays the exception's own.
    AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* info) -> LONG {
        const DWORD code = info->ExceptionRecord->ExceptionCode;
        std::fprintf(stderr, "[FATAL] aether crashed: exception 0x%08lx\n",
                     static_cast<unsigned long>(code));
        std::fflush(stderr);
        crash_print_rva("fault", info->ExceptionRecord->ExceptionAddress);
        void* frames[16]{};
        const WORD taken = CaptureStackBackTrace(0, 16, frames, nullptr);
        for (WORD i = 0; i < taken; ++i) {
            char slot[32]{};
            std::snprintf(slot, sizeof slot, "stack#%u", static_cast<unsigned>(i));
            crash_print_rva(slot, frames[i]);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    SetUnhandledExceptionFilter(&crash_filter);
    std::set_terminate(&crash_terminated);
}

// ---- Winsock lifetime ---------------------------------------------------------------------------

// Rust's tokio runtime brings Winsock up on the first socket; the GUI's port must do it itself
// before the listener probe. WSAStartup/WSACleanup are refcounted, so this guard is process-wide.
struct Winsock {
    Winsock() {
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        code_ = rc == 0 ? 0 : rc;
    }
    ~Winsock() {
        if (code_ == 0) WSACleanup();
    }
    [[nodiscard]] int code() const { return code_; }

    int code_ = -1;
};

} // namespace

namespace aether::core {

int run_inproc(const std::vector<std::string>& args,
               const std::map<std::string, std::string>& settings_env,
               Cancel& cancel,
               InprocCallbacks callbacks) {
    install_crash_report();
    const Winsock winsock;
    if (winsock.code() != 0) {
        if (callbacks.on_log) callbacks.on_log("Error: Io(\"WSAStartup 2.2 failed\")");
        return 1;
    }

    g_inproc_log_sink = callbacks.on_log;
    g_inproc_state_sink = callbacks.on_state_changed;

    Settings settings = settings_from_environment();
    for (const auto& [k, v] : settings_env) {
        settings.set(k, v);
    }

    cf::StartupHooks hooks;
    hooks.prompt = make_prompt();
    hooks.bind_listener = make_bind_listener();
    hooks.install_netstack_guard = [] {};
    hooks.spawn_stats_reporter = [&settings, &cancel, callbacks] {
        if (!::aether::core::enabled()) return;
        const auto every = ::aether::core::report_interval(settings);
        std::thread([every, settings, &cancel, callbacks] {
            while (!cancel.is_cancelled()) {
                interruptible_sleep(every, cancel);
                if (cancel.is_cancelled()) break;
                const auto counters = ::aether::core::snapshot();
                if (callbacks.on_stats) {
                    callbacks.on_stats(counters.up, counters.down, counters.uptime.count());
                }
                emit(Level::Info, "[=] up " + ::aether::core::format_bytes(counters.up) +
                                      " down " + ::aether::core::format_bytes(counters.down) +
                                      " uptime " +
                                      ::aether::core::format_uptime(counters.uptime));
            }
        }).detach();
    };
    hooks.team.prompt = hooks.prompt;
    hooks.team.hooks = make_team_hooks(settings);
    hooks.team.list_dir = make_list_dir();

    if (callbacks.on_state_changed) callbacks.on_state_changed("Connecting");

    auto started = cf::startup(args, settings, hooks);
    if (!started.has_value()) {
        if (callbacks.on_state_changed) callbacks.on_state_changed("Error");
        return fail(started.error());
    }

    if (started->kind == cf::Startup::Kind::Exit) {
        if (started->cli == CliOutcome::Version) out_line("aether " + std::string(cf::CORE_VERSION));
        else if (started->cli == CliOutcome::Help) out_raw(started->banner);
        return 0;
    }

    emit_all(started->notes);

    if (started->kind == cf::Startup::Kind::Register) {
        cf::Notes notes;
        auto ready = cf::register_identities(settings, *started->register_set, started->base_config,
                                             make_account_seams(settings), notes);
        emit_all(notes);
        if (!ready.has_value()) {
            if (callbacks.on_state_changed) callbacks.on_state_changed("Error");
            return fail(ready.error());
        }
        return 0;
    }

    const cf::RunPlan plan = cf::run_plan(settings, started->protocol, started->classic_gool,
                                         started->base_config);
    int res = run_dispatch(settings, *started, plan, hooks, cancel);
    if (callbacks.on_state_changed) {
        callbacks.on_state_changed(cancel.is_cancelled() ? "Disconnected" : (res == 0 ? "Disconnected" : "Error"));
    }
    return res;
}

} // namespace aether::core
