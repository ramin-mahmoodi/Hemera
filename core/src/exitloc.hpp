#pragma once

#include "settings.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aether::core::exitloc {

// Port of exitloc.rs: the country an exit lands in, read from Cloudflare's /cdn-cgi/trace, and
// the allow/deny policy the user asks for with AETHER_EXIT_LOC. Everything that decides is here;
// the sockets, the task spawns and the sleeps belong to the engine, which is where the event
// loop lives. The engine calls the pieces below in the order the Rust async functions did:
//
//   read_trace    : send trace_request(), feed the bytes it gets back to trace_answered() until
//                   that says stop, and use TIMEOUT_MESSAGE if LOOKUP_TIMEOUT runs out.
//   lookup        : lookup_from(body).
//   report        : parse_exit(body, rtt), then log report_line(); log probe_failure_line() when
//                   the trace cannot be read.
//   settle        : settle(policy, exit) once report has an answer, log the line it carries and
//                   stop on the error it carries. With no policy the engine spawns a background
//                   report itself, which is what the Rust spawn arm does.
//   watch         : sleep policy.interval(), look the location up again, hand the answer to
//                   watch_step() and act on what it returns.
//   report_through_socks is reqwest over a SOCKS proxy end to end: it stays with the engine.

inline constexpr std::string_view TRACE_HOST = "www.cloudflare.com";
inline constexpr std::string_view TRACE_PATH = "/cdn-cgi/trace";
inline constexpr std::uint16_t TRACE_PORT = 80;
inline constexpr std::chrono::seconds LOOKUP_TIMEOUT{10};
inline constexpr std::chrono::seconds DEFAULT_INTERVAL_SECS{60};
// A check period longer than a day is a typo, not a wish.
inline constexpr std::chrono::seconds MAX_INTERVAL_SECS{86'400};
// read_trace gives up on an answer that never carries a location once it passes this size.
inline constexpr std::size_t TRACE_BUFFER_LIMIT = 8192;

// The error text read_trace produces when the lookup times out; the timeout itself is the
// engine's to raise, so the message is what this module keeps.
inline constexpr std::string_view TIMEOUT_MESSAGE = "looking up the exit location timed out";

// The log level a Rust call site used; carried with the text so the ported line cannot silently
// change its level on the way to the logger.
enum class Level {
    Debug,
    Info,
    Warn,
};

struct LogLine {
    Level level = Level::Info;
    std::string text;
};

// AETHER_EXIT_LOC as a policy: a list of two-letter country codes an exit must (or must not)
// be in, checked every interval against the location the trace reports.
class Policy {
public:
    // Rust's parse() reads AETHER_EXIT_LOC_SECS itself; here the interval arrives as an argument
    // so parse stays pure and Settings remains the only source of environment, as in every
    // other ported module. from_env() wires the two together exactly like Rust did.
    [[nodiscard]] static std::optional<Policy> parse(std::string_view raw,
                                                     std::chrono::seconds interval);
    [[nodiscard]] static std::optional<Policy> from_env(const Settings& settings);

    [[nodiscard]] bool accepts(std::string_view loc) const;
    [[nodiscard]] std::string describe() const;
    [[nodiscard]] std::chrono::seconds interval() const;

private:
    std::vector<std::string> allow_;
    std::vector<std::string> deny_;
    std::chrono::seconds interval_ = DEFAULT_INTERVAL_SECS;
};

// AETHER_EXIT_LOC_SECS as the check interval: 0, junk and a missing value all mean the default,
// anything above a day is capped at a day.
[[nodiscard]] std::chrono::seconds interval_from_env(const Settings& settings);

// The two-letter location out of a trace body, or nothing when the body carries no usable loc.
[[nodiscard]] std::optional<std::string> parse_trace(std::string_view body);

// What an exit turned out to be, as the trace body and the round-trip time say.
struct Exit {
    std::optional<std::string> address;
    std::optional<std::string> country;
    std::optional<std::string> colo;
    bool warp = false;
    std::chrono::milliseconds rtt{0};

    [[nodiscard]] std::string describe() const;
};

[[nodiscard]] Exit parse_exit(std::string_view body, std::chrono::milliseconds rtt);

// The request read_trace writes to the socket, byte for byte.
[[nodiscard]] std::string trace_request();

// The stop condition read_trace applies to the bytes collected so far: the answer is done once
// it carries a location or the buffer has passed TRACE_BUFFER_LIMIT. Rust runs it on the lossy
// UTF-8 reading of the buffer; the loc= check is ASCII, and a byte view answers the same for
// every body a trace server really sends.
[[nodiscard]] bool trace_answered(std::string_view body);

// lookup's verdict once the body is in hand: the location, or the error the Rust core returns.
[[nodiscard]] std::expected<std::string, std::string> lookup_from(std::string_view body);

// The line report logs when it has read an exit, and the debug line it logs when it could not.
[[nodiscard]] std::string report_line(std::string_view what, const Exit& exit);
[[nodiscard]] LogLine probe_failure_line(std::string_view what, std::string_view error);

// settle once the report answer is in hand. The verdict is the line to log, and the error to
// stop on when the policy is not honoured. An empty verdict with no policy means the caller is
// in Rust's spawn arm: report in the background and carry on.
struct Verdict {
    std::optional<LogLine> log;
    std::optional<std::string> error;
};

[[nodiscard]] Verdict settle(const std::optional<Policy>& policy, const std::optional<Exit>& exit);

// One round of watch: the line the loop logs for this answer, and the error watch returns when
// the location has moved and the tunnel must reconnect.
struct WatchStep {
    LogLine log;
    std::optional<std::string> reconnect;
};

[[nodiscard]] WatchStep watch_step(const Policy& policy,
                                   const std::expected<std::string, std::string>& answer);

} // namespace aether::core::exitloc
