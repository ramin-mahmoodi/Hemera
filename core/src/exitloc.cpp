// Port of aether/src/exitloc.rs.

#include "exitloc.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <format>
#include <utility>

namespace aether::core::exitloc {
namespace {

// to_ascii_uppercase: only A-Z move, whatever the locale says about the rest.
std::string ascii_upper(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char byte) {
        return byte >= 'a' && byte <= 'z' ? static_cast<char>(byte - 'a' + 'A')
                                          : static_cast<char>(byte);
    });
    return out;
}

// eq_ignore_ascii_case.
bool same_ignore_case(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        const char a = left[i] >= 'a' && left[i] <= 'z' ? static_cast<char>(left[i] - 32) : left[i];
        const char b = right[i] >= 'a' && right[i] <= 'z' ? static_cast<char>(right[i] - 32) : right[i];
        if (a != b) return false;
    }
    return true;
}

// trim_start_matches: every leading instance of the character goes, not just one.
void strip_all(std::string_view& text, char marker) {
    while (!text.empty() && text.front() == marker) text.remove_prefix(1);
}

bool two_ascii_letters(const std::string& code) {
    return code.size() == 2 && std::all_of(code.begin(), code.end(), [](char byte) {
               return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
           });
}

std::string join(const std::vector<std::string>& items) {
    std::string out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i != 0) out += ", ";
        out += items[i];
    }
    return out;
}

// field(): the value of the first line that starts with `name=`. find_map stops on that line
// even when its value is empty, so `loc=` above `loc=DE` is no location at all.
std::optional<std::string> trace_field(std::string_view body, std::string_view name) {
    const std::string prefix = std::string(name) + "=";
    std::size_t at = 0;
    while (at < body.size()) {
        const std::size_t end = body.find('\n', at);
        std::string_view line =
            body.substr(at, end == std::string_view::npos ? std::string_view::npos : end - at);
        // Rust's str::lines drops the carriage return in front of each newline. Dropping one at
        // the end of the last line too changes nothing, since the value is trimmed below.
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.starts_with(prefix)) {
            const std::string_view value = trim(line.substr(prefix.size()));
            if (value.empty()) return std::nullopt;
            return std::string(value);
        }
        if (end == std::string_view::npos) break;
        at = end + 1;
    }
    return std::nullopt;
}

} // namespace

std::optional<Policy> Policy::parse(std::string_view raw, std::chrono::seconds interval) {
    const std::string_view spec = trim(raw);
    if (spec.empty() || same_ignore_case(spec, "any") || same_ignore_case(spec, "off")) {
        return std::nullopt;
    }

    const bool negated = spec.front() == '!';
    std::string_view body = spec;
    strip_all(body, '!');
    strip_all(body, '=');
    strip_all(body, '!');

    std::vector<std::string> codes;
    for (std::size_t at = 0;;) {
        const std::size_t comma = body.find(',', at);
        const std::string_view piece =
            body.substr(at, comma == std::string_view::npos ? std::string_view::npos : comma - at);
        // Only a two-letter code is kept; junk between the commas is dropped, not fatal.
        const std::string code = ascii_upper(trim(piece));
        if (two_ascii_letters(code)) codes.push_back(code);
        if (comma == std::string_view::npos) break;
        at = comma + 1;
    }
    // An empty body splits into one empty piece, so "!" and "germany" carry no codes at all.
    if (codes.empty()) return std::nullopt;

    Policy policy;
    if (negated) {
        policy.deny_ = std::move(codes);
    } else {
        policy.allow_ = std::move(codes);
    }
    policy.interval_ = interval;
    return policy;
}

std::optional<Policy> Policy::from_env(const Settings& settings) {
    return parse(settings.get("AETHER_EXIT_LOC").value_or(std::string_view{}),
                 interval_from_env(settings));
}

bool Policy::accepts(std::string_view loc) const {
    const std::string code = ascii_upper(trim(loc));
    if (std::find(deny_.begin(), deny_.end(), code) != deny_.end()) {
        return false;
    }
    return allow_.empty() || std::find(allow_.begin(), allow_.end(), code) != allow_.end();
}

std::string Policy::describe() const {
    if (deny_.empty()) {
        return "exit must be in " + join(allow_);
    }
    return "exit must not be in " + join(deny_);
}

std::chrono::seconds Policy::interval() const {
    return interval_;
}

std::chrono::seconds interval_from_env(const Settings& settings) {
    const auto value = settings.get("AETHER_EXIT_LOC_SECS");
    if (value) {
        std::string_view text = *value;
        // Rust's u64::from_str admits a leading '+'; spaces around the number it does not, and
        // neither does from_chars, so the value is read exactly as it stands.
        if (!text.empty() && text.front() == '+') text.remove_prefix(1);
        std::uint64_t secs = 0;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), secs);
        if (parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && secs > 0) {
            return std::chrono::seconds(
                std::min<std::uint64_t>(secs, MAX_INTERVAL_SECS.count()));
        }
    }
    return DEFAULT_INTERVAL_SECS;
}

std::optional<std::string> parse_trace(std::string_view body) {
    const auto code = trace_field(body, "loc");
    if (!code) return std::nullopt;
    std::string upper = ascii_upper(*code);
    // Rust filters on a byte length of two; anything that spells two bytes is a location to it.
    if (upper.size() != 2) return std::nullopt;
    return upper;
}

std::string Exit::describe() const {
    std::vector<std::string> parts;
    if (address) parts.push_back(*address);
    if (country && colo) {
        parts.push_back(*country + " via " + *colo);
    } else if (country) {
        parts.push_back(*country);
    } else if (colo) {
        parts.push_back(*colo);
    }
    parts.push_back(std::format("{}ms to cloudflare", rtt.count()));
    if (warp) parts.push_back("warp on");
    return join(parts);
}

Exit parse_exit(std::string_view body, std::chrono::milliseconds rtt) {
    Exit parsed;
    parsed.address = trace_field(body, "ip");
    parsed.country = parse_trace(body);
    parsed.colo = trace_field(body, "colo");
    parsed.warp = trace_field(body, "warp") == std::optional<std::string>("on");
    parsed.rtt = rtt;
    return parsed;
}

std::string trace_request() {
    return std::format("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: "
                       "aether\r\n\r\n",
                       TRACE_PATH, TRACE_HOST);
}

bool trace_answered(std::string_view body) {
    return body.size() > TRACE_BUFFER_LIMIT || parse_trace(body).has_value();
}

std::expected<std::string, std::string> lookup_from(std::string_view body) {
    if (auto loc = parse_trace(body)) return *loc;
    return std::unexpected(std::string("the trace answer carried no location"));
}

std::string report_line(std::string_view what, const Exit& exit) {
    return "[+] " + std::string(what) + " exit: " + exit.describe();
}

LogLine probe_failure_line(std::string_view what, std::string_view error) {
    return LogLine{Level::Debug, "could not read the exit of " + std::string(what) + ": " +
                                     std::string(error)};
}

Verdict settle(const std::optional<Policy>& policy, const std::optional<Exit>& exit) {
    // No policy is Rust's spawn arm: the engine fires a background report and carries on, so
    // there is nothing to log or fail on here.
    if (!policy) return Verdict{};

    if (!exit) {
        return Verdict{std::nullopt, std::string(
            "the exit location could not be read, so the policy cannot be honoured")};
    }

    const std::string loc = exit->country.value_or(std::string{});
    if (policy->accepts(loc)) {
        return Verdict{LogLine{Level::Info, "[+] exit location " + loc + " accepted (" +
                                                policy->describe() + ")"},
                       std::nullopt};
    }
    return Verdict{LogLine{Level::Warn, "[-] exit location " + loc + " rejected (" +
                                             policy->describe() + ")"},
                   std::string("exit location " + loc + " does not satisfy the requested policy")};
}

WatchStep watch_step(const Policy& policy, const std::expected<std::string, std::string>& answer) {
    if (!answer) {
        return WatchStep{LogLine{Level::Debug, "exit location check did not answer: " +
                                                    answer.error()},
                        std::nullopt};
    }
    const std::string& loc = *answer;
    if (policy.accepts(loc)) {
        return WatchStep{LogLine{Level::Debug, "exit location is still " + loc}, std::nullopt};
    }
    return WatchStep{LogLine{Level::Warn, "[-] exit location changed to " + loc + "; reconnecting"},
                     "exit location changed to " + loc};
}

} // namespace aether::core::exitloc
