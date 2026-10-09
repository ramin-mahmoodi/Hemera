// Port of aether/src/ffi.rs (commit 6175b67): the C ABI of core/include/aether_core.h. See
// ffi.hpp for the shape of the port and for the one thing the Rust gets from its own crate that
// the port takes from the supervisor instead (the Host). Everything else follows ffi.rs line for
// line: the reply envelope, the serde wording of a refused payload, the three registries behind
// one never-reused id counter, the job lifecycle from {"job":id} through poll/cancel/free, and
// the panic guard that turns a blown-up job into "the core panicked" instead of a crash across
// the C boundary.
//
// Three divergences the pinned Rust cannot show, all documented where they happen:
//   * json.hpp's parser reports no position, so a payload that is not json at all says
//     "invalid syntax" where serde would say "expected value at line 1 column 1". The prefix the
//     caller sees -- "the payload is not usable json: " -- is the Rust's.
//   * json.hpp holds every number as a double, so `5.0` and `5` arrive as one value: a whole
//     number is read as an integer and named `integer `5`` in a refusal. No payload this ABI
//     accepts changes meaning -- the u16 fields take the same values, and only the wording of an
//     exotic refusal can differ.
//   * Rust's jobs are futures on a shared runtime; the port's are worker threads, one per job,
//     and cancellation is the cooperative flag localapi.hpp already fixed as the module's only
//     cancellation divergence. No outcome a poll can show changes: a job is "running" until its
//     worker writes "done", exactly as the Rust's JobState does.
//
// SECURITY. Nothing here prints a payload, a token or a key: errors name fields and lengths,
// never values, and the identity registry only ever renders through IdentitySummary.

#include "ffi.hpp"

#include "identity.hpp"
#include "settings.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#include <thread>
#include <utility>

namespace aether::core::ffi {
namespace {

// ffi.rs's "could not start the async runtime": the port's counterpart, for a call that would
// do engine work with no host installed, or a job whose worker thread could not start.
constexpr std::string_view RUNTIME_ERROR = "could not start the async runtime";

// What aether_string_free-compatible replies are allocated with, and the reply a text with an
// embedded null byte is replaced by (ffi.rs::into_c_string's static fallback).
constexpr const char* NULL_BYTE_REPLY = R"({"error":"the reply held a null byte","ok":false})";
constexpr const char* PANIC_REPLY = R"({"error":"the core panicked","ok":false})";

// ffi.rs::next_id: process-wide, from 1, never reused, relaxed exactly as the Rust's counter.
std::uint64_t next_id() {
    static std::atomic<std::uint64_t> next{1};
    return next.fetch_add(1, std::memory_order_relaxed);
}

// ---- The host ----

// The registries and the host slot are heap-leaked on purpose, the way Rust's OnceLock statics
// live to the end of the process: a detached worker that outlives main must never write into a
// destroyed mutex.
std::mutex& host_mutex() {
    static auto& mutex = *new std::mutex;
    return mutex;
}

Host& host_slot() {
    static auto& slot = *new Host;
    return slot;
}

// The installed host, or nothing when no engine is wired: every job reads this when it starts,
// the way Rust's jobs reach the runtime that always exists.
std::optional<Host> current_host() {
    const std::lock_guard guard(host_mutex());
    if (host_slot().engine == nullptr) return std::nullopt;
    return host_slot();
}

// ---- Jobs ----

// ffi.rs::JobState: Running, or Done(Value) once the worker wrote the envelope.
struct JobSlot {
    bool done = false;
    json::Value result;
};

// ffi.rs::Job { cancel, state }.
struct Job {
    localapi::Cancel cancel;
    std::shared_ptr<std::mutex> state_mutex;
    std::shared_ptr<JobSlot> slot;
};

std::mutex& jobs_mutex() {
    static auto& mutex = *new std::mutex;
    return mutex;
}

std::map<std::uint64_t, Job>& jobs() {
    static auto& registry = *new std::map<std::uint64_t, Job>;
    return registry;
}

// ---- Identities and sign-in sessions ----

std::mutex& identities_mutex() {
    static auto& mutex = *new std::mutex;
    return mutex;
}

std::map<std::uint64_t, std::shared_ptr<Identity>>& identities() {
    static auto& registry = *new std::map<std::uint64_t, std::shared_ptr<Identity>>;
    return registry;
}

// ffi.rs keeps Arc<tokio::sync::Mutex<EmailSignIn>>; the port's session is localapi's
// EmailSession -- the engine keeps the client -- and the mutex is a std::mutex of its own, so a
// resend and a submit of one session serialize the way the Rust's async mutex serializes them.
struct SessionSlot {
    std::mutex mutex;
    localapi::EmailSession session;
};

std::mutex& sessions_mutex() {
    static auto& mutex = *new std::mutex;
    return mutex;
}

std::map<std::uint64_t, std::shared_ptr<SessionSlot>>& sessions() {
    static auto& registry = *new std::map<std::uint64_t, std::shared_ptr<SessionSlot>>;
    return registry;
}

std::expected<std::shared_ptr<Identity>, std::string> identity_of(std::uint64_t id) {
    const std::lock_guard guard(identities_mutex());
    const auto found = identities().find(id);
    if (found == identities().end()) {
        return std::unexpected(std::format("there is no identity {}", id));
    }
    return found->second;
}

std::expected<std::shared_ptr<SessionSlot>, std::string> session_of(std::uint64_t id) {
    const std::lock_guard guard(sessions_mutex());
    const auto found = sessions().find(id);
    if (found == sessions().end()) {
        return std::unexpected(std::format("there is no sign-in session {}", id));
    }
    return found->second;
}

// ---- The reply envelope ----

// ffi.rs::ok_value: an object gains "ok":true among its own fields; anything else is wrapped.
// json.hpp's object is a sorted map, which is serde_json's default Map, so the key order of the
// text a caller parses is the Rust's.
json::Value ok_value(json::Value value) {
    if (value.is_object()) {
        json::Object object = value.as_object();
        object["ok"] = json::Value(true);
        return json::Value(std::move(object));
    }
    json::Object object;
    object["ok"] = json::Value(true);
    object["result"] = std::move(value);
    return json::Value(std::move(object));
}

// ffi.rs::error_value.
json::Value error_value(std::string message) {
    json::Object object;
    object["error"] = json::Value(std::move(message));
    object["ok"] = json::Value(false);
    return json::Value(std::move(object));
}

// ffi.rs::into_c_string: a malloc'd copy the caller must hand back to aether_string_free, and
// the static refusal for a text that holds a null byte (json::Value::dump escapes every control
// character, so the fallback is unreachable through a reply -- kept because the Rust keeps it).
char* into_c_string(const std::string& text) {
    const std::string_view out =
        text.find('\0') == std::string_view::npos ? std::string_view(text) : NULL_BYTE_REPLY;
    char* raw = static_cast<char*>(std::malloc(out.size() + 1));
    if (raw == nullptr) return nullptr;
    std::memcpy(raw, out.data(), out.size());
    raw[out.size()] = '\0';
    return raw;
}

// ffi.rs::respond: run the work, fold success into ok_value, a refusal into error_value and a
// panic into "the core panicked", and hand the envelope back as a C string. No exception ever
// reaches the C boundary; the second catch is for the envelope building itself, which allocates.
template <class Work>
char* respond(Work&& work) {
    try {
        auto outcome = work();
        const json::Value value =
            outcome ? ok_value(std::move(*outcome)) : error_value(std::move(outcome.error()));
        return into_c_string(value.dump());
    } catch (...) {
        try {
            return into_c_string(error_value("the core panicked").dump());
        } catch (...) {
            char* raw = static_cast<char*>(std::malloc(std::strlen(PANIC_REPLY) + 1));
            if (raw == nullptr) return nullptr;
            std::memcpy(raw, PANIC_REPLY, std::strlen(PANIC_REPLY) + 1);
            return raw;
        }
    }
}

// ---- The job runner ----

// The worker half of ffi.rs::spawn_job: the outcome of the work, folded into the envelope the
// Rust folds it into -- including the catch-all that stands in for catch_unwind -- written
// under the slot's mutex, where aether_job_poll reads it.
void run_job_work(const JobWork& work, localapi::Cancel cancel,
                  const std::shared_ptr<std::mutex>& state_mutex,
                  const std::shared_ptr<JobSlot>& slot) {
    json::Value reply;
    try {
        auto outcome = work(cancel);
        reply = outcome ? ok_value(std::move(*outcome)) : error_value(std::move(outcome.error()));
    } catch (...) {
        reply = error_value("the core panicked");
    }
    const std::lock_guard guard(*state_mutex);
    slot->done = true;
    slot->result = std::move(reply);
}

// ---- Reading arguments ----

// A strict UTF-8 walk: no overlong form, no surrogate, nothing past U+10FFFF -- the shape
// CStr::to_str refuses, which read_str reports as "an argument was not valid utf-8".
bool is_valid_utf8(std::string_view text) {
    for (std::size_t at = 0; at < text.size();) {
        const auto lead = static_cast<unsigned char>(text[at]);
        if (lead < 0x80) {
            ++at;
            continue;
        }
        std::size_t extra;
        std::uint32_t point;
        std::uint32_t least;
        if ((lead & 0xE0) == 0xC0) {
            extra = 1;
            point = lead & 0x1Fu;
            least = 0x80;
        } else if ((lead & 0xF0) == 0xE0) {
            extra = 2;
            point = lead & 0x0Fu;
            least = 0x800;
        } else if ((lead & 0xF8) == 0xF0) {
            extra = 3;
            point = lead & 0x07u;
            least = 0x10000;
        } else {
            return false;
        }
        if (extra > text.size() - at - 1) return false;
        for (std::size_t step = 1; step <= extra; ++step) {
            const auto tail = static_cast<unsigned char>(text[at + step]);
            if ((tail & 0xC0) != 0x80) return false;
            point = (point << 6) | (tail & 0x3Fu);
        }
        if (point < least || point > 0x10FFFF) return false;
        if (point >= 0xD800 && point <= 0xDFFF) return false;
        at += extra + 1;
    }
    return true;
}

// ffi.rs::read_str.
std::expected<std::string, std::string> read_str(const char* raw) {
    if (raw == nullptr) {
        return std::unexpected(std::string("a required argument was null"));
    }
    const std::string_view text(raw);
    if (!is_valid_utf8(text)) {
        return std::unexpected(std::string("an argument was not valid utf-8"));
    }
    return std::string(text);
}

// ---- serde's shape of a refusal ----

// json.hpp keeps every number as a double, so a whole number is shown the way serde shows an
// integer only while it fits the i64 range; past that the double text stands in, because a cast
// out of range would be undefined.
std::string integer_text(double number) {
    if (number >= -9223372036854775808.0 && number <= 9223372036854775807.0) {
        return std::format("{}", static_cast<long long>(number));
    }
    return std::format("{}", number);
}

// How serde_json names the value it found where another kind was wanted: `integer `5``,
// `string "text"`, `sequence`, and the rest. A string is dumped, which escapes it the way serde's
// own rendering does.
std::string found_type(const json::Value& value) {
    if (value.is_null()) return "null";
    if (value.is_bool()) {
        return std::format("boolean `{}`", value.as_bool() ? "true" : "false");
    }
    if (value.is_number()) {
        const double number = value.as_double();
        if (number == std::floor(number) && std::fabs(number) < 9007199254740992.0) {
            return std::format("integer `{}`", integer_text(number));
        }
        return std::format("floating point `{}`", number);
    }
    if (value.is_string()) return std::format("string {}", value.dump());
    if (value.is_array()) return "sequence";
    return "map";
}

std::expected<std::string, std::string> required_string(const json::Value& object,
                                                        std::string_view key) {
    if (!object.contains(key)) return std::unexpected(std::format("missing field `{}`", key));
    const json::Value value = object.get(key);
    if (value.is_string()) return value.as_string();
    return std::unexpected(
        std::format("invalid type: {}, expected a string", found_type(value)));
}

// An Option<String> with #[serde(default)]: absent or null is None, a string is Some, anything
// else is serde's invalid-type refusal.
std::expected<std::optional<std::string>, std::string> optional_string(const json::Value& object,
                                                                       std::string_view key) {
    if (!object.contains(key)) return std::optional<std::string>(std::nullopt);
    const json::Value value = object.get(key);
    if (value.is_null()) return std::optional<std::string>(std::nullopt);
    if (value.is_string()) return std::optional<std::string>(value.as_string());
    return std::unexpected(
        std::format("invalid type: {}, expected a string", found_type(value)));
}

std::expected<std::optional<bool>, std::string> optional_bool(const json::Value& object,
                                                              std::string_view key) {
    if (!object.contains(key)) return std::optional<bool>(std::nullopt);
    const json::Value value = object.get(key);
    if (value.is_null()) return std::optional<bool>(std::nullopt);
    if (value.is_bool()) return std::optional<bool>(value.as_bool());
    return std::unexpected(
        std::format("invalid type: {}, expected a boolean", found_type(value)));
}

// An Option<u16>: a whole number inside the u16 range, or serde's own two refusals --
// "invalid type" for a value that is no integer, "invalid value" for one that overflows it.
std::expected<std::optional<std::uint16_t>, std::string> optional_u16(const json::Value& object,
                                                                      std::string_view key) {
    if (!object.contains(key)) return std::optional<std::uint16_t>(std::nullopt);
    const json::Value value = object.get(key);
    if (value.is_null()) return std::optional<std::uint16_t>(std::nullopt);
    if (!value.is_number()) {
        return std::unexpected(std::format("invalid type: {}, expected u16", found_type(value)));
    }
    const double number = value.as_double();
    if (number != std::floor(number)) {
        return std::unexpected(std::format("invalid type: {}, expected u16", found_type(value)));
    }
    if (number < 0.0 || number > 65535.0) {
        return std::unexpected(std::format(
            "invalid value: integer `{}`, expected u16", integer_text(number)));
    }
    return std::optional<std::uint16_t>(static_cast<std::uint16_t>(number));
}

// An Option<Vec<u16>>, element by element with the same two refusals.
std::expected<std::optional<std::vector<std::uint16_t>>, std::string> optional_ports(
    const json::Value& object, std::string_view key) {
    if (!object.contains(key)) return std::optional<std::vector<std::uint16_t>>(std::nullopt);
    const json::Value value = object.get(key);
    if (value.is_null()) return std::optional<std::vector<std::uint16_t>>(std::nullopt);
    if (!value.is_array()) {
        return std::unexpected(
            std::format("invalid type: {}, expected a sequence", found_type(value)));
    }
    std::vector<std::uint16_t> ports;
    for (const json::Value& element : value.as_array()) {
        if (!element.is_number()) {
            return std::unexpected(
                std::format("invalid type: {}, expected u16", found_type(element)));
        }
        const double number = element.as_double();
        if (number != std::floor(number)) {
            return std::unexpected(
                std::format("invalid type: {}, expected u16", found_type(element)));
        }
        if (number < 0.0 || number > 65535.0) {
            return std::unexpected(std::format(
                "invalid value: integer `{}`, expected u16", integer_text(number)));
        }
        ports.push_back(static_cast<std::uint16_t>(number));
    }
    return std::optional<std::vector<std::uint16_t>>(std::move(ports));
}

// An Option<Vec<String>>.
std::expected<std::optional<std::vector<std::string>>, std::string> optional_strings(
    const json::Value& object, std::string_view key) {
    if (!object.contains(key)) return std::optional<std::vector<std::string>>(std::nullopt);
    const json::Value value = object.get(key);
    if (value.is_null()) return std::optional<std::vector<std::string>>(std::nullopt);
    if (!value.is_array()) {
        return std::unexpected(
            std::format("invalid type: {}, expected a sequence", found_type(value)));
    }
    std::vector<std::string> texts;
    for (const json::Value& element : value.as_array()) {
        if (!element.is_string()) {
            return std::unexpected(
                std::format("invalid type: {}, expected a string", found_type(element)));
        }
        texts.push_back(element.as_string());
    }
    return std::optional<std::vector<std::string>>(std::move(texts));
}

// ---- Addresses ----

// Rust's u16::from_str for the port half of a SocketAddr: an optional '+', then digits only,
// leading zeros allowed, and anything past 65535 refused.
std::optional<std::uint16_t> parse_port(std::string_view text) {
    if (!text.empty() && text.front() == '+') text.remove_prefix(1);
    if (text.empty()) return std::nullopt;
    std::uint32_t value = 0;
    for (const char c : text) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
        value = value * 10 + static_cast<std::uint32_t>(c - '0');
        if (value > 65535) return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

// Rust's Ipv4Addr::from_str: four decimal octets of one to three digits, no leading zero on any
// octet but a bare "0", each at most 255, and nothing else in the text.
std::optional<IpAddress> parse_ipv4_strict(std::string_view text) {
    IpAddress address;
    address.v4 = true;
    std::size_t at = 0;
    for (int octet = 0; octet < 4; ++octet) {
        const std::size_t dot = text.find('.', at);
        if (octet < 3 && dot == std::string_view::npos) return std::nullopt;
        const std::size_t end = octet == 3 ? text.size() : dot;
        const std::string_view part = text.substr(at, end - at);
        if (part.empty() || part.size() > 3) return std::nullopt;
        if (part.size() > 1 && part.front() == '0') return std::nullopt;
        std::uint32_t value = 0;
        for (const char c : part) {
            if (std::isdigit(static_cast<unsigned char>(c)) == 0) return std::nullopt;
            value = value * 10 + static_cast<std::uint32_t>(c - '0');
        }
        if (value > 255) return std::nullopt;
        address.bytes[12 + static_cast<std::size_t>(octet)] = static_cast<std::uint8_t>(value);
        at = end + 1;
    }
    return address;
}

// One colon-separated run of an IPv6 text: groups of one to four hex digits, and -- only where
// `v4_allowed`, which is the run that ends the address -- a trailing dotted quad worth two
// groups, exactly where Rust's Ipv6Addr::from_str takes one.
bool parse_ipv6_groups(std::string_view text, bool v4_allowed, std::vector<std::uint16_t>& groups) {
    if (text.empty()) return true; // the empty side of a leading or trailing "::"
    std::size_t at = 0;
    for (;;) {
        const std::size_t colon = text.find(':', at);
        const std::string_view token =
            text.substr(at, colon == std::string_view::npos ? std::string_view::npos : colon - at);
        if (token.find('.') != std::string_view::npos) {
            if (!v4_allowed || colon != std::string_view::npos) return false;
            const auto v4 = parse_ipv4_strict(token);
            if (!v4) return false;
            groups.push_back(static_cast<std::uint16_t>(
                (static_cast<std::uint32_t>(v4->bytes[12]) << 8) | v4->bytes[13]));
            groups.push_back(static_cast<std::uint16_t>(
                (static_cast<std::uint32_t>(v4->bytes[14]) << 8) | v4->bytes[15]));
            return true;
        }
        if (token.empty() || token.size() > 4) return false;
        std::uint32_t value = 0;
        for (const char c : token) {
            std::uint32_t digit;
            if (c >= '0' && c <= '9') digit = static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') digit = static_cast<std::uint32_t>(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') digit = static_cast<std::uint32_t>(c - 'A') + 10;
            else return false;
            value = value * 16 + digit;
        }
        groups.push_back(static_cast<std::uint16_t>(value));
        if (colon == std::string_view::npos) return true;
        at = colon + 1;
    }
}

// Rust's Ipv6Addr::from_str: at most one "::" standing for at least one zero group, eight
// groups in all, a dotted quad only at the very end, and no zone id -- SocketAddr's parse takes
// no "%" and neither does this.
std::optional<IpAddress> parse_ipv6_strict(std::string_view text) {
    if (text.empty()) return std::nullopt;
    if (text.find_first_of("%[]") != std::string_view::npos) return std::nullopt;

    std::vector<std::uint16_t> groups;
    const std::size_t dcolon = text.find("::");
    if (dcolon == std::string_view::npos) {
        if (!parse_ipv6_groups(text, true, groups)) return std::nullopt;
        if (groups.size() != 8) return std::nullopt;
    } else {
        if (text.find("::", dcolon + 2) != std::string_view::npos) return std::nullopt;
        std::vector<std::uint16_t> head;
        std::vector<std::uint16_t> tail;
        if (!parse_ipv6_groups(text.substr(0, dcolon), false, head)) return std::nullopt;
        if (!parse_ipv6_groups(text.substr(dcolon + 2), true, tail)) return std::nullopt;
        // "::" stands for at least one zero group, so the two sides leave room for one.
        if (head.size() + tail.size() > 7) return std::nullopt;
        groups = head;
        groups.resize(8 - tail.size(), 0);
        groups.insert(groups.end(), tail.begin(), tail.end());
    }

    IpAddress address;
    address.v4 = false;
    for (std::size_t group = 0; group < 8; ++group) {
        address.bytes[group * 2] = static_cast<std::uint8_t>(groups[group] >> 8);
        address.bytes[group * 2 + 1] = static_cast<std::uint8_t>(groups[group] & 0xff);
    }
    return address;
}

// Rust's SocketAddr::from_str, which ffi.rs's socket_of and the excluded list parse with:
// "a.b.c.d:port", port 0 included, or "[v6]:port"; a bare v6 text is a host, never a socket.
std::optional<localapi::SocketAddr> parse_socket(std::string_view text) {
    if (!text.empty() && text.front() == '[') {
        const std::size_t close = text.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        const auto ip = parse_ipv6_strict(text.substr(1, close - 1));
        if (!ip) return std::nullopt;
        const std::string_view rest = text.substr(close + 1);
        if (rest.empty() || rest.front() != ':') return std::nullopt;
        const auto port = parse_port(rest.substr(1));
        if (!port) return std::nullopt;
        return localapi::SocketAddr{*ip, *port};
    }
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos) return std::nullopt;
    if (text.find(':', colon + 1) != std::string_view::npos) return std::nullopt;
    const auto ip = parse_ipv4_strict(text.substr(0, colon));
    if (!ip) return std::nullopt;
    const auto port = parse_port(text.substr(colon + 1));
    if (!port) return std::nullopt;
    return localapi::SocketAddr{*ip, *port};
}

// ffi.rs::socket_of.
std::expected<localapi::SocketAddr, std::string> socket_of(std::string_view raw,
                                                           std::string_view label) {
    if (const auto address = parse_socket(trim(raw))) return *address;
    return std::unexpected(std::format("{} '{}' is not an address:port", label, raw));
}

// ---- The payload structs ----

// ffi.rs::TeamPayload.
struct TeamPayload {
    std::string team;
    std::optional<std::string> client_id;
    std::optional<std::string> client_secret;
    std::optional<std::string> token;
    std::optional<std::string> email;

    // TeamPayload::credentials: the team name normalized now or refused with the Api error,
    // then the four options carried across as they arrived. `client_secret` and `token` are key
    // material: they travel in fields only, and no error here repeats one.
    [[nodiscard]] std::expected<localapi::TeamCredentials, std::string> credentials() const {
        auto made = localapi::TeamCredentials::make(team);
        if (!made) return std::unexpected(made.error().to_string());
        made->settings.client_id = client_id;
        made->settings.client_secret = client_secret;
        made->settings.token = token;
        made->settings.email = email;
        return std::move(*made);
    }
};

// ffi.rs::OpenPayload.
struct OpenPayload {
    std::string path;
    std::optional<std::string> transport;
    std::optional<std::string> model;
    std::optional<std::string> locale;
    std::optional<TeamPayload> team;
};

// ffi.rs::ScanPayload.
struct ScanPayload {
    std::optional<std::string> transport;
    std::optional<std::string> mode;
    std::optional<std::string> ip;
    std::optional<std::string> profile;
    std::optional<std::vector<std::uint16_t>> ports;
    std::optional<std::vector<std::string>> excluded;
    std::optional<bool> ech;
};

// ffi.rs::TunnelPayload.
struct TunnelPayload {
    std::string peer;
    std::optional<std::string> transport;
    std::optional<std::string> socks;
    std::optional<std::string> http;
    std::optional<std::string> profile;
    std::optional<std::uint16_t> keepalive;
    std::optional<bool> ech;
};

std::expected<TeamPayload, std::string> parse_team_payload(const json::Value& value) {
    if (!value.is_object()) {
        return std::unexpected(
            std::format("invalid type: {}, expected struct TeamPayload", found_type(value)));
    }
    TeamPayload payload;
    auto team = required_string(value, "team");
    if (!team) return std::unexpected(team.error());
    payload.team = std::move(*team);
    auto client_id = optional_string(value, "client_id");
    if (!client_id) return std::unexpected(client_id.error());
    payload.client_id = std::move(*client_id);
    auto client_secret = optional_string(value, "client_secret");
    if (!client_secret) return std::unexpected(client_secret.error());
    payload.client_secret = std::move(*client_secret);
    auto token = optional_string(value, "token");
    if (!token) return std::unexpected(token.error());
    payload.token = std::move(*token);
    auto email = optional_string(value, "email");
    if (!email) return std::unexpected(email.error());
    payload.email = std::move(*email);
    return payload;
}

std::expected<OpenPayload, std::string> parse_open_payload(const json::Value& value) {
    if (!value.is_object()) {
        return std::unexpected(
            std::format("invalid type: {}, expected struct OpenPayload", found_type(value)));
    }
    OpenPayload payload;
    auto path = required_string(value, "path");
    if (!path) return std::unexpected(path.error());
    payload.path = std::move(*path);
    auto transport = optional_string(value, "transport");
    if (!transport) return std::unexpected(transport.error());
    payload.transport = std::move(*transport);
    auto model = optional_string(value, "model");
    if (!model) return std::unexpected(model.error());
    payload.model = std::move(*model);
    auto locale = optional_string(value, "locale");
    if (!locale) return std::unexpected(locale.error());
    payload.locale = std::move(*locale);
    if (value.contains("team") && !value.get("team").is_null()) {
        auto team = parse_team_payload(value.get("team"));
        if (!team) return std::unexpected(team.error());
        payload.team = std::move(*team);
    }
    return payload;
}

std::expected<ScanPayload, std::string> parse_scan_payload(const json::Value& value) {
    if (!value.is_object()) {
        return std::unexpected(
            std::format("invalid type: {}, expected struct ScanPayload", found_type(value)));
    }
    ScanPayload payload;
    auto transport = optional_string(value, "transport");
    if (!transport) return std::unexpected(transport.error());
    payload.transport = std::move(*transport);
    auto mode = optional_string(value, "mode");
    if (!mode) return std::unexpected(mode.error());
    payload.mode = std::move(*mode);
    auto ip = optional_string(value, "ip");
    if (!ip) return std::unexpected(ip.error());
    payload.ip = std::move(*ip);
    auto profile = optional_string(value, "profile");
    if (!profile) return std::unexpected(profile.error());
    payload.profile = std::move(*profile);
    auto ports = optional_ports(value, "ports");
    if (!ports) return std::unexpected(ports.error());
    payload.ports = std::move(*ports);
    auto excluded = optional_strings(value, "excluded");
    if (!excluded) return std::unexpected(excluded.error());
    payload.excluded = std::move(*excluded);
    auto ech = optional_bool(value, "ech");
    if (!ech) return std::unexpected(ech.error());
    payload.ech = *ech;
    return payload;
}

std::expected<TunnelPayload, std::string> parse_tunnel_payload(const json::Value& value) {
    if (!value.is_object()) {
        return std::unexpected(
            std::format("invalid type: {}, expected struct TunnelPayload", found_type(value)));
    }
    TunnelPayload payload;
    auto peer = required_string(value, "peer");
    if (!peer) return std::unexpected(peer.error());
    payload.peer = std::move(*peer);
    auto transport = optional_string(value, "transport");
    if (!transport) return std::unexpected(transport.error());
    payload.transport = std::move(*transport);
    auto socks = optional_string(value, "socks");
    if (!socks) return std::unexpected(socks.error());
    payload.socks = std::move(*socks);
    auto http = optional_string(value, "http");
    if (!http) return std::unexpected(http.error());
    payload.http = std::move(*http);
    auto profile = optional_string(value, "profile");
    if (!profile) return std::unexpected(profile.error());
    payload.profile = std::move(*profile);
    auto keepalive = optional_u16(value, "keepalive");
    if (!keepalive) return std::unexpected(keepalive.error());
    payload.keepalive = *keepalive;
    auto ech = optional_bool(value, "ech");
    if (!ech) return std::unexpected(ech.error());
    payload.ech = *ech;
    return payload;
}

// ffi.rs::read_json: read_str, then the json parse, then the struct -- a failure of either of
// the last two under the Rust's one prefix. json.hpp's parser reports no position, which is the
// one wording divergence named at the top of this file.
template <class Payload>
std::expected<Payload, std::string> read_json(
    const char* raw, std::expected<Payload, std::string> (*parse)(const json::Value&)) {
    auto text = read_str(raw);
    if (!text) return std::unexpected(text.error());
    const auto parsed = json::parse(*text);
    if (!parsed) {
        return std::unexpected(std::string("the payload is not usable json: invalid syntax"));
    }
    auto payload = parse(*parsed);
    if (!payload) {
        return std::unexpected("the payload is not usable json: " + payload.error());
    }
    return payload;
}

// ---- The payload-to-request shaping ffi.rs does before it spawns ----

// ffi.rs::transport_of: the name the payload gives, or Masque when it gives none.
localapi::Transport transport_of(const std::optional<std::string>& raw) {
    return raw ? localapi::parse_transport(*raw) : localapi::Transport::Masque;
}

// ffi.rs::tunnel_spec_of.
std::expected<localapi::TunnelSpec, std::string> tunnel_spec_of(const TunnelPayload& payload) {
    auto spec = localapi::TunnelSpec::for_transport(transport_of(payload.transport));
    if (payload.profile) spec = spec.with_profile(*payload.profile);
    if (payload.socks) {
        auto socks = socket_of(*payload.socks, "the socks address");
        if (!socks) return std::unexpected(socks.error());
        spec.socks = *socks;
    }
    if (payload.http) {
        auto http = socket_of(*payload.http, "the http proxy address");
        if (!http) return std::unexpected(http.error());
        spec.http = *http;
    }
    if (payload.keepalive) spec.keepalive = *payload.keepalive;
    return spec;
}

// ffi.rs::describe.
std::string describe(const localapi::ApiError& error) { return error.to_string(); }

// ffi.rs::job_ech: the ECH key of a job whose payload asks for ECH on MASQUE -- none for
// WireGuard, which has no TLS handshake to hide a name in -- or the error that ends the job
// before any handshake. The lookup reads the settings the way the Rust reads the environment at
// lookup time, through settings.hpp; the resolver socket itself is the host's EchTransport.
std::expected<std::optional<std::vector<std::uint8_t>>, std::string> job_ech(
    const Host& host, bool want, localapi::Transport transport) {
    if (!want || transport != localapi::Transport::Masque) {
        return std::optional<std::vector<std::uint8_t>>(std::nullopt);
    }
    if (!host.ech_transport) {
        // No resolver wired: the lookup cannot be made, and going on without a key would send
        // the server name in the clear, so the job ends the way a failed lookup ends it.
        return std::unexpected(describe(
            localapi::ApiError{localapi::ErrorKind::Ech, std::string(localapi::NO_ECH_KEY)}));
    }
    const Settings settings = settings_from_environment();
    auto key = localapi::fetch_ech_config(settings, host.ech_transport);
    if (!key) return std::unexpected(describe(key.error()));
    return std::optional<std::vector<std::uint8_t>>(std::move(*key));
}

// Small reply builders the entry points share, named as the Rust's json! fragments are.
json::Value object_reply(std::string key, json::Value value) {
    json::Object object;
    object[std::move(key)] = std::move(value);
    return json::Value(std::move(object));
}

} // namespace

// ---- The internals ffi.hpp exposes ----

void install_host(Host host) {
    const std::lock_guard guard(host_mutex());
    host_slot() = std::move(host);
}

void clear_host() {
    const std::lock_guard guard(host_mutex());
    host_slot() = Host{};
}

bool host_installed() {
    const std::lock_guard guard(host_mutex());
    return host_slot().engine != nullptr;
}

Reply spawn_job(JobWork work) {
    if (!host_installed()) return std::unexpected(std::string(RUNTIME_ERROR));

    const localapi::Cancel cancel;
    auto state_mutex = std::make_shared<std::mutex>();
    auto slot = std::make_shared<JobSlot>();
    const std::uint64_t id = next_id();

    {
        const std::lock_guard guard(jobs_mutex());
        jobs().emplace(id, Job{cancel, state_mutex, slot});
    }

    try {
        std::thread worker(run_job_work, work, cancel, state_mutex, slot);
        worker.detach();
    } catch (const std::system_error&) {
        const std::lock_guard guard(jobs_mutex());
        jobs().erase(id);
        return std::unexpected(std::string(RUNTIME_ERROR));
    }

    return object_reply("job", json::Value(id));
}

json::Value keep_identity(Identity identity) {
    const auto summary = localapi::IdentitySummary::of(identity);
    const std::uint64_t id = next_id();
    {
        const std::lock_guard guard(identities_mutex());
        identities().emplace(id, std::make_shared<Identity>(std::move(identity)));
    }
    json::Object object;
    object["identity"] = json::Value(id);
    object["summary"] = summary.to_json();
    return json::Value(std::move(object));
}

// ---- The ABI ----

extern "C" {

char* aether_version() {
    return respond([]() -> Reply {
        return object_reply("version", json::Value(std::string(CORE_VERSION)));
    });
}

void aether_string_free(char* raw) {
    // ffi.rs::aether_string_free: NULL is ignored, and the string dies by the allocator that
    // made it -- the malloc into_c_string used. free() throws nothing, so the C boundary holds.
    std::free(raw);
}

char* aether_job_poll(std::uint64_t id) {
    return respond([id]() -> Reply {
        const std::lock_guard guard(jobs_mutex());
        const auto found = jobs().find(id);
        if (found == jobs().end()) {
            return std::unexpected(std::format("there is no job {}", id));
        }
        const std::lock_guard state_guard(*found->second.state_mutex);
        if (!found->second.slot->done) return object_reply("state", json::Value("running"));
        json::Object object;
        object["result"] = found->second.slot->result;
        object["state"] = json::Value("done");
        return json::Value(std::move(object));
    });
}

char* aether_job_cancel(std::uint64_t id) {
    return respond([id]() -> Reply {
        const std::lock_guard guard(jobs_mutex());
        const auto found = jobs().find(id);
        if (found == jobs().end()) {
            return std::unexpected(std::format("there is no job {}", id));
        }
        found->second.cancel.cancel();
        return object_reply("cancelled", json::Value(id));
    });
}

char* aether_job_free(std::uint64_t id) {
    return respond([id]() -> Reply {
        // As the Rust removes first and cancels after: the job leaves the registry under the
        // lock, and the flag goes up outside it. Freeing an id that was never there is not an
        // error; the reply says freed:null.
        std::optional<Job> removed;
        {
            const std::lock_guard guard(jobs_mutex());
            const auto found = jobs().find(id);
            if (found != jobs().end()) {
                removed = std::move(found->second);
                jobs().erase(found);
            }
        }
        if (!removed) return object_reply("freed", json::Value(nullptr));
        removed->cancel.cancel();
        return object_reply("freed", json::Value(id));
    });
}

char* aether_identity_open(const char* payload) {
    return respond([payload]() -> Reply {
        auto parsed = read_json<OpenPayload>(payload, parse_open_payload);
        if (!parsed) return std::unexpected(parsed.error());
        const OpenPayload& open = *parsed;
        const localapi::Transport transport = transport_of(open.transport);

        auto request = localapi::ProvisionRequest::for_transport(transport);
        if (open.model) request.model = *open.model;
        if (open.locale) request.locale = *open.locale;

        std::optional<localapi::TeamCredentials> team;
        if (open.team) {
            auto credentials = open.team->credentials();
            if (!credentials) return std::unexpected(credentials.error());
            team = std::move(*credentials);
        }
        std::optional<std::string> team_name;
        if (team) team_name = team->settings.team;
        request.team = std::move(team);

        std::optional<std::string_view> team_view;
        if (team_name) team_view = *team_name;
        const std::string path = localapi::identity_path(open.path, transport, team_view);

        return spawn_job([path, request](const localapi::Cancel&) -> Reply {
            // Rust's identity-open job takes no cancel token (`move |_|`): provisioning is not
            // interruptible there and is not here either.
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto identity = localapi::open_identity(*host->engine, path, request);
            if (!identity) return std::unexpected(describe(identity.error()));
            auto reply = keep_identity(std::move(*identity));
            reply["path"] = json::Value(path);
            reply["lastconn_path"] = json::Value(localapi::lastconn_path(path));
            return reply;
        });
    });
}

char* aether_identity_summary(std::uint64_t id) {
    return respond([id]() -> Reply {
        auto identity = identity_of(id);
        if (!identity) return std::unexpected(identity.error());
        return object_reply("summary", localapi::IdentitySummary::of(**identity).to_json());
    });
}

char* aether_identity_free(std::uint64_t id) {
    return respond([id]() -> Reply {
        {
            const std::lock_guard guard(identities_mutex());
            identities().erase(id);
        }
        return object_reply("freed", json::Value(id));
    });
}

char* aether_scan_start(std::uint64_t identity, const char* payload) {
    return respond([identity, payload]() -> Reply {
        auto parsed = read_json<ScanPayload>(payload, parse_scan_payload);
        if (!parsed) return std::unexpected(parsed.error());
        auto account = identity_of(identity);
        if (!account) return std::unexpected(account.error());
        const ScanPayload& scan = *parsed;

        auto request = localapi::ScanRequest::for_transport(transport_of(scan.transport));
        if (scan.profile) request = request.with_profile(*scan.profile);
        if (scan.mode) request.mode = *scan.mode;
        if (scan.ip) request.ip = localapi::parse_ip_scan(*scan.ip);
        if (scan.ports && !scan.ports->empty()) request.ports = *scan.ports;
        if (scan.excluded) {
            // Rust inserts into a set, so each address lands once and a text that is no
            // address:port is skipped silently -- both kept.
            for (const std::string& raw : *scan.excluded) {
                const auto address = parse_socket(trim(raw));
                if (!address) continue;
                if (std::find(request.excluded.begin(), request.excluded.end(), *address) !=
                    request.excluded.end()) {
                    continue;
                }
                request.excluded.push_back(*address);
            }
        }

        const bool want_ech = scan.ech.value_or(false);
        return spawn_job([account, request,
                          want_ech](const localapi::Cancel& cancel) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto ech = job_ech(*host, want_ech, request.transport);
            if (!ech) return std::unexpected(ech.error());
            // The Rust's `let mut request = request;` inside the job: the key lands on the copy
            // the job runs with, not on the one the entry point shaped.
            auto job_request = request;
            job_request.ech_config_list = std::move(*ech);
            auto endpoint = localapi::scan(*host->engine, **account, job_request, cancel);
            if (!endpoint) return std::unexpected(describe(endpoint.error()));
            return object_reply("endpoint", endpoint->to_json());
        });
    });
}

char* aether_verify_start(std::uint64_t identity, const char* payload) {
    return respond([identity, payload]() -> Reply {
        auto parsed = read_json<TunnelPayload>(payload, parse_tunnel_payload);
        if (!parsed) return std::unexpected(parsed.error());
        auto account = identity_of(identity);
        if (!account) return std::unexpected(account.error());
        auto peer = socket_of(parsed->peer, "the peer address");
        if (!peer) return std::unexpected(peer.error());
        auto spec = tunnel_spec_of(*parsed);
        if (!spec) return std::unexpected(spec.error());
        const bool want_ech = parsed->ech.value_or(false);

        return spawn_job([account, peer = *peer, spec = *spec,
                          want_ech](const localapi::Cancel& cancel) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto mutable_spec = spec;
            auto ech = job_ech(*host, want_ech, mutable_spec.transport);
            if (!ech) return std::unexpected(ech.error());
            mutable_spec.ech = std::move(*ech);
            auto reachable =
                localapi::verify_endpoint(*host->engine, **account, peer, mutable_spec, cancel);
            if (!reachable) return std::unexpected(describe(reachable.error()));
            return object_reply("reachable", json::Value(*reachable));
        });
    });
}

char* aether_tunnel_start(std::uint64_t identity, const char* payload) {
    return respond([identity, payload]() -> Reply {
        auto parsed = read_json<TunnelPayload>(payload, parse_tunnel_payload);
        if (!parsed) return std::unexpected(parsed.error());
        auto account = identity_of(identity);
        if (!account) return std::unexpected(account.error());
        auto peer = socket_of(parsed->peer, "the peer address");
        if (!peer) return std::unexpected(peer.error());
        auto spec = tunnel_spec_of(*parsed);
        if (!spec) return std::unexpected(spec.error());
        const bool want_ech = parsed->ech.value_or(false);

        return spawn_job([account, peer = *peer, spec = *spec,
                          want_ech](const localapi::Cancel& cancel) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto mutable_spec = spec;
            auto ech = job_ech(*host, want_ech, mutable_spec.transport);
            if (!ech) return std::unexpected(ech.error());
            mutable_spec.ech = std::move(*ech);

            // ffi.rs's three outcomes of api::connect: a clean end is "closed", a cancel is
            // "stopped" -- an answer, not an error -- and anything else is the error's text.
            auto outcome = localapi::connect(*host->engine, **account, peer, mutable_spec, cancel);
            if (outcome) return object_reply("state", json::Value("closed"));
            if (outcome.error().kind == localapi::ErrorKind::Cancelled) {
                return object_reply("state", json::Value("stopped"));
            }
            return std::unexpected(describe(outcome.error()));
        });
    });
}

char* aether_core_start(const char* arguments) {
    return respond([arguments]() -> Reply {
        std::vector<std::string> argument_list;
        if (arguments != nullptr) {
            auto text = read_str(arguments);
            if (!text) return std::unexpected(text.error());
            if (!trim(*text).empty()) {
                const auto parsed = json::parse(*text);
                if (!parsed) {
                    return std::unexpected(std::string(
                        "the argument list is not a json array of strings: invalid syntax"));
                }
                if (!parsed->is_array()) {
                    return std::unexpected(std::format(
                        "the argument list is not a json array of strings: invalid type: {}, "
                        "expected a sequence",
                        found_type(*parsed)));
                }
                for (const json::Value& element : parsed->as_array()) {
                    if (!element.is_string()) {
                        return std::unexpected(std::format(
                            "the argument list is not a json array of strings: invalid type: {}, "
                            "expected a string",
                            found_type(element)));
                    }
                    argument_list.push_back(element.as_string());
                }
            }
        }

        const auto host = current_host();
        if (!host || !host->run_core) return std::unexpected(std::string(RUNTIME_ERROR));

        return spawn_job([argument_list](const localapi::Cancel& cancel) -> Reply {
            const auto host = current_host();
            if (!host || !host->run_core) return std::unexpected(std::string(RUNTIME_ERROR));
            // The `biased` arm of the Rust's select: a cancel already up when the work would
            // start beats any result it could produce.
            if (cancel.is_cancelled()) return object_reply("state", json::Value("stopped"));
            auto outcome = host->run_core(argument_list, cancel);
            if (outcome) return object_reply("state", json::Value("closed"));
            if (outcome.error().kind == localapi::ErrorKind::Cancelled) {
                return object_reply("state", json::Value("stopped"));
            }
            return std::unexpected(describe(outcome.error()));
        });
    });
}

char* aether_team_sign_in(const char* payload) {
    return respond([payload]() -> Reply {
        auto parsed = read_json<TeamPayload>(payload, parse_team_payload);
        if (!parsed) return std::unexpected(parsed.error());
        auto credentials = parsed->credentials();
        if (!credentials) return std::unexpected(credentials.error());

        return spawn_job([credentials = *credentials](const localapi::Cancel&) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto token = localapi::team_sign_in(*host->engine, credentials);
            if (!token) return std::unexpected(describe(token.error()));
            return object_reply("token", json::Value(std::move(*token)));
        });
    });
}

char* aether_team_code_request(const char* payload) {
    return respond([payload]() -> Reply {
        auto parsed = read_json<TeamPayload>(payload, parse_team_payload);
        if (!parsed) return std::unexpected(parsed.error());
        if (!parsed->email) {
            return std::unexpected(
                std::string("an email address is needed to request a login code"));
        }
        const std::string email = *parsed->email;
        auto credentials = parsed->credentials();
        if (!credentials) return std::unexpected(credentials.error());

        return spawn_job([credentials = *credentials, email](const localapi::Cancel&) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            auto session = localapi::team_email_code_request(*host->engine, credentials, email);
            if (!session) return std::unexpected(describe(session.error()));
            std::string signed_up = session->email;
            const std::uint64_t id = next_id();
            {
                const std::lock_guard guard(sessions_mutex());
                auto slot = std::make_shared<SessionSlot>();
                slot->session = std::move(*session);
                sessions().emplace(id, std::move(slot));
            }
            json::Object object;
            object["email"] = json::Value(std::move(signed_up));
            object["session"] = json::Value(id);
            return json::Value(std::move(object));
        });
    });
}

char* aether_team_code_resend(std::uint64_t session) {
    return respond([session]() -> Reply {
        auto slot = session_of(session);
        if (!slot) return std::unexpected(slot.error());

        return spawn_job([slot](const localapi::Cancel&) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            // The slot's mutex is the Rust's tokio::sync::Mutex: one exchange of a session at a
            // time, in the order the calls arrived.
            const std::lock_guard guard((*slot)->mutex);
            auto outcome = localapi::team_email_code_resend(*host->engine, (*slot)->session);
            if (!outcome) return std::unexpected(describe(outcome.error()));
            return object_reply("sent", json::Value(true));
        });
    });
}

char* aether_team_code_submit(std::uint64_t session, const char* code) {
    return respond([session, code]() -> Reply {
        // The Rust reads the code before it looks the session up, so a null code is reported
        // even against a session that does not exist.
        auto code_text = read_str(code);
        if (!code_text) return std::unexpected(code_text.error());
        auto slot = session_of(session);
        if (!slot) return std::unexpected(slot.error());

        return spawn_job([slot, code = *code_text](const localapi::Cancel&) -> Reply {
            const auto host = current_host();
            if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
            const std::lock_guard guard((*slot)->mutex);
            auto token = localapi::team_email_code_submit(*host->engine, (*slot)->session, code);
            if (!token) return std::unexpected(describe(token.error()));
            if (*token) {
                json::Object object;
                object["signed_in"] = json::Value(true);
                object["token"] = json::Value(std::move(**token));
                return json::Value(std::move(object));
            }
            return object_reply("signed_in", json::Value(false));
        });
    });
}

char* aether_team_session_free(std::uint64_t id) {
    return respond([id]() -> Reply {
        {
            const std::lock_guard guard(sessions_mutex());
            sessions().erase(id);
        }
        return object_reply("freed", json::Value(id));
    });
}

char* aether_team_token_set(const char* token) {
    return respond([token]() -> Reply {
        auto token_text = read_str(token);
        if (!token_text) return std::unexpected(token_text.error());
        // The Rust blocks its runtime on team_use_token here: no job, the answer comes back on
        // the caller's thread, and what runs is the engine's validation and cache, not a socket.
        const auto host = current_host();
        if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
        auto outcome = localapi::team_use_token(*host->engine, *token_text);
        if (!outcome) return std::unexpected(describe(outcome.error()));
        return object_reply("stored", json::Value(true));
    });
}

char* aether_team_token_clear() {
    return respond([]() -> Reply {
        const auto host = current_host();
        if (!host) return std::unexpected(std::string(RUNTIME_ERROR));
        localapi::team_forget_token(*host->engine);
        return object_reply("cleared", json::Value(true));
    });
}

} // extern "C"

} // namespace aether::core::ffi
