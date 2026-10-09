#include "fragment.hpp"

#include "settings.hpp"

#include <algorithm>
#include <charconv>
#include <random>
#include <string_view>

namespace hemera::core {
namespace {

std::mt19937_64& entropy() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

// Inclusive on both ends, exactly like the Rust core's `lo..=hi`.
template <typename N>
N between(N lo, N hi) {
    return std::uniform_int_distribution<N>{lo, hi}(entropy());
}

std::optional<std::uint64_t> number(std::string_view text) {
    std::uint64_t value = 0;
    const char* first = text.data();
    const char* last = text.data() + text.size();
    const auto parsed = std::from_chars(first, last, value);
    if (parsed.ec != std::errc{} || parsed.ptr != last) return std::nullopt;
    return value;
}

// "a-b" is a range, "n" is both ends of one, stray text falls back to the default for that end.
// A range the wrong way round is swapped rather than refused.
std::pair<std::uint64_t, std::uint64_t> parse_range(std::string_view spec,
                                                    std::pair<std::uint64_t, std::uint64_t> def) {
    spec = trim(spec);
    if (spec.empty()) return def;

    const auto dash = spec.find('-');
    if (dash != std::string_view::npos) {
        const std::uint64_t lo = number(trim(spec.substr(0, dash))).value_or(def.first);
        const std::uint64_t hi = number(trim(spec.substr(dash + 1))).value_or(def.second);
        return hi < lo ? std::pair{hi, lo} : std::pair{lo, hi};
    }
    const std::uint64_t single = number(spec).value_or(def.first);
    return {single, single};
}

bool flag(const Settings& settings, std::string_view key) {
    const std::string* value = settings.find(key);
    return value != nullptr && is_truthy(*value);
}

} // namespace

FragmentConfig FragmentConfig::disabled() {
    return {};
}

FragmentConfig FragmentConfig::configured(const Settings& settings) {
    const auto [size_lo, size_hi] =
        parse_range(settings.get("HEMERA_MASQUE_H2_FRAGMENT_SIZE").value_or(""), {8, 16});
    const auto [delay_lo, delay_hi] =
        parse_range(settings.get("HEMERA_MASQUE_H2_FRAGMENT_DELAY").value_or(""), {2, 10});

    FragmentConfig config;
    config.enabled = flag(settings, "HEMERA_MASQUE_H2_FRAGMENT");
    config.size_min = static_cast<std::size_t>(std::max<std::uint64_t>(size_lo, 1));
    config.size_max = static_cast<std::size_t>(std::max<std::uint64_t>(size_hi, config.size_min));
    config.delay_min_ms = delay_lo;
    config.delay_max_ms = std::max(delay_hi, delay_lo);
    config.sni_split = flag(settings, "HEMERA_MASQUE_H2_FRAGMENT_SNI");
    return config;
}

std::size_t FragmentConfig::chunk_len(std::size_t remaining) const {
    const std::size_t hi = std::min(std::max<size_t>(size_max, 1), remaining);
    const std::size_t lo = std::min(std::max<size_t>(size_min, 1), hi);
    return lo >= hi ? hi : between(lo, hi);
}

std::uint64_t FragmentConfig::delay_ms() const {
    if (delay_max_ms == 0) return 0;
    return delay_max_ms <= delay_min_ms ? delay_min_ms : between(delay_min_ms, delay_max_ms);
}

std::optional<std::pair<std::size_t, std::size_t>> sni_host_range(
    std::span<const std::uint8_t> buffer) {
    // read_be: the width-byte big-endian value at `at`, or nothing when it runs off the buffer.
    const auto read_be = [&](std::size_t at, std::size_t width) -> std::optional<std::size_t> {
        if (at + width < at || at + width > buffer.size()) return std::nullopt;
        std::size_t value = 0;
        for (std::size_t i = 0; i < width; ++i) value = (value << 8) | buffer[at + i];
        return value;
    };

    if (buffer.empty() || buffer[0] != 0x16) return std::nullopt;
    const std::optional<std::size_t> handshake_type = read_be(5, 1);
    if (!handshake_type || *handshake_type != 0x01) return std::nullopt;

    // legacy_version (2) + random (32) sit between the header and the session id.
    std::size_t at = 43;
    const std::optional<std::size_t> session_id = read_be(at, 1);
    if (!session_id) return std::nullopt;
    at += 1 + *session_id;
    const std::optional<std::size_t> suites = read_be(at, 2);
    if (!suites) return std::nullopt;
    at += 2 + *suites;
    const std::optional<std::size_t> compression = read_be(at, 1);
    if (!compression) return std::nullopt;
    at += 1 + *compression;
    const std::optional<std::size_t> extensions = read_be(at, 2);
    if (!extensions) return std::nullopt;
    const std::size_t extensions_end = at + 2 + *extensions;
    at += 2;

    while (at + 4 <= extensions_end) {
        const std::optional<std::size_t> kind = read_be(at, 2);
        const std::optional<std::size_t> length = read_be(at + 2, 2);
        if (!kind || !length) return std::nullopt;
        const std::size_t body = at + 4;
        if (*kind == 0x0000) {
            const std::size_t entry = body + 2;
            if (read_be(entry, 1) != 0) return std::nullopt; // a hostname list entry that is no DNS name
            const std::optional<std::size_t> host_len = read_be(entry + 1, 2);
            if (!host_len || *host_len == 0) return std::nullopt;
            const std::size_t host = entry + 3;
            if (host + *host_len > buffer.size()) return std::nullopt;
            return std::pair{host, host + *host_len};
        }
        at = body + *length;
    }
    return std::nullopt;
}

FragmentWriter::FragmentWriter(FragmentConfig config)
    : config_(config), fragmenting_(config.enabled) {}

std::optional<FragmentWriter::Piece> FragmentWriter::plan(
    std::span<const std::uint8_t> buffer) const {
    if (buffer.empty() || !fragmenting_) return std::nullopt;

    std::optional<std::size_t> targeted;
    if (first_write_ && config_.sni_split) {
        if (const auto host = sni_host_range(buffer)) {
            targeted = host->first + (host->second - host->first) / 2;
        }
    }
    const std::size_t len =
        targeted && *targeted > 0 && *targeted < buffer.size() ? *targeted
                                                               : config_.chunk_len(buffer.size());
    return Piece{len, config_.delay_ms()};
}

void FragmentWriter::advance(std::size_t written) {
    if (written > 0) first_write_ = false;
}

void FragmentWriter::stop() {
    fragmenting_ = false;
}

} // namespace hemera::core
