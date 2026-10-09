#include "stats.hpp"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace hemera::core {
namespace {

std::atomic<std::uint64_t> up{0};
std::atomic<std::uint64_t> down{0};
std::atomic<bool> on{false};

// The Rust core sets its start clock once and keeps it through a later init().
std::atomic<bool> running{false};
std::chrono::steady_clock::time_point started;

constexpr const char* UNITS[] = {"B", "KiB", "MiB", "GiB", "TiB"};

} // namespace

void init(const Settings& settings) {
    on.store(is_truthy(settings.get("HEMERA_STATS").value_or(std::string_view{})),
             std::memory_order_relaxed);
    if (!running.exchange(true, std::memory_order_relaxed)) {
        started = std::chrono::steady_clock::now();
    }
}

bool enabled() {
    return on.load(std::memory_order_relaxed);
}

void add_up(std::size_t bytes) {
    if (enabled()) up.fetch_add(static_cast<std::uint64_t>(bytes), std::memory_order_relaxed);
}

void add_down(std::size_t bytes) {
    if (enabled()) down.fetch_add(static_cast<std::uint64_t>(bytes), std::memory_order_relaxed);
}

Counters snapshot() {
    Counters counters;
    counters.up = up.load(std::memory_order_relaxed);
    counters.down = down.load(std::memory_order_relaxed);
    if (running.load(std::memory_order_relaxed)) {
        counters.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started);
    }
    return counters;
}

std::string format_bytes(std::uint64_t bytes) {
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(UNITS)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) return std::to_string(bytes) + " B";
    return std::format("{:.1f} {}", value, UNITS[unit]);
}

std::string format_uptime(std::chrono::seconds uptime) {
    const std::uint64_t total = static_cast<std::uint64_t>(uptime.count());
    const std::uint64_t days = total / 86'400;
    const std::uint64_t hours = (total % 86'400) / 3600;
    const std::uint64_t minutes = (total % 3600) / 60;
    const std::uint64_t seconds = total % 60;

    if (days > 0) {
        return std::format("{}d {:02}:{:02}:{:02}", days, hours, minutes, seconds);
    }
    return std::format("{:02}:{:02}:{:02}", hours, minutes, seconds);
}

std::chrono::seconds report_interval(const Settings& settings) {
    const auto value = settings.get("HEMERA_STATS_SECS");
    if (!value) return DEFAULT_REPORT_SECS;

    std::string_view text = trim(*value);
    std::uint64_t secs = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), secs);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || secs == 0) {
        return DEFAULT_REPORT_SECS;
    }
    return std::chrono::seconds(static_cast<std::uint64_t>(
        std::min<std::uint64_t>(secs, MAX_REPORT_SECS.count())));
}

} // namespace hemera::core
