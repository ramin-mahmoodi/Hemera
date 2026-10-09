#pragma once

#include "settings.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace hemera::core {

// Port of stats.rs: the byte counters a running tunnel keeps and the two lines of text they
// make. The reporter loop is the engine's to spawn, since it needs a task and a logger; what
// it would print every round is decided here.

inline constexpr std::chrono::seconds DEFAULT_REPORT_SECS{60};
// A report period longer than a day is a typo, not a wish.
inline constexpr std::chrono::seconds MAX_REPORT_SECS{86'400};

struct Counters {
    std::uint64_t up = 0;
    std::uint64_t down = 0;
    std::chrono::seconds uptime{0};
};

// HEMERA_STATS, and the moment the clock starts running.
void init(const Settings& settings);
[[nodiscard]] bool enabled();
void add_up(std::size_t bytes);
void add_down(std::size_t bytes);
[[nodiscard]] Counters snapshot();

// A count as it reads: plain bytes under a kibibyte, then KiB, MiB, GiB and TiB to one decimal.
[[nodiscard]] std::string format_bytes(std::uint64_t bytes);

// Uptime as hh:mm:ss, with `Nd ` in front once it is past a day.
[[nodiscard]] std::string format_uptime(std::chrono::seconds uptime);

// How often the report goes out: HEMERA_STATS_SECS, or a minute.
[[nodiscard]] std::chrono::seconds report_interval(const Settings& settings);

} // namespace hemera::core
