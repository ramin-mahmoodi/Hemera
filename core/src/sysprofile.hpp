#pragma once

#include "settings.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace aether::core::sysprofile {

// Port of sysprofile.rs: how the machine the core runs on sizes its buffers. raise_fd_limit() and
// open_file_limit() of the Rust core are Unix-only and do nothing on Windows, so they are not here.

enum class Tier {
    Low,
    Medium,
    High,
};

[[nodiscard]] std::string_view label(Tier tier);

struct Tuning {
    Tier tier = Tier::High;
    std::size_t cpus = 1;
    std::optional<std::uint64_t> mem_mb;
    std::size_t scan_concurrency_cap = 0;
    std::size_t udp_socket_buf = 0;
    std::size_t netstack_tcp_rx_buf = 0;
    std::size_t netstack_tcp_tx_buf = 0;
    std::size_t netstack_udp_buf = 0;
    std::size_t channel_capacity = 0;
    std::uint32_t h2_stream_window = 0;
    std::uint32_t h2_connection_window = 0;

    [[nodiscard]] bool operator==(const Tuning&) const = default;
};

// The tier `AETHER_PERF_PROFILE` names, or the one `cpus` and `mem_mb` fall to: 2 cores or 384 MB
// is Low, 4 cores or 1536 MB is Medium, and anything a machine cannot answer for is not Low.
[[nodiscard]] Tier detect_tier(std::size_t cpus, std::optional<std::uint64_t> mem_mb,
                               const Settings& settings);

// The whole shape for a machine and a setting set. Kept apart from detection so it can be checked
// against the numbers the Rust core picks.
[[nodiscard]] Tuning build(std::size_t cpus, std::optional<std::uint64_t> mem_mb,
                           const Settings& settings);

// This machine, read once: the first call decides, as the Rust core's OnceLock does, so a later
// change to the environment is not picked up mid-run.
[[nodiscard]] const Tuning& tuning(const Settings& settings);

[[nodiscard]] std::size_t cap_concurrency(const Settings& settings, std::size_t requested);
[[nodiscard]] std::size_t udp_socket_buf_bytes(const Settings& settings);
[[nodiscard]] std::size_t netstack_tcp_rx_buf_bytes(const Settings& settings);
[[nodiscard]] std::size_t netstack_tcp_tx_buf_bytes(const Settings& settings);
[[nodiscard]] std::size_t netstack_udp_buf_bytes(const Settings& settings);
[[nodiscard]] std::size_t channel_capacity(const Settings& settings);
[[nodiscard]] std::uint32_t h2_stream_window_bytes(const Settings& settings);
[[nodiscard]] std::uint32_t h2_connection_window_bytes(const Settings& settings);

// The line the Rust core logs once at start-up.
[[nodiscard]] std::string summary(const Tuning& tuning);

} // namespace aether::core::sysprofile
