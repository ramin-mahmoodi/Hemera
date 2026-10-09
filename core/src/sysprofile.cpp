#include "sysprofile.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <limits>
#include <thread>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX // std::min and std::max are used below
#define NOMINMAX
#endif
#include <windows.h>

namespace hemera::core::sysprofile {
namespace {

constexpr std::size_t MIN_BUFFER = 16 * 1024;
constexpr std::size_t MAX_BUFFER = 64 * 1024 * 1024;
constexpr std::size_t NO_CAP = std::numeric_limits<std::size_t>::max();

std::string lowered(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return out;
}

// The cores this process may run on. Rust's available_parallelism() reads the process affinity
// mask on Windows, not the machine, so an affinity-limited process lands in a lower tier; the
// mask is what is counted here too, with the machine's count only as the fallback.
std::size_t detected_cpus() {
    DWORD_PTR system_mask = 0;
    DWORD_PTR process_mask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &system_mask, &process_mask) != 0 &&
        process_mask != 0) {
        std::size_t cpus = 0;
        for (DWORD_PTR bits = process_mask; bits != 0; bits &= bits - 1) ++cpus;
        return cpus;
    }
    const unsigned n = std::thread::hardware_concurrency();
    return n == 0 ? 1 : static_cast<std::size_t>(n);
}

std::optional<std::uint64_t> total_mem_mb() {
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status) == 0) return std::nullopt;
    return status.ullTotalPhys / 1024 / 1024;
}

// A buffer size in bytes from the setting, ignoring anything outside what a socket can sensibly
// be given.
std::size_t buffer_override(const Settings& settings, std::string_view key, std::size_t fallback) {
    const auto value = settings.get(key);
    if (!value) return fallback;

    const std::string_view text = trim(*value);
    std::size_t bytes = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), bytes);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return fallback;
    if (bytes < MIN_BUFFER || bytes > MAX_BUFFER) return fallback;
    return bytes;
}

} // namespace

std::string_view label(Tier tier) {
    switch (tier) {
        case Tier::Low: return "Low";
        case Tier::Medium: return "Medium";
        case Tier::High: return "High";
    }
    return "High";
}

Tier detect_tier(std::size_t cpus, std::optional<std::uint64_t> mem_mb, const Settings& settings) {
    if (const auto named = settings.get("HEMERA_PERF_PROFILE")) {
        const std::string wanted = lowered(trim(*named));
        if (wanted == "low") return Tier::Low;
        if (wanted == "medium" || wanted == "mid") return Tier::Medium;
        if (wanted == "high") return Tier::High;
    }

    const bool mem_low = mem_mb.has_value() && *mem_mb <= 384;
    const bool mem_medium = mem_mb.has_value() && *mem_mb <= 1536;

    if (cpus <= 2 || mem_low) return Tier::Low;
    if (cpus <= 4 || mem_medium) return Tier::Medium;
    return Tier::High;
}

Tuning build(std::size_t cpus, std::optional<std::uint64_t> mem_mb, const Settings& settings) {
    Tuning tuning;
    tuning.tier = detect_tier(cpus, mem_mb, settings);
    tuning.cpus = cpus;
    tuning.mem_mb = mem_mb;

    switch (tuning.tier) {
        case Tier::Low:
            tuning.scan_concurrency_cap = 4;
            tuning.udp_socket_buf = 256 * 1024;
            tuning.netstack_udp_buf = 32 * 1024;
            tuning.channel_capacity = 128;
            tuning.netstack_tcp_rx_buf = 256 * 1024;
            tuning.netstack_tcp_tx_buf = 128 * 1024;
            tuning.h2_stream_window = 2 * 1024 * 1024;
            tuning.h2_connection_window = 4 * 1024 * 1024;
            break;
        case Tier::Medium:
            tuning.scan_concurrency_cap = 10;
            tuning.udp_socket_buf = 2 * 1024 * 1024;
            tuning.netstack_udp_buf = 64 * 1024;
            tuning.channel_capacity = 512;
            tuning.netstack_tcp_rx_buf = 1024 * 1024;
            tuning.netstack_tcp_tx_buf = 256 * 1024;
            tuning.h2_stream_window = 8 * 1024 * 1024;
            tuning.h2_connection_window = 16 * 1024 * 1024;
            break;
        case Tier::High:
            tuning.scan_concurrency_cap = NO_CAP;
            tuning.udp_socket_buf = 7 * 1024 * 1024;
            tuning.netstack_udp_buf = 128 * 1024;
            tuning.channel_capacity = 1024;
            tuning.netstack_tcp_rx_buf = 2 * 1024 * 1024;
            tuning.netstack_tcp_tx_buf = 512 * 1024;
            tuning.h2_stream_window = 16 * 1024 * 1024;
            tuning.h2_connection_window = 32 * 1024 * 1024;
            break;
    }

    // A netstack TCP socket advertises the room left in its receive buffer as the window, so this
    // is the second ceiling on a download; both halves are paid up front per connection, so the
    // receive side gets the room.
    tuning.netstack_tcp_rx_buf =
        buffer_override(settings, "HEMERA_NETSTACK_TCP_RX", tuning.netstack_tcp_rx_buf);
    tuning.netstack_tcp_tx_buf =
        buffer_override(settings, "HEMERA_NETSTACK_TCP_TX", tuning.netstack_tcp_tx_buf);
    return tuning;
}

const Tuning& tuning(const Settings& settings) {
    static const Tuning detected = build(detected_cpus(), total_mem_mb(), settings);
    return detected;
}

std::size_t cap_concurrency(const Settings& settings, std::size_t requested) {
    return std::min(requested, tuning(settings).scan_concurrency_cap);
}

std::size_t udp_socket_buf_bytes(const Settings& settings) {
    return tuning(settings).udp_socket_buf;
}

std::size_t netstack_tcp_rx_buf_bytes(const Settings& settings) {
    return tuning(settings).netstack_tcp_rx_buf;
}

std::size_t netstack_tcp_tx_buf_bytes(const Settings& settings) {
    return tuning(settings).netstack_tcp_tx_buf;
}

std::size_t netstack_udp_buf_bytes(const Settings& settings) {
    return tuning(settings).netstack_udp_buf;
}

std::size_t channel_capacity(const Settings& settings) {
    return tuning(settings).channel_capacity;
}

std::uint32_t h2_stream_window_bytes(const Settings& settings) {
    return tuning(settings).h2_stream_window;
}

std::uint32_t h2_connection_window_bytes(const Settings& settings) {
    return tuning(settings).h2_connection_window;
}

std::string summary(const Tuning& tuning) {
    const std::string mem =
        tuning.mem_mb ? std::to_string(*tuning.mem_mb) + "MB" : std::string("unknown");
    const std::string cap = tuning.scan_concurrency_cap == NO_CAP
                                ? std::string("unlimited")
                                : std::to_string(tuning.scan_concurrency_cap);
    return "[*] performance profile: " + std::string(label(tuning.tier)) + " (cpus=" +
           std::to_string(tuning.cpus) + " mem=" + mem + "); scan concurrency cap=" + cap +
           ", udp socket buffer=" + std::to_string(tuning.udp_socket_buf / 1024) +
           "KB, netstack tcp buffers=" + std::to_string(tuning.netstack_tcp_rx_buf / 1024) +
           "KB rx/" + std::to_string(tuning.netstack_tcp_tx_buf / 1024) + "KB tx, netstack udp buffer=" +
           std::to_string(tuning.netstack_udp_buf / 1024) + "KB, channel capacity=" +
           std::to_string(tuning.channel_capacity) + ", h2 windows=" +
           std::to_string(tuning.h2_stream_window / 1024) + "KB/" +
           std::to_string(tuning.h2_connection_window / 1024) + "KB";
}

} // namespace hemera::core::sysprofile
