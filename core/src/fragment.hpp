#pragma once

#include "settings.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace hemera::core {

// Port of fragment.rs. Only the HTTP/2 (TCP) carrier uses this: it splits the TLS ClientHello so
// a middlebox never sees a whole one. QUIC needs nothing here, its packets are already pieces.
struct FragmentConfig {
    bool enabled = false;
    std::size_t size_min = 1;
    std::size_t size_max = 1;
    std::uint64_t delay_min_ms = 0;
    std::uint64_t delay_max_ms = 0;
    bool sni_split = false;

    static FragmentConfig disabled();
    static FragmentConfig configured(const Settings& settings);

    // How many bytes to hand over next, never more than `remaining`.
    [[nodiscard]] std::size_t chunk_len(std::size_t remaining) const;
    // How long to wait before the piece after that one.
    [[nodiscard]] std::uint64_t delay_ms() const;
};

// Where the server name sits inside a ClientHello, so a split can land in the middle of it
// instead of at an arbitrary byte count. Nothing when the buffer is no ClientHello.
[[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>> sni_host_range(
    std::span<const std::uint8_t> buffer);

// The write half of fragment.rs's stream wrapper: only the first write is fragmented, and the
// first read of the connection stops it for good.
class FragmentWriter {
  public:
    struct Piece {
        std::size_t len = 0;
        std::uint64_t delay_ms = 0;
    };

    explicit FragmentWriter(FragmentConfig config);

    // Nothing means "send this buffer as it is".
    [[nodiscard]] std::optional<Piece> plan(std::span<const std::uint8_t> buffer) const;
    void advance(std::size_t written);
    void stop();
    [[nodiscard]] bool fragmenting() const { return fragmenting_; }
    [[nodiscard]] const FragmentConfig& config() const { return config_; }

  private:
    FragmentConfig config_;
    bool fragmenting_ = true;
    bool first_write_ = true;
};

} // namespace hemera::core
