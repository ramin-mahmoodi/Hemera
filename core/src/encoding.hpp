#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace aether::core {

// Standard base64, padding included. The identity file keeps its keys in this form, and the
// decode has to be as strict as the Rust engine's: an illegal character or a wrong amount of
// padding is refused rather than quietly ignored.
[[nodiscard]] std::string base64_encode(std::span<const uint8_t> data);

[[nodiscard]] std::optional<std::vector<uint8_t>> base64_decode(std::string_view text);

} // namespace aether::core
