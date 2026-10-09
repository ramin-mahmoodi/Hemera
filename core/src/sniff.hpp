#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace hemera::core {

// Port of hemera/src/sniff.rs: the name a connection is for, read out of the first bytes of
// either a TLS ClientHello or a plain HTTP request, so a rule can match before the traffic
// goes anywhere.

// How much of the stream is looked at.
inline constexpr std::size_t PEEK_BUDGET = 4096;

// `raw` as a host worth matching: of letters, digits, '-', '.' and '_', with a dot in it, no
// address, and lower case with its trailing dots gone; nothing when it is none of that.
[[nodiscard]] std::optional<std::string> plausible_host(std::span<const std::uint8_t> raw);

// The server name of a TLS ClientHello in `buf`.
[[nodiscard]] std::optional<std::string> tls_sni(std::span<const std::uint8_t> buf);

// The Host header of an HTTP request in `buf`, with its port gone.
[[nodiscard]] std::optional<std::string> http_host(std::span<const std::uint8_t> buf);

// One or the other: what `buf` is a connection to.
[[nodiscard]] std::optional<std::string> sniff_hostname(std::span<const std::uint8_t> buf);

} // namespace hemera::core
