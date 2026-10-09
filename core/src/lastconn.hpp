#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace hemera::core {

// Port of lastconn.rs: the gateways the tunnel last got through to, kept in a small TOML file so
// a restart tries them before it goes probing again. Gateways are only carried over between runs
// of the same carrier -- an address proved over MASQUE/HTTP/3 says nothing about WireGuard.

inline constexpr std::size_t RECENT_CAP = 8;

inline constexpr const char* CARRIER_MASQUE_H3 = "masque-h3";
inline constexpr const char* CARRIER_MASQUE_H2 = "masque-h2";
inline constexpr const char* CARRIER_WIREGUARD = "wireguard";

struct LastConnection {
    std::string peer;
    std::string profile;
    std::string carrier;
    std::vector<std::string> recent;
};

// The file, or nothing when it is missing or no table it could be.
[[nodiscard]] std::optional<LastConnection> load_last_connection(const std::string& path);

// The file as the next run will find it: `peer` first, and behind it up to RECENT_CAP of the
// entries carried over from the same carrier.
[[nodiscard]] std::expected<void, std::string> save_last_connection(const std::string& path,
                                                                    std::string_view peer,
                                                                    std::string_view profile,
                                                                    std::string_view carrier);

// The gateways worth trying, newest first, without repeats and without the entries that are no
// address. Empty when the file was written for another carrier.
[[nodiscard]] std::vector<std::pair<std::string, std::uint16_t>> usable_peers(
    const LastConnection& cached, std::string_view carrier);

} // namespace hemera::core
