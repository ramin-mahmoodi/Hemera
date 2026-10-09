#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace hemera::core {

// One enrolled tunnel account, exactly as the Rust core keeps it.
struct Identity {
    std::string device_id;
    std::string access_token;
    std::string cert_pem;
    std::string key_pem;
    uint64_t cert_issued_at = 0;
    std::string ipv4;
    std::string ipv6;
    std::array<uint8_t, 32> wg_private_key{};
    std::array<uint8_t, 32> wg_peer_public_key{};
    std::array<uint8_t, 3> client_id{};
    std::string organization;
    std::string gateway_proxy;
    std::string assigned_endpoint;
    bool refused = false;

    [[nodiscard]] bool has_masque_credentials() const;
};

inline constexpr uint64_t MASQUE_CERT_LIFETIME_DAYS = 365;
inline constexpr uint64_t MASQUE_CERT_RENEW_BEFORE_SECS = 7 * 86'400;

[[nodiscard]] uint64_t now_unix();

// A certificate counts as expiring once it is inside the renewal window, so a tunnel never
// discovers mid-handshake that the certificate it is about to present is already refused.
[[nodiscard]] bool masque_cert_expiring(uint64_t issued_at);
[[nodiscard]] bool cert_still_usable(const Identity& identity);

// The identity file is a flat TOML table: `key = "text"` and `key = 123`, one per line, keys
// base64. Written by the Rust core, read and written here unchanged, so both builds share one
// account. A file that cannot be understood is moved to <path>.corrupt and reported, which lets
// the caller provision a fresh identity instead of dying on a half-written one.
[[nodiscard]] std::expected<std::optional<Identity>, std::string> load_identity(
    const std::string& path);

[[nodiscard]] std::expected<void, std::string> save_identity(const std::string& path,
                                                             const Identity& identity);

// Refreshes only the MASQUE client certificate of an existing file. A missing file is left
// missing: credentials without an account mean nothing.
[[nodiscard]] std::expected<void, std::string> save_masque_creds(const std::string& path,
                                                                 std::string_view cert_pem,
                                                                 std::string_view key_pem,
                                                                 uint64_t issued_at);

// A flat TOML table: one `key = value` per line, with an array value carried whole so the
// reader can walk it. The identity file is read this way, and so is the last-connection file.
using TomlFields = std::map<std::string, std::string>;

[[nodiscard]] std::expected<TomlFields, std::string> parse_toml_fields(std::string_view text);

// `text` as TOML writes it: in double quotes, with the escapes that survive a read back.
[[nodiscard]] std::string toml_quote(std::string_view text);

} // namespace hemera::core
