#pragma once

// Live exchange half of account.rs: api_call and the register / enable_warp / enroll_key /
// register_with_team / provision / fetch / refresh / ensure_masque_enrolled round trips over
// https_runtime::send. account.hpp owns the pure halves (bodies, parsing, plans, log text);
// this owns the sockets. Errors carry their AetherError kind so the engine can tell a dead
// identity (re-register) from a transport failure (keep the saved profile).

#include "account.hpp"
#include "dns.hpp"
#include "settings.hpp"
#include "zerotrust.hpp"

#include <array>
#include <chrono>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace aether::core::account {

enum class LiveKind { Api, IdentityRefused, Ech, Tls };

struct LiveError {
    LiveKind kind = LiveKind::Api;
    std::string message; // "{label}: ..." already prefixed, like the Rust builds it
};

template <typename T>
using LiveResult = std::expected<T, LiveError>;

// Everything api_call reads without owning. Unset sinks drop their lines, which is what a
// caller that logs nothing wants.
struct LiveEnv {
    const Settings* settings = nullptr;
    // dns::fetch_ech_config's resolver, for --ech=auto lookups (ech_transport.cpp: a real DNS
    // socket transport -- UDP/TCP straight at the resolver, DoH through https_runtime::send).
    EchTransport ech_transport;
    // provision_team's resolve_token hooks (the CLI's team hooks).
    zerotrust::Hooks team_hooks;
    std::function<void(std::string)> info;
    std::function<void(std::string)> warn;
    std::function<void(std::string)> debug;
};

// P-256 key generation and a self-signed X509, the boring::x509 builder calls in order.
[[nodiscard]] std::expected<MasqueKeyPair, std::string> generate_masque_keypair();

[[nodiscard]] LiveResult<AccountData> api_call(std::string_view label, std::string_view method,
                                              std::string_view path,
                                              std::optional<std::span<const std::uint8_t>> body,
                                              std::optional<std::string_view> bearer,
                                              std::optional<std::string_view> jwt,
                                              const LiveEnv& env);

[[nodiscard]] LiveResult<std::pair<AccountData, std::array<std::uint8_t, 32>>> register_device(
    std::string_view model, std::string_view locale, std::optional<std::string_view> jwt,
    const LiveEnv& env);
[[nodiscard]] LiveResult<void> enable_warp(std::string_view device_id, std::string_view token,
                                           const LiveEnv& env);
[[nodiscard]] LiveResult<AccountData> enroll_key(std::string_view device_id,
                                                std::string_view token,
                                                std::span<const std::uint8_t> spki_der,
                                                const std::optional<std::string>& name,
                                                const LiveEnv& env);
[[nodiscard]] LiveResult<std::pair<AccountData, std::array<std::uint8_t, 32>>> register_with_team(
    std::string_view model, std::string_view locale, std::string_view token, const LiveEnv& env);
[[nodiscard]] LiveResult<Identity> provision_team(std::string_view model, std::string_view locale,
                                                  const zerotrust::TeamSettings& team,
                                                  const LiveEnv& env);
[[nodiscard]] LiveResult<Identity> provision_wg(std::string_view model, std::string_view locale,
                                               std::optional<std::string_view> jwt,
                                               const LiveEnv& env);
[[nodiscard]] LiveResult<AccountData> fetch_device(std::string_view device_id,
                                                   std::string_view token, const LiveEnv& env);
// Never fails: a refusal marks the identity, any other failure keeps the saved profile.
[[nodiscard]] Identity refresh_profile(Identity identity, const LiveEnv& env);
[[nodiscard]] LiveResult<MasqueEnrollment> ensure_masque_enrolled(const Identity& identity,
                                                                 const LiveEnv& env);

} // namespace aether::core::account
