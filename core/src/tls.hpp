#pragma once

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hemera::core {

struct Settings;

// Port of hemera/src/tls.rs. What a real TLS stack already does -- GREASE points, extension
// permutation, cipher and group resolution, the ECH inner ClientHello, HPKE, TLS 1.3 suite
// ordering -- stays inside BoringSSL. What is written here is the shaping around it, plus the
// checks BoringSSL will not make for us: it accepts an unusable ECH key silently and runs the
// handshake with GREASE and the server name in the clear.

inline constexpr std::string_view CHROME_CIPHERS = "ALL:!aPSK:!ECDSA+SHA1:!3DES";
inline constexpr std::string_view CHROME_GROUPS = "P-256:X25519:P-384";

// SHA-256 over the SubjectPublicKeyInfo DER of a leaf certificate. consts.rs MASQUE_PINS.
using SpkiPin = std::array<uint8_t, 32>;
[[nodiscard]] const std::vector<SpkiPin>& masque_pins();

// The ClientHello shape. `groups` order matters: the first group is the one the key share uses.
struct Fingerprint {
    std::optional<std::string> ciphers;
    std::string groups = std::string(CHROME_GROUPS);
    bool grease = true;

    [[nodiscard]] static Fingerprint configured(const Settings& settings);

    // The per-CTX sequence of tls.rs::Fingerprint::apply, in order. ALPN is wire format: each
    // protocol preceded by its own length byte.
    [[nodiscard]] std::expected<void, std::string> apply(SSL_CTX* ctx,
                                                         std::span<const uint8_t> alpn) const;
};

// Refuses a --tls-ciphers or --tls-groups value BoringSSL would reject later, mid handshake.
// The messages carry the `--tls-ciphers: ` / `--tls-groups: ` prefix the Rust core prints.
[[nodiscard]] std::expected<void, std::string> check_tls_options(const Settings& settings);

// The WARP device certificate, straight out of the account file. Without it the MASQUE edge
// finishes the TLS handshake and then closes it with crypto alert 116, `certificate_required`
// (transport code 0x174), so this is what turns an identity into a working tunnel. The Rust core
// reads the same two PEM blocks at tls.rs:327-335.
[[nodiscard]] std::expected<void, std::string> use_device_certificate(
    SSL_CTX* ctx, std::string_view cert_pem, std::string_view key_pem);

// Pin-based verification: only the leaf is hashed and the chain is never walked, so a spoofed
// SNI still connects while a man in the middle does not. Off unless HEMERA_TLS_VERIFY is truthy.
[[nodiscard]] bool verify_enabled(const Settings& settings);
[[nodiscard]] std::optional<SpkiPin> spki_sha256(X509* cert);

// Installs the callback and returns the one-line notice for the log the first time it speaks;
// empty afterwards, so a hundred reconnects announce the mode once, not a hundred times.
[[nodiscard]] std::string install_verification(SSL_CTX* ctx, bool pin_endpoint,
                                               std::vector<SpkiPin> pins,
                                               const Settings& settings);

// ---- ECH ----

// A list that parses but holds nothing BoringSSL will offer is worse than no list at all, so
// these checks are what makes `--ech` fail loudly instead of quietly running in the clear.
[[nodiscard]] std::expected<void, std::string> check_ech_config_list(
    std::span<const uint8_t> list);
[[nodiscard]] std::expected<void, std::string> ensure_offerable(std::span<const uint8_t> list);
[[nodiscard]] bool valid_public_name(std::string_view name);

// The key every MASQUE handshake offers, shared by the H2 and H3 paths (tls.rs SESSION_ECH).
void use_ech(std::optional<std::vector<uint8_t>> config_list);
[[nodiscard]] std::optional<std::vector<uint8_t>> session_ech();

// Takes a retry config the server handed back, but only while a key is already in play: a
// session that started without ECH never acquires one this way.
void adopt_ech_retry(std::vector<uint8_t> retry);

// Keeps the session key alive while at least one tunnel runs. A session starting without a key
// leaves an existing one in place; one ending leaves its key to whoever is still running.
class EchSession {
public:
    explicit EchSession(std::optional<std::vector<uint8_t>> config_list);
    ~EchSession();
    EchSession(const EchSession&) = delete;
    EchSession& operator=(const EchSession&) = delete;
};

// Offers the session's key on one connection. An empty result means no key was in play, which
// has to stay distinguishable from a handshake that was asked for ECH and refused it.
[[nodiscard]] std::expected<std::optional<std::vector<uint8_t>>, std::string> inject_ech(
    SSL* ssl);
[[nodiscard]] bool ech_accepted(SSL* ssl);

// A close with crypto error 0x179 is the client's own `ech_required` alert; an application error
// carrying the same number means something else entirely, and only the transport-level one makes
// BoringSSL expose retry configs that are more than a placeholder.
[[nodiscard]] bool ech_rejected(bool application_error, std::uint32_t crypto_error_code);
[[nodiscard]] std::optional<std::vector<uint8_t>> extract_ech_retry_configs(SSL* ssl);

// How the core says it goes no further for want of an ECH key: with --ech given, going on without
// a key it can offer would send the server name in the clear. An app that runs the core reads this
// phrase to tell its user why it stopped, so every --ech failure carries it.
inline constexpr std::string_view NO_ECH_KEY = "ECH is on but there is no ECH key to offer";

// Turns an --ech / HEMERA_ECH value into a key to offer: nothing when unset, a fetched list for
// `auto`, otherwise base64. A key that cannot be offered is an error naming the refusal, since
// sending the server name in the clear is not an acceptable fallback.
enum class EchPurpose { Session, Api };

[[nodiscard]] std::expected<std::optional<std::vector<uint8_t>>, std::string> ech_key(
    const Settings& settings, EchPurpose purpose,
    const std::function<std::expected<std::vector<uint8_t>, std::string>()>& fetch);

} // namespace hemera::core
