#pragma once

// Port of hemera/src/account.rs, commit 6175b67: the WARP account layer -- the bodies a
// registration sends, the answer it gets back, the retry arithmetic around the calls, the texts
// a refused call turns into, the device's own keys, and the identity the whole core hangs off.
//
// What is here is everything that only thinks. What is NOT, because it needs a socket, a TLS
// handshake or the tokio runtime and is never faked in a port:
//   * `api_call` itself -- the retry loop, `tokio::time::sleep`, `https::send` and the ECH offer.
//     Its wording is ported (the three log lines and the four error texts below), its sending is
//     the engine's.
//   * `register`, `register_with_team`, `enable_warp`, `enroll_key`, `fetch_device`,
//     `provision_team`, `provision_wg` and `api_ech` -- each one an exchange. Every value they
//     build (the registration body, the path, the headers, the key) is produced here, so an
//     engine call site is "build, send, hand the answer to `account_data_from_json`".
//   * `refresh_profile`'s fetch and `ensure_masque_enrolled`'s enrollment round trip: both
//     decision halves are here (`refresh_from_profile`, `refresh_after_refusal`,
//     `refresh_with_saved_profile`, `plan_masque_enrollment`, `masque_enrollment_after_error`),
//     the round trips are not.
//   * `generate_masque_keypair` -- P-256 key generation and a self-signed X509. That is key
//     creation rather than data logic, so the engine's crypto layer owns it; `MasqueKeyPair` is
//     the shape it hands back, unchanged.
//   * `handshake_identity`, which Rust keeps behind `#[cfg(test)]`.
//
// SECURITY. No error string, note or log line here repeats a token, a key or a private value:
// the two access tokens only ever travel in fields, and the base64 of a key appears in a body
// the caller built. `hemera-masque.toml` is never opened by this module -- reading and writing
// the account file is identity.hpp's, and a damaged one is quarantined there.
//
// Environment reads go through Settings (settings.hpp), never std::getenv, so an accessor takes
// `const Settings&`; the keys are the HEMERA_* names the Rust core reads.

#include "identity.hpp"
#include "settings.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hemera::core::account {

// -- Names the Rust keeps to itself, and the ones a caller reads -------------------------------

// HEMERA_ENROLL_ADDRESS, the variable --enroll-address sets.
inline constexpr std::string_view ENROLL_ADDRESS_ENV = "HEMERA_ENROLL_ADDRESS";
// The host the API is reached on when nothing else is given, and the port that host is reached
// on. Rust's `unwrap_or("api.cloudflareclient.com")` names this literal; it is only reachable
// through an API_URL with no leading segment at all.
inline constexpr std::string_view DEFAULT_API_HOST = "api.cloudflareclient.com";
inline constexpr std::uint16_t DEFAULT_API_PORT = 443;

// How long one attempt at a call to the WARP API may take.
inline constexpr std::chrono::milliseconds API_TIMEOUT{20'000};
inline constexpr std::uint32_t API_ATTEMPTS = 5;
inline constexpr std::uint64_t API_BACKOFF_BASE_MS = 900;
inline constexpr std::uint64_t API_BACKOFF_CAP_MS = 15'000;
inline constexpr std::uint64_t API_RETRY_AFTER_CAP_SECS = 30;

// The lifetime of the MASQUE certificate, in the two units account.rs spells it in. The day
// count and the renewal window live in identity.hpp; this is `MASQUE_CERT_LIFETIME_DAYS as u64 *
// 86_400`, and it is the same number identity.cpp's two checks multiply out.
inline constexpr std::uint64_t MASQUE_CERT_LIFETIME_SECS =
    ::hemera::core::MASQUE_CERT_LIFETIME_DAYS * 86'400;

// Identity, the clock it is aged against and the two certificate checks on it already live in
// identity.hpp, which owns the struct: `hemera::core::Identity`, `hemera::core::now_unix()`,
// `hemera::core::masque_cert_expiring()` and `hemera::core::cert_still_usable()`. They are
// re-exported rather than defined again, so this module carries account.rs's whole surface
// without a second copy of the arithmetic -- and without a duplicate symbol when both land in
// one library.
using ::hemera::core::Identity;
using ::hemera::core::cert_still_usable;
using ::hemera::core::masque_cert_expiring;
using ::hemera::core::now_unix;

// error.rs's Display for HemeraError::Api, which is the prefix every error this module raises
// carries. `enroll_address` and friends return the text with it already on; an engine that keeps
// its own HemeraError needs only the reason.
[[nodiscard]] std::string api_error(std::string_view reason);

// A header list: names and values in the order they go on the wire, exactly the pairs
// https.hpp's Request takes and Http1Answer's answer hands back.
using HeaderFields = std::vector<std::pair<std::string, std::string>>;

// -- The bodies a registration sends ----------------------------------------------------------
//
// Serde writes a struct's fields in declaration order, which is why these three render to text
// rather than to a json::Value: that library's object is a sorted map, and a body whose keys came
// out alphabetical would be a different request.

// `Registration`, the plain WARP device registration. `install_id`, `fcm_token` and `os_version`
// are there because the API's schema wants them, and Rust sends them empty.
struct Registration {
    std::string key;
    std::string install_id;
    std::string fcm_token;
    std::string tos;
    std::string model;
    std::string serial_number;
    std::string os_version;
    std::string key_type;
    std::string tunnel_type;
    std::string locale;

    [[nodiscard]] bool operator==(const Registration&) const = default;

    // The bytes serde_json::to_vec gives: field order, `":"` and `","` with no spaces.
    [[nodiscard]] std::string to_json_text() const;
};

// `TeamRegistration`, the same device enrolled into a team: no key type or tunnel type, and the
// install id stands in for both the device name and the serial number.
struct TeamRegistration {
    std::string key;
    std::string install_id;
    std::string fcm_token;
    std::string tos;
    std::string model;
    std::string name;
    std::string serial_number;
    std::string locale;

    [[nodiscard]] bool operator==(const TeamRegistration&) const = default;
    [[nodiscard]] std::string to_json_text() const;
};

// `DeviceUpdate`, the PATCH that puts a MASQUE key on an existing device. `name` is
// skip_serializing_if = "Option::is_none", so an absent one leaves the key out of the body.
struct DeviceUpdate {
    std::string key;
    std::string key_type;
    std::string tunnel_type;
    std::optional<std::string> name;

    [[nodiscard]] bool operator==(const DeviceUpdate&) const = default;
    [[nodiscard]] std::string to_json_text() const;
};

// Text of a JSON string the way serde_json escapes it: `"`, `\`, the five named controls, and
// anything below 0x20 as `\u00xx`. Bytes at or above 0x7f go out as they are, UTF-8 included --
// Rust escapes neither DEL nor anything non-ASCII.
[[nodiscard]] std::string json_quote(std::string_view text);

// The device's identifiers and its ToS stamp, exactly as `register` fills them: key type
// "curve25519", tunnel type "wireguard", install id, fcm token and os version empty.
[[nodiscard]] Registration new_registration(std::string wg_public_key, std::string_view model,
                                             std::string_view serial_number, std::string_view tos,
                                             std::string_view locale);

// `team_registration_body`: a fresh install id, the fcm token built on it, and that id used for
// the device name and the serial number as well. `public_key` is the base64 x25519 key, already
// drawn, because drawing it is the caller's half of `register_with_team`.
[[nodiscard]] TeamRegistration team_registration_body(std::string public_key,
                                                      std::string_view model,
                                                      std::string_view locale);

// The device update `enroll_key` sends: the SPKI base64'd in the standard padded alphabet, key
// type consts::KEY_TYPE_MASQUE and tunnel type consts::TUN_TYPE_MASQUE, with the device name the
// caller has one of.
[[nodiscard]] DeviceUpdate device_update_body(std::span<const std::uint8_t> spki_der,
                                              const std::optional<std::string>& name);

// -- The answer a call gets back --------------------------------------------------------------
//
// Every struct below is the serde form of the account API's JSON: the field names are the JSON
// keys, `#[serde(default)]` becomes the member's default, and a field without it is required --
// an answer missing one is an error naming the field, which is what the Rust's decode error says.

struct Addresses {
    std::string v4;
    std::string v6;

    [[nodiscard]] bool operator==(const Addresses&) const = default;
};

struct Interface {
    Addresses addresses;

    [[nodiscard]] bool operator==(const Interface&) const = default;
};

struct PeerEndpoint {
    std::string v4;
    std::string v6;
    std::string host;

    [[nodiscard]] bool operator==(const PeerEndpoint&) const = default;
};

// `public_key` has no default in Rust, so a peer that omits it fails the whole answer.
struct Peer {
    std::string public_key;
    PeerEndpoint endpoint;

    [[nodiscard]] bool operator==(const Peer&) const = default;
};

struct Services {
    std::string http_proxy;

    [[nodiscard]] bool operator==(const Services&) const = default;
};

struct AccountInfo {
    std::string id;
    std::string account_type;
    std::string organization;

    [[nodiscard]] bool operator==(const AccountInfo&) const = default;
};

struct Config {
    Interface interface;
    std::vector<Peer> peers;
    std::string client_id;
    Services services;

    [[nodiscard]] bool operator==(const Config&) const = default;
};

struct AccountData {
    std::string id;
    std::string token;
    Config config;
    AccountInfo account;

    [[nodiscard]] bool operator==(const AccountData&) const = default;
};

// `serde_json::from_str::<AccountData>`, for the body of an API answer: nothing parsed is
// dropped, an unknown key is ignored, and a key of the wrong kind is refused the way serde
// refuses it ("invalid type: integer `5`, expected a string"), a missing required one the way it
// refuses that ("missing field `id`"). The error is the message on its own; api_call wraps it as
// "{label} decode: {message} ({n} byte answer)", which is `decode_error` below.
//
// One divergence, in what JSON numbers can say: json.hpp keeps every number as a double, so a
// value above 2^53 has already lost precision before serde-like reading begins. No account field
// is a number, so nothing here is affected.
[[nodiscard]] std::expected<AccountData, std::string> account_data_from_json(std::string_view body);

// -- Identity's own methods -------------------------------------------------------------------

// `Identity::private_key_bytes` and `Identity::peer_public_key_bytes`. Rust returns a Result for
// both and never an error -- the bytes are stored inline -- so the `std::expected` keeps the
// caller's shape rather than the failure. `has_masque_credentials` is already a member of the
// struct in identity.hpp and is not repeated here.
[[nodiscard]] std::expected<std::array<std::uint8_t, 32>, std::string>
private_key_bytes(const Identity& identity);
[[nodiscard]] std::expected<std::array<std::uint8_t, 32>, std::string>
peer_public_key_bytes(const Identity& identity);

// -- The retry arithmetic ---------------------------------------------------------------------

// `backoff_delay`: the exponential step, the cap, and the jitter drawn under it. The wait is
// always at least half the capped step and never more than half plus a third of it, so
// API_BACKOFF_CAP_MS bounds both.
[[nodiscard]] std::chrono::milliseconds backoff_delay(std::uint32_t attempt);

// The same with the draw given, which is how the bounds and the growth are testable: `draw`
// stands in for `rand::rng().next_u32()`.
[[nodiscard]] std::chrono::milliseconds backoff_delay_at(std::uint32_t attempt, std::uint32_t draw);

// The capped step of `attempt` before the half and the jitter -- API_BACKOFF_BASE_MS shifted
// left by min(attempt, 5), saturating, then held down to API_BACKOFF_CAP_MS.
[[nodiscard]] std::uint64_t backoff_step_ms(std::uint32_t attempt);

// `retry_after`: the first `Retry-After` header, as whole seconds, capped at
// API_RETRY_AFTER_CAP_SECS. A header that is absent, no text, not a plain number, or empty after
// the spaces come off gives nothing -- Rust's `?` on each of those steps. The name is matched
// case-insensitively, the first of several wins, and a value with a leading `+` parses because
// Rust's integer parse accepts one.
[[nodiscard]] std::optional<std::chrono::seconds> retry_after(const HeaderFields& headers);

// -- Which answers mean what ------------------------------------------------------------------

// `refuses_identity`: 401, 404 and 410, the three codes that say this identity is gone. Not 403,
// which is the network being refused rather than the device, and not 429.
[[nodiscard]] bool refuses_identity(std::uint16_t status);

// `worth_retrying`: 429, 408 and any 5xx -- 500 through 599 exactly, which is `is_server_error`,
// so 600 is not retried.
[[nodiscard]] bool worth_retrying(std::uint16_t status);

// -- Where the calls go, and what goes on them -----------------------------------------------

// `api_host`: consts::API_URL down to its first '/' after every leading "https://" and then every
// leading "http://" has been dropped. Both strips repeat, so "https://https://api.x" gives
// "api.x", and neither can fail, so the DEFAULT_API_HOST fallback is out of reach of the real
// URL; `api_host_from` is the same function over any URL, which is where those two behaviours
// are checkable.
[[nodiscard]] std::string_view api_host();
[[nodiscard]] std::string_view api_host_from(std::string_view url);

// `front_headers`: the four headers every call carries, then the bearer token as
// `Authorization: Bearer {token}`, then the JWT as `CF-Access-Jwt-Assertion: {token}`, in that
// order -- the order Rust builds the vector in, which is the order they go on the wire.
[[nodiscard]] HeaderFields front_headers(const std::optional<std::string_view>& bearer,
                                         const std::optional<std::string_view>& jwt);

// -- The API's ECH stash ----------------------------------------------------------------------

// The ECH key the calls to the WARP API offer for the rest of the run: set by a lookup or by a
// key a server handed back, and cleared when a run of the core starts. One process-wide slot,
// mutex-guarded, as Rust's static Mutex<Option<Vec<u8>>> is; a C++ mutex carries no poisoned
// state, and the two writes are single assignments, so there is nothing to poison.
void remember_api_ech(std::vector<std::uint8_t> ech);
[[nodiscard]] std::optional<std::vector<std::uint8_t>> api_ech_in_use();
void forget_api_ech();

// -- What a refusal says ----------------------------------------------------------------------

// `describe_rejection`: "status {status}: {detail}{hint}", the status spelled the way Rust's
// StatusCode spells it (zerotrust::status_display, shared so the two modules cannot drift), the
// detail the API's own errors when it carries any, else the trimmed body cut to 220 characters
// with an ellipsis -- characters, not bytes, so a body in any script is cut without splitting a
// code point. The hint is the 403 note about a flagged address, the 429 note about waiting, and
// nothing for every other code.
[[nodiscard]] std::string describe_rejection(std::uint16_t status, std::string_view body);

// `extract_api_error`: the `errors` array of a JSON answer, each entry's `message` -- "unknown"
// when it is missing, not a string, or the entry is no object at all -- with " (code {n})" behind
// it when `code` is there and is an integer, joined with "; ". Nothing when the body is no JSON,
// carries no `errors`, has one that is no array, or holds no entries.
[[nodiscard]] std::optional<std::string> extract_api_error(std::string_view body);

// -- The three error texts and the three log lines api_call builds ----------------------------
//
// The loop that uses them is the engine's; the wording is this module's, because a log line and
// an error message are data.

// `HemeraError::Api("{label}: no attempt was made")`, the error an api_call that never sent
// anything returns.
[[nodiscard]] std::string no_attempt_error(std::string_view label);
// `HemeraError::Api("{label}: {error}")` for a transport failure.
[[nodiscard]] std::string transport_error(std::string_view label, std::string_view error);
// `HemeraError::Api("{label}: status {status}")`, which StatusCode::from_u16 raises for a code
// outside 100..=999 -- 0 for an answer the engine never read, or a nonsense one.
[[nodiscard]] std::string status_error(std::string_view label, std::uint16_t status);
// `HemeraError::Api("{label} decode: {reason} ({n} byte answer)")`, for a 2xx that is not an
// AccountData. The length is in bytes, which is all `body.len()` can mean.
[[nodiscard]] std::string decode_error(std::string_view label, std::string_view reason,
                                       std::size_t body_len);
// The rejection: `describe_rejection` behind the label, and behind `identity refused: ` or
// `api: ` according to `refuses_identity` -- the two variants are chosen before the retry test,
// so a 401 that would be retried is still named for the identity.
[[nodiscard]] std::string rejection_error(std::string_view label, std::uint16_t status,
                                          std::string_view body);

// `log::warn!("[!] {label} retry {}/{} in {:.1}s: {last_error}")`, with attempt 1-based as the
// loop reaches it and the total Rust prints as API_ATTEMPTS - 1. `{:.1}` is one decimal place,
// which is why the seconds are formatted with an explicit fixed one: the default float format
// with a precision would give significant digits instead.
[[nodiscard]] std::string retry_line(std::string_view label, std::uint32_t attempt,
                                     std::chrono::milliseconds wait, std::string_view last_error);
// `log::warn!("[!] {label} asked us to wait {n}s before retrying")`, whole seconds, the header's
// own count after the cap.
[[nodiscard]] std::string cooldown_line(std::string_view label, std::chrono::seconds wait);
// `log::info!("[+] {label} went over ECH")`.
[[nodiscard]] std::string ech_line(std::string_view label);

// -- Where the calls go: --enroll-address -----------------------------------------------------

// `enroll_address` (HEMERA_ENROLL_ADDRESS): an IP address or a domain name, its port 443 unless
// `:port` follows it, an IPv6 one then in brackets. Unset, or nothing but spaces, gives the API's
// own host on 443; anything the address rules refuse is an error naming the option and the value
// as it was given, spaces and all after the trim. The connection goes there; the API's name stays
// the server name and the HTTP host, which is the engine's business, not this function's.
[[nodiscard]] std::expected<std::pair<std::string, std::uint16_t>, std::string>
enroll_address(const Settings& settings);

// `check_enroll_address`: the same reading, with only the verdict kept, as the core starts.
[[nodiscard]] std::expected<void, std::string> check_enroll_address(const Settings& settings);

// -- The device's own keys and stamps ---------------------------------------------------------

// `generate_x25519_keypair`: 32 bytes of randomness, clamped the way the Rust clamps them before
// dalek sees them, and the base64 of the public key that belongs to them. The randomness comes
// from BoringSSL's RAND_bytes, and the key from its x25519, as every other key in this core does.
// The first return is the private scalar in WireGuard's order; nothing prints it.
[[nodiscard]] std::pair<std::array<std::uint8_t, 32>, std::string> generate_x25519_keypair();

// The public half on its own: a private scalar -- clamped or not, `x25519-dalek` clamps inside
// its base-point multiply and so does this -- to the base64 of the 32-byte public value.
[[nodiscard]] std::string x25519_public_key_base64(const std::array<std::uint8_t, 32>& private_key);

// `random_android_serial`: 8 random bytes, lower-case hex, which is 16 characters.
[[nodiscard]] std::string random_android_serial();

// `tos_timestamp`: the local clock as `%Y-%m-%dT%H:%M:%S%.3f%:z` --
// "2026-02-03T04:05:06.789+02:00", the offset always signed and always with its colon, the
// fractional part always three digits, the whole thing read at the local zone of that instant,
// DST included.
[[nodiscard]] std::string tos_timestamp();

// The same format with the instant, the milliseconds and the offset given, so the shape is
// testable without waiting for a clock. `offset_secs` is the zone's distance ahead of UTC.
[[nodiscard]] std::string tos_timestamp_at(std::int64_t unix_secs, std::uint64_t millis,
                                           std::int32_t offset_secs);

// -- The profile, once it is in hand ---------------------------------------------------------

// `extract_wg_peer`: the first peer's public key, base64'd, into 32 bytes. No peers, a value that
// is no base64, or one that decodes to any other length is an HemeraError::Api with the Rust's
// own reason; the base64 failure keeps the crate's own message out, since encoding.hpp's decode
// says only that it refused.
[[nodiscard]] std::expected<std::array<std::uint8_t, 32>, std::string>
extract_wg_peer(const AccountData& reg);

// `endpoint_from`: the first peer's v4 endpoint, trimmed, with a trailing `:port` dropped -- but
// only when there is something before the colon, so ":443" stands as it is, and a second colon
// keeps everything up to the last one. No peers at all gives the empty string.
[[nodiscard]] std::string endpoint_from(const AccountData& reg);

// `finish_provision`, the assembly half: an empty token and no peer are errors, the client id is
// read with all four of Rust's ways to come away with zeros, and the identity that comes back
// carries the addresses exactly as the answer wrote them -- untrimmed, unlike refresh_profile,
// which trims every one. `notes` collects the `[account]` lines the Rust logs.
[[nodiscard]] std::expected<Identity, std::string> finish_provision(const AccountData& reg,
                                                                  const std::array<std::uint8_t, 32>& wg_private,
                                                                  std::vector<std::string>& notes);

// `refresh_profile`'s arms, once the device fetch has answered. A refusal marks the saved
// identity refused and says so twice; anything else that went wrong keeps the saved profile
// whole; an answer replaces what it carries and leaves the rest.
[[nodiscard]] Identity refresh_after_refusal(const Identity& identity, std::string_view reason,
                                             std::vector<std::string>& notes);
[[nodiscard]] Identity refresh_with_saved_profile(const Identity& identity, std::string_view error,
                                                 std::vector<std::string>& notes);
[[nodiscard]] Identity refresh_from_profile(const AccountData& reg, const Identity& identity,
                                            std::vector<std::string>& notes);

// -- The MASQUE certificate, and when it has to be replaced ---------------------------------

// What `generate_masque_keypair` hands the engine, field for field: the PKCS#8 private key PEM,
// the self-signed certificate PEM, and the DER SubjectPublicKeyInfo the enrollment body base64's.
struct MasqueKeyPair {
    std::vector<std::uint8_t> key_pem;
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> spki_der;

    [[nodiscard]] bool operator==(const MasqueKeyPair&) const = default;
};

// What `ensure_masque_enrolled` hands back: the certificate in force and whether this call put a
// fresh one there.
struct MasqueEnrollment {
    std::vector<std::uint8_t> cert_pem;
    std::vector<std::uint8_t> key_pem;
    std::uint64_t issued_at = 0;
    bool renewed = false;

    [[nodiscard]] bool operator==(const MasqueEnrollment&) const = default;
};

// Whether an enrollment round trip is needed at all, and which of the two lines
// ensure_masque_enrolled logs before asking for one: the expiring one for a certificate that is
// there but stale, the enrolling one for a device that never had one.
struct EnrollmentPlan {
    bool needs_enrollment = false;
    std::string note;
};

[[nodiscard]] EnrollmentPlan plan_masque_enrollment(const Identity& identity);

// The certificate a fresh key pair brings in force, issued now.
[[nodiscard]] MasqueEnrollment new_masque_enrollment(const MasqueKeyPair& pair,
                                                     std::uint64_t issued_at);

// The failed-enrollment arm: the certificate already on disk stands, with the warn line naming
// the failure, only while `cert_still_usable` says it may; otherwise the enrollment's own error
// is what the caller returns.
[[nodiscard]] std::expected<MasqueEnrollment, std::string>
masque_enrollment_after_error(const Identity& identity, std::string_view error,
                              std::vector<std::string>& notes);

} // namespace hemera::core::account
