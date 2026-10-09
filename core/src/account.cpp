#include "account.hpp"

#include "consts.hpp"
#include "dns.hpp"
#include "encoding.hpp"
#include "zerotrust.hpp"

#include "json.hpp"

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <ctime>
#include <expected>
#include <format>
#include <limits>
#include <mutex>
#include <random>
#include <string_view>

namespace aether::core::account {
namespace {

// The longest rejection detail `describe_rejection` keeps ahead of its ellipsis. Rust counts it in
// characters, not bytes.
constexpr std::size_t MAX_REJECTION_CHARS = 220;

// The largest value an i64 holds, as a double -- which is the only form json.hpp keeps a number
// in, and so the only form a `code` can arrive as.
constexpr double INT64_MAX_AS_DOUBLE = 9223372036854775807.0;
constexpr double INT64_MIN_AS_DOUBLE = -9223372036854775808.0;

// error.rs's Display for AetherError::IdentityRefused.
std::string identity_refused(std::string_view reason) {
    return "identity refused: " + std::string(reason);
}

void fill_random(std::uint8_t* out, std::size_t len) {
    // RAND_bytes rather than a local generator: a device key and a serial number both reach the
    // account, so they have to be unpredictable, not merely different.
    if (RAND_bytes(out, static_cast<int>(len)) == 1) return;
    // Without the TLS library's entropy the operating system is asked, which fails loudly rather
    // than writing keys anyone could guess.
    std::random_device device;
    for (std::size_t at = 0; at < len; ++at) out[at] = static_cast<std::uint8_t>(device());
}

// Rust's `str::parse::<u64>()`: digits only, with a leading `+` that from_chars refuses. An empty
// string, stray text, or a number u64 cannot hold is no number at all.
std::optional<std::uint64_t> parse_u64(std::string_view text) {
    if (text.starts_with('+')) text.remove_prefix(1);
    if (text.empty()) return std::nullopt;

    std::uint64_t value = 0;
    const auto read = std::from_chars(text.data(), text.data() + text.size(), value);
    if (read.ec != std::errc{} || read.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::string hex_lower(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t byte : bytes) {
        out += digits[byte >> 4];
        out += digits[byte & 0x0f];
    }
    return out;
}

// `text` with every leading `needle` dropped -- Rust's `trim_start_matches`, which repeats rather
// than stripping once.
std::string_view strip_start(std::string_view text, std::string_view needle) {
    while (text.starts_with(needle)) text.remove_prefix(needle.size());
    return text;
}

// The number of characters in a UTF-8 string, which is what Rust counts when it caps a rejection:
// a byte in 0x80..=0xBF continues the character in front of it, so it is not counted.
std::size_t char_count(std::string_view text) {
    std::size_t chars = 0;
    for (const char c : text) {
        if ((static_cast<std::uint8_t>(c) & 0xc0U) != 0x80U) ++chars;
    }
    return chars;
}

// The first `count` characters of `text`, on whole code points only.
std::string_view chars_prefix(std::string_view text, std::size_t count) {
    std::size_t at = 0;
    for (std::size_t seen = 0; seen < count && at < text.size(); ++seen) {
        const auto byte = static_cast<std::uint8_t>(text[at]);
        std::size_t width = 1;
        if ((byte & 0xe0U) == 0xc0U) width = 2;
        else if ((byte & 0xf0U) == 0xe0U) width = 3;
        else if ((byte & 0xf8U) == 0xf0U) width = 4;
        at += std::min(width, text.size() - at);
    }
    return text.substr(0, at);
}

// `{:?}` of a Rust string: quoted, with `"\` and the three named controls escaped, and any other
// control character written `\u{...}` with lowercase, unpadded digits. Text above 0x7f belongs to
// printable characters, which Rust keeps as it is, so it is kept here too.
std::string debug_quoted(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        const auto value = static_cast<std::uint8_t>(c);
        switch (value) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (value < 0x20U || value == 0x7fU) {
                    out += std::format("\\u{:x}", static_cast<unsigned>(value));
                } else {
                    out += c;
                }
        }
    }
    out += '"';
    return out;
}

// `{:02x?}` of a byte array: `[0a, 1b, 2c]`, lower case, two digits each.
std::string hex_debug(std::span<const std::uint8_t> bytes) {
    std::string out = "[";
    for (std::size_t at = 0; at < bytes.size(); ++at) {
        if (at != 0) out += ", ";
        out += std::format("{:02x}", static_cast<unsigned>(bytes[at]));
    }
    out += ']';
    return out;
}

// The PEM bytes of an account file, which identity.hpp keeps as text, in the byte form
// account.rs's `Vec<u8>` writes them.
std::vector<std::uint8_t> bytes_of(std::string_view text) {
    std::vector<std::uint8_t> out;
    out.reserve(text.size());
    for (const char c : text) out.push_back(static_cast<std::uint8_t>(c));
    return out;
}

std::array<std::uint8_t, 32> clamp_x25519(std::array<std::uint8_t, 32> key) {
    key[0] = static_cast<std::uint8_t>(key[0] & 248U);
    key[31] = static_cast<std::uint8_t>(key[31] & 127U);
    key[31] = static_cast<std::uint8_t>(key[31] | 64U);
    return key;
}

// Rust's `Duration::as_secs_f32()` printed with `{:.1}` -- one decimal place, which an explicit
// fixed format is the only way to get: the default float format with a precision counts
// significant digits instead.
std::string secs_text(std::chrono::milliseconds wait) {
    const float seconds = static_cast<float>(static_cast<double>(wait.count()) / 1000.0);
    return std::format("{:.1f}", static_cast<double>(seconds));
}

bool name_matches(std::string_view name, std::string_view wanted) {
    if (name.size() != wanted.size()) return false;
    for (std::size_t at = 0; at < name.size(); ++at) {
        const auto one = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(name[at])));
        const auto two = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(wanted[at])));
        if (one != two) return false;
    }
    return true;
}

// Days since the Unix epoch for a civil date, and its inverse: the two halves of reading the
// local zone's offset off a broken-down time, which is what chrono's `Local` does for `%.3f%:z`.
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) {
    year -= month <= 2U ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto yoe = static_cast<unsigned>(year - era * 400);
    const unsigned shifted = month > 2U ? month - 3U : month + 9U;
    const unsigned doy = (153U * shifted + 2U) / 5U + day - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t days, std::int64_t& year, unsigned& month, unsigned& day) {
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const auto doe = static_cast<std::uint64_t>(days - era * 146097);
    const auto yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t adjusted = static_cast<std::int64_t>(yoe) + era * 400;
    const auto doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const auto mp = (5 * doy + 2) / 153;
    day = static_cast<unsigned>(doy - (153 * mp + 2) / 5 + 1);
    month = static_cast<unsigned>(mp + (mp < 10 ? 3 : -9));
    year = adjusted + (month <= 2U ? 1 : 0);
}

// The zone's distance ahead of UTC at `when`, DST and all: the local broken-down time and the UTC
// one, turned back into absolute seconds and subtracted. A read that fails is no offset at all,
// which is what a machine with no zone configured says anyway.
std::int32_t local_offset_secs(std::time_t when) {
    std::tm local{};
    std::tm utc{};
    if (localtime_s(&local, &when) != 0) return 0;
    if (gmtime_s(&utc, &when) != 0) return 0;

    const std::int64_t local_day = days_from_civil(static_cast<std::int64_t>(local.tm_year) + 1900,
                                                   static_cast<unsigned>(local.tm_mon) + 1U,
                                                   static_cast<unsigned>(local.tm_mday));
    const std::int64_t utc_day = days_from_civil(static_cast<std::int64_t>(utc.tm_year) + 1900,
                                                 static_cast<unsigned>(utc.tm_mon) + 1U,
                                                 static_cast<unsigned>(utc.tm_mday));
    const std::int64_t local_secs =
        local_day * 86400 + static_cast<std::int64_t>(local.tm_hour) * 3600 +
        static_cast<std::int64_t>(local.tm_min) * 60 + local.tm_sec;
    const std::int64_t utc_secs = utc_day * 86400 + static_cast<std::int64_t>(utc.tm_hour) * 3600 +
                                  static_cast<std::int64_t>(utc.tm_min) * 60 + utc.tm_sec;
    return static_cast<std::int32_t>(local_secs - utc_secs);
}

// -- the account answer's reader ---------------------------------------------------------------

using aether::json::Object;
using aether::json::Value;

// serde::de::Unexpected, which is how an "invalid type" message names what the reader found.
std::string unexpected_text(const Value& value) {
    if (value.is_bool()) return value.as_bool() ? "boolean `true`" : "boolean `false`";
    if (value.is_string()) return "string " + debug_quoted(value.as_string());
    if (value.is_array()) return "sequence";
    if (value.is_object()) return "map";
    if (value.is_number()) {
        const double raw = value.as_double();
        if (std::isfinite(raw) && raw == std::floor(raw) && raw >= INT64_MIN_AS_DOUBLE &&
            raw <= INT64_MAX_AS_DOUBLE) {
            return "integer `" + std::to_string(static_cast<std::int64_t>(raw)) + "`";
        }
        return "floating point `" + std::format("{}", raw) + "`";
    }
    return "null";
}

std::string invalid_type(const Value& value, std::string_view expected) {
    return "invalid type: " + unexpected_text(value) + ", expected " + std::string(expected);
}

// A `String` field: required, or defaulted to empty the way `#[serde(default)]` defaults it. A
// value of any other kind is refused the way serde refuses it.
std::expected<std::string, std::string> text_member(const Object& object, std::string_view key,
                                                   bool required) {
    const auto found = object.find(key);
    if (found == object.end()) {
        if (required) return std::unexpected("missing field `" + std::string(key) + "`");
        return std::string{};
    }
    if (!found->second.is_string()) return std::unexpected(invalid_type(found->second, "a string"));
    return found->second.as_string();
}

// A nested struct, which every one of these carries as `#[serde(default)]`: absent reads as the
// default, so as an empty object, and anything that is no object is refused.
std::expected<Object, std::string> object_member(const Object& object, std::string_view key,
                                                 std::string_view expected) {
    const auto found = object.find(key);
    if (found == object.end()) return Object{};
    if (!found->second.is_object()) return std::unexpected(invalid_type(found->second, expected));
    return found->second.as_object();
}

std::expected<Addresses, std::string> addresses_from(const Object& object) {
    Addresses addresses;
    const auto v4 = text_member(object, "v4", false);
    if (!v4) return std::unexpected(v4.error());
    const auto v6 = text_member(object, "v6", false);
    if (!v6) return std::unexpected(v6.error());
    addresses.v4 = *v4;
    addresses.v6 = *v6;
    return addresses;
}

std::expected<Interface, std::string> iface_from(const Object& object) {
    Interface iface;
    const auto addresses = object_member(object, "addresses", "struct Addresses");
    if (!addresses) return std::unexpected(addresses.error());
    const auto parsed = addresses_from(*addresses);
    if (!parsed) return std::unexpected(parsed.error());
    iface.addresses = *parsed;
    return iface;
}

std::expected<PeerEndpoint, std::string> endpoint_from_object(const Object& object) {
    PeerEndpoint endpoint;
    const auto v4 = text_member(object, "v4", false);
    if (!v4) return std::unexpected(v4.error());
    const auto v6 = text_member(object, "v6", false);
    if (!v6) return std::unexpected(v6.error());
    const auto host = text_member(object, "host", false);
    if (!host) return std::unexpected(host.error());
    endpoint.v4 = *v4;
    endpoint.v6 = *v6;
    endpoint.host = *host;
    return endpoint;
}

std::expected<Peer, std::string> peer_from(const Object& object) {
    Peer peer;
    // The one field in the answer's schema with no default at all.
    const auto public_key = text_member(object, "public_key", true);
    if (!public_key) return std::unexpected(public_key.error());
    peer.public_key = *public_key;

    const auto endpoint = object_member(object, "endpoint", "struct PeerEndpoint");
    if (!endpoint) return std::unexpected(endpoint.error());
    const auto parsed = endpoint_from_object(*endpoint);
    if (!parsed) return std::unexpected(parsed.error());
    peer.endpoint = *parsed;
    return peer;
}

std::expected<Services, std::string> services_from(const Object& object) {
    Services services;
    const auto http_proxy = text_member(object, "http_proxy", false);
    if (!http_proxy) return std::unexpected(http_proxy.error());
    services.http_proxy = *http_proxy;
    return services;
}

std::expected<AccountInfo, std::string> account_info_from(const Object& object) {
    AccountInfo info;
    const auto id = text_member(object, "id", false);
    if (!id) return std::unexpected(id.error());
    const auto account_type = text_member(object, "account_type", false);
    if (!account_type) return std::unexpected(account_type.error());
    const auto organization = text_member(object, "organization", false);
    if (!organization) return std::unexpected(organization.error());
    info.id = *id;
    info.account_type = *account_type;
    info.organization = *organization;
    return info;
}

std::expected<Config, std::string> config_from(const Object& object) {
    Config config;

    const auto iface = object_member(object, "interface", "struct Interface");
    if (!iface) return std::unexpected(iface.error());
    const auto parsed_interface = iface_from(*iface);
    if (!parsed_interface) return std::unexpected(parsed_interface.error());
    config.interface = *parsed_interface;

    const auto peers = object.find("peers");
    if (peers != object.end()) {
        if (!peers->second.is_array()) {
            return std::unexpected(invalid_type(peers->second, "a sequence"));
        }
        for (const Value& entry : peers->second.as_array()) {
            if (!entry.is_object()) {
                return std::unexpected(invalid_type(entry, "struct Peer"));
            }
            const auto peer = peer_from(entry.as_object());
            if (!peer) return std::unexpected(peer.error());
            config.peers.push_back(*peer);
        }
    }

    const auto client_id = text_member(object, "client_id", false);
    if (!client_id) return std::unexpected(client_id.error());
    config.client_id = *client_id;

    const auto services = object_member(object, "services", "struct Services");
    if (!services) return std::unexpected(services.error());
    const auto parsed_services = services_from(*services);
    if (!parsed_services) return std::unexpected(parsed_services.error());
    config.services = *parsed_services;

    return config;
}

// A `code` read the way serde's `as_i64` reads one: a number that is a whole one and fits.
std::optional<std::int64_t> integer_of(const Value& value) {
    if (!value.is_number()) return std::nullopt;
    const double raw = value.as_double();
    if (!std::isfinite(raw) || raw != std::floor(raw)) return std::nullopt;
    if (raw < INT64_MIN_AS_DOUBLE || raw > INT64_MAX_AS_DOUBLE) return std::nullopt;
    return static_cast<std::int64_t>(raw);
}

} // namespace

// -- Names, constants and the error prefix ------------------------------------------------------

std::string api_error(std::string_view reason) { return "api: " + std::string(reason); }

// -- The bodies a registration sends ------------------------------------------------------------

std::string json_quote(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        const auto value = static_cast<std::uint8_t>(c);
        switch (value) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\f': out += "\\f"; break;
            case '\r': out += "\\r"; break;
            default:
                // serde_json escapes neither DEL nor anything above it, so UTF-8 goes out as it
                // came in.
                if (value < 0x20U) {
                    out += std::format("\\u{:04x}", static_cast<unsigned>(value));
                } else {
                    out += c;
                }
        }
    }
    out += '"';
    return out;
}

std::string Registration::to_json_text() const {
    std::string out = "{";
    out += "\"key\":" + json_quote(key);
    out += ",\"install_id\":" + json_quote(install_id);
    out += ",\"fcm_token\":" + json_quote(fcm_token);
    out += ",\"tos\":" + json_quote(tos);
    out += ",\"model\":" + json_quote(model);
    out += ",\"serial_number\":" + json_quote(serial_number);
    out += ",\"os_version\":" + json_quote(os_version);
    out += ",\"key_type\":" + json_quote(key_type);
    out += ",\"tunnel_type\":" + json_quote(tunnel_type);
    out += ",\"locale\":" + json_quote(locale);
    out += '}';
    return out;
}

std::string TeamRegistration::to_json_text() const {
    std::string out = "{";
    out += "\"key\":" + json_quote(key);
    out += ",\"install_id\":" + json_quote(install_id);
    out += ",\"fcm_token\":" + json_quote(fcm_token);
    out += ",\"tos\":" + json_quote(tos);
    out += ",\"model\":" + json_quote(model);
    out += ",\"name\":" + json_quote(name);
    out += ",\"serial_number\":" + json_quote(serial_number);
    out += ",\"locale\":" + json_quote(locale);
    out += '}';
    return out;
}

std::string DeviceUpdate::to_json_text() const {
    std::string out = "{";
    out += "\"key\":" + json_quote(key);
    out += ",\"key_type\":" + json_quote(key_type);
    out += ",\"tunnel_type\":" + json_quote(tunnel_type);
    // skip_serializing_if = "Option::is_none": a device with no new name keeps the one it has.
    if (name.has_value()) out += ",\"name\":" + json_quote(*name);
    out += '}';
    return out;
}

Registration new_registration(std::string wg_public_key, std::string_view model,
                               std::string_view serial_number, std::string_view tos,
                               std::string_view locale) {
    Registration body;
    body.key = std::move(wg_public_key);
    // Empty, and sent empty, because the API's schema wants the fields and an Android install id
    // means nothing to this core.
    body.tos = std::string(tos);
    body.model = std::string(model);
    body.serial_number = std::string(serial_number);
    body.key_type = "curve25519";
    body.tunnel_type = "wireguard";
    body.locale = std::string(locale);
    return body;
}

TeamRegistration team_registration_body(std::string public_key, std::string_view model,
                                        std::string_view locale) {
    const std::string install_id = ::aether::core::zerotrust::generate_install_id();
    const std::string fcm_token = ::aether::core::zerotrust::generate_fcm_token(install_id);

    TeamRegistration body;
    body.key = std::move(public_key);
    body.tos = tos_timestamp();
    body.model = std::string(model);
    // The install id names the device three times over: as itself, as the name, and as the serial.
    body.name = install_id;
    body.serial_number = install_id;
    body.locale = std::string(locale);
    body.install_id = std::move(install_id);
    body.fcm_token = std::move(fcm_token);
    return body;
}

DeviceUpdate device_update_body(std::span<const std::uint8_t> spki_der,
                                const std::optional<std::string>& name) {
    DeviceUpdate body;
    body.key = ::aether::core::base64_encode(spki_der);
    body.key_type = std::string(::aether::core::KEY_TYPE_MASQUE);
    body.tunnel_type = std::string(::aether::core::TUN_TYPE_MASQUE);
    body.name = name;
    return body;
}

// -- The answer a call gets back ----------------------------------------------------------------

std::expected<AccountData, std::string> account_data_from_json(std::string_view body) {
    const std::optional<Value> parsed = aether::json::parse(body);
    if (!parsed) return std::unexpected("expected value");
    if (!parsed->is_object()) return std::unexpected(invalid_type(*parsed, "struct AccountData"));

    const Object& root = parsed->as_object();

    AccountData data;
    const auto id = text_member(root, "id", true);
    if (!id) return std::unexpected(id.error());
    data.id = *id;

    const auto token = text_member(root, "token", false);
    if (!token) return std::unexpected(token.error());
    data.token = *token;

    const auto config = object_member(root, "config", "struct Config");
    if (!config) return std::unexpected(config.error());
    const auto parsed_config = config_from(*config);
    if (!parsed_config) return std::unexpected(parsed_config.error());
    data.config = *parsed_config;

    const auto account = object_member(root, "account", "struct AccountInfo");
    if (!account) return std::unexpected(account.error());
    const auto parsed_account = account_info_from(*account);
    if (!parsed_account) return std::unexpected(parsed_account.error());
    data.account = *parsed_account;

    return data;
}

// -- Identity's own methods ---------------------------------------------------------------------

std::expected<std::array<std::uint8_t, 32>, std::string> private_key_bytes(
    const Identity& identity) {
    return identity.wg_private_key;
}

std::expected<std::array<std::uint8_t, 32>, std::string> peer_public_key_bytes(
    const Identity& identity) {
    return identity.wg_peer_public_key;
}

// -- The retry arithmetic -----------------------------------------------------------------------

std::uint64_t backoff_step_ms(std::uint32_t attempt) {
    // attempt.min(5) caps the shift, so the multiply cannot overflow with this base; saturating
    // stays because that is what the Rust says, and what would keep a wider base honest.
    const std::uint32_t shift = std::min<std::uint32_t>(attempt, 5U);
    const std::uint64_t factor = std::uint64_t{1} << shift;
    const std::uint64_t exponential =
        API_BACKOFF_BASE_MS > std::numeric_limits<std::uint64_t>::max() / factor
            ? std::numeric_limits<std::uint64_t>::max()
            : API_BACKOFF_BASE_MS * factor;
    return std::min(exponential, API_BACKOFF_CAP_MS);
}

std::chrono::milliseconds backoff_delay_at(std::uint32_t attempt, std::uint32_t draw) {
    const std::uint64_t capped = backoff_step_ms(attempt);
    // The draw stands in for `rand::rng().next_u32()`. The modulus is one wider than a third of
    // the step, so a jitter of exactly zero is as reachable as the largest one, and half the step
    // is the floor of the wait.
    const std::uint64_t jitter = static_cast<std::uint64_t>(draw) % (capped / 3 + 1);
    return std::chrono::milliseconds(capped / 2 + jitter);
}

std::chrono::milliseconds backoff_delay(std::uint32_t attempt) {
    std::array<std::uint8_t, 4> raw{};
    fill_random(raw.data(), raw.size());
    const std::uint32_t draw = (static_cast<std::uint32_t>(raw[0]) << 24) |
                               (static_cast<std::uint32_t>(raw[1]) << 16) |
                               (static_cast<std::uint32_t>(raw[2]) << 8) |
                               static_cast<std::uint32_t>(raw[3]);
    return backoff_delay_at(attempt, draw);
}

std::optional<std::chrono::seconds> retry_after(const HeaderFields& headers) {
    // HeaderMap::get hands back the first of several, and to_str refuses what is no text. The
    // trim below is the only other step that can still turn a value into a refusal, and it is
    // Rust's own: the integer parse takes nothing but digits after it.
    for (const auto& [name, value] : headers) {
        if (!name_matches(name, "Retry-After")) continue;
        const std::optional<std::uint64_t> seconds = parse_u64(::aether::core::trim(value));
        if (!seconds) return std::nullopt;
        return std::chrono::seconds(std::min(*seconds, API_RETRY_AFTER_CAP_SECS));
    }
    return std::nullopt;
}

// -- Which answers mean what --------------------------------------------------------------------

bool refuses_identity(std::uint16_t status) {
    // UNAUTHORIZED, NOT_FOUND, GONE.
    return status == 401 || status == 404 || status == 410;
}

bool worth_retrying(std::uint16_t status) {
    // TOO_MANY_REQUESTS, REQUEST_TIMEOUT, or is_server_error(), which is 500 through 599 only.
    return status == 429 || status == 408 || (status >= 500 && status <= 599);
}

// -- Where the calls go, and what goes on them --------------------------------------------------

std::string_view api_host() { return api_host_from(::aether::core::API_URL); }

std::string_view api_host_from(std::string_view url) {
    std::string_view rest = strip_start(url, "https://");
    rest = strip_start(rest, "http://");
    // split('/').next() is everything before the first '/', and an empty string still has one
    // empty segment, so a URL that is nothing at all gives a host that is nothing at all.
    return rest.substr(0, rest.find('/'));
}

HeaderFields front_headers(const std::optional<std::string_view>& bearer,
                           const std::optional<std::string_view>& jwt) {
    HeaderFields headers{
        {"Content-Type", "application/json; charset=UTF-8"},
        {"User-Agent", std::string(::aether::core::UA_REGISTER)},
        {"CF-Client-Version", std::string(::aether::core::CF_CLIENT_VERSION)},
        {"Accept", "application/json"},
    };
    if (bearer.has_value()) {
        headers.emplace_back("Authorization", "Bearer " + std::string(*bearer));
    }
    if (jwt.has_value()) {
        headers.emplace_back("CF-Access-Jwt-Assertion", std::string(*jwt));
    }
    return headers;
}

// -- The API's ECH stash ------------------------------------------------------------------------

namespace {

std::mutex& api_ech_mutex() {
    static std::mutex slot_mutex;
    return slot_mutex;
}

std::optional<std::vector<std::uint8_t>>& api_ech_slot() {
    static std::optional<std::vector<std::uint8_t>> slot;
    return slot;
}

} // namespace

void remember_api_ech(std::vector<std::uint8_t> ech) {
    const std::lock_guard<std::mutex> held(api_ech_mutex());
    api_ech_slot() = std::move(ech);
}

std::optional<std::vector<std::uint8_t>> api_ech_in_use() {
    const std::lock_guard<std::mutex> held(api_ech_mutex());
    return api_ech_slot();
}

void forget_api_ech() {
    const std::lock_guard<std::mutex> held(api_ech_mutex());
    api_ech_slot().reset();
}

// -- What a refusal says ------------------------------------------------------------------------

std::optional<std::string> extract_api_error(std::string_view body) {
    const std::optional<Value> parsed = aether::json::parse(body);
    if (!parsed || !parsed->is_object()) return std::nullopt;

    const Object& root = parsed->as_object();
    const auto errors = root.find("errors");
    if (errors == root.end()) return std::nullopt;
    if (!errors->second.is_array()) return std::nullopt;

    std::vector<std::string> parts;
    for (const Value& entry : errors->second.as_array()) {
        // A non-object entry has no `message` and no `code`, which is exactly what Rust's
        // Value::get returns nothing for: the entry still counts, as "unknown".
        std::string message = "unknown";
        std::optional<std::int64_t> code;
        if (entry.is_object()) {
            const auto& fields = entry.as_object();
            const auto found_message = fields.find("message");
            if (found_message != fields.end() && found_message->second.is_string()) {
                message = found_message->second.as_string();
            }
            const auto found_code = fields.find("code");
            if (found_code != fields.end()) code = integer_of(found_code->second);
        }

        if (code.has_value()) {
            parts.push_back(message + " (code " + std::to_string(*code) + ")");
        } else {
            parts.push_back(std::move(message));
        }
    }

    // An empty array is no detail at all, so the caller falls back to the body it was given.
    if (parts.empty()) return std::nullopt;

    std::string joined;
    for (std::size_t at = 0; at < parts.size(); ++at) {
        if (at != 0) joined += "; ";
        joined += parts[at];
    }
    return joined;
}

std::string describe_rejection(std::uint16_t status, std::string_view body) {
    std::string detail;
    if (const auto found = extract_api_error(body)) {
        detail = *found;
    } else {
        const std::string_view trimmed = ::aether::core::trim(body);
        if (trimmed.empty()) {
            detail = "no details returned";
        } else if (char_count(trimmed) > MAX_REJECTION_CHARS) {
            // "…" is U+2026, which Rust writes as three bytes.
            detail = std::string(chars_prefix(trimmed, MAX_REJECTION_CHARS)) + "\xe2\x80\xa6";
        } else {
            detail = std::string(trimmed);
        }
    }

    std::string_view hint;
    switch (status) {
        case 403:
            hint = " (cloudflare refused this network; the address looks flagged, "
                   "try again later, switch network, or import an existing identity)";
            break;
        case 429:
            hint = " (too many registrations from this address; wait a few minutes "
                   "before trying again)";
            break;
        default:
            hint = {};
    }

    return "status " + ::aether::core::zerotrust::status_display(status) + ": " + detail +
           std::string(hint);
}

// -- The error texts and the log lines api_call builds -----------------------------------------

std::string no_attempt_error(std::string_view label) {
    return api_error(std::string(label) + ": no attempt was made");
}

std::string transport_error(std::string_view label, std::string_view error) {
    return api_error(std::string(label) + ": " + std::string(error));
}

std::string status_error(std::string_view label, std::uint16_t status) {
    return api_error(std::string(label) + ": status " + std::to_string(status));
}

std::string decode_error(std::string_view label, std::string_view reason, std::size_t body_len) {
    return api_error(std::string(label) + " decode: " + std::string(reason) + " (" +
                     std::to_string(body_len) + " byte answer)");
}

std::string rejection_error(std::string_view label, std::uint16_t status, std::string_view body) {
    const std::string described = std::string(label) + ": " + describe_rejection(status, body);
    // The variant is chosen on the status alone, before anything is known about whether the call
    // will be tried again, so a 401 that is retried is still named for the identity.
    return refuses_identity(status) ? identity_refused(described) : api_error(described);
}

std::string retry_line(std::string_view label, std::uint32_t attempt, std::chrono::milliseconds wait,
                       std::string_view last_error) {
    return "[!] " + std::string(label) + " retry " + std::to_string(attempt) + "/" +
           std::to_string(API_ATTEMPTS - 1) + " in " + secs_text(wait) + "s: " +
           std::string(last_error);
}

std::string cooldown_line(std::string_view label, std::chrono::seconds wait) {
    return "[!] " + std::string(label) + " asked us to wait " + std::to_string(wait.count()) +
           "s before retrying";
}

std::string ech_line(std::string_view label) {
    return "[+] " + std::string(label) + " went over ECH";
}

// -- --enroll-address ---------------------------------------------------------------------------

std::expected<std::pair<std::string, std::uint16_t>, std::string> enroll_address(
    const Settings& settings) {
    // Rust reads the variable and then trims it, so a value of nothing but spaces is the same as
    // no value at all -- and the error names the trimmed one.
    const std::string_view raw = settings.get(ENROLL_ADDRESS_ENV).value_or(std::string_view{});
    const std::string_view value = ::aether::core::trim(raw);
    if (value.empty()) return std::pair{std::string(api_host()), DEFAULT_API_PORT};

    // dns.hpp's host_and_port is the same helper the Rust hands the value to, brackets included.
    // It refuses a port of zero and one above 65535, a scheme, a space, and a bare IPv6 with a
    // port, and it takes a plain IPv6 with no brackets at all.
    if (const auto address = ::aether::core::host_and_port(value, DEFAULT_API_PORT)) {
        return *address;
    }
    return std::unexpected(api_error("--enroll-address: " + std::string(value) +
                                     " is no IP address or domain name, with or without a port"));
}

std::expected<void, std::string> check_enroll_address(const Settings& settings) {
    // Rust's `enroll_address().map(drop)`: the address itself is dropped and the refusal, which
    // already names the option, travels up unchanged.
    if (const auto address = enroll_address(settings); address) {
        static_cast<void>(*address);
        return {};
    } else {
        return std::unexpected(address.error());
    }
}

// -- The device's own keys and stamps ----------------------------------------------------------

std::string x25519_public_key_base64(const std::array<std::uint8_t, 32>& private_key) {
    // x25519-dalek clamps inside its base-point multiply and so does BoringSSL; clamping here as
    // well keeps an unclamped scalar reading the same in both.
    const std::array<std::uint8_t, 32> clamped = clamp_x25519(private_key);
    std::array<std::uint8_t, X25519_PUBLIC_VALUE_LEN> public_key{};
    X25519_public_from_private(public_key.data(), clamped.data());
    return ::aether::core::base64_encode(public_key);
}

std::pair<std::array<std::uint8_t, 32>, std::string> generate_x25519_keypair() {
    std::array<std::uint8_t, 32> private_key{};
    fill_random(private_key.data(), private_key.size());
    private_key = clamp_x25519(private_key);
    return {private_key, x25519_public_key_base64(private_key)};
}

std::string random_android_serial() {
    std::array<std::uint8_t, 8> raw{};
    fill_random(raw.data(), raw.size());
    return hex_lower(raw);
}

std::string tos_timestamp_at(std::int64_t unix_secs, std::uint64_t millis,
                             std::int32_t offset_secs) {
    const std::int64_t local = unix_secs + offset_secs;
    std::int64_t day = local / 86400;
    std::int64_t second_of_day = local % 86400;
    if (second_of_day < 0) {
        second_of_day += 86400;
        --day;
    }

    std::int64_t year = 0;
    unsigned month = 0;
    unsigned day_of_month = 0;
    civil_from_days(day, year, month, day_of_month);

    const unsigned hour = static_cast<unsigned>(second_of_day / 3600);
    const unsigned minute = static_cast<unsigned>((second_of_day % 3600) / 60);
    const unsigned second = static_cast<unsigned>(second_of_day % 60);

    const char sign = offset_secs < 0 ? '-' : '+';
    // Rust's %:z keeps the sign and divides the magnitude by 60 twice over; a negative offset of
    // under a minute would round toward zero the same way chrono's does.
    const std::int32_t offset_minutes = offset_secs / 60;
    const unsigned magnitude = offset_minutes < 0 ? static_cast<unsigned>(-offset_minutes)
                                                  : static_cast<unsigned>(offset_minutes);
    const unsigned offset_hours = magnitude / 60U;
    const unsigned offset_tail = magnitude % 60U;

    // chrono's `%Y` pads the year to four digits, the rest to two, `%.3f` to three, and `%:z`
    // always carries its sign and always its colon.
    return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}{}{:02d}:{:02d}",
                       static_cast<int>(year), month, day_of_month, hour, minute, second,
                       millis % 1000U, sign, offset_hours, offset_tail);
}

std::string tos_timestamp() {
    const auto since = std::chrono::system_clock::now().time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(since).count();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(since).count() % 1000;
    if (millis < 0) millis = -millis;
    return tos_timestamp_at(secs, static_cast<std::uint64_t>(millis),
                            local_offset_secs(static_cast<std::time_t>(secs)));
}

// -- The profile, once it is in hand ------------------------------------------------------------

std::expected<std::array<std::uint8_t, 32>, std::string> extract_wg_peer(const AccountData& reg) {
    if (reg.config.peers.empty()) {
        return std::unexpected(api_error("no peers in registration response"));
    }
    const std::optional<std::vector<std::uint8_t>> decoded =
        ::aether::core::base64_decode(reg.config.peers.front().public_key);
    // encoding.hpp's decode says only that it refused, so the crate's own index-and-symbol reason
    // behind "decode peer pubkey: " is not repeated here.
    if (!decoded) return std::unexpected(api_error("decode peer pubkey: invalid base64"));
    if (decoded->size() != 32) return std::unexpected(api_error("invalid peer pubkey length"));

    std::array<std::uint8_t, 32> peer{};
    std::copy(decoded->begin(), decoded->end(), peer.begin());
    return peer;
}

std::string endpoint_from(const AccountData& reg) {
    const std::string_view raw = reg.config.peers.empty()
                                      ? std::string_view{}
                                      : ::aether::core::trim(reg.config.peers.front().endpoint.v4);
    if (raw.empty()) return {};

    // rsplit_once(':') cuts at the LAST colon; only a cut that leaves something behind drops the
    // port, and only the tail is thrown away, so a second colon survives inside the host.
    const std::size_t colon = raw.rfind(':');
    if (colon != std::string_view::npos) {
        const std::string_view host = raw.substr(0, colon);
        if (!host.empty()) return std::string(host);
    }
    return std::string(raw);
}

std::expected<Identity, std::string> finish_provision(const AccountData& reg,
                                                   const std::array<std::uint8_t, 32>& wg_private,
                                                   std::vector<std::string>& notes) {
    if (reg.token.empty()) {
        return std::unexpected(api_error("registration returned empty token"));
    }

    const auto wg_peer_public = extract_wg_peer(reg);
    if (!wg_peer_public) return std::unexpected(wg_peer_public.error());

    std::array<std::uint8_t, 3> client_id{};
    if (reg.config.client_id.empty()) {
        notes.push_back("[account] API response has empty client_id, using zeros");
    } else {
        notes.push_back("[account] received client_id from API: " +
                        debug_quoted(reg.config.client_id));
        const std::optional<std::vector<std::uint8_t>> decoded =
            ::aether::core::base64_decode(reg.config.client_id);
        if (!decoded) {
            notes.push_back("[account] failed to decode client_id base64");
        } else if (decoded->size() != 3) {
            notes.push_back("[account] client_id decoded but wrong length: " +
                            std::to_string(decoded->size()));
        } else {
            std::copy(decoded->begin(), decoded->end(), client_id.begin());
            notes.push_back("[account] decoded client_id: " + hex_debug(client_id));
        }
    }

    Identity identity;
    identity.device_id = reg.id;
    identity.access_token = reg.token;
    identity.cert_issued_at = 0;
    // Straight out of the answer, spaces and all: unlike every other field below, and unlike
    // refresh_profile, the addresses are not trimmed here.
    identity.ipv4 = reg.config.interface.addresses.v4;
    identity.ipv6 = reg.config.interface.addresses.v6;
    identity.wg_private_key = wg_private;
    identity.wg_peer_public_key = *wg_peer_public;
    identity.client_id = client_id;
    identity.organization = std::string(::aether::core::trim(reg.account.organization));
    identity.gateway_proxy = std::string(::aether::core::trim(reg.config.services.http_proxy));
    identity.assigned_endpoint = endpoint_from(reg);
    identity.refused = false;
    return identity;
}

Identity refresh_after_refusal(const Identity& identity, std::string_view reason,
                               std::vector<std::string>& notes) {
    notes.push_back("[-] cloudflare no longer accepts the saved identity for device " +
                    identity.device_id + ": " + std::string(reason));
    notes.push_back("[-] the tunnel will handshake but carry no traffic until this identity is "
                    "replaced");

    Identity refused = identity;
    refused.refused = true;
    return refused;
}

Identity refresh_with_saved_profile(const Identity& identity, std::string_view error,
                                    std::vector<std::string>& notes) {
    notes.push_back("[!] could not reach the account api to check the identity: " +
                    std::string(error));
    notes.push_back("[!] carrying on with the saved profile; it may be out of date");
    return identity;
}

Identity refresh_from_profile(const AccountData& reg, const Identity& identity,
                              std::vector<std::string>& notes) {
    const std::string ipv4(::aether::core::trim(reg.config.interface.addresses.v4));
    const std::string ipv6(::aether::core::trim(reg.config.interface.addresses.v6));
    const std::string organization(::aether::core::trim(reg.account.organization));
    const std::string gateway_proxy(::aether::core::trim(reg.config.services.http_proxy));
    const std::string assigned_endpoint = endpoint_from(reg);

    if (!ipv4.empty() && ipv4 != identity.ipv4) {
        notes.push_back("[+] the account moved this device from " + identity.ipv4 + " to " + ipv4 +
                        "; using the assigned address");
    }
    if (!organization.empty()) {
        notes.push_back("[+] confirmed membership of organization " + organization +
                        " (account type " + reg.account.account_type + ")");
    }
    if (!gateway_proxy.empty()) {
        notes.push_back("[zerotrust] the organization publishes a gateway http proxy at " +
                        gateway_proxy);
    }

    // An empty half of the answer keeps the saved one rather than blanking the identity, which is
    // why the address can move but never disappear.
    Identity refreshed = identity;
    refreshed.ipv4 = ipv4.empty() ? identity.ipv4 : ipv4;
    refreshed.ipv6 = ipv6.empty() ? identity.ipv6 : ipv6;
    refreshed.organization = organization;
    refreshed.gateway_proxy = gateway_proxy;
    refreshed.assigned_endpoint = assigned_endpoint;
    refreshed.refused = false;
    return refreshed;
}

// -- The MASQUE certificate ---------------------------------------------------------------------

EnrollmentPlan plan_masque_enrollment(const Identity& identity) {
    const bool usable = !identity.cert_pem.empty() && !identity.key_pem.empty();
    if (usable && !masque_cert_expiring(identity.cert_issued_at)) return EnrollmentPlan{};

    EnrollmentPlan plan;
    plan.needs_enrollment = true;
    plan.note = usable ? "[*] masque certificate is expiring, enrolling a fresh key"
                       : "[+] enrolling MASQUE key for device " + identity.device_id;
    return plan;
}

MasqueEnrollment new_masque_enrollment(const MasqueKeyPair& pair, std::uint64_t issued_at) {
    MasqueEnrollment enrollment;
    enrollment.cert_pem = pair.cert_pem;
    enrollment.key_pem = pair.key_pem;
    enrollment.issued_at = issued_at;
    enrollment.renewed = true;
    return enrollment;
}

std::expected<MasqueEnrollment, std::string> masque_enrollment_after_error(
    const Identity& identity, std::string_view error, std::vector<std::string>& notes) {
    // `error` is the enrollment failure as its Display reads, which the warn line repeats.
    if (!cert_still_usable(identity)) return std::unexpected(std::string(error));

    notes.push_back("[!] key enrollment failed (" + std::string(error) +
                    "); keeping the certificate already on disk");
    MasqueEnrollment kept;
    kept.cert_pem = bytes_of(identity.cert_pem);
    kept.key_pem = bytes_of(identity.key_pem);
    kept.issued_at = identity.cert_issued_at;
    kept.renewed = false;
    return kept;
}

} // namespace aether::core::account
