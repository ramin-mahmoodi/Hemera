#include "zerotrust.hpp"

#include "json.hpp" // the JWT payload's `exp` claim is the only JSON this module reads

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <mutex>
#include <random>

namespace hemera::core::zerotrust {

namespace {

// The alphabet Rust's `ALPHANUM` draws an install id and an FCM tail from.
constexpr std::string_view ALPHANUM =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

std::mt19937_64& enrolment_entropy() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

bool ascii_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

// Rust's trim is Unicode-wide; the core's values are ASCII, and settings.hpp's trim, which this
// uses, is too. Same for to_lowercase: only ASCII case is folded here, and a name with anything
// else in it fails the ASCII-alphanumeric test further down either way.
std::string lowered_ascii(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char c : text) {
        out += (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
    }
    return out;
}

bool ascii_alnum(char c) {
    const unsigned char byte = static_cast<unsigned char>(c);
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9');
}

bool jwt_body_char(char c) {
    return ascii_alnum(c) || c == '.' || c == '-' || c == '_';
}

// Rust's char::is_whitespace, cut down to the bytes an enrolment page puts between a token and
// whatever follows it. Bytes above 0x7f are part of the value, as they are for Rust's ASCII test.
bool html_stop(char c) {
    return c == '"' || c == '\'' || c == '&' || c == '<' || ascii_space(c);
}

std::string_view trim_start(std::string_view text) {
    const size_t begin = text.find_first_not_of(" \t\r\n\v\f");
    return begin == std::string_view::npos ? std::string_view{} : text.substr(begin);
}

std::vector<std::string_view> split_on(std::string_view text, char separator) {
    std::vector<std::string_view> parts;
    size_t at = 0;
    while (true) {
        const size_t found = text.find(separator, at);
        if (found == std::string_view::npos) {
            parts.push_back(text.substr(at));
            return parts;
        }
        parts.push_back(text.substr(at, found - at));
        at = found + 1;
    }
}

void push_utf8(std::string& out, std::uint32_t code) {
    if (code < 0x80) {
        out += static_cast<char>(code);
    } else if (code < 0x800) {
        out += static_cast<char>(0xc0 | (code >> 6));
        out += static_cast<char>(0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
        out += static_cast<char>(0xe0 | (code >> 12));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (code & 0x3f));
    } else {
        out += static_cast<char>(0xf0 | (code >> 18));
        out += static_cast<char>(0x80 | ((code >> 12) & 0x3f));
        out += static_cast<char>(0x80 | ((code >> 6) & 0x3f));
        out += static_cast<char>(0x80 | (code & 0x3f));
    }
}

// `bytes` as text, with what is no UTF-8 sequence replaced by U+FFFD, which is what Rust's
// from_utf8_lossy ends up with. Divergence: Rust replaces the whole maximal ill-formed subpart
// with one U+FFFD; this walks one byte at a time, so a truncated three-byte sequence can cost more
// than one. Only a mis-encoded query parameter can reach it.
std::string utf8_lossy(std::string_view bytes) {
    static constexpr std::string_view replacement = "\xef\xbf\xbd";
    std::string out;
    out.reserve(bytes.size());

    size_t at = 0;
    while (at < bytes.size()) {
        const unsigned char lead = static_cast<unsigned char>(bytes[at]);
        if (lead < 0x80) {
            out += static_cast<char>(lead);
            ++at;
            continue;
        }

        size_t width = 0;
        std::uint32_t code = 0;
        std::uint32_t lowest = 0;
        if (lead >= 0xc2 && lead <= 0xdf) {
            width = 2;
            code = lead & 0x1fu;
            lowest = 0x80;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            width = 3;
            code = lead & 0x0fu;
            lowest = 0x800;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            width = 4;
            code = lead & 0x07u;
            lowest = 0x10000;
        }

        bool whole = width != 0 && at + width <= bytes.size();
        for (size_t step = 1; whole && step < width; ++step) {
            const unsigned char next = static_cast<unsigned char>(bytes[at + step]);
            if ((next & 0xc0u) != 0x80u) {
                whole = false;
                break;
            }
            code = (code << 6) | (next & 0x3fu);
        }
        // An overlong form, a surrogate half, or a code past the last plane is no character, and
        // each of them falls outside the range its own lead byte had to land in.
        if (whole && (code < lowest || code > 0x10ffffu || (code >= 0xd800 && code <= 0xdfff))) {
            whole = false;
        }

        if (!whole) {
            out.append(replacement);
            ++at;
            continue;
        }
        push_utf8(out, code);
        at += width;
    }
    return out;
}

int url_symbol(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

// base64::engine::general_purpose::URL_SAFE_NO_PAD, which is what a JWT's segments are written in.
// encoding.hpp's base64_decode cannot serve: it speaks the standard alphabet and insists on padding.
// Missing padding is allowed and present padding tolerated, but a symbol that is no part of the
// URL alphabet, a stray `=`, an odd length or bits left over in the last symbol are refused.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> url_segment(std::string_view text) {
    std::string_view body = text;
    size_t pads = 0;
    while (!body.empty() && body.back() == '=') {
        body.remove_suffix(1);
        ++pads;
        if (pads > 2) return std::nullopt; // "A===" is no base64
    }
    if (body.find('=') != std::string_view::npos) return std::nullopt;

    std::vector<std::uint8_t> out;
    const size_t whole = body.size() / 4;
    out.reserve(whole * 3 + 2);

    for (size_t group = 0; group < whole; ++group) {
        std::array<int, 4> part{};
        for (size_t j = 0; j < 4; ++j) {
            part[j] = url_symbol(body[group * 4 + j]);
            if (part[j] < 0) return std::nullopt;
        }
        const unsigned bits = (part[0] << 18) | (part[1] << 12) | (part[2] << 6) | part[3];
        out.push_back(static_cast<std::uint8_t>(bits >> 16));
        out.push_back(static_cast<std::uint8_t>((bits >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(bits & 0xff));
    }

    const std::string_view tail = body.substr(whole * 4);
    if (tail.empty()) return out;
    if (tail.size() == 1) return std::nullopt; // Rust: invalid input length

    std::array<int, 3> part{};
    for (size_t j = 0; j < tail.size(); ++j) {
        part[j] = url_symbol(tail[j]);
        if (part[j] < 0) return std::nullopt;
    }

    if (tail.size() == 2) {
        const unsigned bits = (static_cast<unsigned>(part[0]) << 12) | (static_cast<unsigned>(part[1]) << 6);
        if ((bits & 0x3fu) != 0) return std::nullopt; // trailing bits, which the engine refuses
        out.push_back(static_cast<std::uint8_t>(bits >> 16));
        // Padding the segment carries anyway has to line up with the two symbols.
        if (pads != 0 && pads != 2) return std::nullopt;
        return out;
    }

    const unsigned bits =
        (static_cast<unsigned>(part[0]) << 18) | (static_cast<unsigned>(part[1]) << 12) |
        (static_cast<unsigned>(part[2]) << 6);
    if ((bits & 0x3fu) != 0) return std::nullopt;
    out.push_back(static_cast<std::uint8_t>(bits >> 16));
    out.push_back(static_cast<std::uint8_t>((bits >> 8) & 0xff));
    if (pads != 0 && pads != 1) return std::nullopt;
    return out;
}

int hex_symbol(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Rust's `u32::from_str_radix(text, radix)`: at least one digit, no sign, underscores allowed only
// between digits, and nothing that overflows.
[[nodiscard]] std::optional<std::uint32_t> from_radix(std::string_view text, int radix) {
    if (text.empty()) return std::nullopt;
    std::uint64_t value = 0;
    bool digit_seen = false;
    bool last_was_digit = false;

    for (const char c : text) {
        if (c == '_') {
            if (!digit_seen || !last_was_digit) return std::nullopt;
            last_was_digit = false;
            continue;
        }
        const int digit = radix == 16 ? hex_symbol(c) : (c >= '0' && c <= '9' ? c - '0' : -1);
        if (digit < 0 || digit >= radix) return std::nullopt;
        value = value * static_cast<std::uint64_t>(radix) + static_cast<unsigned>(digit);
        if (value > 0xffffffffull) return std::nullopt;
        digit_seen = true;
        last_was_digit = true;
    }

    if (!digit_seen || !last_was_digit) return std::nullopt;
    return static_cast<std::uint32_t>(value);
}

std::optional<std::string> percent_decode(std::string_view raw);

// One entity's name, `amp` or `#x2F`, as the character it stands for.
[[nodiscard]] std::optional<char32_t> entity_char(std::string_view entity) {
    if (entity == "amp") return U'&';
    if (entity == "lt") return U'<';
    if (entity == "gt") return U'>';
    if (entity == "quot") return U'"';
    if (entity == "apos" || entity == "#39") return U'\'';

    std::optional<std::uint32_t> code;
    if (entity.starts_with("#x") || entity.starts_with("#X")) {
        code = from_radix(entity.substr(2), 16);
    } else if (entity.starts_with("#")) {
        code = from_radix(entity.substr(1), 10);
    }
    if (!code) return std::nullopt;
    // char::from_u32: no surrogate halves, nothing past the last plane.
    if (*code >= 0xd800 && *code <= 0xdfff) return std::nullopt;
    if (*code > 0x10ffff) return std::nullopt;
    return static_cast<char32_t>(*code);
}

std::optional<std::string> percent_decode(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    size_t index = 0;

    while (index < raw.size()) {
        const char byte = raw[index];
        if (byte == '%' && index + 2 < raw.size()) {
            const int hi = hex_symbol(raw[index + 1]);
            const int lo = hex_symbol(raw[index + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                index += 3;
                continue;
            }
            out += '%';
            ++index;
            continue;
        }
        if (byte == '+') {
            out += ' ';
            ++index;
            continue;
        }
        out += byte;
        ++index;
    }

    return utf8_lossy(out);
}

// The enrolment client's two shapes, as the Rust builds them: the email flow's client keeps a
// cookie jar and follows redirects; the service-token one keeps neither.
AccessRequest make_request(std::string_view method, std::string_view url, bool follow_redirects,
                           bool keep_cookies) {
    AccessRequest request;
    request.method = std::string(method);
    request.url = std::string(url);
    request.follow_redirects = follow_redirects;
    request.keep_cookies = keep_cookies;
    return request;
}

std::mutex& cache_gate() {
    static std::mutex gate;
    return gate;
}

std::optional<std::string>& cache_slot() {
    static std::optional<std::string> slot;
    return slot;
}

// A secret's shape only: how much of it there is, never what is in it.
std::string secret_shape(const std::optional<std::string>& value) {
    if (!value || value->empty()) return "unset";
    return "set(" + std::to_string(value->size()) + " bytes)";
}

// Rust's `Duration::from_secs(300).as_secs()`, integer-truncated; the string a timeout is reported
// in.
std::string secs_text(std::uint64_t secs) {
    return std::to_string(secs);
}

} // namespace

// -- Team name -----------------------------------------------------------------------------------

std::optional<std::string> normalize_team(std::string_view raw) {
    std::string value = lowered_ascii(trim(raw));
    if (value.empty()) return std::nullopt;

    // Both prefixes are tried in turn, each once and only where the value stands at that moment,
    // which is what Rust's loop over the two does -- not `else if`, and not a repeated strip.
    for (std::string_view prefix : {std::string_view("https://"), std::string_view("http://")}) {
        if (value.starts_with(prefix)) value.erase(0, prefix.size());
    }

    // trim_end_matches('/') takes every trailing slash, not one.
    while (!value.empty() && value.back() == '/') value.pop_back();

    const size_t slash = value.find('/');
    if (slash != std::string_view::npos) value.erase(slash);

    if (value.size() >= TEAM_SUFFIX.size() &&
        value.compare(value.size() - TEAM_SUFFIX.size(), TEAM_SUFFIX.size(), TEAM_SUFFIX) == 0) {
        value.erase(value.size() - TEAM_SUFFIX.size());
        while (!value.empty() && value.back() == '.') value.pop_back();
    }

    if (value.empty()) return std::nullopt;
    for (const char c : value) {
        if (!ascii_alnum(c) && c != '-' && c != '_') return std::nullopt;
    }
    return value;
}

std::string team_domain(std::string_view team) {
    return "https://" + std::string(team) + "." + std::string(TEAM_SUFFIX);
}

std::optional<TeamSettings> TeamSettings::from_env(const Settings& settings) {
    const std::string* team = settings.find(TEAM_ENV);
    const std::optional<std::string> normalized =
        normalize_team(team == nullptr ? std::string_view{} : std::string_view(*team));
    if (!normalized) return std::nullopt;

    // `non_empty`: the value trimmed, and gone when nothing is left of it.
    const auto option_of = [&settings](std::string_view key) -> std::optional<std::string> {
        const std::string* found = settings.find(key);
        if (found == nullptr) return std::nullopt;
        const std::string_view text = trim(std::string_view(*found));
        if (text.empty()) return std::nullopt;
        return std::string(text);
    };

    TeamSettings result;
    result.team = *normalized;
    result.client_id = option_of(CLIENT_ID_ENV);
    result.client_secret = option_of(CLIENT_SECRET_ENV);
    result.token = option_of(TOKEN_ENV);
    result.email = option_of(EMAIL_ENV);
    return result;
}

bool TeamSettings::has_service_token() const {
    return client_id.has_value() && client_secret.has_value();
}

std::string TeamSettings::team_domain() const { return zerotrust::team_domain(team); }

std::string TeamSettings::login_url() const { return team_domain() + std::string(ENROLL_PATH); }

std::string redacted(const TeamSettings& settings) {
    return "team=" + settings.team + "; client_id=" + secret_shape(settings.client_id) +
           "; client_secret=" + secret_shape(settings.client_secret) +
           "; token=" + secret_shape(settings.token) + "; email=" +
           (settings.email ? *settings.email : std::string("unset"));
}

// -- JWT reading ---------------------------------------------------------------------------------

bool looks_like_jwt(std::string_view token) {
    token = trim(token);
    if (token.size() < JWT_MIN_LEN) return false;

    const std::vector<std::string_view> segments = split_on(token, '.');
    if (segments.size() != 3) return false;
    for (const std::string_view segment : segments) {
        if (segment.empty()) return false;
    }
    for (const char c : token) {
        if (!jwt_body_char(c)) return false;
    }
    return url_segment(segments[0]).has_value();
}

std::optional<std::uint64_t> jwt_expiry(std::string_view token) {
    const std::vector<std::string_view> segments = split_on(token, '.');
    if (segments.size() != 3) return std::nullopt;
    const std::optional<std::vector<std::uint8_t>> payload = url_segment(segments[1]);
    if (!payload) return std::nullopt;

    // serde_json::from_slice over the payload, then value["exp"].as_u64(). Divergence: json.hpp
    // keeps every number as a double, so a claim above 2^53 loses precision, and one written with a
    // fraction or a trailing dot -- which serde_json reads as a float and `as_u64` refuses -- reads
    // back as the truncated integer here rather than as nothing.
    const std::string text(payload->begin(), payload->end());
    const std::optional<hemera::json::Value> parsed = hemera::json::parse(text);
    if (!parsed) return std::nullopt;
    if (!parsed->contains("exp")) return std::nullopt;

    const hemera::json::Value& claim = parsed->get("exp");
    if (!claim.is_number()) return std::nullopt;
    const double raw = claim.as_double();
    if (!(raw >= 0.0) || !std::isfinite(raw) || raw != std::floor(raw)) return std::nullopt;
    if (raw > 18446744073709551615.0) return std::nullopt;
    return static_cast<std::uint64_t>(raw);
}

bool jwt_expired(std::string_view token, std::uint64_t now) {
    const std::optional<std::uint64_t> expiry = jwt_expiry(token);
    if (!expiry) return false;
    return *expiry <= now;
}

std::optional<std::string> extract_jwt_from_html(std::string_view html) {
    const size_t start = html.find(JWT_MARKER);
    if (start == std::string_view::npos) return std::nullopt;

    const std::string_view rest = html.substr(start + JWT_MARKER.size());
    size_t end = 0;
    while (end < rest.size() && !html_stop(rest[end])) ++end;

    const std::string_view candidate = trim(rest.substr(0, end));
    if (!looks_like_jwt(candidate)) return std::nullopt;
    return std::string(candidate);
}

std::optional<std::string> extract_jwt_from_cookie(std::string_view header) {
    for (const std::string_view part : split_on(header, ';')) {
        const std::string_view entry = trim(part);
        std::string_view value = {};
        if (entry.starts_with(AUTH_COOKIE)) {
            value = entry.substr(AUTH_COOKIE.size());
        } else if (entry.starts_with(AUTH_COOKIE_LOWER)) {
            value = entry.substr(AUTH_COOKIE_LOWER.size());
        } else {
            // Rust's `?` on the failed strip leaves the function, so no part behind this one is
            // ever looked at. Kept, because a cookie line that leads with `Path=` reads as nothing.
            return std::nullopt;
        }
        if (looks_like_jwt(value)) return std::string(value);
    }
    return std::nullopt;
}

// -- Device identifiers --------------------------------------------------------------------------

std::string random_alphanumeric(std::size_t len) {
    std::uniform_int_distribution<std::size_t> pick(0, ALPHANUM.size() - 1);
    std::mt19937_64& rng = enrolment_entropy();

    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) out += ALPHANUM[pick(rng)];
    return out;
}

std::string generate_install_id() { return random_alphanumeric(INSTALL_ID_LEN); }

std::string generate_fcm_token(std::string_view install_id) {
    return std::string(install_id) + std::string(FCM_TOKEN_PREFIX) +
           random_alphanumeric(FCM_SUFFIX_LEN);
}

// -- The enrolment page, read as text -------------------------------------------------------------

std::optional<std::string> extract_totp_form_action(std::string_view html) {
    static constexpr std::string_view anchor_text = "id=\"totp-form\"";
    const size_t anchor = html.find(anchor_text);
    if (anchor == std::string_view::npos) return std::nullopt;

    const size_t form_start = html.substr(0, anchor).rfind("<form");
    if (form_start == std::string_view::npos) return std::nullopt;

    const size_t tag_end = html.find('>', form_start);
    if (tag_end == std::string_view::npos) return std::nullopt;
    const std::string_view tag = html.substr(form_start, tag_end - form_start);

    static constexpr std::string_view key = "action=";
    const size_t key_at = tag.find(key);
    if (key_at == std::string_view::npos) return std::nullopt;

    const std::string_view rest = trim_start(tag.substr(key_at + key.size()));
    if (rest.empty()) return std::nullopt;
    const char quote = rest.front();
    if (quote != '\'' && quote != '"') return std::nullopt;

    const std::string_view body = rest.substr(1);
    const size_t end = body.find(quote);
    if (end == std::string_view::npos) return std::nullopt;

    const std::string action = decode_entities(body.substr(0, end));
    if (!action.starts_with("https://")) return std::nullopt;
    return action;
}

std::string decode_entities(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    std::string_view rest = raw;

    while (true) {
        const size_t at = rest.find('&');
        if (at == std::string_view::npos) break;
        out.append(rest.substr(0, at));
        rest = rest.substr(at);

        const size_t end = rest.find(';');
        if (end == std::string_view::npos || end > ENTITY_MAX_LEN) {
            // No `;` in reach: the `&` was a plain one, and the scan carries on after it.
            out += '&';
            rest.remove_prefix(1);
            continue;
        }

        const std::optional<char32_t> decoded = entity_char(rest.substr(1, end - 1));
        if (decoded) {
            push_utf8(out, *decoded);
            rest = rest.substr(end + 1);
        } else {
            out += '&';
            rest.remove_prefix(1);
        }
    }

    out.append(rest);
    return out;
}

std::optional<std::string> query_value(std::string_view url, std::string_view key) {
    const size_t mark = url.find('?');
    if (mark == std::string_view::npos) return std::nullopt;
    const std::string_view query = url.substr(mark + 1);

    size_t at = 0;
    while (true) {
        const size_t amp = query.find('&', at);
        const std::string_view pair =
            query.substr(at, amp == std::string_view::npos ? std::string_view::npos : amp - at);
        const size_t eq = pair.find('=');
        if (eq == std::string_view::npos) {
            // Again Rust's `?`: a pair with no `=` ends the search, so a nonce written after one is
            // never found.
            return std::nullopt;
        }
        if (pair.substr(0, eq) == key) return percent_decode(pair.substr(eq + 1));
        if (amp == std::string_view::npos) return std::nullopt;
        at = amp + 1;
    }
}

// -- Statuses --------------------------------------------------------------------------------------

bool status_is_success(std::uint16_t status) { return status >= 200 && status <= 299; }

// The reason phrases the http crate carries for a canonical status code, in its RFC 9110 wording
// (413 Content Too Large, 422 Unprocessable Content). A code with none is printed as its number
// alone, which is what Rust's Display for StatusCode does too.
std::string status_display(std::uint16_t status) {
    struct Named {
        std::uint16_t code;
        std::string_view reason;
    };
    static constexpr Named table[] = {
        {100, "Continue"},
        {101, "Switching Protocols"},
        {102, "Processing"},
        {103, "Early Hints"},
        {200, "OK"},
        {201, "Created"},
        {202, "Accepted"},
        {203, "Non-Authoritative Information"},
        {204, "No Content"},
        {205, "Reset Content"},
        {206, "Partial Content"},
        {207, "Multi-Status"},
        {208, "Already Reported"},
        {226, "IM Used"},
        {300, "Multiple Choices"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {303, "See Other"},
        {304, "Not Modified"},
        {305, "Use Proxy"},
        {307, "Temporary Redirect"},
        {308, "Permanent Redirect"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {402, "Payment Required"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {406, "Not Acceptable"},
        {407, "Proxy Authentication Required"},
        {408, "Request Timeout"},
        {409, "Conflict"},
        {410, "Gone"},
        {411, "Length Required"},
        {412, "Precondition Failed"},
        {413, "Content Too Large"},
        {414, "URI Too Long"},
        {415, "Unsupported Media Type"},
        {416, "Range Not Satisfiable"},
        {417, "Expectation Failed"},
        {418, "I'm a teapot"},
        {421, "Misdirected Request"},
        {422, "Unprocessable Content"},
        {423, "Locked"},
        {424, "Failed Dependency"},
        {425, "Too Early"},
        {426, "Upgrade Required"},
        {428, "Precondition Required"},
        {429, "Too Many Requests"},
        {431, "Request Header Fields Too Large"},
        {451, "Unavailable For Legal Reasons"},
        {500, "Internal Server Error"},
        {501, "Not Implemented"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"},
        {504, "Gateway Timeout"},
        {505, "HTTP Version Not Supported"},
        {506, "Variant Also Negotiates"},
        {507, "Insufficient Storage"},
        {508, "Loop Detected"},
        {510, "Not Extended"},
        {511, "Network Authentication Required"},
    };

    const std::string number = std::to_string(status);
    for (const Named& entry : table) {
        if (entry.code == status) return number + " " + std::string(entry.reason);
    }
    return number;
}

// -- Requests --------------------------------------------------------------------------------------

bool is_secret_field(std::string_view name) {
    const std::string lowered = lowered_ascii(name);
    static constexpr std::string_view secrets[] = {
        "cf-access-client-id", "cf-access-client-secret", "client_id", "client_secret",
        "token",              "access_token",            "code",      "nonce",
    };
    for (std::string_view secret : secrets) {
        if (lowered == secret) return true;
    }
    return false;
}

AccessRequest landing_request(const std::string& login_url) {
    // The email flow's client: a cookie jar, and redirects followed, since the landing page answers
    // with the URL the enrolment really sits at.
    return make_request("GET", login_url, true, true);
}

AccessRequest service_token_request(const std::string& login_url, std::string_view client_id,
                                   std::string_view client_secret) {
    AccessRequest request = make_request("GET", login_url, false, false);
    request.headers.push_back(AccessField{std::string(CLIENT_ID_HEADER), std::string(client_id)});
    request.headers.push_back(
        AccessField{std::string(CLIENT_SECRET_HEADER), std::string(client_secret)});
    return request;
}

AccessRequest code_request(std::string_view verify_url, std::string_view email) {
    AccessRequest request = make_request("POST", verify_url, true, true);
    // The five fields, in the order and with the empty values Rust's `.form()` sends. The engine
    // urlencodes them.
    request.form.push_back(AccessField{"email", std::string(email)});
    request.form.push_back(AccessField{"client_id", ""});
    request.form.push_back(AccessField{"connector_id", ""});
    request.form.push_back(AccessField{"connector_type", ""});
    request.form.push_back(AccessField{"redirect_url", ""});
    return request;
}

AccessRequest callback_request(const std::string& domain, std::string_view code,
                              std::string_view nonce) {
    AccessRequest request =
        make_request("POST", domain + std::string(CALLBACK_PATH), true, true);
    request.form.push_back(AccessField{"code", std::string(code)});
    request.form.push_back(AccessField{"nonce", std::string(nonce)});
    return request;
}

std::string redacted(const AccessRequest& request) {
    std::string out = request.method + " ";
    // Only as far as the query: an enrolment redirect carries `?token=<jwt>` in its URL, and the
    // verify URL can carry a bound redirect. Neither belongs in a log.
    const size_t mark = request.url.find('?');
    out += mark == std::string::npos ? request.url : request.url.substr(0, mark) + " (query hidden)";

    const auto fields = [](const std::vector<AccessField>& list) {
        std::string text;
        for (const AccessField& field : list) {
            if (!text.empty()) text += ", ";
            text += field.name;
            if (field.value.empty()) {
                text += "=<empty>";
            } else if (is_secret_field(field.name)) {
                text += " set(" + std::to_string(field.value.size()) + " bytes)";
            } else {
                text += "=" + field.value;
            }
        }
        return text;
    };

    out += "; headers: " + fields(request.headers);
    out += "; form: " + fields(request.form);
    out += request.follow_redirects ? "; redirects followed" : "; redirects refused";
    out += request.keep_cookies ? "; cookies kept" : "; no cookies";
    return out;
}

// -- The login code prompt --------------------------------------------------------------------------

std::string code_prompt_line(std::string_view email, std::uint32_t attempt) {
    return std::string(CODE_PROMPT_MARKER) + " attempt=" + std::to_string(attempt) +
           " email=" + std::string(email);
}

std::string code_banner(bool interactive, std::string_view email, std::uint32_t attempt) {
    const std::string address(email);
    if (!interactive) return code_prompt_line(email, attempt) + "\n";
    if (attempt == 1) return "\nA login code was emailed to " + address + ".\nEnter the code: ";
    return "\nThat code was not accepted. Enter the code emailed to " + address + " again: ";
}

CodePromptAsk code_prompt_ask(std::string_view email, std::uint32_t attempt, bool interactive) {
    CodePromptAsk ask;
    ask.email = std::string(email);
    ask.attempt = attempt;
    ask.interactive = interactive;
    ask.banner = code_banner(interactive, email, attempt);
    // A terminal waits for the person; a pipe waits CODE_WAIT_SECS and then says so.
    ask.wait_secs = interactive ? 0 : CODE_WAIT_SECS;
    return ask;
}

std::expected<std::string, std::string> code_prompt_result(const CodePromptAsk& asked,
                                                           const CodePromptReply& got) {
    if (!asked.interactive && got.read == CodeRead::TimedOut) {
        return std::unexpected("no login code arrived within " + secs_text(CODE_WAIT_SECS) +
                               "s; request a fresh code and try again");
    }
    if (got.read == CodeRead::Closed || got.read == CodeRead::Failed) {
        // Rust folds an end of input and a read error into one branch: Ok(0) | Err(()).
        return std::unexpected(asked.interactive ? std::string("no login code was entered")
                                                 : "a login code was emailed to " + asked.email +
                                                       " but nothing was sent back to answer it");
    }

    const std::string code(trim(got.line));
    if (code.empty()) return std::unexpected("no login code was entered");
    return code;
}

std::expected<std::string, std::string> prompt_login_code(const Hooks& hooks, std::string_view email,
                                                         std::uint32_t attempt,
                                                         std::vector<std::string>& notes) {
    const CodePromptAsk asked = code_prompt_ask(email, attempt, hooks.interactive);
    // The Rust prints the banner first and logs after it; this module prints nothing, so the note
    // arrives before the engine's prompt does.
    if (!asked.interactive) {
        notes.push_back("[*] waiting for the login code emailed to " + std::string(email));
    }
    if (!hooks.code_prompt) return std::unexpected("no way to ask for a login code");
    return code_prompt_result(asked, hooks.code_prompt(asked));
}

// -- The flow ---------------------------------------------------------------------------------------

Method sign_in_method(const TeamSettings& settings) {
    if (settings.token) return Method::SuppliedToken;
    if (settings.has_service_token()) return Method::ServiceToken;
    if (settings.email) return Method::EmailCode;
    return Method::None;
}

Stage stage_of(const TeamSettings& settings, bool cache_holds_token) {
    if (settings.team.empty()) return Stage::NoTeam;
    if (cache_holds_token) return Stage::Cached;
    switch (sign_in_method(settings)) {
        case Method::SuppliedToken: return Stage::SuppliedToken;
        case Method::ServiceToken: return Stage::ServiceToken;
        case Method::EmailCode: return Stage::EmailCode;
        case Method::None: return Stage::NoMethod;
    }
    return Stage::NoMethod;
}

std::string_view label(Stage stage) {
    switch (stage) {
        case Stage::NoTeam: return "no-team";
        case Stage::Cached: return "cached";
        case Stage::NoMethod: return "no-sign-in-method";
        case Stage::SuppliedToken: return "supplied-token";
        case Stage::ServiceToken: return "service-token";
        case Stage::EmailCode: return "email-code";
    }
    return "no-sign-in-method";
}

std::uint32_t attempts_left(std::uint32_t attempt) {
    return attempt >= CODE_ATTEMPTS ? 0 : CODE_ATTEMPTS - attempt;
}

CodeOutcome CodeOutcome::accepted(std::string token) {
    CodeOutcome outcome;
    outcome.kind = CodeOutcome::Kind::Token;
    outcome.token = std::move(token);
    return outcome;
}

CodeOutcome CodeOutcome::refused(std::uint16_t status) {
    CodeOutcome outcome;
    outcome.kind = CodeOutcome::Kind::Rejected;
    outcome.status = status;
    return outcome;
}

std::expected<std::optional<std::string>, std::string> request_email_code(
    const AccessHttp& http, std::string_view verify_url, std::string_view email,
    const std::optional<std::string>& fallback_url, std::vector<std::string>& notes) {
    notes.push_back("[*] asking cloudflare to email a login code to " + std::string(email));

    const AccessRequest request = code_request(verify_url, email);
    const auto sent = http(request);
    if (!sent) return std::unexpected("requesting a login code: " + sent.error());

    // Rust discards the body here, and a body it could not read is discarded with it, so
    // `body_error` says nothing about the outcome.
    if (!status_is_success(sent->status)) {
        return std::unexpected("cloudflare refused to send a login code (status " +
                               status_display(sent->status) + ")");
    }

    std::optional<std::string> nonce = query_value(sent->final_url, "nonce");
    if (!nonce && fallback_url) nonce = query_value(*fallback_url, "nonce");
    return nonce;
}

std::expected<EmailSignIn, std::string> begin_email_signin(const TeamSettings& settings,
                                                          std::string_view email,
                                                          const AccessHttp& http,
                                                          std::vector<std::string>& notes) {
    const std::string_view address = trim(email);
    if (address.empty()) {
        return std::unexpected("an email address is needed to request a login code");
    }

    notes.push_back("[*] opening the device enrolment page for team " + settings.team);
    const auto landing = http(landing_request(settings.login_url()));
    if (!landing) return std::unexpected("enrolment page: " + landing.error());
    if (landing->body_error) {
        return std::unexpected("enrolment page body: " + *landing->body_error);
    }

    const std::optional<std::string> verify_url = extract_totp_form_action(landing->body);
    if (!verify_url) {
        return std::unexpected("team " + settings.team +
                               " does not offer an email one-time code on its enrolment page; use "
                               "a service token or sign in at " +
                               settings.login_url());
    }

    // The URL the page redirected to is the fallback the nonce may still be read off.
    const std::optional<std::string> fallback{landing->final_url};
    const auto nonce = request_email_code(http, *verify_url, address, fallback, notes);
    if (!nonce.has_value()) return std::unexpected(nonce.error());
    if (!nonce->has_value()) {
        return std::unexpected(
            "cloudflare did not return a nonce for the login code; the enrolment flow may have "
            "changed");
    }

    return EmailSignIn(http, settings.team, std::string(address), **nonce, *verify_url);
}

std::expected<std::string, std::string> fetch_token_with_service_token(const TeamSettings& settings,
                                                                       const AccessHttp& http,
                                                                       std::vector<std::string>& notes) {
    if (!settings.client_id) return std::unexpected("missing access client id");
    if (!settings.client_secret) return std::unexpected("missing access client secret");

    notes.push_back("[*] asking " + settings.team_domain() +
                    " for a device enrolment token using the service token");

    const auto response =
        http(service_token_request(settings.login_url(), *settings.client_id, *settings.client_secret));
    if (!response) return std::unexpected("access request: " + response.error());

    for (const std::string& header : response->set_cookie) {
        if (const std::optional<std::string> token = extract_jwt_from_cookie(header)) {
            notes.push_back("[+] access issued a device enrolment token");
            return *token;
        }
    }

    // A body that could not be read is, as in Rust's `unwrap_or_default()`, simply no body.
    if (const std::optional<std::string> token = extract_jwt_from_html(response->body)) {
        notes.push_back("[+] access issued a device enrolment token");
        return *token;
    }

    return std::unexpected(
        "access did not return a device enrolment token (status " +
        status_display(response->status) +
        "); confirm the service token has Service Auth device enrolment permission for team " +
        settings.team);
}

EmailSignIn::EmailSignIn(AccessHttp http, std::string team, std::string email, std::string nonce,
                         std::string verify_url)
    : http_(std::move(http)), team_(std::move(team)), email_(std::move(email)),
      nonce_(std::move(nonce)), verify_url_(std::move(verify_url)) {}

std::expected<void, std::string> EmailSignIn::resend_code(std::vector<std::string>& notes) {
    const auto again = request_email_code(http_, verify_url_, email_, std::nullopt, notes);
    if (!again.has_value()) return std::unexpected(again.error());
    // A fresh nonce replaces the held one; no nonce leaves it alone and the call still succeeds.
    if (again->has_value()) nonce_ = **again;
    return {};
}

std::expected<CodeOutcome, std::string> EmailSignIn::submit_code(std::string_view code,
                                                                std::vector<std::string>& notes) const {
    const std::string_view trimmed = trim(code);
    if (trimmed.empty()) return std::unexpected("no login code was entered");

    const auto confirmed = http_(callback_request(team_domain(team_), trimmed, nonce_));
    if (!confirmed) {
        return std::unexpected("confirming the login code: " + confirmed.error());
    }
    if (confirmed->body_error) {
        return std::unexpected("callback body: " + *confirmed->body_error);
    }

    if (const std::optional<std::string> token = extract_jwt_from_html(confirmed->body)) {
        notes.push_back("[+] signed in to team " + team_ + " with the email code");
        return CodeOutcome::accepted(*token);
    }
    return CodeOutcome::refused(confirmed->status);
}

std::expected<std::string, std::string> fetch_token_with_email_code(const TeamSettings& settings,
                                                                    std::string_view email,
                                                                    const Hooks& hooks,
                                                                    std::vector<std::string>& notes) {
    auto session = begin_email_signin(settings, email, hooks.http, notes);
    if (!session.has_value()) return std::unexpected(session.error());

    std::optional<std::uint16_t> last_status;
    for (std::uint32_t attempt = 1; attempt <= CODE_ATTEMPTS; ++attempt) {
        const auto code = prompt_login_code(hooks, session->email(), attempt, notes);
        if (!code.has_value()) return std::unexpected(code.error());

        const auto outcome = session->submit_code(*code, notes);
        if (!outcome.has_value()) return std::unexpected(outcome.error());

        if (outcome->accepted()) return outcome->token;
        last_status = outcome->status;
        const std::uint32_t left = attempts_left(attempt);
        if (left > 0) {
            notes.push_back("[-] that code was not accepted; " + std::to_string(left) +
                            " attempt(s) left");
        }
    }

    return std::unexpected(
        "the login code was not accepted after " + std::to_string(CODE_ATTEMPTS) +
        " attempts (last status " +
        (last_status ? std::to_string(*last_status) : std::string("unknown")) +
        "); request a fresh code and try again");
}

std::expected<std::string, std::string> sign_in(const TeamSettings& settings, const Hooks& hooks,
                                                std::vector<std::string>& notes) {
    switch (sign_in_method(settings)) {
        case Method::SuppliedToken: {
            // Rust hands on the stored value as it stands -- from_env already trimmed it -- and
            // only the shape and expiry tests do their own trimming.
            const std::string& token = *settings.token;
            if (!looks_like_jwt(token)) {
                return std::unexpected(
                    "the supplied access token is not a jwt; copy the value that follows token= on "
                    "the enrolment page");
            }
            if (jwt_expired(token, now_unix())) {
                return std::unexpected(
                    "the supplied access token has expired; sign in again to get a fresh one");
            }
            notes.push_back("[+] using the access token supplied for team " + settings.team);
            return token;
        }
        case Method::ServiceToken:
            return fetch_token_with_service_token(settings, hooks.http, notes);
        case Method::EmailCode:
            return fetch_token_with_email_code(settings, *settings.email, hooks, notes);
        case Method::None:
            return std::unexpected("team " + settings.team +
                                   " needs a way to sign in. pick one: a service token via " +
                                   std::string(CLIENT_ID_ENV) + " and " +
                                   std::string(CLIENT_SECRET_ENV) + ", an email one-time code via " +
                                   std::string(EMAIL_ENV) + ", or a token you already hold via " +
                                   std::string(TOKEN_ENV) + " (sign in at " +
                                   settings.login_url() + ")");
    }
    return std::unexpected("team " + settings.team + " needs a way to sign in");
}

std::expected<std::string, std::string> resolve_token(const TeamSettings& settings,
                                                     const Hooks& hooks,
                                                     std::vector<std::string>& notes) {
    {
        const std::lock_guard<std::mutex> held(cache_gate());
        if (cache_slot().has_value()) {
            if (!jwt_expired(*cache_slot(), now_unix())) {
                notes.push_back("[zerotrust] reusing the enrolment token from this session");
                return *cache_slot();
            }
            notes.push_back("[zerotrust] the cached enrolment token expired; signing in again");
            cache_slot().reset();
        }
    }

    auto token = sign_in(settings, hooks, notes);
    if (token.has_value()) {
        const std::lock_guard<std::mutex> held(cache_gate());
        cache_slot() = *token;
    }
    return token;
}

std::expected<void, std::string> store_token(std::string_view token) {
    const std::string_view trimmed = trim(token);
    if (!looks_like_jwt(trimmed)) {
        return std::unexpected(
            "that value is not a jwt; copy the value that follows token= on the enrolment page");
    }
    if (jwt_expired(trimmed, now_unix())) {
        return std::unexpected("that token has already expired; sign in again to get a fresh one");
    }
    const std::lock_guard<std::mutex> held(cache_gate());
    cache_slot() = std::string(trimmed);
    return {};
}

std::optional<std::string> cached_token() {
    const std::lock_guard<std::mutex> held(cache_gate());
    if (!cache_slot().has_value()) return std::nullopt;
    if (jwt_expired(*cache_slot(), now_unix())) return std::nullopt;
    return cache_slot();
}

void clear_token() {
    const std::lock_guard<std::mutex> held(cache_gate());
    cache_slot().reset();
}

} // namespace hemera::core::zerotrust
