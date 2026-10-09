#include "identity.hpp"

#include "encoding.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <format>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace hemera::core {

namespace {

using Fields = TomlFields;

// Reads one double-quoted value, consuming it from the front of `rest`.
bool unquote(std::string_view& rest, std::string& out) {
    if (rest.empty() || rest.front() != '"') return false;
    rest.remove_prefix(1);

    std::string text;
    while (!rest.empty()) {
        const char c = rest.front();
        rest.remove_prefix(1);

        if (c == '"') {
            out = std::move(text);
            return true;
        }

        if (c != '\\') {
            text += c;
            continue;
        }

        if (rest.empty()) return false;
        const char escape = rest.front();
        rest.remove_prefix(1);
        switch (escape) {
            case '"': text += '"'; break;
            case '\\': text += '\\'; break;
            case 'b': text += '\b'; break;
            case 't': text += '\t'; break;
            case 'n': text += '\n'; break;
            case 'f': text += '\f'; break;
            case 'r': text += '\r'; break;
            case 'u': {
                if (rest.size() < 4) return false;
                const unsigned long code = std::stoul(std::string(rest.substr(0, 4)), nullptr, 16);
                rest.remove_prefix(4);
                // The core only escapes control bytes, and identity files are ASCII apart from
                // UTF-8 text, which is written literally rather than escaped.
                if (code < 0x80) {
                    text += static_cast<char>(code);
                } else {
                    text += static_cast<char>(0xc0 | (code >> 6));
                    text += static_cast<char>(0x80 | (code & 0x3f));
                }
                break;
            }
            default: return false;
        }
    }
    return false;
}

std::string_view trim(std::string_view text) {
    const size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    return text.substr(begin, text.find_last_not_of(" \t\r\n") - begin + 1);
}

std::string_view strip_quotes(std::string_view text) {
    if (text.size() >= 2 && text.front() == text.back() &&
        (text.front() == '"' || text.front() == '\'')) {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

// The Rust core writes a multi-line value as `key = """` followed by the raw lines and a
// closing `"""`, which is how a PEM certificate survives in the account file. Without this the
// opening delimiter reads as an empty string and every PEM line after it fails the `key = value`
// test, so the whole file would be reported corrupt and moved aside.
std::string_view multi_line_open(std::string_view value) {
    if (value.starts_with("\"\"\"")) return std::string_view("\"\"\"");
    if (value.starts_with("'''")) return std::string_view("'''");
    return {};
}

} // namespace

// The flat TOML table the account file and the last-connection file are written in.
std::expected<TomlFields, std::string> parse_toml_fields(std::string_view text) {
    Fields fields;

    while (!text.empty()) {
        const size_t newline = text.find('\n');
        const std::string_view line = text.substr(0, newline);
        text = newline == std::string_view::npos ? std::string_view{} : text.substr(newline + 1);

        const std::string_view trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') continue;

        const size_t separator = trimmed.find('=');
        if (separator == std::string_view::npos) {
            return std::unexpected("expected `key = value`, found '" + std::string(trimmed) + "'");
        }

        const std::string key(strip_quotes(trim(trimmed.substr(0, separator))));
        std::string_view value = trim(trimmed.substr(separator + 1));
        if (value.empty()) return std::unexpected("no value for '" + key + "'");

        std::string decoded;
        const std::string_view open = multi_line_open(value);
        if (!open.empty()) {
            // ponytail: the body is taken literally, as the Rust core writes PEM and other
            // account values. TOML also allows escapes inside `"""`; add unquote() here if an
            // account file ever carries one.
            if (const size_t same_line = value.find(open, 3); same_line != std::string_view::npos) {
                decoded = std::string(value.substr(3, same_line - 3));
            } else {
                std::string body;
                bool first_row = true;
                bool closed = false;
                while (!text.empty()) {
                    const size_t next = text.find('\n');
                    std::string_view row = text.substr(0, next);
                    text = next == std::string_view::npos ? std::string_view{}
                                                          : text.substr(next + 1);
                    if (!row.empty() && row.back() == '\r') row.remove_suffix(1);

                    // TOML trims only the newline right after the opening delimiter; every other
                    // row separator is part of the value, including the one before the closing.
                    if (!first_row) body += '\n';
                    first_row = false;

                    const size_t closing = row.find(open);
                    if (closing != std::string_view::npos) {
                        body.append(row.substr(0, closing));
                        closed = true;
                        break;
                    }
                    body.append(row);
                }
                if (!closed) {
                    return std::unexpected("unterminated multi-line string for '" + key + "'");
                }
                decoded = std::move(body);
            }
        } else if (value.front() == '\'') {
            const size_t closing = value.find('\'', 1);
            if (closing == std::string_view::npos) {
                return std::unexpected("unterminated literal string for '" + key + "'");
            }
            decoded = std::string(value.substr(1, closing - 1));
        } else if (value.front() == '"') {
            if (!unquote(value, decoded)) {
                return std::unexpected("unterminated or malformed string for '" + key + "'");
            }
        } else if (value.front() == '[') {
            // An array is kept as the text it is written in, on one line or over several, for
            // the reader to walk. No account file carries one; the last-connection file does.
            std::string list(value);
            while (list.find(']') == std::string::npos && !text.empty()) {
                const size_t next = text.find('\n');
                const std::string_view row = text.substr(0, next);
                text = next == std::string_view::npos ? std::string_view{}
                                                      : text.substr(next + 1);
                list += ' ';
                list.append(row);
            }
            if (list.find(']') == std::string::npos) {
                return std::unexpected("unterminated array for '" + key + "'");
            }
            decoded = std::move(list);
        } else {
            decoded = std::string(value);
        }

        fields[key] = std::move(decoded);
    }

    return fields;
}

namespace {

std::string text_of(const Fields& fields, const std::string& key) {
    const auto found = fields.find(key);
    return found == fields.end() ? std::string{} : found->second;
}

template <size_t N>
std::expected<std::array<uint8_t, N>, std::string> decode_fixed(const std::string& field,
                                                                 const std::string& value) {
    const std::optional decoded = base64_decode(value);
    if (!decoded.has_value()) {
        return std::unexpected("config field " + field + " is not valid base64");
    }
    if (decoded->size() != N) {
        return std::unexpected("config field " + field + " must decode to " + std::to_string(N) +
                               " bytes, found " + std::to_string(decoded->size()));
    }

    std::array<uint8_t, N> bytes{};
    std::ranges::copy(*decoded, bytes.begin());
    return bytes;
}

std::expected<Identity, std::string> identity_from(const Fields& fields) {
    for (const std::string& required : {"device_id", "access_token", "ipv4", "ipv6",
                                        "wg_private_key", "wg_peer_public_key"}) {
        if (fields.find(required) == fields.end()) {
            return std::unexpected("missing field `" + required + "`");
        }
    }

    const auto private_key = decode_fixed<32>("wg_private_key", fields.at("wg_private_key"));
    if (!private_key.has_value()) return std::unexpected(private_key.error());
    const auto peer_key = decode_fixed<32>("wg_peer_public_key", fields.at("wg_peer_public_key"));
    if (!peer_key.has_value()) return std::unexpected(peer_key.error());

    Identity identity;
    identity.device_id = fields.at("device_id");
    identity.access_token = fields.at("access_token");
    identity.ipv4 = fields.at("ipv4");
    identity.ipv6 = fields.at("ipv6");
    identity.wg_private_key = *private_key;
    identity.wg_peer_public_key = *peer_key;

    identity.cert_pem = text_of(fields, "cert_pem");
    identity.key_pem = text_of(fields, "key_pem");
    identity.organization = text_of(fields, "organization");
    identity.gateway_proxy = text_of(fields, "gateway_proxy");
    identity.assigned_endpoint = text_of(fields, "assigned_endpoint");

    const std::string issued = text_of(fields, "cert_issued_at");
    if (!issued.empty()) {
        identity.cert_issued_at = std::stoull(issued);
    }

    // A client id is three bytes of Zero Trust routing. A file that carries a broken one came
    // from an account that was never enrolled, so it reads as zeros instead of failing.
    const std::string client_id = text_of(fields, "client_id");
    if (!client_id.empty()) {
        if (const auto decoded = decode_fixed<3>("client_id", client_id)) {
            identity.client_id = *decoded;
        }
    }

    return identity;
}

std::string base64_of(const uint8_t* data, size_t size) {
    return base64_encode(std::span<const uint8_t>(data, size));
}

// Field order of the Rust core's PersistedIdentity, so both cores write the same bytes.
std::string serialize(const Identity& identity) {
    std::ostringstream out;
    out << "device_id = " << toml_quote(identity.device_id) << '\n'
        << "access_token = " << toml_quote(identity.access_token) << '\n'
        << "cert_pem = " << toml_quote(identity.cert_pem) << '\n'
        << "key_pem = " << toml_quote(identity.key_pem) << '\n'
        << "cert_issued_at = " << identity.cert_issued_at << '\n'
        << "ipv4 = " << toml_quote(identity.ipv4) << '\n'
        << "ipv6 = " << toml_quote(identity.ipv6) << '\n'
        << "wg_private_key = " << toml_quote(base64_of(identity.wg_private_key.data(), 32)) << '\n'
        << "wg_peer_public_key = " << toml_quote(base64_of(identity.wg_peer_public_key.data(), 32)) << '\n'
        << "client_id = " << toml_quote(base64_of(identity.client_id.data(), 3)) << '\n'
        << "organization = " << toml_quote(identity.organization) << '\n'
        << "gateway_proxy = " << toml_quote(identity.gateway_proxy) << '\n'
        << "assigned_endpoint = " << toml_quote(identity.assigned_endpoint) << '\n';
    return out.str();
}

std::optional<std::filesystem::path> quarantine(const std::filesystem::path& path) {
    auto target = path;
    target.replace_filename(path.filename().string() + ".corrupt");
    if (MoveFileExW(path.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) != 0) {
        return target;
    }
    return std::nullopt;
}

// The account file holds keys, so it is never left half-written: the new contents go to a
// temporary name in the same folder and are moved over the old file in one step.
std::expected<void, std::string> write_private(const std::filesystem::path& path,
                                               const std::string& contents) {
    const auto directory = path.parent_path();
    if (!directory.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
        if (ec) return std::unexpected("cannot create " + directory.string() + ": " + ec.message());
    }

    const auto temp = directory / ("." + path.filename().string() + "." +
                                   std::to_string(GetCurrentProcessId()) + ".tmp");

    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file) return std::unexpected("cannot write " + temp.string());
        file << contents;
        file.flush();
        if (!file) return std::unexpected("cannot write " + temp.string());
    }

    const HANDLE handle = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(handle);
        CloseHandle(handle);
    }

    if (MoveFileExW(temp.c_str(), path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        DeleteFileW(temp.c_str());
        return std::unexpected("cannot replace " + path.string());
    }

    return {};
}

std::expected<std::string, std::string> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return std::unexpected("cannot read " + path.string());
    std::ostringstream text;
    text << file.rdbuf();
    return text.str();
}

} // namespace

// Named toml_quote, not quoted: an unqualified `quoted(std::string)` also sees std::quoted
// through ADL, and that exact match wins over this string_view overload -- std::quoted leaves
// newlines raw, which writes an account file no reader can parse back.
std::string toml_quote(std::string_view text) {
    std::string out = "\"";
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\t': out += "\\t"; break;
            case '\n': out += "\\n"; break;
            case '\f': out += "\\f"; break;
            case '\r': out += "\\r"; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    out += std::format("\\u{:04x}", c);
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
    return out;
}

uint64_t now_unix() {
    const auto since = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(since).count());
}

bool masque_cert_expiring(uint64_t issued_at) {
    if (issued_at == 0) return true;
    const uint64_t now = now_unix();
    if (now < issued_at) return true;
    return (now - issued_at) + MASQUE_CERT_RENEW_BEFORE_SECS >= MASQUE_CERT_LIFETIME_DAYS * 86'400;
}

bool cert_still_usable(const Identity& identity) {
    if (identity.cert_pem.empty() || identity.key_pem.empty() || identity.cert_issued_at == 0) {
        return false;
    }
    const uint64_t now = now_unix();
    if (now < identity.cert_issued_at) return false;
    return now - identity.cert_issued_at < MASQUE_CERT_LIFETIME_DAYS * 86'400;
}

bool Identity::has_masque_credentials() const {
    return !cert_pem.empty() && !key_pem.empty() && !masque_cert_expiring(cert_issued_at);
}

std::expected<std::optional<Identity>, std::string> load_identity(const std::string& path) {
    const std::filesystem::path file(path);
    if (!std::filesystem::exists(file)) return std::optional<Identity>{std::nullopt};

    const auto text = read_file(file);
    if (!text.has_value()) return std::unexpected(text.error());

    auto damaged = [&](std::string message) {
        if (const auto moved = quarantine(file)) {
            message += "; the damaged file was moved to " + moved->string() +
                       " so a fresh identity can be provisioned";
        } else {
            message += "; delete " + file.string() + " to provision a fresh identity";
        }
        return std::unexpected(message);
    };

    const auto fields = parse_toml_fields(*text);
    if (!fields.has_value()) {
        return damaged("config parse: " + fields.error());
    }

    const auto identity = identity_from(*fields);
    if (!identity.has_value()) {
        return damaged(identity.error());
    }

    return std::optional<Identity>{*identity};
}

std::expected<void, std::string> save_identity(const std::string& path, const Identity& identity) {
    return write_private(std::filesystem::path(path), serialize(identity));
}

std::expected<void, std::string> save_masque_creds(const std::string& path,
                                                   std::string_view cert_pem,
                                                   std::string_view key_pem,
                                                   uint64_t issued_at) {
    const std::filesystem::path file(path);
    if (!std::filesystem::exists(file)) return {};

    const auto text = read_file(file);
    if (!text.has_value()) return std::unexpected(text.error());

    const auto fields = parse_toml_fields(*text);
    if (!fields.has_value()) return std::unexpected("config parse: " + fields.error());

    const auto identity = identity_from(*fields);
    if (!identity.has_value()) return std::unexpected(identity.error());

    Identity refreshed = *identity;
    refreshed.cert_pem = std::string(cert_pem);
    refreshed.key_pem = std::string(key_pem);
    refreshed.cert_issued_at = issued_at;

    return write_private(file, serialize(refreshed));
}

} // namespace hemera::core
