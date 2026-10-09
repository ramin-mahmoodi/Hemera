#include "lastconn.hpp"

#include "dns.hpp"
#include "identity.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace hemera::core {
namespace {

    std::string field(const TomlFields& fields, std::string_view key) {
        const auto found = fields.find(std::string(key));
        return found == fields.end() ? std::string{} : found->second;
    }

    // The entries of a `recent = ["a", "b"]` value, which the table reader keeps as the bracketed
    // text it is written in.
    std::vector<std::string> string_list(std::string_view text) {
        std::vector<std::string> out;
        const std::size_t first = text.find('[');
        if (first == std::string_view::npos) return out;
        const std::size_t closing = text.find(']');
        const std::size_t end = closing == std::string_view::npos ? text.size() : closing;

        std::size_t at = first + 1;
        while (at < end) {
            const std::size_t open = text.find('"', at);
            if (open == std::string_view::npos || open >= end) break;

            std::string item;
            std::size_t i = open + 1;
            while (i < end) {
                if (text[i] == '\\' && i + 1 < end) {
                    item += text[i + 1];
                    i += 2;
                    continue;
                }
                if (text[i] == '"') {
                    ++i;
                    break;
                }
                item += text[i];
                ++i;
            }
            out.push_back(std::move(item));
            at = i;
        }
        return out;
    }

    // `raw` as an address and a port: a literal IP, in brackets when it is IPv6, then `:port`. An
    // address and nothing else, which is why a domain name is refused here.
    std::optional<std::pair<std::string, std::uint16_t>> socket_address(std::string_view raw) {
        std::string_view host = raw;
        std::string_view port_text;

        if (!raw.empty() && raw.front() == '[') {
            const std::size_t closing = raw.find(']');
            if (closing == std::string_view::npos || closing + 2 >= raw.size() ||
                raw[closing + 1] != ':') {
                return std::nullopt;
            }
            host = raw.substr(1, closing - 1);
            port_text = raw.substr(closing + 2);
        } else {
            const std::size_t colon = raw.rfind(':');
            if (colon == std::string_view::npos) return std::nullopt;
            host = raw.substr(0, colon);
            port_text = raw.substr(colon + 1);
        }

        if (port_text.empty() || port_text.size() > 5) return std::nullopt;
        std::uint32_t port = 0;
        for (const char c : port_text) {
            if (c < '0' || c > '9') return std::nullopt;
            port = port * 10 + static_cast<std::uint32_t>(c - '0');
        }
        if (port > 65'535) return std::nullopt;

        const auto address = ip_literal(host);
        if (!address) return std::nullopt;
        return std::pair<std::string, std::uint16_t>{*address, static_cast<std::uint16_t>(port)};
    }

} // namespace

std::optional<LastConnection> load_last_connection(const std::string& path) {
    std::ifstream file(std::filesystem::path(path), std::ios::binary);
    if (!file) return std::nullopt;
    std::ostringstream text;
    text << file.rdbuf();

    const auto fields = parse_toml_fields(text.str());
    if (!fields) return std::nullopt;

    LastConnection conn;
    conn.peer = field(*fields, "peer");
    conn.profile = field(*fields, "profile");
    conn.carrier = field(*fields, "carrier");
    conn.recent = string_list(field(*fields, "recent"));
    return conn;
}

std::expected<void, std::string> save_last_connection(const std::string& path,
                                                      std::string_view peer,
                                                      std::string_view profile,
                                                      std::string_view carrier) {
    std::vector<std::string> carried;
    if (const auto previous = load_last_connection(path)) {
        if (previous->carrier.empty() || previous->carrier == carrier) {
            carried = previous->recent;
        }
    }

    std::vector<std::string> recent;
    recent.emplace_back(peer);
    for (const std::string& entry : carried) {
        if (entry == peer || recent.size() >= RECENT_CAP) continue;
        recent.push_back(entry);
    }

    std::string text = "peer = " + toml_quote(peer) + "\nprofile = " + toml_quote(profile) +
                       "\ncarrier = " + toml_quote(carrier) + "\nrecent = [";
    for (std::size_t i = 0; i < recent.size(); ++i) {
        text += (i == 0 ? "" : ", ") + toml_quote(recent[i]);
    }
    text += "]\n";

    std::ofstream file(std::filesystem::path(path), std::ios::binary | std::ios::trunc);
    if (!file) return std::unexpected("cannot write " + path);
    file << text;
    return {};
}

std::vector<std::pair<std::string, std::uint16_t>> usable_peers(const LastConnection& cached,
                                                                std::string_view carrier) {
    if (!cached.carrier.empty() && cached.carrier != carrier) return {};

    std::vector<std::pair<std::string, std::uint16_t>> out;
    std::vector<std::string> seen;

    const auto consider = [&](std::string_view raw) {
        const auto address = socket_address(raw);
        if (!address) return;
        const std::string key = std::format("{}:{}", address->first, address->second);
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) return;
        seen.push_back(key);
        out.push_back(*address);
    };

    consider(cached.peer);
    for (const std::string& entry : cached.recent) {
        consider(entry);
    }
    return out;
}

} // namespace hemera::core
