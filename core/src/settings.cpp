#include "settings.hpp"

#include <algorithm>
#include <cctype>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace aether::core {

namespace {

// Marks a row whose value comes from the following argument.
constexpr std::string_view arg_value = "@";

struct Row {
    std::string_view flag;
    std::string_view key;
    std::string_view value;
    std::string_view second_key;
    std::string_view second_value;
};

// One row per match arm of aether/src/cli.rs::parse_args, minus its tor and psiphon
// arms, which this port drops. An alias gets its own row because the Rust table does
// the same, and a diff of the two lists is the check that the port stayed complete.
constexpr Row rows[] = {
    // Connection
    {"--bind", "AETHER_SOCKS", arg_value},
    {"--http-proxy", "AETHER_HTTP_PROXY", arg_value},
    {"--upstream", "AETHER_UPSTREAM", arg_value},
    {"--mark", "AETHER_MARK", arg_value},
    {"--exit-loc", "AETHER_EXIT_LOC", arg_value},
    {"--exit-loc-secs", "AETHER_EXIT_LOC_SECS", arg_value},
    {"--stats", "AETHER_STATS", "1"},
    {"--stats-secs", "AETHER_STATS_SECS", arg_value},
    {"--quick-reconnect", "AETHER_QUICK_RECONNECT", "1"},
    {"--no-quick-reconnect", "AETHER_QUICK_RECONNECT", "0"},

    // IP version
    {"-4", "AETHER_IP", "v4"},
    {"-6", "AETHER_IP", "v6"},
    {"--dual", "AETHER_IP", "both"},
    {"--ip", "AETHER_IP", arg_value},
    {"--peer", "AETHER_PEER", arg_value},
    {"--wg-peer", "AETHER_WG_PEER", arg_value},

    // Classic gool (warp-in-warp) endpoints
    {"--wiw-outer", "AETHER_WIW_OUTER_PEER", arg_value},
    {"--gool-outer", "AETHER_WIW_OUTER_PEER", arg_value},
    {"--outer-peer", "AETHER_WIW_OUTER_PEER", arg_value},
    {"--wiw-inner", "AETHER_WIW_INNER_PEER", arg_value},
    {"--gool-inner", "AETHER_WIW_INNER_PEER", arg_value},
    {"--inner-peer", "AETHER_WIW_INNER_PEER", arg_value},
    {"--wiw-peers", "AETHER_WIW_PEERS", arg_value},
    {"--gool-peers", "AETHER_WIW_PEERS", arg_value},
    {"--wiw-scan", "AETHER_WIW_PEERS", "auto"},
    {"--gool-scan", "AETHER_WIW_PEERS", "auto"},

    // Protocol
    {"--masque", "AETHER_PROTOCOL", "masque"},
    {"--wg", "AETHER_PROTOCOL", "wg"},
    {"--wireguard", "AETHER_PROTOCOL", "wg"},
    {"--warp", "AETHER_PROTOCOL", "wg"},
    {"--gool", "AETHER_PROTOCOL", "gool"},
    {"--wiw", "AETHER_PROTOCOL", "gool"},
    {"--gool-peer", "AETHER_PROTOCOL", "gool", "AETHER_GOOL_INNER", arg_value},
    {"--api-fragment", "AETHER_API_FRAGMENT", "1"},
    {"--gool-classic", "AETHER_PROTOCOL", "gool", "AETHER_GOOL_MODE", "classic"},
    {"--mim", "AETHER_PROTOCOL", "mim"},
    {"--masque-in-masque", "AETHER_PROTOCOL", "mim"},
    {"--mim-outer", "AETHER_MIM_OUTER_PEER", arg_value},
    {"--mim-inner", "AETHER_MIM_INNER_PEER", arg_value},
    {"--mim-peers", "AETHER_MIM_PEERS", arg_value},
    {"--mim-scan", "AETHER_MIM_PEERS", "auto"},
    {"--protocol", "AETHER_PROTOCOL", arg_value},

    // Scan mode
    {"--scan", "AETHER_SCAN", arg_value},
    {"--turbo", "AETHER_SCAN", "turbo"},
    {"--balanced", "AETHER_SCAN", "balanced"},
    {"--thorough", "AETHER_SCAN", "thorough"},
    {"--verified", "AETHER_SCAN", "verified"},
    {"--stealth", "AETHER_SCAN", "verified"},
    {"--ironclad", "AETHER_SCAN", "ironclad"},
    {"--noize", "AETHER_NOIZE", arg_value},

    // MASQUE transport
    {"--h2", "AETHER_MASQUE_HTTP2", "1"},
    {"--http2", "AETHER_MASQUE_HTTP2", "1"},
    {"--h3", "AETHER_MASQUE_HTTP2", "0"},
    {"--quic", "AETHER_MASQUE_HTTP2", "0"},
    {"--no-quic-v2", "AETHER_QUIC_V2", "0"},
    {"--h2-peer", "AETHER_MASQUE_H2_PEER", arg_value},
    {"--ech", "AETHER_ECH", arg_value},
    {"--ech-dns", "AETHER_ECH_DNS", arg_value},
    {"--ech-domain", "AETHER_ECH_DOMAIN", arg_value},
    {"--no-data-check", "AETHER_MASQUE_NO_DATA_CHECK", "1", "AETHER_WG_NO_DATA_CHECK", "1"},
    {"--validate-secs", "AETHER_MASQUE_VALIDATE_SECS", arg_value, "AETHER_WG_VALIDATE_SECS", arg_value},
    {"--startup-secs", "AETHER_MASQUE_STARTUP_SECS", arg_value},
    {"--reconnect-secs", "AETHER_MASQUE_RECONNECT_SECS", arg_value, "AETHER_WG_RECONNECT_SECS", arg_value},
    {"--dns", "AETHER_DNS", arg_value},
    {"--fragment", "AETHER_MASQUE_H2_FRAGMENT", "1"},
    {"--no-fragment", "AETHER_MASQUE_H2_FRAGMENT", "0"},
    {"--fragment-size", "AETHER_MASQUE_H2_FRAGMENT_SIZE", arg_value},
    {"--fragment-delay", "AETHER_MASQUE_H2_FRAGMENT_DELAY", arg_value},

    // WireGuard
    {"--keepalive", "AETHER_WG_KEEPALIVE", arg_value},
    {"--no-profile-retry", "AETHER_WG_NO_PROFILE_RETRY", "1"},

    // Config files
    {"--config", "AETHER_CONFIG", arg_value},
    {"--wg-config", "AETHER_WG_CONFIG", arg_value},
    {"--masque-config", "AETHER_MASQUE_CONFIG", arg_value},
    {"--register", "AETHER_REGISTER", arg_value},
    {"--enroll-address", "AETHER_ENROLL_ADDRESS", arg_value},

    // Zero Trust
    {"--team", "AETHER_TEAM", arg_value},
    {"--organization", "AETHER_TEAM", arg_value},
    {"--access-id", "AETHER_ACCESS_CLIENT_ID", arg_value},
    {"--access-secret", "AETHER_ACCESS_CLIENT_SECRET", arg_value},
    {"--access-token", "AETHER_ACCESS_TOKEN", arg_value},
    {"--access-email", "AETHER_ACCESS_EMAIL", arg_value},
    {"--gateway", "AETHER_GATEWAY", "1"},

    // Routing
    {"--route-block", "AETHER_ROUTE_BLOCK", arg_value},
    {"--route-direct", "AETHER_ROUTE_DIRECT", arg_value},
    {"--routes", "AETHER_ROUTES_FILE", arg_value},

    // TLS
    {"--tls-groups", "AETHER_TLS_GROUPS", arg_value},
    {"--tls-ciphers", "AETHER_TLS_CIPHERS", arg_value},
    {"--disable-grease", "AETHER_DISABLE_GREASE", "1"},
    {"--tls-verify", "AETHER_TLS_VERIFY", "1"},

    // Advanced
    {"--perf", "AETHER_PERF_PROFILE", arg_value},
    {"--log-level", "AETHER_LOG_LEVEL", arg_value},
    {"--verbose", "AETHER_LOG_LEVEL", "debug"},
};

} // namespace

const std::string* Settings::find(std::string_view key) const {
    const auto found = values.find(key);
    return found == values.end() ? nullptr : &found->second;
}

void Settings::set(std::string_view key, std::string_view value) {
    values[std::string(key)] = std::string(value);
}

std::string_view trim(std::string_view text) {
    const size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    return text.substr(begin, text.find_last_not_of(" \t\r\n") - begin + 1);
}

bool is_truthy(std::string_view value) {
    std::string text(trim(value));
    std::ranges::transform(text, text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text == "1" || text == "true" || text == "yes" || text == "on";
}

Settings settings_from_environment() {
    Settings settings;
    const auto absorb = [&](std::string_view name) {
        static thread_local std::wstring buffer;
        const std::wstring wide(name.begin(), name.end());
        for (;;) {
            // A call that fits reports the value's length without the terminating null; a call that
            // had to report a bigger buffer counts the null in that number. Reading the second as a
            // length puts a null at the end of every value taken into a buffer that had to grow.
            const DWORD written = GetEnvironmentVariableW(
                wide.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()));
            if (written == 0) return;
            if (written < buffer.size()) {
                const int bytes = WideCharToMultiByte(CP_UTF8, 0, buffer.data(),
                                                      static_cast<int>(written), nullptr, 0, nullptr,
                                                      nullptr);
                if (bytes <= 0) return;
                std::string value(static_cast<size_t>(bytes), '\0');
                if (WideCharToMultiByte(CP_UTF8, 0, buffer.data(), static_cast<int>(written),
                                        value.data(), bytes, nullptr, nullptr) == 0) {
                    return;
                }
                settings.set(name, std::move(value));
                return;
            }
            buffer.resize(static_cast<size_t>(written) + 1);
        }
    };

    for (const Row& row : rows) {
        absorb(row.key);
        if (!row.second_key.empty()) absorb(row.second_key);
    }
    // AETHER_MASQUE_H2_FRAGMENT_SNI has no flag: cli.rs never named it, fragment.rs reads it.
    absorb("AETHER_MASQUE_H2_FRAGMENT_SNI");
    // Neither does sysprofile.rs's two netstack buffer sizes: they are environment only.
    absorb("AETHER_NETSTACK_TCP_RX");
    absorb("AETHER_NETSTACK_TCP_TX");
    return settings;
}

CliOutcome apply_cli(const std::vector<std::string>& args, Settings& settings, std::string& error) {
    for (size_t index = 0; index < args.size(); ++index) {
        const std::string& flag = args[index];

        if (flag == "-v" || flag == "--version") return CliOutcome::Version;
        if (flag == "-h" || flag == "--help" || flag == "help") return CliOutcome::Help;

        const auto* row = std::ranges::find(rows, flag, &Row::flag);
        if (row == std::ranges::cend(rows)) {
            error = "unknown option '" + flag + "'\n\n" + usage_text();
            return CliOutcome::Failure;
        }

        // A row may read one argument, one shared by both halves, or one per half: --gool-peer
        // wants the address for its second key only, --validate-secs wants one for both.
        std::string value(row->value);
        const bool taken = value == arg_value;
        if (taken) {
            if (++index >= args.size()) {
                error = flag + " requires a value";
                return CliOutcome::Failure;
            }
            value = args[index];
        }

        settings.set(row->key, value);

        if (!row->second_key.empty()) {
            std::string second(row->second_value);
            if (second == arg_value) {
                if (taken) {
                    second = value;
                } else {
                    if (++index >= args.size()) {
                        error = flag + " requires a value";
                        return CliOutcome::Failure;
                    }
                    second = args[index];
                }
            }
            settings.set(row->second_key, second);
        }
    }

    return CliOutcome::Run;
}

} // namespace aether::core
