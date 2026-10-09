#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <chrono>
#include <string_view>
#include <algorithm>

namespace hemera {

// Protocols supported by Hemera core
enum class Protocol {
    Auto,
    Masque,
    Wireguard,
    Gool,
    WarpInWarp,
    Mim
};

inline std::string_view to_string(Protocol p) {
    switch (p) {
        case Protocol::Auto: return "auto";
        case Protocol::Masque: return "masque";
        case Protocol::Wireguard: return "wireguard";
        case Protocol::Gool: return "gool";
        case Protocol::WarpInWarp: return "warp-in-warp";
        case Protocol::Mim: return "mim";
    }
    return "auto";
}

inline Protocol protocol_from_string(std::string_view s) {
    if (s == "masque") return Protocol::Masque;
    if (s == "wireguard" || s == "wg") return Protocol::Wireguard;
    if (s == "gool") return Protocol::Gool;
    if (s == "warp-in-warp" || s == "wiw" || s == "classic" || s == "gool-classic") return Protocol::WarpInWarp;
    if (s == "mim") return Protocol::Mim;
    return Protocol::Auto;
}

// Scan Modes
enum class ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Verified,
    Ironclad
};

inline std::string_view to_string(ScanMode m) {
    switch (m) {
        case ScanMode::Turbo: return "turbo";
        case ScanMode::Balanced: return "balanced";
        case ScanMode::Thorough: return "thorough";
        case ScanMode::Verified: return "verified";
        case ScanMode::Ironclad: return "ironclad";
    }
    return "balanced";
}

inline ScanMode scan_mode_from_string(std::string_view s) {
    if (s == "turbo") return ScanMode::Turbo;
    if (s == "thorough") return ScanMode::Thorough;
    if (s == "verified" || s == "stealth") return ScanMode::Verified;
    if (s == "ironclad") return ScanMode::Ironclad;
    return ScanMode::Balanced;
}

// IP Version
enum class IpVersion {
    V4,
    V6,
    Both
};

inline std::string_view to_string(IpVersion v) {
    switch (v) {
        case IpVersion::V4: return "v4";
        case IpVersion::V6: return "v6";
        case IpVersion::Both: return "both";
    }
    return "v4";
}

inline IpVersion ip_version_from_string(std::string_view s) {
    if (s == "v6") return IpVersion::V6;
    if (s == "both" || s == "dual") return IpVersion::Both;
    return IpVersion::V4;
}

// Obfuscation (MASQUE)
enum class MasqueNoize {
    Firewall,
    Gfw,
    Off
};

inline std::string_view to_string(MasqueNoize n) {
    switch (n) {
        case MasqueNoize::Firewall: return "firewall";
        case MasqueNoize::Gfw: return "gfw";
        case MasqueNoize::Off: return "off";
    }
    return "firewall";
}

inline MasqueNoize masque_noize_from_string(std::string_view s) {
    if (s == "gfw") return MasqueNoize::Gfw;
    if (s == "off") return MasqueNoize::Off;
    return MasqueNoize::Firewall;
}

// Obfuscation (WireGuard / Gool)
enum class WgNoize {
    Balanced,
    Aggressive,
    Light,
    Off
};

inline std::string_view to_string(WgNoize n) {
    switch (n) {
        case WgNoize::Balanced: return "balanced";
        case WgNoize::Aggressive: return "aggressive";
        case WgNoize::Light: return "light";
        case WgNoize::Off: return "off";
    }
    return "balanced";
}

inline WgNoize wg_noize_from_string(std::string_view s) {
    if (s == "aggressive") return WgNoize::Aggressive;
    if (s == "light") return WgNoize::Light;
    if (s == "off") return WgNoize::Off;
    return WgNoize::Balanced;
}

// Zero Trust Authentication
enum class ZeroTrustAuth {
    Email,
    Service,
    Token
};

inline std::string_view to_string(ZeroTrustAuth a) {
    switch (a) {
        case ZeroTrustAuth::Email: return "email";
        case ZeroTrustAuth::Service: return "service";
        case ZeroTrustAuth::Token: return "token";
    }
    return "email";
}

inline ZeroTrustAuth zero_trust_auth_from_string(std::string_view s) {
    if (s == "service") return ZeroTrustAuth::Service;
    if (s == "token") return ZeroTrustAuth::Token;
    return ZeroTrustAuth::Email;
}

// Constants
inline constexpr std::string_view DEFAULT_BIND_ADDRESS = "127.0.0.1:1819";
inline constexpr std::string_view SYSTEM_PROXY_BIND = "127.0.0.1:1822";

inline constexpr uint32_t MAX_AUTO_RETRIES = 3;
inline constexpr std::chrono::milliseconds RETRY_BACKOFF[MAX_AUTO_RETRIES] = {
    std::chrono::seconds(2),
    std::chrono::seconds(5),
    std::chrono::seconds(10)
};

inline constexpr std::chrono::milliseconds GRACEFUL_SHUTDOWN_GRACE = std::chrono::seconds(3);

// Connection Profile
struct ConnectionProfile {
    Protocol protocol = Protocol::Auto;
    ScanMode scan_mode = ScanMode::Balanced;
    IpVersion ip_version = IpVersion::V4;
    bool quick_reconnect = true;
    bool masque_http2 = false;
    MasqueNoize masque_noize = MasqueNoize::Firewall;
    WgNoize wg_noize = WgNoize::Balanced;
    std::string bind_address = std::string(DEFAULT_BIND_ADDRESS);
    std::string dns;
    std::string zero_trust_team;
    ZeroTrustAuth zero_trust_auth = ZeroTrustAuth::Email;
    std::string access_email;
    std::string access_client_id;
    std::string access_client_secret;
    std::string access_token;
    bool zero_trust_gateway = false;
    std::string route_block;
    std::string route_direct;
    std::string routes_file;
    std::string http_proxy;
    std::string upstream;
    std::string exit_loc;
    bool system_proxy = true;
    bool tun_mode = false;
    bool fragment = false;
    bool ech = false;

    [[nodiscard]] std::chrono::seconds connect_timeout() const noexcept {
        uint64_t base = 0;
        switch (scan_mode) {
            case ScanMode::Turbo: base = 90; break;
            case ScanMode::Balanced: base = 150; break;
            case ScanMode::Thorough: base = 330; break;
            case ScanMode::Verified: base = 210; break;
            case ScanMode::Ironclad: base = 240; break;
        }
        return std::chrono::seconds(base);
    }

    [[nodiscard]] std::string primary_addr() const {
        return bind_address.empty() ? std::string(DEFAULT_BIND_ADDRESS) : bind_address;
    }

    [[nodiscard]] std::optional<std::string> http_front() const {
        if (!http_proxy.empty()) return http_proxy;
        if (system_proxy) return std::string(SYSTEM_PROXY_BIND);
        return std::nullopt;
    }

    // The TUN adapter's resolver, as a bare address literal for netsh. An interface with no DNS
    // server resolves nothing, and --dns is an argument for the core rather than for Windows, so
    // the interface is pointed at the same resolver. A scheme, a port or an IPv6 literal yields
    // the empty string, which means "leave the adapter's DNS alone".
    [[nodiscard]] std::string adapter_dns() const {
        std::string host = dns.empty() ? std::string("1.1.1.1") : dns;
        if (const auto scheme = host.find("://"); scheme != std::string::npos) {
            host.erase(0, scheme + 3);
        }
        if (const auto slash = host.find('/'); slash != std::string::npos) {
            host.erase(slash);
        }
        if (const auto colon = host.find(':'); colon != std::string::npos) {
            if (host.find(':', colon + 1) != std::string::npos) return {}; // IPv6, not netsh-able here
            host.erase(colon); // a port
        }
        for (const char c : host) {
            const bool ok = (c >= '0' && c <= '9') || c == '.' ||
                            (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return {};
        }
        return host;
    }

    [[nodiscard]] std::vector<std::string> ready_addrs() const {
        return { primary_addr() };
    }

    [[nodiscard]] std::vector<std::string> as_args() const {
        std::vector<std::string> args;
        args.reserve(24);

        switch (protocol) {
            case Protocol::Auto: break;
            case Protocol::Masque: args.push_back("--masque"); break;
            case Protocol::Wireguard: args.push_back("--wg"); break;
            case Protocol::Gool: args.push_back("--gool"); break;
            case Protocol::WarpInWarp: args.push_back("--gool-classic"); break;
            case Protocol::Mim: args.push_back("--mim"); break;
        }

        // Scan mode
        switch (scan_mode) {
            case ScanMode::Turbo: args.push_back("--turbo"); break;
            case ScanMode::Balanced: args.push_back("--balanced"); break;
            case ScanMode::Thorough: args.push_back("--thorough"); break;
            case ScanMode::Verified: args.push_back("--verified"); break;
            case ScanMode::Ironclad: args.push_back("--ironclad"); break;
        }

        // IP version
        switch (ip_version) {
            case IpVersion::V4: args.push_back("-4"); break;
            case IpVersion::V6: args.push_back("-6"); break;
            case IpVersion::Both: args.push_back("--dual"); break;
        }

        // Quick reconnect
        args.push_back(quick_reconnect ? "--quick-reconnect" : "--no-quick-reconnect");

        // MASQUE HTTP/2 transport
        if (masque_http2) {
            args.push_back("--h2");
        }

        // Anti-censorship: TLS fragmentation & ECH
        if (fragment) {
            args.push_back("--fragment");
        }
        if (ech) {
            args.push_back("--ech");
            args.push_back("auto");
        }

        // Noize obfuscation
        args.push_back("--noize");
        if (protocol == Protocol::Wireguard || protocol == Protocol::Gool) {
            args.push_back(std::string(to_string(wg_noize)));
        } else {
            args.push_back(std::string(to_string(masque_noize)));
        }

        // Bind address (only pass when non-default)
        if (!bind_address.empty() && bind_address != DEFAULT_BIND_ADDRESS) {
            args.push_back("--bind");
            args.push_back(bind_address);
        }

        // DNS
        if (!dns.empty()) {
            args.push_back("--dns");
            args.push_back(dns);
        }

        // Zero Trust
        if (!zero_trust_team.empty()) {
            args.push_back("--team");
            args.push_back(zero_trust_team);
            if (zero_trust_gateway) {
                args.push_back("--gateway");
            }
        }

        // HTTP Front
        auto front = http_front();
        if (front) {
            args.push_back("--http-proxy");
            args.push_back(*front);
        }

        // Upstream & Exit Location
        if (!upstream.empty()) {
            args.push_back("--upstream");
            args.push_back(upstream);
        }
        if (!exit_loc.empty()) {
            args.push_back("--exit-loc");
            args.push_back(exit_loc);
        }

        // Routing rules
        if (!route_block.empty()) {
            args.push_back("--route-block");
            args.push_back(route_block);
        }
        if (!route_direct.empty()) {
            args.push_back("--route-direct");
            args.push_back(route_direct);
        }
        if (!routes_file.empty()) {
            args.push_back("--routes");
            args.push_back(routes_file);
        }

        return args;
    }
};

// Application State Machine
enum class StateKind {
    Idle,
    Launching,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error
};

inline std::string_view to_string(StateKind s) {
    switch (s) {
        case StateKind::Idle: return "Idle";
        case StateKind::Launching: return "Launching";
        case StateKind::Connecting: return "Connecting";
        case StateKind::Connected: return "Connected";
        case StateKind::Reconnecting: return "Reconnecting";
        case StateKind::Disconnecting: return "Disconnecting";
        case StateKind::Error: return "Error";
    }
    return "Idle";
}

struct ConnectionState {
    StateKind kind = StateKind::Idle;
    std::string socks_addr;
    uint64_t connected_at_ms = 0;
    uint32_t retry_attempt = 0;
    uint32_t max_retries = MAX_AUTO_RETRIES;
    std::string error_message;
    std::string error_phase;
};

struct LogLine {
    std::string line;
    uint64_t timestamp_ms = 0;
};

struct AppSettings {
    bool close_to_tray = false;
    bool autostart = false;
    bool auto_connect = false;
    std::string theme = "dark"; // "system", "light", "dark"
    bool kill_switch = false;
};

inline uint64_t current_time_ms() noexcept {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} // namespace hemera
