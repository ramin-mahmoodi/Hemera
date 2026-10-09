// Port of aether/src/api.rs (commit 6175b67): the core's control-plane API. See localapi.hpp for
// what the surface is and for the two divergences it notes (cooperative cancellation, the
// ECH wrap the Rust's tls::ech_key does that the ported tls module leaves to the caller).

#include "localapi.hpp"

#include "tls.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <span>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace aether::core::localapi {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char byte) { return static_cast<char>(std::tolower(byte)); });
    return out;
}

// quic.rs::default_authority / default_path, the MASQUE handshake's authority and request path.
constexpr std::string_view MASQUE_AUTHORITY = "cloudflareaccess.com";
constexpr std::string_view MASQUE_PATH = "/";

// lib.rs::parse_local_v4: the address before any `/prefix`, and 0.0.0.0 when it is no IPv4
// address at all -- the probe carries an address, never an option.
IpAddress parse_local_v4(std::string_view text) {
    const std::size_t slash = text.find('/');
    const std::string_view head = slash == std::string_view::npos ? text : text.substr(0, slash);
    IpAddress out;
    out.v4 = true;
    if (const auto parsed = parse_address(head); parsed && parsed->v4) {
        return *parsed;
    }
    return out; // bytes stay zero, which is 0.0.0.0
}

// api.rs::wg_local_v4: unlike the probe's fallback, the WireGuard paths refuse an identity
// whose ipv4 is not a usable IPv4 address, with the Rust's exact text.
std::expected<IpAddress, ApiError> wg_local_v4(const Identity& identity) {
    if (const auto parsed = parse_address(identity.ipv4); parsed && parsed->v4) {
        return *parsed;
    }
    return std::unexpected(
        ApiError{ErrorKind::Other,
                 std::format("identity has an unusable ipv4 {}", identity.ipv4)});
}

// lib.rs::derive_sibling_path: `base` with `-suffix` inserted before the file extension, in the
// directory the base names. The split is byte-wise and covers both separators, as the Rust is.
std::string derive_sibling_path(std::string_view base, std::string_view suffix) {
    std::size_t dir_end = 0;
    for (std::size_t i = 0; i < base.size(); ++i) {
        if (base[i] == '/' || base[i] == '\\') dir_end = i + 1;
    }
    const std::string_view name = base.substr(dir_end);
    const std::size_t dot = name.find_last_of('.');
    if (dot != std::string_view::npos) {
        const std::size_t at = dir_end + dot;
        return std::string(base.substr(0, at)) + "-" + std::string(suffix) +
               std::string(base.substr(at));
    }
    return std::string(base) + "-" + std::string(suffix);
}

std::string port_text(std::uint16_t port) {
    return std::to_string(port);
}

} // namespace

// ---- Transport ----

Transport parse_transport(std::string_view raw) {
    const std::string name = lowered(trim(raw));
    if (name == "wg" || name == "wireguard" || name == "warp") return Transport::WireGuard;
    return Transport::Masque;
}

std::string_view transport_label(Transport transport) {
    return transport == Transport::WireGuard ? "wireguard" : "masque";
}

std::uint16_t transport_assigned_port(Transport transport) {
    return transport == Transport::WireGuard ? 2408 : 443;
}

const std::vector<std::uint16_t>& transport_default_ports(Transport transport) {
    // prober.rs::MASQUE_PORTS.
    static const std::vector<std::uint16_t> masque_ports = {443, 500, 1701, 4500, 4443, 8443,
                                                            8095};
    // wireguard.rs::WG_PORTS.
    static const std::vector<std::uint16_t> wg_ports = {
        2408, 500,  1701, 4500, 854,  859,  864,  878,  880,  890,  891,  894,  903,
        908,  928,  934,  939,  942,  943,  945,  946,  955,  968,  987,  988,  1002,
        1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581,
        3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
        8854, 8886};
    return transport == Transport::WireGuard ? wg_ports : masque_ports;
}

// ---- Errors ----

std::string ApiError::to_string() const {
    // error.rs's Display for each variant api.rs can raise or pass on.
    switch (kind) {
        case ErrorKind::Io:              return "io: " + message;
        case ErrorKind::Quic:            return "quic: " + message;
        case ErrorKind::H3:              return "h3: " + message;
        case ErrorKind::Tls:             return "tls: " + message;
        case ErrorKind::Ech:             return "ech: " + message;
        case ErrorKind::Masque:          return "masque: " + message;
        case ErrorKind::NoCleanEndpoint: return "prober: no clean endpoint found";
        case ErrorKind::Capsule:         return "capsule: " + message;
        case ErrorKind::Api:             return "api: " + message;
        case ErrorKind::IdentityRefused: return "identity refused: " + message;
        case ErrorKind::Cancelled:       return "cancelled";
        case ErrorKind::Other:           return "other: " + message;
    }
    return "other: " + message;
}

// ---- Scan knobs ----

IpScan parse_ip_scan(std::string_view raw) {
    const std::string name = lowered(trim(raw));
    if (name == "6" || name == "v6" || name == "ipv6") return IpScan::V6;
    if (name == "both" || name == "all" || name == "dual") return IpScan::Both;
    return IpScan::V4;
}

std::string_view ip_scan_label(IpScan ip) {
    switch (ip) {
        case IpScan::V4:   return "ipv4";
        case IpScan::V6:   return "ipv6";
        case IpScan::Both: return "dual-stack";
    }
    return "ipv4";
}

bool ip_scan_want_v4(IpScan ip) { return ip == IpScan::V4 || ip == IpScan::Both; }
bool ip_scan_want_v6(IpScan ip) { return ip == IpScan::V6 || ip == IpScan::Both; }

// The mode table prober.rs::ScanMode::parse and wg_prober.rs::WgScanMode::parse share.
namespace {
template <class Mode>
Mode parse_mode(std::string_view raw, Mode turbo, Mode thorough, Mode verified, Mode ironclad,
                Mode balanced) {
    const std::string name = lowered(trim(raw));
    if (name == "turbo" || name == "fast") return turbo;
    if (name == "thorough" || name == "deep" || name == "pro") return thorough;
    if (name == "verified" || name == "proven" || name == "stealth" || name == "quiet") {
        return verified;
    }
    if (name == "ironclad" || name == "real" || name == "verify" || name == "guaranteed") {
        return ironclad;
    }
    return balanced;
}
} // namespace

ScanMode parse_scan_mode(std::string_view raw) {
    return parse_mode(raw, ScanMode::Turbo, ScanMode::Thorough, ScanMode::Verified,
                      ScanMode::Ironclad, ScanMode::Balanced);
}

std::string_view scan_mode_label(ScanMode mode) {
    switch (mode) {
        case ScanMode::Turbo:     return "turbo";
        case ScanMode::Balanced:  return "balanced";
        case ScanMode::Thorough:  return "thorough";
        case ScanMode::Verified:  return "verified";
        case ScanMode::Ironclad:  return "ironclad";
    }
    return "balanced";
}

WgScanMode parse_wg_scan_mode(std::string_view raw) {
    return parse_mode(raw, WgScanMode::Turbo, WgScanMode::Thorough, WgScanMode::Verified,
                      WgScanMode::Ironclad, WgScanMode::Balanced);
}

std::string_view wg_scan_mode_label(WgScanMode mode) {
    switch (mode) {
        case WgScanMode::Turbo:    return "turbo";
        case WgScanMode::Balanced: return "balanced";
        case WgScanMode::Thorough: return "thorough";
        case WgScanMode::Verified: return "verified";
        case WgScanMode::Ironclad: return "ironclad";
    }
    return "balanced";
}

// ---- Zero trust teams ----

std::optional<std::string> normalize_team(std::string_view raw) {
    std::string value = lowered(trim(raw));
    if (value.empty()) return std::nullopt;

    // Rust strips both prefixes in a loop, so each is tried once on the value as it stands. This
    // has to happen first: otherwise the `//` of the scheme is what split('/') cuts at.
    for (const std::string_view prefix : {std::string_view("https://"), std::string_view("http://")}) {
        if (value.starts_with(prefix)) value.erase(0, prefix.size());
    }

    // Rust's trim_end_matches('/'), then split('/').next(): every trailing slash goes, and the
    // head before the first remaining slash is kept -- whole, when it is the only segment.
    while (!value.empty() && value.back() == '/') value.pop_back();
    const std::size_t slash = value.find('/');
    if (slash != std::string_view::npos) value.erase(slash);

    constexpr std::string_view TEAM_SUFFIX = "cloudflareaccess.com";
    if (value.ends_with(TEAM_SUFFIX)) {
        value.erase(value.size() - TEAM_SUFFIX.size());
        while (!value.empty() && value.back() == '.') value.pop_back();
    }

    if (value.empty()) return std::nullopt;
    // is_ascii_alphanumeric keeps ASCII only, so non-ASCII names are refused as the Rust is.
    for (const char ch : value) {
        const auto byte = static_cast<unsigned char>(ch);
        const bool alnum = byte < 0x80 && std::isalnum(byte) != 0;
        if (!alnum && byte != '-' && byte != '_') return std::nullopt;
    }
    return value;
}

std::string team_domain(std::string_view team) {
    return "https://" + std::string(team) + ".cloudflareaccess.com";
}

bool TeamSettings::has_service_token() const {
    return client_id.has_value() && client_secret.has_value();
}

std::string TeamSettings::team_domain() const { return localapi::team_domain(team); }

std::string TeamSettings::login_url() const { return team_domain() + "/warp"; }

std::expected<TeamCredentials, ApiError> TeamCredentials::make(std::string_view raw) {
    auto team = normalize_team(raw);
    if (!team) {
        return std::unexpected(ApiError{
            ErrorKind::Api,
            std::format("'{}' is not a usable zero trust team name", raw)});
    }
    TeamCredentials credentials;
    credentials.settings.team = *team;
    return credentials;
}

TeamCredentials TeamCredentials::with_service_token(std::string_view client_id,
                                                   std::string_view client_secret) const {
    TeamCredentials out = *this;
    out.settings.client_id = std::string(client_id);
    out.settings.client_secret = std::string(client_secret);
    return out;
}

TeamCredentials TeamCredentials::with_token(std::string_view token) const {
    TeamCredentials out = *this;
    out.settings.token = std::string(token);
    return out;
}

TeamCredentials TeamCredentials::with_email(std::string_view email) const {
    TeamCredentials out = *this;
    out.settings.email = std::string(email);
    return out;
}

std::string TeamCredentials::login_url() const { return settings.login_url(); }

// ---- Addresses ----

std::string address_text(const IpAddress& ip) {
    if (ip.v4) {
        return std::format("{}.{}.{}.{}", ip.bytes[12], ip.bytes[13], ip.bytes[14],
                           ip.bytes[15]);
    }

    // Rust's Ipv6Addr Display: lower-case hex, no leading zeros, the longest run of two or more
    // zero groups folded to "::" -- the leftmost run wins a tie, and an all-zero address prints
    // as "::".
    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < 8; ++i) {
        groups[i] = static_cast<std::uint16_t>((static_cast<std::uint32_t>(ip.bytes[2 * i])
                                                << 8) |
                                               ip.bytes[2 * i + 1]);
    }

    int best_start = -1;
    int best_len = 0;
    int run_start = -1;
    for (int i = 0; i <= 8; ++i) {
        if (i < 8 && groups[static_cast<std::size_t>(i)] == 0) {
            if (run_start < 0) run_start = i;
            continue;
        }
        if (run_start >= 0 && i - run_start > best_len) {
            best_start = run_start;
            best_len = i - run_start;
        }
        run_start = -1;
    }

    std::string out;
    if (best_len < 2) {
        for (std::size_t i = 0; i < 8; ++i) {
            if (i != 0) out.push_back(':');
            out += std::format("{:x}", groups[i]);
        }
        return out;
    }

    for (int i = 0; i < best_start; ++i) {
        if (i != 0) out.push_back(':');
        out += std::format("{:x}", groups[static_cast<std::size_t>(i)]);
    }
    out += "::";
    for (int i = best_start + best_len; i < 8; ++i) {
        out += std::format("{:x}", groups[static_cast<std::size_t>(i)]);
        if (i + 1 < 8) out.push_back(':');
    }
    return out;
}

std::string socket_text(const SocketAddr& addr) {
    // SocketAddr's Display: a v6 address brackets, a v4 one does not.
    if (addr.ip.v4) {
        return address_text(addr.ip) + ":" + port_text(addr.port);
    }
    return "[" + address_text(addr.ip) + "]:" + port_text(addr.port);
}

// ---- Requests and summaries ----

ProvisionRequest ProvisionRequest::for_transport(Transport transport) {
    ProvisionRequest request;
    request.masque_cert = transport == Transport::Masque;
    return request;
}

ProvisionRequest ProvisionRequest::in_team(TeamCredentials credentials) const {
    ProvisionRequest out = *this;
    out.team = credentials;
    return out;
}

IdentitySummary IdentitySummary::of(const Identity& identity) {
    IdentitySummary summary;
    summary.device_id = identity.device_id;
    summary.ipv4 = identity.ipv4;
    summary.ipv6 = identity.ipv6;
    summary.organization = identity.organization;
    summary.gateway_proxy = identity.gateway_proxy;
    summary.assigned_endpoint = identity.assigned_endpoint;
    summary.has_masque_cert = identity.has_masque_credentials();
    summary.cert_issued_at = identity.cert_issued_at;
    summary.cert_usable = cert_still_usable(identity);
    return summary;
}

json::Value IdentitySummary::to_json() const {
    json::Object object;
    object["device_id"] = json::Value(device_id);
    object["ipv4"] = json::Value(ipv4);
    object["ipv6"] = json::Value(ipv6);
    object["organization"] = json::Value(organization);
    object["gateway_proxy"] = json::Value(gateway_proxy);
    object["assigned_endpoint"] = json::Value(assigned_endpoint);
    object["has_masque_cert"] = json::Value(has_masque_cert);
    object["cert_issued_at"] = json::Value(cert_issued_at);
    object["cert_usable"] = json::Value(cert_usable);
    return json::Value(std::move(object));
}

SocketAddr Endpoint::socket() const { return SocketAddr{ip, port}; }

json::Value Endpoint::to_json() const {
    json::Object object;
    object["ip"] = json::Value(address_text(ip));
    object["port"] = json::Value(static_cast<std::uint64_t>(port));
    object["rtt_ms"] = json::Value(rtt_ms);
    return json::Value(std::move(object));
}

ScanRequest ScanRequest::for_transport(Transport transport) {
    ScanRequest request;
    request.transport = transport;
    request.mode = "balanced";
    request.ip = IpScan::V4;
    request.ports = transport_default_ports(transport);
    request.noise = noize::from_profile("firewall");
    request.aethernoize = aethernoize::from_profile("balanced");
    return request;
}

ScanRequest ScanRequest::with_mode(std::string_view new_mode) const {
    ScanRequest out = *this;
    out.mode = std::string(new_mode);
    return out;
}

ScanRequest ScanRequest::with_ip(IpScan new_ip) const {
    ScanRequest out = *this;
    out.ip = new_ip;
    return out;
}

ScanRequest ScanRequest::with_profile(std::string_view profile) const {
    ScanRequest out = *this;
    out.noise = noize::from_profile(profile);
    out.aethernoize = aethernoize::from_profile(profile);
    return out;
}

TunnelSpec TunnelSpec::for_transport(Transport transport) {
    TunnelSpec spec;
    spec.transport = transport;
    spec.socks = SocketAddr{parse_local_v4("127.0.0.1"), 1819};
    spec.http = std::nullopt;
    spec.ech = std::nullopt;
    spec.aethernoize = aethernoize::from_profile("balanced");
    spec.keepalive = 5;
    spec.verify_timeout = std::chrono::milliseconds(10000);
    return spec;
}

TunnelSpec TunnelSpec::with_socks(SocketAddr listen) const {
    TunnelSpec out = *this;
    out.socks = listen;
    return out;
}

TunnelSpec TunnelSpec::with_http(SocketAddr listen) const {
    TunnelSpec out = *this;
    out.http = listen;
    return out;
}

TunnelSpec TunnelSpec::with_profile(std::string_view profile) const {
    TunnelSpec out = *this;
    out.aethernoize = aethernoize::from_profile(profile);
    return out;
}

// ---- Paths ----

std::string identity_path(std::string_view base, Transport transport,
                          std::optional<std::string_view> team) {
    if (team) return derive_sibling_path(base, "team-" + std::string(*team));
    if (transport == Transport::Masque) return derive_sibling_path(base, "masque");
    return std::string(base);
}

std::string lastconn_path(std::string_view path) {
    return derive_sibling_path(path, "lastconn");
}

// api.rs::load_identity and save_identity over config.rs, which the port reads and writes
// through identity.hpp. A file that fails to parse quarantines itself there, as the Rust does.
std::expected<std::optional<Identity>, ApiError> load_identity(const std::string& path) {
    auto loaded = ::aether::core::load_identity(path);
    if (!loaded) return std::unexpected(ApiError{ErrorKind::Other, loaded.error()});
    return *loaded;
}

std::expected<void, ApiError> save_identity(const std::string& path, const Identity& identity) {
    auto saved = ::aether::core::save_identity(path, identity);
    if (!saved) return std::unexpected(ApiError{ErrorKind::Other, saved.error()});
    return {};
}

// ---- Identity lifecycle ----

std::expected<Identity, ApiError> provision_identity(Engine& engine,
                                                    const ProvisionRequest& request) {
    Identity identity;
    if (request.team) {
        const TeamSettings& settings = request.team->settings;
        engine.log(LogLevel::Info,
                   std::format("[*] enrolling this device into the zero trust organization "
                               "{} ({})",
                               settings.team, settings.team_domain()));
        auto enrolled = engine.provision_team(request.model, request.locale, settings);
        if (!enrolled) return std::unexpected(enrolled.error());
        identity = engine.refresh_profile(std::move(*enrolled));
    } else {
        auto enrolled = engine.provision_wg(request.model, request.locale);
        if (!enrolled) return std::unexpected(enrolled.error());
        identity = std::move(*enrolled);
    }

    if (request.masque_cert) return attach_masque_cert(engine, std::move(identity));
    return identity;
}

Identity refresh_identity(Engine& engine, Identity identity) {
    return engine.refresh_profile(std::move(identity));
}

std::expected<Identity, ApiError> attach_masque_cert(Engine& engine, Identity identity) {
    if (identity.has_masque_credentials() && !masque_cert_expiring(identity.cert_issued_at)) {
        return identity;
    }
    auto enrollment = engine.ensure_masque_enrolled(identity);
    if (!enrollment) return std::unexpected(enrollment.error());
    identity.cert_pem = std::move(enrollment->cert_pem);
    identity.key_pem = std::move(enrollment->key_pem);
    identity.cert_issued_at = enrollment->issued_at;
    return identity;
}

std::expected<Identity, ApiError> open_identity(Engine& engine, const std::string& path,
                                                const ProvisionRequest& request) {
    auto loaded = load_identity(path);
    if (!loaded) return std::unexpected(loaded.error());

    if (*loaded) {
        engine.log(LogLevel::Info,
                   std::format("[+] loaded an existing identity from {}", path));
        Identity identity = std::move(**loaded);
        if (request.team) identity = refresh_identity(engine, std::move(identity));
        if (request.masque_cert) {
            auto attached = attach_masque_cert(engine, std::move(identity));
            if (!attached) return std::unexpected(attached.error());
            identity = std::move(*attached);
        }
        if (auto saved = ::aether::core::localapi::save_identity(path, identity); !saved) {
            return std::unexpected(saved.error());
        }
        return identity;
    }

    engine.log(LogLevel::Info,
               std::format("[+] no identity at {}; provisioning a new one", path));
    auto provisioned = provision_identity(engine, request);
    if (!provisioned) return std::unexpected(provisioned.error());
    if (auto saved = ::aether::core::localapi::save_identity(path, *provisioned); !saved) {
        return std::unexpected(saved.error());
    }
    return provisioned;
}

// ---- Team sign-in ----

std::expected<std::string, ApiError> team_sign_in(Engine& engine,
                                                 const TeamCredentials& credentials) {
    return engine.resolve_token(credentials.settings);
}

std::expected<EmailSession, ApiError> team_email_code_request(Engine& engine,
                                                             const TeamCredentials& credentials,
                                                             std::string_view email) {
    return engine.begin_email_signin(credentials.settings, email);
}

std::expected<void, ApiError> team_email_code_resend(Engine& engine, EmailSession& session) {
    return engine.resend_code(session);
}

std::expected<std::optional<std::string>, ApiError> team_email_code_submit(
    Engine& engine, const EmailSession& session, std::string_view code) {
    auto outcome = engine.submit_code(session, code);
    if (!outcome) return std::unexpected(outcome.error());

    if (outcome->accepted) {
        if (auto stored = team_use_token(engine, outcome->token); !stored) {
            return std::unexpected(stored.error());
        }
        return std::optional<std::string>(outcome->token);
    }
    engine.log(LogLevel::Warn, std::format("[-] the login code was not accepted (status {})",
                                           outcome->status));
    return std::optional<std::string>(std::nullopt);
}

std::expected<void, ApiError> team_use_token(Engine& engine, std::string_view token) {
    return engine.store_token(token);
}

std::optional<std::string> team_current_token(Engine& engine) { return engine.cached_token(); }

void team_forget_token(Engine& engine) { engine.clear_token(); }

// ---- ECH ----

std::expected<std::vector<std::uint8_t>, ApiError> fetch_ech_config(
    const Settings& settings, const EchTransport& transport) {
    // job_ech_key: the lookup of --ech-dns and --ech-domain, offered through tls::ech_key with
    // the setting forced to auto, and no path that ends without a key.
    Settings job = settings;
    job.set("AETHER_ECH", "auto");

    auto keyed = ech_key(job, EchPurpose::Session,
                         [&job, &transport]() { return ::aether::core::fetch_ech_config(job, transport); });
    if (!keyed) {
        // tls::ech_key already folded the miss into the NO_ECH_KEY sentence, whatever missed:
        // the lookup, the value, or a key BoringSSL will not offer.
        return std::unexpected(ApiError{ErrorKind::Ech, keyed.error()});
    }
    if (!*keyed) {
        // Unreachable with the setting forced to auto; kept because the Rust says it.
        return std::unexpected(ApiError{ErrorKind::Ech, std::string(NO_ECH_KEY)});
    }
    return **keyed;
}

// ---- Scanning, verifying, connecting ----

std::expected<Endpoint, ApiError> scan(Engine& engine, const Identity& identity,
                                       const ScanRequest& request, const Cancel& cancel) {
    if (request.transport == Transport::Masque) {
        MasqueProbe probe;
        probe.sni = std::string(CONNECT_SNI);
        probe.authority = std::string(MASQUE_AUTHORITY);
        probe.path = std::string(MASQUE_PATH);
        probe.cert_pem = identity.cert_pem;
        probe.key_pem = identity.key_pem;
        probe.ech_config_list = request.ech_config_list;
        probe.noise = request.noise;
        probe.ports = request.ports;
        probe.ip = request.ip;
        probe.local_ipv4 = parse_local_v4(identity.ipv4);

        const ScanMode mode = parse_scan_mode(request.mode);
        return guard<Endpoint>(
            cancel, [&](const Cancel& inner) {
                return engine.hunt_masque_gateway(probe, mode, inner);
            });
    }

    auto local_ipv4 = wg_local_v4(identity);
    if (!local_ipv4) return std::unexpected(local_ipv4.error());

    WgProbe probe;
    probe.private_key = identity.wg_private_key;
    probe.peer_public_key = identity.wg_peer_public_key;
    probe.client_id = identity.client_id;
    probe.local_ipv4 = *local_ipv4;
    probe.noise = request.aethernoize;
    probe.ports = request.ports;
    probe.ip = request.ip;
    probe.excluded = request.excluded;

    const WgScanMode mode = parse_wg_scan_mode(request.mode);
    return guard<Endpoint>(cancel, [&](const Cancel& inner) {
        return engine.hunt_wireguard_gateway(probe, mode, inner);
    });
}

std::expected<bool, ApiError> verify_endpoint(Engine& engine, const Identity& identity,
                                              const SocketAddr& peer, const TunnelSpec& spec,
                                              const Cancel& cancel) {
    if (spec.transport == Transport::Masque) {
        // The check offers the job's ECH key, as its tunnel would.
        return guard<bool>(cancel, [&](const Cancel&) {
            return std::expected<bool, ApiError>{
                engine.quick_verify_masque_peer(identity, peer, spec.ech)};
        });
    }

    auto local_ipv4 = wg_local_v4(identity);
    if (!local_ipv4) return std::unexpected(local_ipv4.error());

    WgVerifyParams params;
    params.peer = peer;
    params.private_key = identity.wg_private_key;
    params.peer_public_key = identity.wg_peer_public_key;
    params.client_id = identity.client_id;
    params.local_ipv4 = *local_ipv4;
    params.noise = spec.aethernoize;
    params.verify_timeout = spec.verify_timeout;
    params.keepalive = spec.keepalive;

    // Divergence from the Rust, in the engine's direction: identity.private_key_bytes() can
    // fail on a stored key that no longer parses; the ported Identity keeps the bytes, so the
    // key is always there and only the ipv4 guard is left.
    auto outcome = guard<void>(cancel, [&](const Cancel&) {
        return engine.verify_wireguard_endpoint(params);
    });
    if (outcome) return true;
    if (outcome.error().kind == ErrorKind::Cancelled) return std::unexpected(outcome.error());
    engine.log(LogLevel::Debug, std::format("[-] {} did not verify: {}", socket_text(peer),
                                            outcome.error().to_string()));
    return false;
}

std::expected<void, ApiError> connect(Engine& engine, const Identity& identity,
                                      const SocketAddr& peer, const TunnelSpec& spec,
                                      const Cancel& cancel) {
    // api.rs sets AETHER_HTTP_PROXY for the whole process before it runs the tunnel, and
    // removes it -- not blanks it -- when the job names no http listener.
    if (spec.http) {
        const std::string listen = socket_text(*spec.http);
        ::SetEnvironmentVariableA("AETHER_HTTP_PROXY", listen.c_str());
    } else {
        ::SetEnvironmentVariableA("AETHER_HTTP_PROXY", nullptr);
    }

    if (spec.transport == Transport::Masque) {
        return guard<void>(cancel, [&](const Cancel& inner) {
            return engine.run_masque_tunnel(identity, peer, spec.ech, spec.socks, inner);
        });
    }
    return guard<void>(cancel, [&](const Cancel& inner) {
        return engine.run_wireguard_tunnel(identity, peer, spec.aethernoize, spec.socks, inner);
    });
}

} // namespace aether::core::localapi
