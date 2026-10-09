#pragma once
// Port of aether/src/api.rs (commit 6175b67): the core's control-plane API -- the surface the
// CLI, the FFI and the supervisor drive to pick a transport, sign into a team, provision an
// identity, scan for a gateway, verify it and connect the tunnel.

#include "aethernoize.hpp"
#include "consts.hpp"
#include "dns.hpp"
#include "identity.hpp"
#include "json.hpp"
#include "noize.hpp"
#include "settings.hpp"
#include "tls.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aether::core::localapi {

// api.rs is not an HTTP server: the pinned Rust core opens no listening socket and parses no
// request line anywhere (no route table, no auth header, no CORS exists to keep). What api.rs
// is, is the library API the whole core hangs off, and it is ported here whole. Everything the
// surface needs live for -- sockets, the probes, the team sign-in round trips, the tunnel run
// loops -- sits behind Engine, exactly where the Rust hands off to account/prober/wireguard/
// zerotrust/dns; what is pure (paths, labels, defaults, guards, the summary JSON) is ported as
// free functions and is fully testable without an engine.

// ---- Transport ----

enum class Transport {
    Masque,
    WireGuard,
};

// "wg", "wireguard" and "warp" (any case, any padding) pick WireGuard; everything else picks
// Masque, the way the CLI's --transport falls back rather than refusing a name.
[[nodiscard]] Transport parse_transport(std::string_view raw);
[[nodiscard]] std::string_view transport_label(Transport transport);
[[nodiscard]] std::uint16_t transport_assigned_port(Transport transport);
[[nodiscard]] const std::vector<std::uint16_t>& transport_default_ports(Transport transport);

// ---- Errors ----

// The error vocabulary of error.rs that api.rs can raise or pass on. `message` is the text the
// Rust carries inside the variant; to_string() is Rust's Display, prefix and all, which is what
// the log lines and the CLI print.
enum class ErrorKind {
    Io,
    Quic,
    H3,
    Tls,
    Ech,
    Masque,
    NoCleanEndpoint,
    Capsule,
    Api,
    IdentityRefused,
    Cancelled,
    Other,
};

struct ApiError {
    ErrorKind kind = ErrorKind::Other;
    std::string message;

    [[nodiscard]] std::string to_string() const;
};

// api.rs raises this message itself; every other error the surface returns is the engine's,
// kinds assigned by the engine. tls.rs owns the wording, so this is the same constant, not a copy.
inline constexpr std::string_view NO_ECH_KEY = ::aether::core::NO_ECH_KEY;

// ---- Cancellation ----

// The watch flag of api.rs::Cancel: copies share one state, and cancelling is seen by
// everyone holding a copy.
class Cancel {
public:
    Cancel() : flag_(std::make_shared<std::atomic<bool>>(false)) {}

    void cancel() const { flag_->store(true); }
    [[nodiscard]] bool is_cancelled() const { return flag_->load(); }

private:
    std::shared_ptr<std::atomic<bool>> flag_;
};

// api.rs::guard. Rust races the work against the flag, `biased` so a flag already raised beats
// any work that could finish later, and work that finishes first is not treated as cancelled.
// C++ work is synchronous, so the mid-flight half of that race is the engine's: every engine
// method is handed the Cancel and must return the Cancelled error itself once it sees the flag.
// This is the module's only cancellation divergence and it changes no outcome the Rust can show.
template <class T>
[[nodiscard]] std::expected<T, ApiError> guard(
    const Cancel& cancel, const std::function<std::expected<T, ApiError>(const Cancel&)>& work) {
    if (cancel.is_cancelled()) {
        return std::unexpected(ApiError{ErrorKind::Cancelled, {}});
    }
    return work(cancel);
}

// ---- Logging ----

// api.rs logs through the Rust log crate; the port hands every line to the engine so the
// supervisor keeps one sink. No line ever carries key material.
enum class LogLevel {
    Info,
    Warn,
    Debug,
};

// ---- Scan knobs (prober.rs / wg_prober.rs, ported because api.rs parses them) ----

enum class IpScan {
    V4,
    V6,
    Both,
};

[[nodiscard]] IpScan parse_ip_scan(std::string_view raw);
[[nodiscard]] std::string_view ip_scan_label(IpScan ip);
[[nodiscard]] bool ip_scan_want_v4(IpScan ip);
[[nodiscard]] bool ip_scan_want_v6(IpScan ip);

enum class ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Verified,
    Ironclad,
};

[[nodiscard]] ScanMode parse_scan_mode(std::string_view raw);
[[nodiscard]] std::string_view scan_mode_label(ScanMode mode);

enum class WgScanMode {
    Turbo,
    Balanced,
    Thorough,
    Verified,
    Ironclad,
};

[[nodiscard]] WgScanMode parse_wg_scan_mode(std::string_view raw);
[[nodiscard]] std::string_view wg_scan_mode_label(WgScanMode mode);

// ---- Zero trust teams (the pure half of zerotrust.rs that api.rs calls) ----

[[nodiscard]] std::optional<std::string> normalize_team(std::string_view raw);
[[nodiscard]] std::string team_domain(std::string_view team);

// zerotrust.rs::TeamSettings.
struct TeamSettings {
    std::string team;
    std::optional<std::string> client_id;
    std::optional<std::string> client_secret;
    std::optional<std::string> token;
    std::optional<std::string> email;

    [[nodiscard]] bool has_service_token() const;
    [[nodiscard]] std::string team_domain() const;
    [[nodiscard]] std::string login_url() const;
};

// api.rs::TeamCredentials. `client_secret` and `token` are key material: never log them, never
// put them in a summary -- the Rust carries them and shows nothing.
struct TeamCredentials {
    TeamSettings settings;

    // TeamCredentials::new: a team name normalized now or refused with the Api error
    // "'{raw}' is not a usable zero trust team name".
    [[nodiscard]] static std::expected<TeamCredentials, ApiError> make(std::string_view raw);

    [[nodiscard]] TeamCredentials with_service_token(std::string_view client_id,
                                                     std::string_view client_secret) const;
    [[nodiscard]] TeamCredentials with_token(std::string_view token) const;
    [[nodiscard]] TeamCredentials with_email(std::string_view email) const;
    [[nodiscard]] std::string login_url() const;
};

// ---- Addresses ----

struct SocketAddr {
    IpAddress ip{};
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const SocketAddr&) const = default;
};

// IpAddr/SocketAddr as Rust's Display writes them: dotted quads, and lower-case IPv6 with the
// longest run of zero groups folded to "::", bracketed inside an address:port.
[[nodiscard]] std::string address_text(const IpAddress& ip);
[[nodiscard]] std::string socket_text(const SocketAddr& addr);

// ---- Requests and summaries ----

// api.rs::ProvisionRequest.
struct ProvisionRequest {
    std::string model{std::string(DEFAULT_MODEL)};
    std::string locale{std::string(DEFAULT_LOCALE)};
    std::optional<TeamCredentials> team;
    bool masque_cert = false;

    [[nodiscard]] static ProvisionRequest for_transport(Transport transport);
    [[nodiscard]] ProvisionRequest in_team(TeamCredentials credentials) const;
};

// api.rs::IdentitySummary -- the identity minus its secrets, so a caller can show an account
// without ever touching a certificate, a private key or a token: those appear here only as
// presence (has_masque_cert) and an issue time.
struct IdentitySummary {
    std::string device_id;
    std::string ipv4;
    std::string ipv6;
    std::string organization;
    std::string gateway_proxy;
    std::string assigned_endpoint;
    bool has_masque_cert = false;
    std::uint64_t cert_issued_at = 0;
    bool cert_usable = false;

    [[nodiscard]] static IdentitySummary of(const Identity& identity);
    // The serde shape: these field names, and nothing else.
    [[nodiscard]] json::Value to_json() const;
};

// api.rs::Endpoint.
struct Endpoint {
    IpAddress ip{};
    std::uint16_t port = 0;
    std::uint64_t rtt_ms = 0;

    [[nodiscard]] SocketAddr socket() const;
    // The serde shape: ip as its display text, port and rtt_ms as numbers.
    [[nodiscard]] json::Value to_json() const;
};

// account.rs::MasqueEnrollment, the engine's hand-back after a certificate enrolment. The two
// PEM blocks are key material.
struct MasqueEnrollment {
    std::string cert_pem;
    std::string key_pem;
    std::uint64_t issued_at = 0;
    bool renewed = false;
};

// What api.rs::scan builds for prober::MasqueProbe; the engine reads it and does the hunting.
struct MasqueProbe {
    std::string sni;
    std::string authority;
    std::string path;
    std::string cert_pem; // key material: never log, never echo
    std::string key_pem;  // key material: never log, never echo
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    noize::NoizeConfig noise;
    std::vector<std::uint16_t> ports;
    IpScan ip = IpScan::V4;
    IpAddress local_ipv4{};
};

// What api.rs::scan builds for wg_prober::WgProbe.
struct WgProbe {
    std::array<std::uint8_t, 32> private_key{}; // key material: never log, never echo
    std::array<std::uint8_t, 32> peer_public_key{};
    std::array<std::uint8_t, 3> client_id{};
    IpAddress local_ipv4{};
    aethernoize::AetherNoizeConfig noise;
    std::vector<std::uint16_t> ports;
    IpScan ip = IpScan::V4;
    std::vector<SocketAddr> excluded;
};

// What api.rs::verify_endpoint builds for wireguard::verify_endpoint.
struct WgVerifyParams {
    SocketAddr peer{};
    std::array<std::uint8_t, 32> private_key{}; // key material: never log, never echo
    std::array<std::uint8_t, 32> peer_public_key{};
    std::array<std::uint8_t, 3> client_id{};
    IpAddress local_ipv4{};
    aethernoize::AetherNoizeConfig noise;
    std::chrono::milliseconds verify_timeout{10000};
    std::uint16_t keepalive = 5; // Rust passes Some(keepalive): the check keeps the tunnel too
};

// api.rs::ScanRequest.
struct ScanRequest {
    Transport transport = Transport::Masque;
    std::string mode = "balanced";
    IpScan ip = IpScan::V4;
    std::vector<std::uint16_t> ports;
    std::vector<SocketAddr> excluded;
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    noize::NoizeConfig noise;
    aethernoize::AetherNoizeConfig aethernoize;

    [[nodiscard]] static ScanRequest for_transport(Transport transport);
    [[nodiscard]] ScanRequest with_mode(std::string_view new_mode) const;
    [[nodiscard]] ScanRequest with_ip(IpScan new_ip) const;
    // Both noise dialects, as the Rust does: the profile names each module's own shape.
    [[nodiscard]] ScanRequest with_profile(std::string_view profile) const;
};

// api.rs::TunnelSpec.
struct TunnelSpec {
    Transport transport = Transport::Masque;
    SocketAddr socks{};
    std::optional<SocketAddr> http;
    // The ECH key the MASQUE handshakes of the job offer -- the tunnel's and the check's; with
    // none the server name goes out in the clear.
    std::optional<std::vector<std::uint8_t>> ech;
    aethernoize::AetherNoizeConfig aethernoize;
    std::uint16_t keepalive = 5;
    std::chrono::milliseconds verify_timeout{10000};

    [[nodiscard]] static TunnelSpec for_transport(Transport transport);
    [[nodiscard]] TunnelSpec with_socks(SocketAddr listen) const;
    [[nodiscard]] TunnelSpec with_http(SocketAddr listen) const;
    [[nodiscard]] TunnelSpec with_profile(std::string_view profile) const;
};

// ---- Email sign-in (zerotrust.rs::EmailSignIn, as far as api.rs uses it) ----

// The session handle api.rs hands back: the visible fields are the Rust's accessors, and
// `handle` is where the engine keeps its own client and state.
struct EmailSession {
    std::string team;
    std::string email;
    std::string nonce;
    std::string verify_url;
    std::uint64_t handle = 0;
};

// zerotrust.rs::CodeOutcome.
struct CodeOutcome {
    bool accepted = false;
    std::string token;       // set when accepted; key material: never log
    std::uint16_t status = 0; // set when rejected
};

// ---- The engine ----

// Everything api.rs reaches through tokio, sockets and the account API. The supervisor
// implements this; the port adds no behaviour beyond shaping the arguments, applying the guard
// and writing the log lines the Rust writes.
class Engine {
public:
    virtual ~Engine() = default;

    // Every log line api.rs writes, at the level it writes it.
    virtual void log(LogLevel level, const std::string& line) = 0;

    // -- account.rs --
    // provision_wg is called with no jwt, exactly as api.rs does.
    [[nodiscard]] virtual std::expected<Identity, ApiError> provision_wg(
        const std::string& model, const std::string& locale) = 0;
    [[nodiscard]] virtual std::expected<Identity, ApiError> provision_team(
        const std::string& model, const std::string& locale, const TeamSettings& team) = 0;
    // refresh_profile never fails in Rust (it keeps the identity it was handed).
    [[nodiscard]] virtual Identity refresh_profile(Identity identity) = 0;
    [[nodiscard]] virtual std::expected<MasqueEnrollment, ApiError> ensure_masque_enrolled(
        const Identity& identity) = 0;

    // -- zerotrust.rs: token cache, sign-in, email code --
    [[nodiscard]] virtual std::expected<std::string, ApiError> resolve_token(
        const TeamSettings& team) = 0;
    [[nodiscard]] virtual std::expected<EmailSession, ApiError> begin_email_signin(
        const TeamSettings& team, std::string_view email) = 0;
    [[nodiscard]] virtual std::expected<void, ApiError> resend_code(EmailSession& session) = 0;
    [[nodiscard]] virtual std::expected<CodeOutcome, ApiError> submit_code(
        const EmailSession& session, std::string_view code) = 0;
    [[nodiscard]] virtual std::expected<void, ApiError> store_token(std::string_view token) = 0;
    [[nodiscard]] virtual std::optional<std::string> cached_token() = 0;
    virtual void clear_token() = 0;

    // -- prober.rs / wg_prober.rs: the gateway hunt; cancel must be honoured --
    [[nodiscard]] virtual std::expected<Endpoint, ApiError> hunt_masque_gateway(
        const MasqueProbe& probe, ScanMode mode, const Cancel& cancel) = 0;
    [[nodiscard]] virtual std::expected<Endpoint, ApiError> hunt_wireguard_gateway(
        const WgProbe& probe, WgScanMode mode, const Cancel& cancel) = 0;

    // -- lib.rs / wireguard.rs: the check and the run loops; cancel must be honoured --
    // quick_verify_masque_peer answers with a plain bool in Rust (a failed check is not an
    // error), on the carrier the session uses.
    [[nodiscard]] virtual bool quick_verify_masque_peer(
        const Identity& identity, const SocketAddr& peer,
        const std::optional<std::vector<std::uint8_t>>& ech) = 0;
    [[nodiscard]] virtual std::expected<void, ApiError> verify_wireguard_endpoint(
        const WgVerifyParams& params) = 0;
    [[nodiscard]] virtual std::expected<void, ApiError> run_masque_tunnel(
        const Identity& identity, const SocketAddr& peer,
        std::optional<std::vector<std::uint8_t>> ech, const SocketAddr& socks,
        const Cancel& cancel) = 0;
    [[nodiscard]] virtual std::expected<void, ApiError> run_wireguard_tunnel(
        const Identity& identity, const SocketAddr& peer,
        const aethernoize::AetherNoizeConfig& noise, const SocketAddr& socks,
        const Cancel& cancel) = 0;
};

// ---- Paths ----

// api.rs::identity_path: team accounts live beside the base file under a team-<name> suffix;
// with no team, MASQUE lives beside it under masque and WireGuard keeps the base file itself.
[[nodiscard]] std::string identity_path(std::string_view base, Transport transport,
                                        std::optional<std::string_view> team);

// api.rs::lastconn_path = lib.rs::lastconn_path: the sibling file with the lastconn suffix.
[[nodiscard]] std::string lastconn_path(std::string_view path);

// api.rs::load_identity / save_identity over config.rs. Errors come back as Other.
[[nodiscard]] std::expected<std::optional<Identity>, ApiError> load_identity(
    const std::string& path);
[[nodiscard]] std::expected<void, ApiError> save_identity(const std::string& path,
                                                          const Identity& identity);

// ---- Identity lifecycle ----

// api.rs::provision_identity / refresh_identity / attach_masque_cert / open_identity.
[[nodiscard]] std::expected<Identity, ApiError> provision_identity(Engine& engine,
                                                                   const ProvisionRequest& request);
[[nodiscard]] Identity refresh_identity(Engine& engine, Identity identity);
[[nodiscard]] std::expected<Identity, ApiError> attach_masque_cert(Engine& engine,
                                                                   Identity identity);
[[nodiscard]] std::expected<Identity, ApiError> open_identity(Engine& engine, const std::string& path,
                                                              const ProvisionRequest& request);

// ---- Team sign-in ----

// api.rs::team_sign_in / team_email_code_request / team_email_code_resend /
// team_email_code_submit / team_use_token / team_current_token / team_forget_token.
[[nodiscard]] std::expected<std::string, ApiError> team_sign_in(Engine& engine,
                                                                const TeamCredentials& credentials);
[[nodiscard]] std::expected<EmailSession, ApiError> team_email_code_request(
    Engine& engine, const TeamCredentials& credentials, std::string_view email);
[[nodiscard]] std::expected<void, ApiError> team_email_code_resend(Engine& engine,
                                                                  EmailSession& session);
// Some(token) once stored, nothing when the code was rejected -- with the Rust's warn line.
[[nodiscard]] std::expected<std::optional<std::string>, ApiError> team_email_code_submit(
    Engine& engine, const EmailSession& session, std::string_view code);
[[nodiscard]] std::expected<void, ApiError> team_use_token(Engine& engine, std::string_view token);
[[nodiscard]] std::optional<std::string> team_current_token(Engine& engine);
void team_forget_token(Engine& engine);

// ---- ECH ----

// api.rs::fetch_ech_config: the key of a job that asks for ECH, found by the --ech-dns and
// --ech-domain lookup the settings name, asked over `transport` (the resolver is the engine's,
// as the Rust's socket is). With no key BoringSSL can offer, an error that says NO_ECH_KEY and
// why, and the job goes no further: going on without ECH would send the server name in the
// clear.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, ApiError> fetch_ech_config(
    const Settings& settings, const EchTransport& transport);

// ---- Scanning, verifying, connecting ----

[[nodiscard]] std::expected<Endpoint, ApiError> scan(Engine& engine, const Identity& identity,
                                                     const ScanRequest& request,
                                                     const Cancel& cancel);

// The check of api.rs::verify_endpoint: with WireGuard a failed check is an answer (false),
// not an error -- unless the job was cancelled, which always travels up.
[[nodiscard]] std::expected<bool, ApiError> verify_endpoint(Engine& engine,
                                                            const Identity& identity,
                                                            const SocketAddr& peer,
                                                            const TunnelSpec& spec,
                                                            const Cancel& cancel);

// api.rs::connect: AETHER_HTTP_PROXY is set (or removed) for the whole process first, then the
// run loop goes on until it ends or the job is cancelled.
[[nodiscard]] std::expected<void, ApiError> connect(Engine& engine, const Identity& identity,
                                                    const SocketAddr& peer, const TunnelSpec& spec,
                                                    const Cancel& cancel);

} // namespace aether::core::localapi
