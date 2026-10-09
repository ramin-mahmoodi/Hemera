#pragma once

// Port of hemera/src/upstream.rs: the proxy HEMERA_UPSTREAM names (--upstream writes the same
// setting), read the way the Rust core reads it, and the pure half of every conversation held
// with that proxy. Live sockets, tasks and the udp detour table stay with the engine, which
// builds on the decisions and byte codecs that are here.

#include "dns.hpp"      // IpAddress, parse_address
#include "settings.hpp" // Settings, trim

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace hemera::core::upstream {

// The socks5 wire constants (RFC 1928, with RFC 1929's password negotiation).
inline constexpr std::uint8_t VER = 0x05;
inline constexpr std::uint8_t AUTH_NONE = 0x00;
inline constexpr std::uint8_t AUTH_USERPASS = 0x02;
inline constexpr std::uint8_t AUTH_REJECTED = 0xff;
inline constexpr std::uint8_t CMD_CONNECT = 0x01;
inline constexpr std::uint8_t CMD_ASSOCIATE = 0x03;
inline constexpr std::uint8_t ATYP_V4 = 0x01;
inline constexpr std::uint8_t ATYP_NAME = 0x03;
inline constexpr std::uint8_t ATYP_V6 = 0x04;
inline constexpr std::uint8_t REP_OK = 0x00;
// RFC 1929's version byte. Rust writes it inline at the request and the answer check; the two
// have to say the same number, so it is named once here.
inline constexpr std::uint8_t USERPASS_VERSION = 0x01;

// HANDSHAKE_TIMEOUT, Duration::from_secs(10): the time one socks5 greeting or http CONNECT
// handshake gets before the attempt is abandoned.
inline constexpr int HANDSHAKE_TIMEOUT_MS = 10000;
// A socks5 user and password are each length-prefixed by one byte, and so is a domain target
// (RFC 1928, 4-5 and RFC 1929).
inline constexpr std::size_t MAX_SOCKS_CREDENTIAL_LEN = 255;
inline constexpr std::size_t MAX_SOCKS_NAME_LEN = 255;
// The head of an http CONNECT answer is refused once it passes this many bytes.
inline constexpr std::size_t MAX_HTTP_CONNECT_HEAD = 8192;

// What recv_from of the udp relay buffers: max(out, 2048) + 512, as Rust sizes it.
[[nodiscard]] inline constexpr std::size_t relay_read_len(std::size_t out) {
    return (out < 2048 ? 2048 : out) + 512;
}
// The datagram buffer the detour pump reads into, both ways.
inline constexpr std::size_t DETOUR_PUMP_BUFFER_LEN = 65535;

// The two answers the CONNECT read loop turns into errors before any status is parsed; the
// engine's loop compares against these, so the strings live with the check.
inline constexpr std::string_view HTTP_OVERSIZED_ANSWER =
    "the upstream proxy sent an oversized answer";
inline constexpr std::string_view HTTP_CLOSED_BEFORE_ANSWER =
    "the upstream proxy closed before answering the connect";

enum class Kind {
    Socks5,
    Http,
};

// As the log names it: "socks5" or "http".
[[nodiscard]] std::string_view label(Kind kind);

// An address with a port: either a resolved IP, or the host text as it was written. Rust holds
// a SocketAddr where the IP is known and a plain string elsewhere; one carrier per half here.
struct SocketTarget {
    std::string host;                  // set when the name has not been resolved
    std::optional<IpAddress> ip;       // set when the address is known
    std::uint16_t port = 0;

    [[nodiscard]] bool operator==(const SocketTarget&) const = default;
};

// The proxy a setting names. `display()` is the only whole-object text there is: like Rust's
// Debug, it keeps the user visible and replaces the password with "<redacted>", so no log line
// or error built from it can carry the secret.
class Upstream {
public:
    Kind kind = Kind::Socks5;
    std::string host;                  // written without brackets, even when it is an IPv6 one
    std::uint16_t port = 0;
    std::optional<std::string> user;   // percent-decoded out of the URL
    std::optional<std::string> password;

    [[nodiscard]] bool operator==(const Upstream&) const = default;

    // The proxy `raw` names: a bare host:port is taken as socks5; the schemes socks5, socks5h
    // and socks all mean socks5, and http and https mean http (an https:// upstream is talked
    // to over plain http, and refused outright when it carries a password). Credentials sit
    // before the last '@' of the rest, split user-first at its first ':'; both halves are
    // percent-decoded. The endpoint keeps the brackets of an IPv6 host, needs a port — Rust
    // defaults none, a missing port is refused — and must not be empty or end in port 0.
    // Any warning the parse carries (the https one) is appended to `notes`.
    [[nodiscard]] static std::expected<Upstream, std::string> parse(std::string_view raw,
                                                                    std::vector<std::string>& notes);
    [[nodiscard]] static std::expected<Upstream, std::string> parse(std::string_view raw);

    // host:port as written, brackets and all — which is what Rust's format does; the text of
    // the timeout messages.
    [[nodiscard]] std::string endpoint() const;

    // The proxy for an HTTP client: socks5h (names resolved by the proxy, never locally) or
    // http, bracketing an IPv6 host. No credentials ride in the URL; basic auth comes from
    // user and password separately, which is what Rust's as_reqwest_proxy layering does.
    [[nodiscard]] std::string url() const;

    // The proxy as psiphon's UpstreamProxyURL takes it: socks5 or http, with any credentials
    // percent-encoded back into the address.
    [[nodiscard]] std::string psiphon_url() const;

    // The address tor can dial through: only a socks5 proxy at an IP address and without a
    // user — a name for tor to not-resolve and a password tor cannot send are both refused.
    [[nodiscard]] std::optional<SocketTarget> socks_address() const;

    // Whether the socks5 greeting should offer the password method: Rust keys it on the user
    // being present, whatever the password holds.
    [[nodiscard]] bool wants_auth() const { return user.has_value(); }

    // The "Proxy-Authorization: Basic …\r\n" line Rust's CONNECT writes when there is a user,
    // the password standing empty when the URL gave none; nothing when there is no user. The
    // token is base64 of "user:password" as stored, which is what the wire carries; this is
    // not a display path and does not redact.
    [[nodiscard]] std::optional<std::string> proxy_authorization() const;

    // The redacted debug text, field for field as Rust formats it.
    [[nodiscard]] std::string display() const;
};

// The proxy `raw` names, announced in `notes` the way Rust logs it: "[+] dialling out through
// the {} proxy at {}:{}" when it parses, "[-] the upstream proxy setting was ignored: {error}"
// when it does not, and nothing at all when the setting is blank.
[[nodiscard]] std::optional<Upstream> from_value(std::string_view raw,
                                                 std::vector<std::string>& notes);

// The last setting read and the proxy parsed for it; the cache Rust's configured() keeps.
using Seen = std::optional<std::pair<std::string, std::optional<Upstream>>>;

// The proxy `raw` names, parsed and announced — but only when it differs from what `seen` last
// holds. A setting is parsed, and announced, only when it changes.
[[nodiscard]] std::optional<Upstream> remembered(Seen& seen, std::string_view raw,
                                                 std::vector<std::string>& notes);

// HEMERA_UPSTREAM looked up on every call, behind a process-wide memo of the last answer —
// Rust's configured(). --upstream writes the same setting through apply_cli().
[[nodiscard]] std::optional<Upstream> configured(const Settings& settings,
                                                 std::vector<std::string>& notes);

// HEMERA_UPSTREAM parsed with no memo, which is Rust's from_env(); no setting at all answers
// without a note, blank answers nothing.
[[nodiscard]] std::optional<Upstream> from_settings(const Settings& settings,
                                                    std::vector<std::string>& notes);

// host and port, brackets read for an IPv6 host; the error names the endpoint, which sits past
// the last '@' of a URL, so it never carries credentials.
[[nodiscard]] std::expected<SocketTarget, std::string> split_endpoint(std::string_view endpoint);

// The selection rule Rust's attach_detour_via writes: a local peer is reached without the
// upstream proxy, so the detour never dials for it. It is routing::is_private by another name.
[[nodiscard]] bool bypasses_upstream(const IpAddress& peer);

// What a handshake that ran past HANDSHAKE_TIMEOUT becomes; `endpoint()` of the proxy is in
// both, so neither can carry a credential.
[[nodiscard]] std::string connect_timed_out(const Upstream& proxy);
[[nodiscard]] std::string relay_timed_out(const Upstream& proxy);

// The socks5 greeting: version, one method, and the method the credentials ask for.
[[nodiscard]] std::vector<std::uint8_t> greet_request(bool wants_auth);

// The two-byte method answer. An AUTH_NONE while credentials are configured is refused — the
// proxy quietly dropping authentication is not a path a secret should go down unauthenticated.
// An AUTH_USERPASS answer says go on and authenticate; anything else names itself in the
// error. A short answer is a deviation: Rust's read_exact turns it into an io error.
[[nodiscard]] std::expected<void, std::string> check_greeting(bool wants_auth,
                                                              std::span<const std::uint8_t> answer);

// The RFC 1929 login message: version 1, one-byte length, user, one-byte length, password.
// Missing halves are sent empty, as Rust's unwrap_or_default does; over 255 bytes of either is
// refused rather than truncated.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string>
authenticate_request(const std::optional<std::string>& user,
                     const std::optional<std::string>& password);

// The two-byte login answer: the wrong version says so, anything but status 0 refused the
// credentials without a reason past that — and never one back about what was sent.
[[nodiscard]] std::expected<void, std::string> check_auth_answer(std::span<const std::uint8_t> answer);

// The four-byte head of a socks5 reply: the version, the refusal code, and an address type
// hemera can read; the type comes back so the engine knows how many bytes follow.
[[nodiscard]] std::expected<std::uint8_t, std::string>
check_reply_head(std::span<const std::uint8_t> head);

// [atyp, address, port in network order] for an IP target; 4+4+2 for v4 and 4+16+2 for v6.
[[nodiscard]] std::vector<std::uint8_t> encode_address(const SocketTarget& target);

// VER, command, reserved 0, then the address.
[[nodiscard]] std::vector<std::uint8_t> encode_request(std::uint8_t command,
                                                       const SocketTarget& target);

// The same asking a name to be resolved by the proxy: VER, command, 0, ATYP_NAME, one-byte
// length, name, port. An empty name or one past 255 bytes is refused rather than guessed at.
[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string>
encode_name_request(std::uint8_t command, std::string_view name, std::uint16_t port);

// A datagram's socks5 UDP frame: three zero bytes, then the address.
[[nodiscard]] std::vector<std::uint8_t> encode_udp_header(const SocketTarget& target);

// The same read back: the origin and the offset its payload starts at. A header with the
// reserved byte set, too short, of an unknown type, or whose domain name is no IP address or
// no valid UTF-8, answers nothing — never a panic.
[[nodiscard]] std::optional<std::pair<SocketTarget, std::size_t>>
decode_udp_header(std::span<const std::uint8_t> buf);

// A name the socks5 relay replied with instead of an address has to be looked up; that is the
// engine's, and this says when it is needed and where.
struct HostLookup {
    std::string host;
    std::uint16_t port = 0;
    [[nodiscard]] bool operator==(const HostLookup&) const = default;
};

// Rust's relay_address: the reply stands when it holds a real address and port, otherwise the
// relay sits at the proxy's own host with the port the reply gave when it had one; a proxy
// named by host, not address, is what comes back for lookup.
[[nodiscard]] std::variant<SocketTarget, HostLookup>
relay_address(const SocketTarget& bound, std::string_view proxy_host, std::uint16_t proxy_port);

// Whether a datagram reached the shim from the socket the detour was put on: the port has to
// match the client's own, and the source either be the client's address itself or a loopback
// one behind a wildcard-bound client.
[[nodiscard]] bool from_detoured_socket(const SocketTarget& client, const SocketTarget& origin);

// A sockaddr_storage as an IpAddress, the address half of a recvfrom. The family decides
// between the four bytes of v4 and the sixteen of v6; anything else answers nothing.
[[nodiscard]] std::optional<IpAddress> sockaddr_to_ip(const sockaddr_storage& storage);

// ---------------------------------------------------------------------------
// The UDP relay: upstream.rs:440-498, 556-608.
//
// A socks5 ASSOCIATE opens a relay at the proxy; every datagram the shim sends is framed with
// encode_udp_header and goes to that relay, and every framed answer is unframed and handed to
// the last sender. The engine owns the sockets and the pump thread; what is here is the
// handshake and the two codecs, so the engine's loop is the only loop.
// ---------------------------------------------------------------------------

// One datagram through the relay: the framed bytes to send, or the payload and where it came
// from. The relay is a socks5 one; an http proxy has no UDP relay and refuses at parse time.
struct RelayDatagram {
    std::vector<std::uint8_t> framed; // encode_udp_header(target) + payload
    SocketTarget target;              // who the payload is really for
};

// upstream.rs:440-470: the ASSOCIATE handshake. The greeting and the login are the same two
// exchanges every other socks5 path makes; what is relay-specific is CMD_ASSOCIATE and the
// reply's address, which is where the relay lives. A proxy that answers a name is a HostLookup
// for the engine to resolve, exactly as relay_address says.
[[nodiscard]] std::expected<std::variant<SocketTarget, HostLookup>, std::string>
associate(const Upstream& proxy, std::chrono::milliseconds timeout);

// upstream.rs:472-498: one datagram out through the relay. The frame is the socks5 UDP header
// for `target` in front of the payload; the caller sends the whole thing to the relay's address.
[[nodiscard]] RelayDatagram relay_send(const SocketTarget& target,
                                      std::span<const std::uint8_t> payload);

// upstream.rs:480-498: one datagram back. The frame is stripped, the origin and the offset of
// the payload come back, and a frame that is not a socks5 UDP header answers nothing.
[[nodiscard]] std::optional<std::pair<SocketTarget, std::size_t>>
relay_receive(std::span<const std::uint8_t> buf);

// ---------------------------------------------------------------------------
// The detour table: upstream.rs:500-544.
//
// One entry per socket the engine put behind the upstream proxy's UDP relay, keyed by the address
// that socket is bound to. The table is what makes relay_target more than a name: a socket bound
// directly answers "the peer itself" forever, and it is only a detour's shim that a later send has
// to be re-aimed at. The engine's bind_via_upstream (upstream.rs:610-625) records the shim here
// between raising the relay and connecting to it, which is upstream.rs:584-593's insert, and the
// DetourGuard's Drop / the pump's end remove it again through forget_detour.
//
// What is deliberately not here: DetourGuard (upstream.rs:506-517) and attach_detour_via's
// associate-and-pump (:556-608), because a guard owns a task handle and this module owns no
// threads; and real_source (:546-554), the read direction's inverse — it maps an observed source
// back to the peer it stands for, and the engine that receives on the shim is the only caller.

// upstream.rs:500-504: the relay endpoint the socket's traffic is really handed to, the peer it was
// meant for, and the id that tells this detour from the next one opened on the same client address.
struct Detour {
    std::uint64_t id = 0;
    SocketAddr shim;
    SocketAddr peer;
};

// upstream.rs:527-530: ids start at 1 and never repeat, atomic and relaxed exactly like Rust's
// AtomicU64 static.
[[nodiscard]] std::uint64_t next_detour_id();

// upstream.rs:584-593: one detour per client address, and a later insert replaces the earlier, which
// is what Rust's map.insert does. Rust wraps it in `if let Ok(mut map)`, which can only fail on a
// poisoned lock; std::mutex has no poisoned state, so there is no skipped insert here.
void remember_detour(const SocketAddr& client, const Detour& detour);

// upstream.rs:519-525: the entry goes only while it is still this id's, which is what stops a stale
// guard from closing a detour that has already been re-attached to the same client address.
void forget_detour(const SocketAddr& client, std::uint64_t id);

// upstream.rs:539-544 — where a packet leaving the socket bound to `local` truly goes: the detour's
// shim when that socket is behind the proxy's relay, and `intended` itself when it is not, which is
// Rust's `map(...).unwrap_or(intended)`. No proxy configured means no entry means the peer, so the
// direct path is the table's empty answer rather than a special case.
//
// The shape is transport.hpp's relay seam (transport.hpp:341-344) — `SocketAddr(const SocketAddr&
// local, const SocketAddr& peer)` — so a host with upstream support binds it with one statement, and
// every UdpIo send, quic.rs's flush included, then asks the same table the Rust does.
[[nodiscard]] SocketAddr relay_target(const SocketAddr& local, const SocketAddr& intended);

// ---------------------------------------------------------------------------
// bind_via_upstream + attach_detour: upstream.rs:556-625.
//
// The engine's detour: a wildcard-bound shim socket, a socks5 ASSOCIATE relay at the proxy, and
// a pump thread that forwards datagrams both ways. The shim is registered in the detour table
// between the relay coming up and the socket connecting to it, so every send through the socket
// is re-aimed at the shim by relay_target. The guard's Drop and the pump's end both call
// forget_detour, and the id test in forget_detour is what stops a stale guard from closing a
// detour that has already been re-attached.
// ---------------------------------------------------------------------------

// A live detour: the shim socket, the relay address, the pump thread, and the id. The guard
// owns the thread and joins it on destruction; the id is what forget_detour checks.
class DetourGuard {
public:
    DetourGuard() = default;
    DetourGuard(SocketAddr client, std::uint64_t id, SocketAddr shim, SocketAddr relay,
                SocketTarget relay_target, std::thread pump,
                std::shared_ptr<std::atomic<bool>> stop);
    ~DetourGuard();

    // The stop flag is shared with the pump thread; the guard sets it before joining.
    [[nodiscard]] std::shared_ptr<std::atomic<bool>> stop_flag() const { return stop_; }

    DetourGuard(DetourGuard&& other) noexcept;
    DetourGuard& operator=(DetourGuard&& other) noexcept;
    DetourGuard(const DetourGuard&) = delete;
    DetourGuard& operator=(const DetourGuard&) = delete;

    [[nodiscard]] std::uint64_t id() const { return id_; }
    [[nodiscard]] const SocketAddr& shim() const { return shim_; }
    [[nodiscard]] const SocketAddr& relay() const { return relay_; }

private:
    void stop();

    SocketAddr client_{};
    std::uint64_t id_ = 0;
    SocketAddr shim_{};
    SocketAddr relay_{};
    SocketTarget relay_target_{};
    std::thread pump_;
    std::shared_ptr<std::atomic<bool>> stop_;
};

// upstream.rs:556-608: attach_detour_via. A local peer is reached without the upstream proxy
// (bypasses_upstream), so the detour never dials for it. Otherwise: ASSOCIATE, bind a loopback
// shim, register the detour, spawn the pump, and return the guard. The caller then connects
// the socket to relay_target(local, peer) and the detour is live.
[[nodiscard]] std::expected<DetourGuard, std::string> attach_detour(const Upstream& proxy,
                                                                   const SocketAddr& client,
                                                                   const SocketAddr& peer,
                                                                   bool client_is_v4);

// upstream.rs:610-625: bind_via_upstream. Binds a wildcard socket, attaches the detour, and
// connects the socket to the relay target. Returns the socket's local address, the connected
// target, and the guard. The caller owns the guard and must keep it alive as long as the
// socket is in use.
struct BoundSocket {
    SocketAddr local;
    SocketAddr target;
    DetourGuard guard;
};

[[nodiscard]] std::expected<BoundSocket, std::string> bind_via_upstream(const Upstream& proxy,
                                                                        const SocketAddr& peer);

// CONNECT, Host, Keep-Alive, the Proxy-Authorization line when the proxy has a user, and the
// empty line — the exact bytes Rust writes before reading the answer back.
[[nodiscard]] std::string connect_request(const Upstream& proxy, std::string_view authority);

// The status code of the answer's first line: a version token starting "HTTP/" and a status
// that reads as u16, or nothing.
[[nodiscard]] std::optional<std::uint16_t> http_status(std::span<const std::uint8_t> head);

// The read head judged: not http at all, or a status outside 200..300, or the status that
// means the tunnel is on.
[[nodiscard]] std::expected<std::uint16_t, std::string>
connect_answer(std::span<const std::uint8_t> head);

} // namespace hemera::core::upstream
