#pragma once

// Port of hemera/src/wireguard.rs (pinned commit 6175b67) and the boringtun-0.7 noise protocol
// surface it drives: the WireGuard message wire layout, the base64/hex key encodings the Rust
// uses, the pure handshake state machine (mac1/mac2, cookie rules, replay window, message
// counters, key rotation and retransmit timing), transport sealing/unsealing framing, and every
// constant a caller reads. The socket loop and the async verify_endpoint task stay in the engine;
// only the protocol is ported here.
//
// The one exception is the loop's three hemeranoize call sites (wireguard.rs:243-288 and :568-575),
// which are ported as the named helpers at the bottom of this header. They are the two latches and
// the send order -- the parts that are protocol-shaped and easy to get wrong -- lifted out of the
// loop rather than re-decided inside it; the engine's loop still owns the socket, the channels and
// the threads, and calls them where the Rust wrote the bare send.

#include <openssl/aead.h>
#include <openssl/curve25519.h>
#include <openssl/mem.h>

#include <array>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dns.hpp" // IpAddress, parse_address -- reused for the cookie's address bytes

// The noise dialect whose senders the three call sites below reach for. No cycle: hemeranoize.hpp
// reads dns.hpp and nothing that reads this header back.
#include "hemeranoize.hpp"

// transport.hpp's UdpIo, the socket the loop writes through. Forward-declared the way noize.hpp and
// hemeranoize.hpp do -- transport.hpp sits on the other side of quic.hpp, and the definition is only
// needed where the sends happen, in wireguard.cpp.
namespace hemera::core::transport {
struct UdpIo;
}

namespace hemera::core::wireguard {

// ---------------------------------------------------------------------------
// Key material and the base64/hex encodings the Rust uses.
// ---------------------------------------------------------------------------

// A WireGuard Curve25519 key: a static secret, a public key, or a preshared key. BoringSSL's
// X25519 scalar form is the same 32 little-endian bytes boringtun's StaticSecret uses.
using Key = std::array<std::uint8_t, 32>;
// The 3-byte client id wireguard.rs stamps into bytes 1..4 of every message.
using ClientId = std::array<std::uint8_t, 3>;

// The two forms a key string arrives in. boringtun's serialization.rs `KeyBytes::from_str` reads
// either, so a caller that is handed text has to tell them apart before decoding.
enum class KeyKind {
    Hex,    // 64 characters
    Base64, // 43 (unpadded) or 44 (padded) characters
};

[[nodiscard]] KeyKind classify_key(std::string_view text);

// `text` as a 32-byte key, exactly as serialization.rs `KeyBytes::from_str` reads it: 64 hex
// characters, or 43/44 base64 characters that decode to exactly 32 bytes. Anything else -- an odd
// hex length, a stray character, base64 of the wrong width, or any other length -- is refused as
// the Rust refuses it. Only `std::nullopt` is returned on failure; nothing throws out.
[[nodiscard]] std::optional<Key> parse_key(std::string_view text);

// A 32-byte key in the base64 form config.rs and account.rs persist it in, and the inverse of
// it read as strictly as config.rs `decode_fixed::<32>` does: standard alphabet with padding, a
// wrong length or an illegal character is refused, never quietly ignored.
[[nodiscard]] std::string encode_key_base64(const Key& key);
[[nodiscard]] std::optional<Key> decode_key_base64(std::string_view text);

// A 3-byte client id, base64-encoded and read back with the same strictness. config.rs reads it
// through `decode_fixed::<3>` and falls back to all-zero when it is absent or wrong.
[[nodiscard]] std::string encode_client_id_base64(const ClientId& id);
[[nodiscard]] std::optional<ClientId> decode_client_id_base64(std::string_view text);

// config.rs `From<&Identity>` -- an enrolled key pair plus its client id, as the account file
// keeps them. These names are the ones the persisted identity table uses.
[[nodiscard]] std::string wg_private_key_to_base64(const Key& key);
[[nodiscard]] std::string wg_peer_public_key_to_base64(const Key& key);

// The public key that belongs to a private key, the same StaticSecret -> PublicKey conversion the
// Rust performs on construction. This clamps the scalar exactly as BoringSSL's X25519 does.
[[nodiscard]] Key public_from_private(const Key& private_key);

// DH(static_private, peer_public). boringtun returns a SharedSecret whose 32 bytes go straight
// into the chaining HMAC; the all-zero result (cofactor/ladder guard) is kept, as Rust does.
[[nodiscard]] Key diffie_hellman(const Key& private_key, const Key& peer_public);

// b2s_hmac and b2s_hmac2, noise/handshake.rs:49: RFC 2104 HMAC over unkeyed BLAKE2s-256 (64-byte
// block). Public so the handshake's key schedule can be checked against HMAC vectors computed
// elsewhere -- an implementation that only ever agrees with itself proves nothing.
[[nodiscard]] Key b2s_hmac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data);
[[nodiscard]] Key b2s_hmac2(std::span<const std::uint8_t> key, std::span<const std::uint8_t> one,
                           std::span<const std::uint8_t> two);

// ---------------------------------------------------------------------------
// Errors. Every WireGuardError variant the Rust defines, mapped 1:1.
// ---------------------------------------------------------------------------

enum class WgError {
    DestinationBufferTooSmall,
    IncorrectPacketLength,
    UnexpectedPacket,
    WrongPacketType,
    WrongIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    LockFailed,
    ConnectionExpired,
    UnderLoad,
};

[[nodiscard]] std::string_view message(WgError error);

// ---------------------------------------------------------------------------
// The client-id obfuscation wireguard.rs applies on top of every message.
// ---------------------------------------------------------------------------

// Bytes 1..4 carry the 3-byte client id when, and only when, the leading byte is a known WG
// message type (1..4) and the packet is at least 4 bytes; every other branch leaves the buffer
// untouched, exactly as inject_client_id/strip_client_id decide.
void inject_client_id(std::span<std::uint8_t> packet, const ClientId& client_id);
void strip_client_id(std::span<std::uint8_t> packet);

// is_transient_socket_error: which socket failures keep the tunnel and which end it.
enum class SocketErrorKind {
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    HostUnreachable,
    NetworkUnreachable,
    Interrupted,
    WouldBlock,
    TimedOut,
    NotConnected,
    AddrNotAvailable,
    PermissionDenied,
    InvalidInput,
    Other,
};

[[nodiscard]] bool is_transient_socket_error(SocketErrorKind kind);

// ---------------------------------------------------------------------------
// Constants a caller reads. The wireguard.rs set first, then the noise timers.
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t timer_tick_ms = 250;
inline constexpr std::uint64_t verify_retry_delays_ms[] = {750, 2000};
inline constexpr std::uint32_t max_transient_recv_errors = 64;
inline constexpr std::uint64_t transient_recv_backoff_ms = 50;
inline constexpr std::size_t max_packet = 65536;
inline constexpr std::uint8_t wg_msg_type_min = 1;
inline constexpr std::uint8_t wg_msg_type_max = 4;

inline constexpr std::uint64_t wg_healthcheck_interval_ms = 3000;
inline constexpr std::uint64_t wg_healthcheck_jitter_ms = 500;
inline constexpr std::uint64_t wg_stale_default_secs = 10;
inline constexpr std::uint64_t wg_stale_max_secs = 86400;
inline constexpr std::uint32_t dataplane_required_successes = 2;
inline constexpr std::uint64_t dataplane_probe_gap_ms = 600;
inline constexpr std::uint64_t dataplane_resend_ms = 700;
inline constexpr std::uint16_t default_persistent_keepalive = 25;

// noise/timers.rs, in seconds: the WireGuard retransmit and key rotation rules.
inline constexpr std::uint64_t rekey_after_time_ms = 120'000;
inline constexpr std::uint64_t reject_after_time_ms = 180'000;
inline constexpr std::uint64_t rekey_attempt_time_ms = 90'000;
inline constexpr std::uint64_t rekey_timeout_ms = 5'000;
inline constexpr std::uint64_t keepalive_timeout_ms = 10'000;
inline constexpr std::uint64_t cookie_expiration_time_ms = 120'000;
// "REKEY_TIMEOUT + jitter, where jitter is some random value between 0 and 333 ms".
inline constexpr std::uint64_t handshake_retry_jitter_max_ms = 333;

// noise/mod.rs: session ring and queue sizes.
inline constexpr std::size_t n_sessions = 8;
inline constexpr std::size_t max_queue_depth = 256;
inline constexpr std::uint64_t peer_handshake_rate_limit = 10;

// noise/rate_limiter.rs: cookie sizing and the reset period. COOKIE_REFRESH is 128 not 120 so a
// division folds away; it is the rotation period of the server's changing secret.
inline constexpr std::uint64_t cookie_refresh_secs = 128;
inline constexpr std::size_t cookie_size = 16;
inline constexpr std::size_t cookie_nonce_size = 24;
inline constexpr std::uint64_t rate_limit_reset_period_secs = 1;

// noise/session.rs: the replay window is a 16-word bitmap, 64*16 = 1024 packets deep.
inline constexpr std::uint64_t replay_word_size = 64;
inline constexpr std::uint64_t replay_n_words = 16;
inline constexpr std::uint64_t replay_n_bits = replay_word_size * replay_n_words; // 1024

// noise/handshake.rs: the labels HASH and MAC are keyed by, and the tai64n epoch base.
inline constexpr std::string_view label_mac1 = "mac1----";
inline constexpr std::string_view label_cookie = "cookie--";
inline constexpr std::uint64_t tai64_base = (1ULL << 62) + 37;

// The Noise_IK initial chaining state, boringtun's INITIAL_CHAIN_KEY/HASH constants.
inline constexpr Key initial_chain_key = {
    96,  226, 109, 174, 243, 39,  239, 192, 46,  195, 53, 226, 160, 37,  210, 208,
    22,  235, 66,  6,   248, 114, 119, 245, 45,  56,  209, 152, 139, 120, 205, 54};
inline constexpr Key initial_chain_hash = {
    34,  17,  179, 97,  8,   26, 197, 102, 105, 18, 67,  219, 69,  138, 213, 50,
    45,  156, 108, 102, 34,  147, 232, 183, 14,  225, 156, 101, 186, 7,   158, 243};

// Message type numbers and exact wire sizes, from noise/mod.rs.
enum MessageType : std::uint32_t {
    handshake_init = 1,
    handshake_resp = 2,
    cookie_reply = 3,
    data = 4,
};

inline constexpr std::size_t handshake_init_size = 148;
inline constexpr std::size_t handshake_resp_size = 92;
inline constexpr std::size_t cookie_reply_size = 64;
inline constexpr std::size_t data_overhead_size = 32; // 16-byte header + 16-byte tag

// The zero-trust ingress ranges, ports and seeds wireguard.rs publishes for the prober. The
// prioritization (prober::prioritize) is a different module and is deliberately left there; only
// the raw constants and their parse checks are ported here.
inline constexpr std::string_view wg_prefixes_v4[] = {
    "162.159.192.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24",
    "188.114.98.0/24",  "188.114.99.0/24",  "162.159.193.0/24"};
inline constexpr std::string_view wg_prefixes_v6[] = {"2606:4700:d0::/64", "2606:4700:d1::/64",
                                                     "2606:4700:100::/48"};
inline constexpr std::string_view wg_zt_prefixes_v4[] = {"162.159.193.0/24"};
inline constexpr std::string_view wg_zt_prefixes_v6[] = {"2606:4700:100::/48"};
inline constexpr std::uint16_t wg_ports[] = {
    2408, 500,  1701, 4500, 854,  859,  864,  878,  880,  890,  891,  894,  903,  908,
    928,  934,  939,  942,  943,  945,  946,  955,  968,  987,  988,  1002, 1010, 1014,
    1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198,
    4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886};
inline constexpr std::string_view wg_seeds_v4[] = {"162.159.192.1", "162.159.195.1",
                                                   "188.114.96.1",  "188.114.97.1", "162.159.193.1"};
inline constexpr std::string_view wg_seeds_v6[] = {"2606:4700:d0::a29f:c001",
                                                  "2606:4700:d1::a29f:c001",
                                                  "2606:4700:d0::a29f:c301",
                                                  "2606:4700:d0::bc72:6001"};

[[nodiscard]] bool has_port(std::uint16_t port);
[[nodiscard]] bool prefix_parses(std::string_view cidr, bool v6);

// ---------------------------------------------------------------------------
// The dataplane probe wireguard.rs builds for its health task.
// ---------------------------------------------------------------------------

// build_dns_query: a fixed cloudflare.com A/IN question with a fresh transaction id.
[[nodiscard]] std::vector<std::uint8_t> build_dns_query(std::uint16_t id);
// ipv4_checksum: the one's-complement checksum of a header, exactly as the Rust folds it.
[[nodiscard]] std::uint16_t ipv4_checksum(std::span<const std::uint8_t> header);
// build_dataplane_probe: that query inside a UDP/IPv4 packet sourced from `src`.
[[nodiscard]] std::vector<std::uint8_t> build_dataplane_probe(const std::array<std::uint8_t, 4>& src,
                                                              std::uint16_t dns_id,
                                                              std::uint16_t ip_id,
                                                              std::uint16_t sport);
// health_check_pause: WG_HEALTHCHECK_INTERVAL +/- WG_HEALTHCHECK_JITTER, `offset` in
// 0..=2*jitter standing in for the RNG so the bounds are testable.
[[nodiscard]] std::uint64_t health_check_pause_ms(std::uint64_t offset);

// ---------------------------------------------------------------------------
// Wire message types and their exact byte layout.
// ---------------------------------------------------------------------------

// A tai64n timestamp: the 12 bytes the handshake encrypts, and the ordering rule the responder
// enforces against replays. parse reads big-endian seconds then nanoseconds, as Rust does.
struct Tai64N {
    std::uint64_t secs = 0;
    std::uint32_t nano = 0;

    [[nodiscard]] static std::optional<Tai64N> parse(std::span<const std::uint8_t> bytes);
    // Chronologically strictly after, matching Tai64N::after: greater seconds, or equal seconds
    // and greater nanoseconds.
    [[nodiscard]] bool after(const Tai64N& other) const;
};

struct HandshakeInitiation {
    std::uint32_t sender_index = 0;
    std::array<std::uint8_t, 32> unencrypted_ephemeral{};
    std::array<std::uint8_t, 48> encrypted_static{}; // 32-byte key + 16-byte tag
    std::array<std::uint8_t, 28> encrypted_timestamp{}; // 12-byte tai64n + 16-byte tag
};

struct HandshakeResponse {
    std::uint32_t sender_index = 0;
    std::uint32_t receiver_index = 0;
    std::array<std::uint8_t, 32> unencrypted_ephemeral{};
    std::array<std::uint8_t, 16> encrypted_nothing{};
};

struct CookieReply {
    std::uint32_t receiver_index = 0;
    std::array<std::uint8_t, 24> nonce{};
    std::array<std::uint8_t, 32> encrypted_cookie{}; // 16-byte cookie + 16-byte tag
};

struct TransportMessage {
    std::uint32_t receiver_index = 0;
    std::uint64_t counter = 0;
    std::vector<std::uint8_t> encrypted_payload; // ciphertext || 16-byte tag
};

// Every message on the wire, tagged by its type.
enum class PacketKind {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    Data,
};

struct Packet {
    PacketKind kind = PacketKind::HandshakeInit;
    HandshakeInitiation init;
    HandshakeResponse response;
    CookieReply cookie;
    TransportMessage data;
};

// parse_incoming_packet: reads the 4-byte little-endian type word -- which doubles as the
// reserved-zero check -- and requires the exact length per type, with data at 32 bytes or more.
// A truncated or oversized message is refused here, never sliced past the end.
[[nodiscard]] std::expected<Packet, WgError> parse_incoming_packet(
    std::span<const std::uint8_t> src);

[[nodiscard]] std::vector<std::uint8_t> serialize(const HandshakeInitiation& msg);
[[nodiscard]] std::vector<std::uint8_t> serialize(const HandshakeResponse& msg);
[[nodiscard]] std::vector<std::uint8_t> serialize(const CookieReply& msg);
[[nodiscard]] std::vector<std::uint8_t> serialize(const TransportMessage& msg);

// dst_address: the destination IP an encappedulated IP packet carries, nothing when it is empty
// or not a v4/v6 packet whose header is long enough to read.
[[nodiscard]] std::optional<IpAddress> dst_address(std::span<const std::uint8_t> packet);

// ---------------------------------------------------------------------------
// Transport session: sealing, unsealing and the replay window.
// ---------------------------------------------------------------------------

// ReceivingKeyCounterValidator, the out-of-order-tolerant replay bitmap. Exposed so the window
// rules -- duplicate, too-far-back, and out-of-order-in-window -- are testable in isolation.
struct ReplayWindow {
    std::uint64_t next = 0;
    std::uint64_t receive_cnt = 0;
    std::array<std::uint64_t, 16> bitmap{};

    // will_accept: true when the counter is not yet received and not too far back.
    [[nodiscard]] std::expected<void, WgError> will_accept(std::uint64_t counter) const;
    // mark_did_receive: accept and record it, shifting the window when it runs ahead.
    std::expected<void, WgError> mark_did_receive(std::uint64_t counter);
};

class Session {
public:
    Session(std::uint32_t local_index, std::uint32_t peer_index, const Key& receiving_key,
            const Key& sending_key);

    [[nodiscard]] std::uint32_t local_index() const { return receiving_index_; }
    [[nodiscard]] std::uint32_t peer_index() const { return sending_index_; }

    // format_packet_data: seal `plain` (an IP packet, or empty for a keepalive) into a transport
    // message under the sending key and counter. The destination must be roomy enough; as in the
    // Rust, an under-sized buffer is a misuse, so this returns nothing rather than overflow.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, WgError> format_packet_data(
        std::span<const std::uint8_t> plain);

    // receive_packet_data: check the index, quick-check the counter, open, then mark the counter
    // used. A wrong index / replay / bad tag each return their own error.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, WgError> receive_packet_data(
        const TransportMessage& packet);

    [[nodiscard]] std::pair<std::uint64_t, std::uint64_t> current_packet_count() const;

private:
    std::uint32_t receiving_index_;
    std::uint32_t sending_index_;
    Key receiving_key_;
    Key sending_key_;
    std::uint64_t sending_counter_ = 0;
    ReplayWindow receiving_;
};

// ---------------------------------------------------------------------------
// The handshake state machine. Every step of noise/handshake.rs, in order.
// ---------------------------------------------------------------------------

// The result of a responder accepting an initiation: the 92-byte response to send back and the
// session that was established from it, exactly the (packet, session) pair the Rust returns.
struct EstablishedHandshake {
    std::vector<std::uint8_t> message;
    Session session;
};

class Handshake {
public:
    Handshake(const Key& static_private, const Key& peer_static_public, std::uint32_t global_index,
              const std::optional<Key>& preshared_key);
    ~Handshake();
    Handshake(Handshake&&) noexcept;
    Handshake& operator=(Handshake&&) noexcept;
    Handshake(const Handshake&) = delete;
    Handshake& operator=(const Handshake&) = delete;

    // The initiator's side: build a fresh 148-byte initiation, macs included, and remember its
    // state. Returns the full wire message, not just the parsed fields.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, WgError> format_initiation();
    [[nodiscard]] std::expected<Session, WgError> receive_response(const HandshakeResponse& packet);

    // The responder's side: verify an initiation, and answer it with a response plus a session.
    [[nodiscard]] std::expected<EstablishedHandshake, WgError>
    receive_initiation(const HandshakeInitiation& packet);

    // A cookie reply decrypts into the write-cookie used for mac2 on the next handshake.
    std::expected<void, WgError> receive_cookie_reply(const CookieReply& packet);

    // The index of the handshake a cookie reply must carry to be accepted.
    [[nodiscard]] std::uint32_t cookie_index() const;

    [[nodiscard]] bool is_in_progress() const;
    [[nodiscard]] bool is_expired() const;
    void set_expired();
    [[nodiscard]] bool has_cookie() const;
    void clear_cookie();
    // Milliseconds since the last initiation was sent, nothing when none is outstanding.
    [[nodiscard]] std::optional<std::uint64_t> initiation_age_ms() const;

    // Rekey a static private key in place; checks the public key really matches, as Rust asserts.
    void set_static_private(const Key& static_private, const Key& static_public);

    [[nodiscard]] std::uint32_t take_next_index(); // inc_index, exposed for the ring's session id

    [[nodiscard]] const Key& peer_static_public() const;

    // Monotonic clock in milliseconds since the tunnel started, supplied by the owning Tunn.
    void set_clock(std::function<std::uint64_t()> clock);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// The failure half of RateLimiter::verify_packet, mirroring boringtun's
// `Result<Packet, TunnResult>` error arm (rate_limiter.rs:153). Exactly one of the two is set:
// an error to report (mac1 invalid, or under load with no source address), or a cookie-reply
// datagram the caller must send back to challenge the peer for a mac2.
struct RateLimitRejection {
    std::optional<WgError> error;
    std::vector<std::uint8_t> cookie_reply;
};

// A responder's rate limiter and cookie authority: noise/rate_limiter.rs. It verifies mac1 on a
// handshake, applies the per-second count, and either checks mac2 or issues a cookie.
class RateLimiter {
public:
    // `static_public` is the responder's OWN static public key: rate_limiter.rs:63 derives
    // mac1_key = HASH(LABEL_MAC1 || public_key) from it, matching the initiator's
    // sending_mac1_key = HASH(LABEL_MAC1 || responder.static_public) (handshake.rs:381).
    RateLimiter(const Key& static_public, std::uint64_t limit, std::array<std::uint8_t, 16> secret,
                std::array<std::uint8_t, 32> nonce_key, std::function<std::uint64_t()> clock);
    ~RateLimiter();

    // verify_packet: parse and, for handshakes, check mac1; under load, check mac2 or hand back a
    // cookie reply that the caller must send. Ok carries the parsed packet, Err a rejection.
    [[nodiscard]] std::expected<Packet, RateLimitRejection> verify_packet(
        std::optional<IpAddress> src_addr, std::span<const std::uint8_t> src);

    void reset_count();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// The tunnel: noise/mod.rs Tunn, the ring of sessions, timers and packet queue.
// ---------------------------------------------------------------------------

// TunnResult, the way the Rust reports what a call produced. Owns its bytes instead of borrowing
// the caller's buffer, which is the one deliberate shape change of the port.
struct TunnResult {
    enum class Kind { Done, Err, WriteToNetwork, WriteToTunnelV4, WriteToTunnelV6 };

    Kind kind = Kind::Done;
    WgError error = WgError::InvalidPacket;
    std::vector<std::uint8_t> bytes;
    std::array<std::uint8_t, 4> v4{};
    std::array<std::uint8_t, 16> v6{};

    [[nodiscard]] static TunnResult done();
    [[nodiscard]] static TunnResult err(WgError error);
    [[nodiscard]] static TunnResult to_network(std::vector<std::uint8_t> bytes);
    [[nodiscard]] static TunnResult to_tunnel_v4(std::vector<std::uint8_t> bytes,
                                                 const std::array<std::uint8_t, 4>& addr);
    [[nodiscard]] static TunnResult to_tunnel_v6(std::vector<std::uint8_t> bytes,
                                                  const std::array<std::uint8_t, 16>& addr);
};

// The tunnel: noise/mod.rs Tunn, the ring of sessions, timers and packet queue.
class Tunn {
public:
    struct Config {
        Key static_private{};
        Key peer_static_public{};
        std::optional<Key> preshared_key;
        std::uint16_t persistent_keepalive = 0; // 0 disables it
        std::uint32_t index = 0;
        // supplied so tests drive time deterministically; defaults to a monotonic clock
        std::function<std::uint64_t()> clock;
    };

    explicit Tunn(Config config);
    ~Tunn();
    Tunn(Tunn&&) noexcept;
    Tunn& operator=(Tunn&&) noexcept;
    Tunn(const Tunn&) = delete;
    Tunn& operator=(const Tunn&) = delete;

    // encapsulate: seal an IP packet under the current session, or, with no session, queue it and
    // kick off a handshake. Mirrors the Rust's four outcomes.
    [[nodiscard]] TunnResult encapsulate(std::span<const std::uint8_t> src);

    // decapsulate: run the rate limiter, dispatch the packet, and drive the state machine. An
    // empty datagram means "drain the queue", as it does in the Rust.
    [[nodiscard]] TunnResult decapsulate(std::optional<IpAddress> src_addr,
                                         std::span<const std::uint8_t> datagram);

    // update_timers: the periodic sweep -- retransmit, rotate, keepalive, expire.
    [[nodiscard]] TunnResult update_timers();

    // A forced handshake initiation, the path the retransmit and the verify loop use.
    [[nodiscard]] TunnResult format_handshake_initiation(bool force_resend);

    [[nodiscard]] bool is_expired() const;
    [[nodiscard]] std::optional<std::uint64_t> time_since_last_handshake_ms() const;
    [[nodiscard]] std::optional<std::uint16_t> persistent_keepalive() const;

    // The most recently used session, present once a handshake completed. Exposed so a caller can
    // hand a Session to a probe; it stays owned by the tunnel.
    [[nodiscard]] Session* current_session();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// wg_stale_timeout, HEMERA_WG_STALE_SECS: parse a positive number, cap it at 86400, and fall back
// to 10 seconds when it is absent, unparseable or zero. It reads the setting, not std::environ.
[[nodiscard]] std::uint64_t wg_stale_timeout_ms(const Settings& settings);

// ---------------------------------------------------------------------------
// The socket loop's hemeranoize call sites: wireguard.rs:243-264, :277-285 and :568-575.
//
// Three functions, each the whole of one Rust arm with the encapsulate/inject_client_id work left
// to the caller -- the engine has already produced `packet` by the time any of these is reached,
// exactly as wireguard.rs:244-246 and :278-280 do before the arm opens. What is ported here is the
// order the bytes go out in, because that order is what a deep-packet box sees:
//
//   apply_obfuscation     -- the curtain, once, before the first packet of the run
//   the packet itself     -- the real WireGuard message
//   send_post_handshake   -- once, and only once, after the first packet
//
// Each of the two latches is a `bool&` for the reason the Rust gives it: `obf_sent` is per-tunnel
// state (wireguard.rs:128, `Arc<Mutex<bool>>`, and from_established starts it `true` at :147 because
// that socket has already been through a verify), while `post_hs_junk_sent` is local to the send
// task (:234). A caller that shares a tunnel across threads owns the mutex around them; the port
// keeps no lock, since it takes the references the loop would hold anyway.
//
// None of the three logs, and none reports a failed send: wireguard.rs drops every one of these
// results (`let _ =`), and hemeranoize.rs:313-400 writes no log line. Blocking is the caller's price,
// and both Rust loops already pay it -- they are the tasks spawned at :232 and :271 -- so a caller of
// these three belongs on a thread that may block, which is where the port's std::this_thread
// stand-ins for tokio::time::sleep put the waiting.

// wireguard.rs:243-264, send_task's TunnResult::WriteToNetwork arm: if this is the tunnel's first
// network packet and the profile is enabled, the latch goes up and the whole curtain runs before
// the packet (apply_obfuscation, :253); then `packet` goes out (:257); then, when the profile asks
// for post-handshake junk at all and none has gone yet, send_post_handshake_junk (:260-263). The
// latch is set before the drop and the await, so a concurrent packet cannot start a second curtain.
void send_data_packet(transport::UdpIo& sock, const SocketAddr& peer,
                      const hemeranoize::HemeraNoizeConfig& cfg,
                      std::span<const std::uint8_t> packet, bool& obfuscation_sent,
                      bool& post_handshake_junk_sent);

// wireguard.rs:277-285, timer_task's update_timers arm: keepalive junk first when the profile is
// enabled (:282-284), then the timer packet itself (:285). The Rust hands send_keepalive_junk only
// the socket and the config (:376), so there is no peer here -- sock_t is the connected socket, and
// the destination is the unset one the connected write ignores. No latch: every tick gets its junk.
void send_timer_packet(transport::UdpIo& sock, const hemeranoize::HemeraNoizeConfig& cfg,
                       std::span<const std::uint8_t> packet);

// wireguard.rs:573-575, verify_endpoint_keep_session's pre-handshake curtain -- not the :253 one.
// A fresh socket bound through bind_via_upstream (:568) gets apply_obfuscation before tunn is even
// built (:580), because the handshake this function drives must arrive behind the noise; the guard
// the Rust writes at :573 is kept, and there is no latch and no post-handshake junk on this path.
void pre_handshake_obfuscation(transport::UdpIo& sock, const SocketAddr& peer,
                               const hemeranoize::HemeraNoizeConfig& cfg);

} // namespace hemera::core::wireguard
