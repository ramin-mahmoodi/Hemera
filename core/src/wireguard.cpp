#include "wireguard.hpp"

#include "encoding.hpp"
#include "transport.hpp" // transport::UdpIo, the socket the three call sites below write through

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <utility>

namespace hemera::core::wireguard {
namespace {

// ---------------------------------------------------------------------------
// BLAKE2s. BoringSSL ships BLAKE2b-256 only, so the hash the WireGuard handshake chains with is
// spelled out here straight from RFC 7693; nothing else in the tree computes it.
// ---------------------------------------------------------------------------

constexpr std::array<std::uint32_t, 8> blake2s_iv = {0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL,
                                                     0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL,
                                                     0x1f83d9abUL, 0x5be0cd19UL};

// Rows are RFC 7693's, verbatim: row 5's tail is 7, 5, 15, 14, 1, 9 and a transposition there is
// invisible to a loopback handshake (both sides hash the same wrong way), so it stays checked only
// by the outside HMAC vectors in tests/wireguard_tests.cpp.
constexpr std::array<std::array<std::uint8_t, 16>, 10> blake2s_sigma = {
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
     {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
     {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
     {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
     {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
     {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
     {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
     {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
     {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
     {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}}};

constexpr std::size_t blake2s_block_size = 64;

std::uint32_t rotate_right(std::uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

std::uint32_t load_le32(const std::uint8_t* bytes) {
    return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) | (static_cast<std::uint32_t>(bytes[3]) << 24);
}

void store_le32(std::uint8_t* bytes, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

struct Blake2s {
    std::array<std::uint32_t, 8> h = blake2s_iv;
    std::uint64_t counter = 0;
    std::vector<std::uint8_t> pending;
    std::size_t out_len = 32;

    // A key, if there is one, is the first block: the parameter block carries its length and the
    // output length, exactly as RFC 7693 section 3.1 describes.
    void start(std::size_t digest_size, std::span<const std::uint8_t> key) {
        out_len = digest_size;
        h[0] ^= 0x01010000UL | (static_cast<std::uint32_t>(key.size()) << 8) |
                static_cast<std::uint32_t>(digest_size);
        if (!key.empty()) {
            std::array<std::uint8_t, blake2s_block_size> block{};
            std::copy(key.begin(), key.end(), block.begin());
            update(block);
        }
    }

    void update(std::span<const std::uint8_t> data) {
        pending.insert(pending.end(), data.begin(), data.end());
        // The final block is compressed by finish(), with the last flag set, so keep at least one
        // byte back here.
        while (pending.size() > blake2s_block_size) {
            compress(pending.data(), false, blake2s_block_size);
            pending.erase(pending.begin(), pending.begin() + blake2s_block_size);
        }
    }

    void finish(std::span<std::uint8_t> out) {
        std::array<std::uint8_t, blake2s_block_size> last{};
        std::copy(pending.begin(), pending.end(), last.begin());
        compress(last.data(), true, pending.size());
        pending.clear();
        std::array<std::uint8_t, 32> words{};
        for (std::size_t i = 0; i < 8; ++i) {
            store_le32(words.data() + i * 4, h[i]);
        }
        std::copy_n(words.begin(), out_len, out.begin());
    }

private:
    void compress(const std::uint8_t* block, bool last, std::size_t used) {
        counter += used;
        std::array<std::uint32_t, 16> m{};
        for (std::size_t i = 0; i < 16; ++i) {
            m[i] = load_le32(block + i * 4);
        }

        std::array<std::uint32_t, 16> v;
        std::copy(h.begin(), h.end(), v.begin());
        std::copy(blake2s_iv.begin(), blake2s_iv.end(), v.begin() + 8);
        v[12] ^= static_cast<std::uint32_t>(counter & 0xffffffffULL);
        v[13] ^= static_cast<std::uint32_t>(counter >> 32);
        if (last) {
            v[14] ^= 0xffffffffUL;
        }

        auto mix = [&v, &m](std::size_t a, std::size_t b, std::size_t c, std::size_t d,
                            std::uint32_t x, std::uint32_t y) {
            v[a] = v[a] + v[b] + x;
            v[d] = rotate_right(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = rotate_right(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = rotate_right(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = rotate_right(v[b] ^ v[c], 7);
        };

        for (std::size_t round = 0; round < 10; ++round) {
            const auto& s = blake2s_sigma[round];
            mix(0, 4, 8, 12, m[s[0]], m[s[1]]);
            mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
            mix(2, 6, 10, 14, m[s[4]], m[s[5]]);
            mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
            mix(0, 5, 10, 15, m[s[8]], m[s[9]]);
            mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
            mix(2, 7, 8, 13, m[s[12]], m[s[13]]);
            mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (std::size_t i = 0; i < 8; ++i) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }
};

using Hash = std::array<std::uint8_t, 32>;
using Mac16 = std::array<std::uint8_t, 16>;
using Mac24 = std::array<std::uint8_t, 24>;

Hash plain_hash(std::span<const std::uint8_t> one, std::span<const std::uint8_t> two) {
    Blake2s state;
    state.start(32, {});
    state.update(one);
    state.update(two);
    Hash out{};
    state.finish(out);
    return out;
}

// b2s_hash, noise/handshake.rs:40.
Hash b2s_hash(std::span<const std::uint8_t> one, std::span<const std::uint8_t> two) {
    return plain_hash(one, two);
}

// b2s_keyed_mac_16 and b2s_keyed_mac_16_2, noise/handshake.rs:69: keyed BLAKE2s whose output is
// 16 bytes, which is what mac1 and mac2 carry.
Mac16 b2s_keyed_mac_16(std::span<const std::uint8_t> key, std::span<const std::uint8_t> one,
                       std::span<const std::uint8_t> two) {
    Blake2s state;
    state.start(16, key);
    state.update(one);
    state.update(two);
    Mac16 out{};
    state.finish(out);
    return out;
}

Mac16 b2s_keyed_mac_16(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    return b2s_keyed_mac_16(key, data, {});
}

// b2s_mac_24, noise/handshake.rs:83: the 24-byte cookie nonce comes out of a 24-byte keyed MAC.
Mac24 b2s_mac_24(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    Blake2s state;
    state.start(24, key);
    state.update(data);
    Mac24 out{};
    state.finish(out);
    return out;
}

// ---------------------------------------------------------------------------
// Byte reading and writing, and the AEAD wrappers.
// ---------------------------------------------------------------------------

constexpr std::uint8_t byte_one = 0x01;
constexpr std::uint8_t byte_two = 0x02;
constexpr std::uint8_t byte_three = 0x03;

void write_u16_be(std::uint8_t* dst, std::uint16_t value) {
    dst[0] = static_cast<std::uint8_t>(value >> 8);
    dst[1] = static_cast<std::uint8_t>(value);
}

void write_u32_le(std::uint8_t* dst, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        dst[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void write_u32_be(std::uint8_t* dst, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        dst[3 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void write_u64_le(std::uint8_t* dst, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        dst[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void write_u64_be(std::uint8_t* dst, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        dst[7 - i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

std::uint16_t read_u16_be(const std::uint8_t* src) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(src[0]) << 8) | src[1]);
}

std::uint32_t read_u32_le(const std::uint8_t* src) {
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(src[i]) << (8 * i);
    }
    return value;
}

std::uint64_t read_u64_le(const std::uint8_t* src) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(src[i]) << (8 * i);
    }
    return value;
}

std::uint64_t read_u64_be(const std::uint8_t* src) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | src[i];
    }
    return value;
}

std::uint32_t read_u32_be(const std::uint8_t* src) {
    return (static_cast<std::uint32_t>(src[0]) << 24) | (static_cast<std::uint32_t>(src[1]) << 16) |
           (static_cast<std::uint32_t>(src[2]) << 8) | static_cast<std::uint32_t>(src[3]);
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    std::uint8_t bytes[4];
    write_u32_le(bytes, value);
    out.insert(out.end(), bytes, bytes + 4);
}

void append_u16_be(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    std::uint8_t bytes[8];
    write_u64_le(bytes, value);
    out.insert(out.end(), bytes, bytes + 8);
}

template <std::size_t N>
void append(std::vector<std::uint8_t>& out, const std::array<std::uint8_t, N>& bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

// The four-byte type word every message opens with, which is also its three reserved zeros, then
// the index that follows it.
void write_type_and_index(std::vector<std::uint8_t>& out, std::uint32_t type, std::uint32_t index) {
    append_u32(out, type);
    append_u32(out, index);
}

std::span<const std::uint8_t> bytes_of(const Key& key) {
    return std::span<const std::uint8_t>(key.data(), key.size());
}

std::span<const std::uint8_t> view(const std::uint8_t* data, std::size_t size) {
    return std::span<const std::uint8_t>(data, size);
}

// The AEAD of the handshake and of the transport: ChaCha20-Poly1305, whose nonce is four zero
// bytes followed by the counter little-endian, so every handshake AEAD runs on an all-zero nonce
// (noise/handshake.rs:91).
constexpr std::size_t aead_tag_size = 16;

class AeadContext {
public:
    AeadContext(const EVP_AEAD* aead, std::span<const std::uint8_t> key) {
        EVP_AEAD_CTX_zero(&ctx_);
        ready_ = EVP_AEAD_CTX_init(&ctx_, aead, key.data(), key.size(), 0, nullptr) == 1;
    }
    AeadContext(const AeadContext&) = delete;
    AeadContext& operator=(const AeadContext&) = delete;
    ~AeadContext() { EVP_AEAD_CTX_cleanup(&ctx_); }

    // dst = ciphertext || 16-byte tag.
    bool seal(std::uint8_t* dst, std::size_t dst_size, std::span<const std::uint8_t> nonce,
              std::span<const std::uint8_t> plain, std::span<const std::uint8_t> ad) const {
        if (!ready_) {
            return false;
        }
        std::size_t written = 0;
        return EVP_AEAD_CTX_seal(&ctx_, dst, &written, dst_size, nonce.data(), nonce.size(),
                                 plain.data(), plain.size(), ad.empty() ? nullptr : ad.data(),
                                 ad.size()) == 1;
    }

    bool open(std::uint8_t* dst, std::size_t dst_size, std::span<const std::uint8_t> nonce,
              std::span<const std::uint8_t> cipher, std::span<const std::uint8_t> ad) const {
        if (!ready_ || cipher.size() < aead_tag_size || dst_size != cipher.size() - aead_tag_size) {
            return false;
        }
        std::size_t written = 0;
        return EVP_AEAD_CTX_open(&ctx_, dst, &written, dst_size, nonce.data(), nonce.size(),
                                 cipher.data(), cipher.size(), ad.empty() ? nullptr : ad.data(),
                                 ad.size()) == 1;
    }

    bool ready() const { return ready_; }

private:
    EVP_AEAD_CTX ctx_;
    bool ready_ = false;
};

std::array<std::uint8_t, 12> counter_nonce(std::uint64_t counter) {
    std::array<std::uint8_t, 12> nonce{};
    write_u64_le(nonce.data() + 4, counter);
    return nonce;
}

Key random_key() {
    Key out{};
    RAND_bytes(out.data(), static_cast<std::uint32_t>(out.size()));
    return out;
}

// The monotonic millisecond clock a Tunn uses when its Config supplies none.
std::uint64_t process_clock_ms() {
    static const auto start = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
}

// Rust's Duration subtraction; the timers only ever subtract an older stamp, so clamping at zero
// keeps that a formality rather than a wrap.
std::uint64_t since(std::uint64_t now_ms, std::uint64_t then_ms) {
    return now_ms >= then_ms ? now_ms - then_ms : 0;
}

bool same_bytes(std::span<const std::uint8_t> one, std::span<const std::uint8_t> two) {
    return one.size() == two.size() && CRYPTO_memcmp(one.data(), two.data(), one.size()) == 0;
}

// ---------------------------------------------------------------------------
// Key text parsing.
// ---------------------------------------------------------------------------

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// u8::from_str_radix(&s[i*2..=i*2+1], 16) over a two-character window: two hex digits, or a
// leading '+' and one digit, which Rust accepts and std::from_chars does not.
bool hex_pair(std::string_view text, std::size_t offset, std::uint8_t& out) {
    // Read inside the two-character window only: Rust is handed exactly that slice, so a third
    // character past it is not part of the number, and a '+' in the last pair must not look there.
    const std::string_view window = text.substr(offset, 2);
    std::size_t index = window.empty() || window.front() != '+' ? 0 : 1;
    if (index >= window.size()) return false;
    int value = 0;
    for (; index < window.size(); ++index) {
        const int digit = hex_digit(window[index]);
        if (digit < 0) return false;
        value = value * 16 + digit;
    }
    out = static_cast<std::uint8_t>(value);
    return true;
}

// Rust's u64::from_str: an optional leading '+', then digits, and nothing else.
bool parse_rust_u64(std::string_view text, std::uint64_t& out) {
    if (text.empty()) {
        return false;
    }
    std::size_t index = text.front() == '+' ? 1 : 0;
    if (index >= text.size()) {
        return false;
    }
    std::uint64_t value = 0;
    for (; index < text.size(); ++index) {
        const char c = text[index];
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
        if (value > (0xffffffffffffffffULL - digit) / 10ULL) {
            return false;
        }
        value = value * 10ULL + digit;
    }
    out = value;
    return true;
}

bool parse_rust_u8(std::string_view text, std::uint8_t& out) {
    std::uint64_t value = 0;
    if (!parse_rust_u64(text, value) || value > 255) {
        return false;
    }
    out = static_cast<std::uint8_t>(value);
    return true;
}

// Base64 of either width: the padded form the STANDARD engine writes, or the unpadded 43-character
// form wireguard.conf keeps, which is the same thing with its pad bit dropped.
std::optional<Key> key_from_base64(std::string_view text) {
    std::string padded(text);
    if (padded.size() == 43) {
        padded.push_back('=');
    }
    const std::optional<std::vector<std::uint8_t>> decoded = base64_decode(padded);
    if (!decoded || decoded->size() != 32) {
        return std::nullopt;
    }
    Key out{};
    std::copy(decoded->begin(), decoded->end(), out.begin());
    return out;
}

// ---------------------------------------------------------------------------
// The rate limiter's state, shared by RateLimiter and by Tunn so the tunnel keeps the exact
// WireGuardError of a rejection instead of only "these bytes, or none".
// ---------------------------------------------------------------------------

struct VerifyOutcome {
    std::optional<Packet> packet;
    std::optional<WgError> error;
    std::vector<std::uint8_t> cookie_reply; // non-empty only when the peer must be challenged
};

struct RateLimiterState {
    Key peer_public{};
    std::uint64_t limit = peer_handshake_rate_limit;
    std::array<std::uint8_t, 16> secret{};
    std::array<std::uint8_t, 32> nonce_key{};
    std::function<std::uint64_t()> clock;
    Hash mac1_key{};
    Hash cookie_key{};
    std::uint64_t origin_ms = 0;
    std::uint64_t nonce_counter = 0;
    std::uint64_t count = 0;
    std::uint64_t last_reset_ms = 0;

    void build_keys() {
        mac1_key = b2s_hash(view(reinterpret_cast<const std::uint8_t*>(label_mac1.data()),
                                 label_mac1.size()),
                            bytes_of(peer_public));
        cookie_key = b2s_hash(view(reinterpret_cast<const std::uint8_t*>(label_cookie.data()),
                                   label_cookie.size()),
                              bytes_of(peer_public));
    }

    // The address as rate_limiter.rs:89 lays it out: an IPv4 address in the FIRST four bytes.
    std::array<std::uint8_t, 16> address_bytes(const IpAddress& address) const {
        std::array<std::uint8_t, 16> out{};
        if (address.v4) {
            std::copy_n(address.bytes.begin() + 12, 4, out.begin());
        } else {
            out = address.bytes;
        }
        return out;
    }

    std::array<std::uint8_t, 16> current_cookie(const IpAddress& address) const {
        const std::uint64_t elapsed_ms = since(clock(), origin_ms);
        std::uint8_t counter_bytes[8];
        write_u64_le(counter_bytes, (elapsed_ms / 1000) / cookie_refresh_secs);
        return b2s_keyed_mac_16(secret, view(counter_bytes, 8), address_bytes(address));
    }

    Mac24 nonce() {
        std::uint8_t counter_bytes[8];
        write_u64_le(counter_bytes, nonce_counter);
        nonce_counter += 1;
        return b2s_mac_24(nonce_key, view(counter_bytes, 8));
    }

    bool is_under_load() { return count++ >= limit; }

    std::vector<std::uint8_t> format_cookie_reply(std::uint32_t idx, const Mac16& cookie,
                                                  std::span<const std::uint8_t> mac1) {
        std::vector<std::uint8_t> dst(cookie_reply_size, 0);
        write_u32_le(dst.data(), cookie_reply);
        write_u32_le(dst.data() + 4, idx);
        const Mac24 generated = nonce();
        std::copy(generated.begin(), generated.end(), dst.begin() + 8);

        AeadContext aead(EVP_aead_xchacha20_poly1305(), cookie_key);
        const std::span<const std::uint8_t> nonce_bytes(dst.data() + 8, 24);
        if (!aead.seal(dst.data() + 32, 32, nonce_bytes, cookie, mac1)) {
            return {};
        }
        return dst;
    }

    VerifyOutcome verify(std::optional<IpAddress> src_addr, std::span<const std::uint8_t> src) {
        VerifyOutcome outcome;
        auto parsed = parse_incoming_packet(src);
        if (!parsed) {
            outcome.error = parsed.error();
            return outcome;
        }

        const bool handshake =
            parsed->kind == PacketKind::HandshakeInit || parsed->kind == PacketKind::HandshakeResponse;
        if (!handshake) {
            outcome.packet = std::move(*parsed);
            return outcome;
        }

        const std::size_t message_size = src.size() - 32;
        const std::span<const std::uint8_t> message(src.data(), message_size);
        const std::span<const std::uint8_t> mac1(src.data() + message_size, 16);
        const std::span<const std::uint8_t> mac2(src.data() + message_size + 16, 16);

        const Mac16 computed_mac1 = b2s_keyed_mac_16(mac1_key, message);
        if (!same_bytes(computed_mac1, mac1)) {
            outcome.error = WgError::InvalidMac;
            return outcome;
        }

        if (is_under_load()) {
            if (!src_addr) {
                outcome.error = WgError::UnderLoad;
                return outcome;
            }
            const Mac16 cookie = current_cookie(*src_addr);
            const Mac16 computed_mac2 = b2s_keyed_mac_16(cookie, message, mac1);
            if (!same_bytes(computed_mac2, mac2)) {
                const std::uint32_t sender_index =
                    parsed->kind == PacketKind::HandshakeInit ? parsed->init.sender_index
                                                              : parsed->response.sender_index;
                outcome.cookie_reply = format_cookie_reply(sender_index, cookie, mac1);
                if (outcome.cookie_reply.empty()) {
                    outcome.error = WgError::DestinationBufferTooSmall;
                }
                return outcome;
            }
        }

        outcome.packet = std::move(*parsed);
        return outcome;
    }

    void reset_count() {
        const std::uint64_t now_ms = clock();
        if (since(now_ms, last_reset_ms) >= rate_limit_reset_period_secs * 1000) {
            count = 0;
            last_reset_ms = now_ms;
        }
    }
};

// ---------------------------------------------------------------------------
// Timers, noise/timers.rs. All stamps are milliseconds since the tunnel started.
// ---------------------------------------------------------------------------

enum TimerName {
    TimeCurrent,
    TimeSessionEstablished,
    TimeLastHandshakeStarted,
    TimeLastPacketReceived,
    TimeLastPacketSent,
    TimeLastDataPacketReceived,
    TimeLastDataPacketSent,
    TimeCookieReceived,
    TimePersistentKeepalive,
    TimerTop,
};

constexpr std::uint64_t ms_of(std::uint64_t seconds) { return seconds * 1000; }

struct Timers {
    bool is_initiator = false;
    std::uint64_t origin_ms = 0;
    std::array<std::uint64_t, TimerTop> stamps{};
    std::array<std::uint64_t, n_sessions> session_stamps{};
    bool want_keepalive = false;
    bool want_handshake = false;
    std::uint64_t persistent_keepalive = 0;
    bool should_reset_rr = true;

    void clear(std::uint64_t now_ms) {
        for (std::uint64_t& stamp : stamps) {
            stamp = now_ms;
        }
        want_handshake = false;
        want_keepalive = false;
    }
};

} // namespace

// ---------------------------------------------------------------------------
// b2s_hmac and b2s_hmac2, noise/handshake.rs:49: RFC 2104 HMAC over unkeyed BLAKE2s-256, whose
// block is 64 bytes. Outside the anonymous namespace because a hand-rolled HMAC proves nothing
// against itself -- the pads need a vector from elsewhere (tests/wireguard_tests.cpp).
// ---------------------------------------------------------------------------

Hash hmac_blake2s(std::span<const std::uint8_t> key, std::span<const std::uint8_t> one,
                  std::span<const std::uint8_t> two) {
    std::array<std::uint8_t, blake2s_block_size> block{};
    if (key.size() > blake2s_block_size) {
        const Hash folded = plain_hash(key, {});
        std::copy(folded.begin(), folded.end(), block.begin());
    } else {
        std::copy(key.begin(), key.end(), block.begin());
    }

    std::array<std::uint8_t, blake2s_block_size> inner_key = block;
    for (std::uint8_t& byte : inner_key) {
        byte ^= 0x36;
    }
    Blake2s inner;
    inner.start(32, {});
    inner.update(inner_key);
    inner.update(one);
    inner.update(two);
    std::array<std::uint8_t, 32> inner_hash{};
    inner.finish(inner_hash);

    // RFC 2104 opad on the padded key: 0x5c, not the inner pad re-XORed.
    std::array<std::uint8_t, blake2s_block_size> outer_key = block;
    for (std::uint8_t& byte : outer_key) {
        byte ^= 0x5c;
    }
    Blake2s outer;
    outer.start(32, {});
    outer.update(outer_key);
    outer.update(inner_hash);
    Hash out{};
    outer.finish(out);
    return out;
}

Hash b2s_hmac(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    return hmac_blake2s(key, data, {});
}

Hash b2s_hmac2(std::span<const std::uint8_t> key, std::span<const std::uint8_t> one,
               std::span<const std::uint8_t> two) {
    return hmac_blake2s(key, one, two);
}

// ---------------------------------------------------------------------------
// Keys and their text forms.
// ---------------------------------------------------------------------------

KeyKind classify_key(std::string_view text) {
    // The Rust switches on the length alone; only 64 is hex, so every other width is handed to
    // the base64 reader, which then refuses the ones that are not 43 or 44.
    return text.size() == 64 ? KeyKind::Hex : KeyKind::Base64;
}

std::optional<Key> parse_key(std::string_view text) {
    Key internal{};

    switch (text.size()) {
    case 64:
        for (std::size_t i = 0; i < 32; ++i) {
            std::uint8_t byte = 0;
            if (!hex_pair(text, i * 2, byte)) {
                return std::nullopt;
            }
            internal[i] = byte;
        }
        return internal;
    case 43:
    case 44:
        return key_from_base64(text);
    default:
        return std::nullopt;
    }
}

std::string encode_key_base64(const Key& key) {
    return base64_encode(std::span<const std::uint8_t>(key.data(), key.size()));
}

std::optional<Key> decode_key_base64(std::string_view text) {
    const std::optional<std::vector<std::uint8_t>> decoded = base64_decode(text);
    if (!decoded || decoded->size() != 32) {
        return std::nullopt;
    }
    Key out{};
    std::copy(decoded->begin(), decoded->end(), out.begin());
    return out;
}

std::string encode_client_id_base64(const ClientId& id) {
    return base64_encode(std::span<const std::uint8_t>(id.data(), id.size()));
}

std::optional<ClientId> decode_client_id_base64(std::string_view text) {
    const std::optional<std::vector<std::uint8_t>> decoded = base64_decode(text);
    if (!decoded || decoded->size() != 3) {
        return std::nullopt;
    }
    ClientId out{};
    std::copy(decoded->begin(), decoded->end(), out.begin());
    return out;
}

std::string wg_private_key_to_base64(const Key& key) { return encode_key_base64(key); }

std::string wg_peer_public_key_to_base64(const Key& key) { return encode_key_base64(key); }

Key public_from_private(const Key& private_key) {
    Key out{};
    X25519_public_from_private(out.data(), private_key.data());
    return out;
}

Key diffie_hellman(const Key& private_key, const Key& peer_public) {
    Key out{};
    // An input the ladder rejects gives the all-zero secret, which is what boringtun keeps too.
    X25519(out.data(), private_key.data(), peer_public.data());
    return out;
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

std::string_view message(WgError error) {
    switch (error) {
    case WgError::DestinationBufferTooSmall: return "DestinationBufferTooSmall";
    case WgError::IncorrectPacketLength: return "IncorrectPacketLength";
    case WgError::UnexpectedPacket: return "UnexpectedPacket";
    case WgError::WrongPacketType: return "WrongPacketType";
    case WgError::WrongIndex: return "WrongIndex";
    case WgError::WrongKey: return "WrongKey";
    case WgError::InvalidTai64nTimestamp: return "InvalidTai64nTimestamp";
    case WgError::WrongTai64nTimestamp: return "WrongTai64nTimestamp";
    case WgError::InvalidMac: return "InvalidMac";
    case WgError::InvalidAeadTag: return "InvalidAeadTag";
    case WgError::InvalidCounter: return "InvalidCounter";
    case WgError::DuplicateCounter: return "DuplicateCounter";
    case WgError::InvalidPacket: return "InvalidPacket";
    case WgError::NoCurrentSession: return "NoCurrentSession";
    case WgError::LockFailed: return "LockFailed";
    case WgError::ConnectionExpired: return "ConnectionExpired";
    case WgError::UnderLoad: return "UnderLoad";
    }
    return "InvalidPacket";
}

// ---------------------------------------------------------------------------
// Client-id injection and the socket-error rule.
// ---------------------------------------------------------------------------

void inject_client_id(std::span<std::uint8_t> packet, const ClientId& client_id) {
    if (packet.size() < 4) {
        return;
    }
    if (packet[0] < wg_msg_type_min || packet[0] > wg_msg_type_max) {
        return;
    }
    std::copy_n(client_id.begin(), client_id.size(), packet.begin() + 1);
}

void strip_client_id(std::span<std::uint8_t> packet) {
    if (packet.size() < 4) {
        return;
    }
    if (packet[0] < wg_msg_type_min || packet[0] > wg_msg_type_max) {
        return;
    }
    std::fill_n(packet.begin() + 1, 3, std::uint8_t{0});
}

bool is_transient_socket_error(SocketErrorKind kind) {
    switch (kind) {
    case SocketErrorKind::ConnectionRefused:
    case SocketErrorKind::ConnectionReset:
    case SocketErrorKind::ConnectionAborted:
    case SocketErrorKind::HostUnreachable:
    case SocketErrorKind::NetworkUnreachable:
    case SocketErrorKind::Interrupted:
    case SocketErrorKind::WouldBlock:
    case SocketErrorKind::TimedOut:
        return true;
    case SocketErrorKind::NotConnected:
    case SocketErrorKind::AddrNotAvailable:
    case SocketErrorKind::PermissionDenied:
    case SocketErrorKind::InvalidInput:
    case SocketErrorKind::Other:
        return false;
    }
    return false;
}

bool has_port(std::uint16_t port) {
    return std::find(std::begin(wg_ports), std::end(wg_ports), port) != std::end(wg_ports);
}

bool prefix_parses(std::string_view cidr, bool v6) {
    const std::size_t slash = cidr.find('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    std::uint8_t bits = 0;
    if (!parse_rust_u8(cidr.substr(slash + 1), bits)) {
        return false;
    }
    const std::optional<IpAddress> address = parse_address(cidr.substr(0, slash));
    if (!address) {
        return false;
    }
    return address->v4 == !v6;
}

// ---------------------------------------------------------------------------
// The dataplane probe.
// ---------------------------------------------------------------------------

std::vector<std::uint8_t> build_dns_query(std::uint16_t id) {
    // wireguard.rs:371 -- cloudflare.com A/IN, one question, nothing else.
    std::vector<std::uint8_t> query;
    query.reserve(32);
    append_u16_be(query, id);
    query.push_back(0x01); // flags: recursion desired
    query.push_back(0x00);
    append_u16_be(query, 1); // one question
    for (int i = 0; i < 6; ++i) {
        query.push_back(0x00); // answer / authority / additional counts
    }
    for (std::string_view label : {std::string_view("cloudflare"), std::string_view("com")}) {
        query.push_back(static_cast<std::uint8_t>(label.size()));
        for (char c : label) {
            query.push_back(static_cast<std::uint8_t>(c));
        }
    }
    query.push_back(0x00); // end of the name
    append_u16_be(query, 1); // qtype A
    append_u16_be(query, 1); // qclass IN
    return query;
}

std::uint16_t ipv4_checksum(std::span<const std::uint8_t> header) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < header.size(); i += 2) {
        sum += static_cast<std::uint32_t>(read_u16_be(header.data() + i));
    }
    if (i < header.size()) {
        sum += static_cast<std::uint32_t>(header[i]) << 8;
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~static_cast<std::uint16_t>(sum));
}

std::vector<std::uint8_t> build_dataplane_probe(const std::array<std::uint8_t, 4>& src,
                                                std::uint16_t dns_id, std::uint16_t ip_id,
                                                std::uint16_t sport) {
    // wireguard.rs:404, with the three random picks -- dns id, ip id, source port -- passed in so
    // the packet is reproducible.
    const std::vector<std::uint8_t> dns = build_dns_query(dns_id);
    const std::size_t udp_len = 8 + dns.size();
    const std::size_t total_len = 20 + udp_len;

    std::vector<std::uint8_t> packet;
    packet.reserve(total_len);
    packet.push_back(0x45); // version 4, IHL 5
    packet.push_back(0x00); // dscp / ecn
    append_u16_be(packet, static_cast<std::uint16_t>(total_len));
    append_u16_be(packet, ip_id);
    append_u16_be(packet, 0); // flags and fragment offset
    packet.push_back(64); // ttl
    packet.push_back(17); // protocol UDP
    append_u16_be(packet, 0); // checksum placeholder
    packet.insert(packet.end(), src.begin(), src.end());
    const std::array<std::uint8_t, 4> resolver{8, 8, 8, 8};
    packet.insert(packet.end(), resolver.begin(), resolver.end());

    const std::uint16_t checksum = ipv4_checksum(std::span<const std::uint8_t>(packet.data(), 20));
    write_u16_be(packet.data() + 10, checksum);

    append_u16_be(packet, sport);
    append_u16_be(packet, 53);
    append_u16_be(packet, static_cast<std::uint16_t>(udp_len));
    append_u16_be(packet, 0); // the UDP checksum is left empty, as the Rust leaves it
    packet.insert(packet.end(), dns.begin(), dns.end());
    return packet;
}

std::uint64_t health_check_pause_ms(std::uint64_t offset) {
    return wg_healthcheck_interval_ms - wg_healthcheck_jitter_ms + offset;
}

std::uint64_t wg_stale_timeout_ms(const Settings& settings) {
    std::uint64_t secs = 0;
    const std::optional<std::string_view> value = settings.get("HEMERA_WG_STALE_SECS");
    if (value && parse_rust_u64(*value, secs) && secs > 0) {
        secs = secs < wg_stale_max_secs ? secs : wg_stale_max_secs;
        return secs * 1000;
    }
    return wg_stale_default_secs * 1000;
}

// ---------------------------------------------------------------------------
// Wire messages.
// ---------------------------------------------------------------------------

std::optional<Tai64N> Tai64N::parse(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 12) {
        return std::nullopt;
    }
    Tai64N stamp;
    stamp.secs = read_u64_be(bytes.data());
    stamp.nano = read_u32_be(bytes.data() + 8);
    return stamp;
}

bool Tai64N::after(const Tai64N& other) const {
    return secs > other.secs || (secs == other.secs && nano > other.nano);
}

std::expected<Packet, WgError> parse_incoming_packet(std::span<const std::uint8_t> src) {
    if (src.size() < 4) {
        return std::unexpected(WgError::InvalidPacket);
    }
    Packet packet;

    switch (read_u32_le(src.data())) {
    case handshake_init:
        if (src.size() != handshake_init_size) {
            return std::unexpected(WgError::InvalidPacket);
        }
        packet.kind = PacketKind::HandshakeInit;
        packet.init.sender_index = read_u32_le(src.data() + 4);
        std::copy_n(src.begin() + 8, packet.init.unencrypted_ephemeral.size(),
                    packet.init.unencrypted_ephemeral.begin());
        std::copy_n(src.begin() + 40, packet.init.encrypted_static.size(),
                    packet.init.encrypted_static.begin());
        std::copy_n(src.begin() + 88, packet.init.encrypted_timestamp.size(),
                    packet.init.encrypted_timestamp.begin());
        return packet;
    case handshake_resp:
        if (src.size() != handshake_resp_size) {
            return std::unexpected(WgError::InvalidPacket);
        }
        packet.kind = PacketKind::HandshakeResponse;
        packet.response.sender_index = read_u32_le(src.data() + 4);
        packet.response.receiver_index = read_u32_le(src.data() + 8);
        std::copy_n(src.begin() + 12, packet.response.unencrypted_ephemeral.size(),
                    packet.response.unencrypted_ephemeral.begin());
        std::copy_n(src.begin() + 44, packet.response.encrypted_nothing.size(),
                    packet.response.encrypted_nothing.begin());
        return packet;
    case cookie_reply:
        if (src.size() != cookie_reply_size) {
            return std::unexpected(WgError::InvalidPacket);
        }
        packet.kind = PacketKind::CookieReply;
        packet.cookie.receiver_index = read_u32_le(src.data() + 4);
        std::copy_n(src.begin() + 8, packet.cookie.nonce.size(), packet.cookie.nonce.begin());
        std::copy_n(src.begin() + 32, packet.cookie.encrypted_cookie.size(),
                    packet.cookie.encrypted_cookie.begin());
        return packet;
    case data:
        if (src.size() < data_overhead_size) {
            return std::unexpected(WgError::InvalidPacket);
        }
        packet.kind = PacketKind::Data;
        packet.data.receiver_index = read_u32_le(src.data() + 4);
        packet.data.counter = read_u64_le(src.data() + 8);
        packet.data.encrypted_payload.assign(src.begin() + 16, src.end());
        return packet;
    default:
        return std::unexpected(WgError::InvalidPacket);
    }
}

std::vector<std::uint8_t> serialize(const HandshakeInitiation& msg) {
    // The MAC fields are not part of the parsed struct, so they go out zeroed; a caller that wants
    // them filled in builds the message through Handshake, which appends them.
    std::vector<std::uint8_t> out;
    out.reserve(handshake_init_size);
    write_type_and_index(out, handshake_init, msg.sender_index);
    append(out, msg.unencrypted_ephemeral);
    append(out, msg.encrypted_static);
    append(out, msg.encrypted_timestamp);
    out.resize(handshake_init_size, 0);
    return out;
}

std::vector<std::uint8_t> serialize(const HandshakeResponse& msg) {
    std::vector<std::uint8_t> out;
    out.reserve(handshake_resp_size);
    write_type_and_index(out, handshake_resp, msg.sender_index);
    append_u32(out, msg.receiver_index);
    append(out, msg.unencrypted_ephemeral);
    append(out, msg.encrypted_nothing);
    out.resize(handshake_resp_size, 0);
    return out;
}

std::vector<std::uint8_t> serialize(const CookieReply& msg) {
    std::vector<std::uint8_t> out;
    out.reserve(cookie_reply_size);
    write_type_and_index(out, cookie_reply, msg.receiver_index);
    append(out, msg.nonce);
    append(out, msg.encrypted_cookie);
    out.resize(cookie_reply_size, 0);
    return out;
}

std::vector<std::uint8_t> serialize(const TransportMessage& msg) {
    std::vector<std::uint8_t> out;
    out.reserve(data_overhead_size + msg.encrypted_payload.size());
    write_type_and_index(out, data, msg.receiver_index);
    append_u64(out, msg.counter);
    out.insert(out.end(), msg.encrypted_payload.begin(), msg.encrypted_payload.end());
    return out;
}

std::optional<IpAddress> dst_address(std::span<const std::uint8_t> packet) {
    if (packet.empty()) {
        return std::nullopt;
    }
    IpAddress address;
    switch (packet[0] >> 4) {
    case 4:
        if (packet.size() < 20) {
            return std::nullopt;
        }
        address.v4 = true;
        std::copy_n(packet.begin() + 16, 4, address.bytes.begin() + 12);
        return address;
    case 6:
        if (packet.size() < 40) {
            return std::nullopt;
        }
        std::copy_n(packet.begin() + 24, 16, address.bytes.begin());
        return address;
    default:
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// Transport session and the replay window.
// ---------------------------------------------------------------------------

std::expected<void, WgError> ReplayWindow::will_accept(std::uint64_t counter) const {
    if (counter >= next) {
        return {};
    }
    if (counter + replay_n_bits < next) {
        return std::unexpected(WgError::InvalidCounter);
    }
    const std::uint64_t bit_index = counter % replay_n_bits;
    const std::size_t word = static_cast<std::size_t>(bit_index / replay_word_size);
    const unsigned bit = static_cast<unsigned>(bit_index % replay_word_size);
    if (((bitmap[word] >> bit) & 1U) == 1U) {
        return std::unexpected(WgError::DuplicateCounter);
    }
    return {};
}

namespace {

void window_set_bit(ReplayWindow& window, std::uint64_t index) {
    const std::uint64_t bit_index = index % replay_n_bits;
    window.bitmap[static_cast<std::size_t>(bit_index / replay_word_size)] |=
        1ULL << static_cast<unsigned>(bit_index % replay_word_size);
}

void window_clear_bit(ReplayWindow& window, std::uint64_t index) {
    const std::uint64_t bit_index = index % replay_n_bits;
    window.bitmap[static_cast<std::size_t>(bit_index / replay_word_size)] &=
        ~(1ULL << static_cast<unsigned>(bit_index % replay_word_size));
}

void window_clear_word(ReplayWindow& window, std::uint64_t index) {
    const std::uint64_t bit_index = index % replay_n_bits;
    window.bitmap[static_cast<std::size_t>(bit_index / replay_word_size)] = 0;
}

bool window_check_bit(const ReplayWindow& window, std::uint64_t index) {
    const std::uint64_t bit_index = index % replay_n_bits;
    const std::size_t word = static_cast<std::size_t>(bit_index / replay_word_size);
    const unsigned bit = static_cast<unsigned>(bit_index % replay_word_size);
    return ((window.bitmap[word] >> bit) & 1ULL) == 1ULL;
}

} // namespace

std::expected<void, WgError> ReplayWindow::mark_did_receive(std::uint64_t counter) {
    ReplayWindow& window = *this;
    if (counter + replay_n_bits < next) {
        return std::unexpected(WgError::InvalidCounter);
    }
    if (counter == next) {
        window_set_bit(window, counter);
        next += 1;
        return {};
    }
    if (counter < next) {
        if (window_check_bit(window, counter)) {
            return std::unexpected(WgError::InvalidCounter);
        }
        window_set_bit(window, counter);
        return {};
    }
    if (counter - next >= replay_n_bits) {
        for (std::uint64_t& word : bitmap) {
            word = 0;
        }
    } else {
        std::uint64_t i = next;
        while (i % replay_word_size != 0 && i < counter) {
            window_clear_bit(window, i);
            i += 1;
        }
        while (i + replay_word_size < counter) {
            window_clear_word(window, i);
            i &= ~(replay_word_size - 1);
            i += replay_word_size;
        }
        while (i < counter) {
            window_clear_bit(window, i);
            i += 1;
        }
    }
    window_set_bit(window, counter);
    next = counter + 1;
    return {};
}

Session::Session(std::uint32_t local_index, std::uint32_t peer_index, const Key& receiving_key,
                 const Key& sending_key)
    : receiving_index_(local_index),
      sending_index_(peer_index),
      receiving_key_(receiving_key),
      sending_key_(sending_key) {}

std::expected<std::vector<std::uint8_t>, WgError> Session::format_packet_data(
    std::span<const std::uint8_t> plain) {
    std::vector<std::uint8_t> out(data_overhead_size + plain.size(), 0);
    write_u32_le(out.data(), data);
    write_u32_le(out.data() + 4, sending_index_);
    const std::uint64_t counter = sending_counter_++;
    write_u64_le(out.data() + 8, counter);

    AeadContext aead(EVP_aead_chacha20_poly1305(), bytes_of(sending_key_));
    const std::array<std::uint8_t, 12> nonce = counter_nonce(counter);
    std::uint8_t* payload = out.data() + 16;
    if (!aead.seal(payload, plain.size() + 16, nonce, plain, {})) {
        return std::unexpected(WgError::InvalidAeadTag);
    }
    return out;
}

std::expected<std::vector<std::uint8_t>, WgError> Session::receive_packet_data(
    const TransportMessage& packet) {
    if (packet.receiver_index != receiving_index_) {
        return std::unexpected(WgError::WrongIndex);
    }
    auto quick = receiving_.will_accept(packet.counter);
    if (!quick) {
        return std::unexpected(quick.error());
    }

    std::vector<std::uint8_t> plain(packet.encrypted_payload.empty()
                                        ? 0
                                        : packet.encrypted_payload.size() - 16);
    AeadContext aead(EVP_aead_chacha20_poly1305(), bytes_of(receiving_key_));
    const std::array<std::uint8_t, 12> nonce = counter_nonce(packet.counter);
    if (!aead.open(plain.data(), plain.size(), nonce, packet.encrypted_payload, {})) {
        return std::unexpected(WgError::InvalidAeadTag);
    }

    auto marked = receiving_.mark_did_receive(packet.counter);
    if (!marked) {
        return std::unexpected(marked.error());
    }
    receiving_.receive_cnt += 1;
    return plain;
}

std::pair<std::uint64_t, std::uint64_t> Session::current_packet_count() const {
    return {receiving_.next, receiving_.receive_cnt};
}

// ---------------------------------------------------------------------------
// The handshake state machine. Every line below traces to noise/handshake.rs in boringtun 0.7.0;
// the comments cite the Rust line the step follows so the port can be checked against it. The
// chaining primitives (b2s_hash / b2s_hmac / b2s_hmac2 / b2s_keyed_mac_16) are the ones defined at
// the top of this file, so no hash or KDF is re-invented here.
// ---------------------------------------------------------------------------

namespace {

// The single-byte infos the chaining mixes with, boringtun's &[0x01], &[0x02], &[0x03].
constexpr std::uint8_t hkdf_one = 0x01;
constexpr std::uint8_t hkdf_two = 0x02;
constexpr std::uint8_t hkdf_three = 0x03;

// one_byte hands a single HKDF info byte to the chaining as a by-value array, NOT as a span over
// the function's own argument. A span pointing at that argument dangles the moment the call
// returns -- the very next call reuses the same stack depth, so each info byte the chaining mixes
// would read whatever happened to land there instead of 1 or 2. That is precisely why this port
// first failed the loopback: the initiator's format_initiation and the responder's
// receive_initiation have different stack shapes, so they mixed different garbage into the same
// HKDF step, their chaining keys diverged, and the responder's AEAD open returned InvalidAeadTag.
// A returned temporary array lives until the end of the full expression -- the HMAC call that
// consumes it -- and std::span<const std::uint8_t> builds implicitly from an rvalue std::array.
constexpr std::array<std::uint8_t, 1> one_byte(std::uint8_t value) {
    return {value};
}

std::span<const std::uint8_t> label_span(std::string_view label) {
    return view(reinterpret_cast<const std::uint8_t*>(label.data()), label.size());
}

// TimeStamper::stamp (handshake.rs:187): the 12-byte tai64n of the current system time, big-endian
// seconds offset by TAI64_BASE then big-endian nanoseconds. The initiator seals this into the
// timestamp field; the responder only needs it to be strictly increasing to reject replays.
std::array<std::uint8_t, 12> stamp_tai64n() {
    const auto epoch = std::chrono::system_clock::now().time_since_epoch();
    const std::uint64_t secs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(epoch).count());
    const std::uint64_t nanos = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(epoch).count());
    std::array<std::uint8_t, 12> out{};
    write_u64_be(out.data(), secs + tai64_base);
    write_u32_be(out.data() + 8, static_cast<std::uint32_t>(nanos % 1'000'000'000ULL));
    return out;
}

} // namespace

// The nested Impl carries NoiseParams (handshake.rs:232) plus the HandshakeState machine
// (handshake.rs:281) and the Cookies record (handshake.rs:313).
class Handshake::Impl {
public:
    Impl(const Key& static_private_in, const Key& peer_static_public_in,
         std::uint32_t global_index, const std::optional<Key>& preshared_key_in)
        : static_private(static_private_in),
          peer_static_public(peer_static_public_in),
          preshared_key(preshared_key_in),
          next_index(global_index) {
        // NoiseParams::new (handshake.rs:378,381): the static DH and the pre-computed
        // HASH("mac1----" || peer_static_public) the initiator keys mac1 with.
        static_public = public_from_private(static_private);
        static_shared = diffie_hellman(static_private, peer_static_public);
        sending_mac1_key = b2s_hash(label_span(label_mac1), bytes_of(peer_static_public));
    }

    // NoiseParams state.
    Key static_private;
    Key static_public{};
    Key peer_static_public;
    Key static_shared{};
    Hash sending_mac1_key{};
    std::optional<Key> preshared_key;
    std::uint32_t next_index;

    // HandshakeState (handshake.rs:281). A state is one of none / initiation-sent /
    // initiation-received / expired; only the payload for the live variant is read.
    enum class Kind { None, InitSent, InitReceived, Expired };
    struct Sent {
        std::uint32_t local_index = 0;
        Hash hash{};
        Hash chaining{};
        Key ephemeral_private{};
        std::uint64_t time_sent_ms = 0;
    };
    struct Received {
        Hash hash{};
        Hash chaining{};
        Key peer_ephemeral{};
        std::uint32_t peer_index = 0;
    };
    Kind previous_kind = Kind::None;
    Kind current_kind = Kind::None;
    Sent previous_sent;
    Sent current_sent;
    Received current_received;

    // Cookies (handshake.rs:313) and the replay clock.
    std::optional<Mac16> last_mac1;
    std::uint32_t cookie_index_value = 0;
    std::optional<Mac16> write_cookie;
    Tai64N last_handshake_timestamp{};
    std::function<std::uint64_t()> clock = process_clock_ms;

    // inc_index (handshake.rs:466): 24-bit peer index, 8-bit cycling session index.
    std::uint32_t inc_index() {
        const std::uint32_t index = next_index;
        const auto idx8 = static_cast<std::uint8_t>(index);
        next_index = (index & ~0xffu) | static_cast<std::uint32_t>(idx8 + 1u);
        return next_index;
    }

    // append_mac1_and_mac2 (handshake.rs:682).
    void append_mac1_and_mac2(std::uint32_t local_index, std::vector<std::uint8_t>& dst) {
        const std::size_t mac1_off = dst.size() - 32;
        const std::size_t mac2_off = dst.size() - 16;
        const Mac16 msg_mac1 = b2s_keyed_mac_16(sending_mac1_key, view(dst.data(), mac1_off));
        std::copy(msg_mac1.begin(), msg_mac1.end(), dst.begin() + static_cast<std::ptrdiff_t>(mac1_off));
        Mac16 msg_mac2{};
        if (write_cookie) {
            // dst[..mac2_off] already carries the message and mac1, so a single keyed MAC over it
            // is exactly boringtun's MAC(cookie, msg[0..mac2_off]).
            msg_mac2 = b2s_keyed_mac_16(*write_cookie, view(dst.data(), mac2_off));
        }
        std::copy(msg_mac2.begin(), msg_mac2.end(), dst.begin() + static_cast<std::ptrdiff_t>(mac2_off));
        cookie_index_value = local_index;
        last_mac1 = msg_mac1;
    }

    // format_handshake_initiation (handshake.rs:709).
    std::expected<std::vector<std::uint8_t>, WgError> format_initiation() {
        std::vector<std::uint8_t> dst(handshake_init_size, 0);
        std::uint8_t* p = dst.data();

        const std::uint32_t local_index = inc_index();
        Hash chaining = initial_chain_key;
        Hash hash = initial_chain_hash;
        hash = b2s_hash(hash, bytes_of(peer_static_public));                 // :729
        const Key ephemeral_private = random_key();                          // :731
        const Key ephemeral_public = public_from_private(ephemeral_private);
        write_u32_le(p, handshake_init);                                      // :734
        write_u32_le(p + 4, local_index);                                    // :736
        std::copy(ephemeral_public.begin(), ephemeral_public.end(), p + 8);  // :738
        const std::span<const std::uint8_t> eph(p + 8, 32);
        hash = b2s_hash(hash, eph);                                          // :741
        chaining = b2s_hmac(b2s_hmac(chaining, eph), one_byte(hkdf_one));    // :744
        const Key ephemeral_shared = diffie_hellman(ephemeral_private, peer_static_public); // :746
        Hash temp = b2s_hmac(chaining, ephemeral_shared);                     // :747
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :749
        Hash key = b2s_hmac2(temp, chaining, one_byte(hkdf_two));            // :751
        AeadContext static_aead(EVP_aead_chacha20_poly1305(), key);
        if (!static_aead.seal(p + 40, 48, counter_nonce(0), bytes_of(static_public), hash)) { // :753
            return std::unexpected(WgError::InvalidAeadTag);
        }
        hash = b2s_hash(hash, view(p + 40, 48));                             // :761
        temp = b2s_hmac(chaining, bytes_of(static_shared));                  // :763
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :765
        key = b2s_hmac2(temp, chaining, one_byte(hkdf_two));                 // :767
        const std::array<std::uint8_t, 12> timestamp = stamp_tai64n();       // :769
        AeadContext ts_aead(EVP_aead_chacha20_poly1305(), key);
        if (!ts_aead.seal(p + 88, 28, counter_nonce(0), timestamp, hash)) {  // :770
            return std::unexpected(WgError::InvalidAeadTag);
        }
        hash = b2s_hash(hash, view(p + 88, 28));                             // :772

        previous_kind = current_kind;                                        // :775 (mem::replace)
        previous_sent = current_sent;
        current_kind = Kind::InitSent;
        current_sent = Sent{local_index, hash, chaining, ephemeral_private, clock()};

        append_mac1_and_mac2(local_index, dst);                              // :786
        return dst;
    }

    // receive_handshake_response (handshake.rs:565), the initiator's half of the response.
    std::expected<Session, WgError> receive_response(const HandshakeResponse& packet) {
        const Sent* chosen = nullptr;
        bool is_previous = false;
        if (current_kind == Kind::InitSent && current_sent.local_index == packet.receiver_index) {
            chosen = &current_sent;                                          // :571
        } else if (previous_kind == Kind::InitSent &&
                   previous_sent.local_index == packet.receiver_index) {
            chosen = &previous_sent;                                         // :572
            is_previous = true;
        } else {
            return std::unexpected(WgError::UnexpectedPacket);               // :573
        }

        const std::uint32_t peer_index = packet.sender_index;                // :576
        const std::uint32_t local_index = chosen->local_index;               // :577
        const Hash state_hash = chosen->hash;
        const Hash state_chaining = chosen->chaining;
        const Key ephemeral_private = chosen->ephemeral_private;

        const Key unencrypted_ephemeral = packet.unencrypted_ephemeral;      // :579
        Hash hash = b2s_hash(state_hash, unencrypted_ephemeral);             // :582
        Hash temp = b2s_hmac(state_chaining, unencrypted_ephemeral);         // :584
        Hash chaining = b2s_hmac(temp, one_byte(hkdf_one));                  // :586
        const Key ephemeral_shared = diffie_hellman(ephemeral_private, unencrypted_ephemeral); // :590
        temp = b2s_hmac(chaining, ephemeral_shared);                         // :591
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :593
        // Rust inlines static_private.diffie_hellman(&unencrypted_ephemeral) (handshake.rs:595-602);
        // the local is named here so it cannot shadow the static-static member.
        const Key static_on_ephemeral = diffie_hellman(static_private, unencrypted_ephemeral); // :600
        temp = b2s_hmac(chaining, static_on_ephemeral);                        // :595
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :604
        const Key psk = preshared_key.value_or(Key{});                       // :608
        temp = b2s_hmac(chaining, psk);                                      // :606
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :611
        const Hash temp2 = b2s_hmac2(temp, chaining, one_byte(hkdf_two));    // :613
        const Hash key = b2s_hmac2(temp, temp2, one_byte(hkdf_three));       // :615
        hash = b2s_hash(hash, temp2);                                        // :617

        AeadContext aead(EVP_aead_chacha20_poly1305(), key);
        std::array<std::uint8_t, 1> scratch{};                               // empty plaintext, :619
        if (!aead.open(scratch.data(), 0, counter_nonce(0), packet.encrypted_nothing, hash)) {
            return std::unexpected(WgError::InvalidAeadTag);
        }

        const Hash tk1 = b2s_hmac(chaining, {});                             // :632
        const Hash tk2 = b2s_hmac(tk1, one_byte(hkdf_one));                  // :633
        const Hash tk3 = b2s_hmac2(tk1, tk2, one_byte(hkdf_two));            // :634

        if (is_previous) {
            previous_kind = Kind::None;                                      // :640
        } else {
            current_kind = Kind::None;                                       // :642
        }
        // Session::new(local_index, peer_index, temp3, temp2): initiator receives with temp3 and
        // sends with temp2 (handshake.rs:644).
        return Session(local_index, peer_index, tk3, tk2);
    }

    // receive_handshake_initialization (handshake.rs:481) followed by format_handshake_response
    // (handshake.rs:789): the responder accepts an initiation and answers with a session.
    std::expected<EstablishedHandshake, WgError> receive_initiation(const HandshakeInitiation& packet) {
        Hash chaining = initial_chain_key;                                   // :487
        Hash hash = initial_chain_hash;                                      // :489
        hash = b2s_hash(hash, bytes_of(static_public));                      // :490
        const std::uint32_t peer_index = packet.sender_index;                // :492
        const Key peer_ephemeral = packet.unencrypted_ephemeral;             // :494
        hash = b2s_hash(hash, peer_ephemeral);                               // :496
        chaining = b2s_hmac(b2s_hmac(chaining, peer_ephemeral), one_byte(hkdf_one)); // :499
        const Key ephemeral_shared = diffie_hellman(static_private, peer_ephemeral); // :507
        Hash temp = b2s_hmac(chaining, ephemeral_shared);                    // :508
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :510
        Hash key = b2s_hmac2(temp, chaining, one_byte(hkdf_two));            // :512

        Key peer_static_decrypted{};
        AeadContext static_aead(EVP_aead_chacha20_poly1305(), key);
        if (!static_aead.open(peer_static_decrypted.data(), 32, counter_nonce(0),
                              packet.encrypted_static, hash)) {              // :516
            return std::unexpected(WgError::InvalidAeadTag);
        }
        if (!same_bytes(bytes_of(peer_static_public), peer_static_decrypted)) {
            return std::unexpected(WgError::WrongKey);                       // :528
        }
        hash = b2s_hash(hash, packet.encrypted_static);                      // :531
        temp = b2s_hmac(chaining, bytes_of(static_shared));                  // :533
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :535
        key = b2s_hmac2(temp, chaining, one_byte(hkdf_two));                 // :537
        std::array<std::uint8_t, 12> timestamp{};
        AeadContext ts_aead(EVP_aead_chacha20_poly1305(), key);
        if (!ts_aead.open(timestamp.data(), 12, counter_nonce(0), packet.encrypted_timestamp, hash)) { // :540
            return std::unexpected(WgError::InvalidAeadTag);
        }
        const std::optional<Tai64N> parsed = Tai64N::parse(timestamp);       // :542
        if (!parsed) {
            return std::unexpected(WgError::InvalidTai64nTimestamp);
        }
        if (!parsed->after(last_handshake_timestamp)) {                      // :543
            return std::unexpected(WgError::WrongTai64nTimestamp);
        }
        last_handshake_timestamp = *parsed;                                  // :547
        hash = b2s_hash(hash, packet.encrypted_timestamp);                   // :550

        // previous = mem::replace(&mut self.state, InitReceived { .. }) (handshake.rs:552). A pure
        // responder's prior current is Kind::None, so this is harmless here, but it keeps the state
        // machine faithful when one object both sends and receives initiations. previous is only ever
        // re-read as Kind::InitSent in receive_response (handshake.rs:572), which previous_sent covers.
        previous_kind = current_kind;                                        // :552
        previous_sent = current_sent;
        current_kind = Kind::InitReceived;
        current_received = Received{hash, chaining, peer_ephemeral, peer_index};

        auto response = format_handshake_response();
        if (!response) {
            return std::unexpected(response.error());
        }
        return response;
    }

    // format_handshake_response (handshake.rs:789), driven from the InitReceived state above.
    std::expected<EstablishedHandshake, WgError> format_handshake_response() {
        if (current_kind != Kind::InitReceived) {
            return std::unexpected(WgError::UnexpectedPacket);               // :806 (a Rust panic)
        }
        Hash chaining = current_received.chaining;
        Hash hash = current_received.hash;
        const Key peer_ephemeral_public = current_received.peer_ephemeral;
        const std::uint32_t peer_index = current_received.peer_index;
        current_kind = Kind::None;                                           // :797 (mem::replace)

        std::vector<std::uint8_t> dst(handshake_resp_size, 0);
        std::uint8_t* p = dst.data();

        const Key ephemeral_private = random_key();                          // :817
        const std::uint32_t local_index = inc_index();                       // :818
        write_u32_le(p, handshake_resp);                                      // :821
        write_u32_le(p + 4, local_index);                                    // :823 sender_index
        write_u32_le(p + 8, peer_index);                                     // :825 receiver_index
        const Key ephemeral_public = public_from_private(ephemeral_private);
        std::copy(ephemeral_public.begin(), ephemeral_public.end(), p + 12); // :827
        const std::span<const std::uint8_t> eph(p + 12, 32);
        hash = b2s_hash(hash, eph);                                          // :830
        Hash temp = b2s_hmac(chaining, eph);                                 // :832
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :834
        const Key ephemeral_shared = diffie_hellman(ephemeral_private, peer_ephemeral_public); // :836
        temp = b2s_hmac(chaining, ephemeral_shared);                          // :837
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :839
        // Rust inlines ephemeral_private.diffie_hellman(&initiator_static_public) (handshake.rs:841-848);
        // the local is named so it cannot shadow the static-static member.
        const Key ephemeral_on_static = diffie_hellman(ephemeral_private, peer_static_public); // :844
        temp = b2s_hmac(chaining, ephemeral_on_static);                         // :841
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :848
        const Key psk = preshared_key.value_or(Key{});                       // :852
        temp = b2s_hmac(chaining, psk);                                      // :850
        chaining = b2s_hmac(temp, one_byte(hkdf_one));                       // :855
        const Hash temp2 = b2s_hmac2(temp, chaining, one_byte(hkdf_two));    // :857
        const Hash key = b2s_hmac2(temp, temp2, one_byte(hkdf_three));       // :859
        hash = b2s_hash(hash, temp2);                                        // :861

        AeadContext aead(EVP_aead_chacha20_poly1305(), key);
        if (!aead.seal(p + 44, 16, counter_nonce(0), std::span<const std::uint8_t>{}, hash)) { // :863
            return std::unexpected(WgError::InvalidAeadTag);
        }

        const Hash tk1 = b2s_hmac(chaining, {});                             // :873
        const Hash tk2 = b2s_hmac(tk1, one_byte(hkdf_one));                  // :874
        const Hash tk3 = b2s_hmac2(tk1, tk2, one_byte(hkdf_two));            // :875

        append_mac1_and_mac2(local_index, dst);                              // :877
        // Session::new(local_index, peer_index, temp2, temp3): the responder receives with temp2
        // and sends with temp3 -- the mirror of the initiator (handshake.rs:879).
        return EstablishedHandshake{std::move(dst), Session(local_index, peer_index, tk2, tk3)};
    }

    // receive_cookie_reply (handshake.rs:647).
    std::expected<void, WgError> receive_cookie_reply(const CookieReply& packet) {
        if (!last_mac1) {
            return std::unexpected(WgError::UnexpectedPacket);               // :654
        }
        if (packet.receiver_index != cookie_index_value) {
            return std::unexpected(WgError::WrongIndex);                     // :660
        }
        const Hash key = b2s_hash(label_span(label_cookie), bytes_of(peer_static_public)); // :663
        AeadContext aead(EVP_aead_xchacha20_poly1305(), key);
        Mac16 cookie{};
        if (!aead.open(cookie.data(), 16, packet.nonce, packet.encrypted_cookie, *last_mac1)) { // :669
            return std::unexpected(WgError::InvalidAeadTag);
        }
        write_cookie = cookie;                                               // :677
        return {};
    }

    void set_static_private(const Key& static_private_in, const Key& static_public_in) {
        // NoiseParams::set_static_private (handshake.rs:399): the caller asserts the public key
        // really belongs to the private one; the port treats a mismatch as a no-op rather than a
        // panic, since nothing here may throw across the boundary.
        if (public_from_private(static_private_in) != static_public_in) {
            return;
        }
        static_private = static_private_in;
        static_public = static_public_in;
        static_shared = diffie_hellman(static_private, peer_static_public);
    }
};

Handshake::Handshake(const Key& static_private, const Key& peer_static_public,
                     std::uint32_t global_index, const std::optional<Key>& preshared_key)
    : impl_(std::make_unique<Impl>(static_private, peer_static_public, global_index,
                                   preshared_key)) {}

Handshake::~Handshake() = default;
Handshake::Handshake(Handshake&&) noexcept = default;
Handshake& Handshake::operator=(Handshake&&) noexcept = default;

std::expected<std::vector<std::uint8_t>, WgError> Handshake::format_initiation() {
    return impl_->format_initiation();
}

std::expected<Session, WgError> Handshake::receive_response(const HandshakeResponse& packet) {
    return impl_->receive_response(packet);
}

std::expected<EstablishedHandshake, WgError> Handshake::receive_initiation(
    const HandshakeInitiation& packet) {
    return impl_->receive_initiation(packet);
}

std::expected<void, WgError> Handshake::receive_cookie_reply(const CookieReply& packet) {
    return impl_->receive_cookie_reply(packet);
}

std::uint32_t Handshake::cookie_index() const { return impl_->cookie_index_value; }

bool Handshake::is_in_progress() const {
    return impl_->current_kind != Impl::Kind::None && impl_->current_kind != Impl::Kind::Expired;
}

bool Handshake::is_expired() const { return impl_->current_kind == Impl::Kind::Expired; }

void Handshake::set_expired() {
    impl_->previous_kind = Impl::Kind::Expired;
    impl_->current_kind = Impl::Kind::Expired;
}

bool Handshake::has_cookie() const { return impl_->write_cookie.has_value(); }

void Handshake::clear_cookie() { impl_->write_cookie.reset(); }

std::optional<std::uint64_t> Handshake::initiation_age_ms() const {
    if (impl_->current_kind != Impl::Kind::InitSent) {
        return std::nullopt;
    }
    return since(impl_->clock(), impl_->current_sent.time_sent_ms);
}

void Handshake::set_static_private(const Key& static_private, const Key& static_public) {
    impl_->set_static_private(static_private, static_public);
}

std::uint32_t Handshake::take_next_index() { return impl_->inc_index(); }

const Key& Handshake::peer_static_public() const { return impl_->peer_static_public; }

void Handshake::set_clock(std::function<std::uint64_t()> clock) {
    impl_->clock = std::move(clock);
}

// ---------------------------------------------------------------------------
// The responder's rate limiter. RateLimiter is a thin owner of the RateLimiterState defined above,
// which is the same state the tunnel drives so the two share the cookie and counter rules exactly.
// ---------------------------------------------------------------------------

class RateLimiter::Impl {
public:
    RateLimiterState state;

    Impl(const Key& static_public, std::uint64_t limit, std::array<std::uint8_t, 16> secret,
         std::array<std::uint8_t, 32> nonce_key, std::function<std::uint64_t()> clock) {
        state.peer_public = static_public;   // the responder's own public, see header note
        state.limit = limit;
        state.secret = secret;
        state.nonce_key = nonce_key;
        state.clock = clock ? std::move(clock) : std::function<std::uint64_t()>(process_clock_ms);
        state.origin_ms = state.clock();
        state.last_reset_ms = state.origin_ms;
        state.build_keys();
    }
};

RateLimiter::RateLimiter(const Key& static_public, std::uint64_t limit,
                         std::array<std::uint8_t, 16> secret, std::array<std::uint8_t, 32> nonce_key,
                         std::function<std::uint64_t()> clock)
    : impl_(std::make_unique<Impl>(static_public, limit, secret, std::move(nonce_key),
                                   std::move(clock))) {}

RateLimiter::~RateLimiter() = default;

std::expected<Packet, RateLimitRejection> RateLimiter::verify_packet(
    std::optional<IpAddress> src_addr, std::span<const std::uint8_t> src) {
    VerifyOutcome outcome = impl_->state.verify(src_addr, src);
    if (outcome.packet) {
        return std::move(*outcome.packet);
    }
    RateLimitRejection rejection;
    if (outcome.error) {
        rejection.error = outcome.error;
        return std::unexpected(std::move(rejection));
    }
    rejection.cookie_reply = std::move(outcome.cookie_reply);
    return std::unexpected(std::move(rejection));
}

void RateLimiter::reset_count() { impl_->state.reset_count(); }

// ---------------------------------------------------------------------------
// TunnResult: boringtun's enum (mod.rs:45), owning its bytes rather than borrowing a caller's.
// ---------------------------------------------------------------------------

TunnResult TunnResult::done() { return TunnResult{}; }

TunnResult TunnResult::err(WgError error) {
    TunnResult result;
    result.kind = Kind::Err;
    result.error = error;
    return result;
}

TunnResult TunnResult::to_network(std::vector<std::uint8_t> bytes) {
    TunnResult result;
    result.kind = Kind::WriteToNetwork;
    result.bytes = std::move(bytes);
    return result;
}

TunnResult TunnResult::to_tunnel_v4(std::vector<std::uint8_t> bytes,
                                    const std::array<std::uint8_t, 4>& addr) {
    TunnResult result;
    result.kind = Kind::WriteToTunnelV4;
    result.bytes = std::move(bytes);
    result.v4 = addr;
    return result;
}

TunnResult TunnResult::to_tunnel_v6(std::vector<std::uint8_t> bytes,
                                     const std::array<std::uint8_t, 16>& addr) {
    TunnResult result;
    result.kind = Kind::WriteToTunnelV6;
    result.bytes = std::move(bytes);
    result.v6 = addr;
    return result;
}

// ---------------------------------------------------------------------------
// The tunnel: noise/mod.rs Tunn plus the timers in noise/timers.rs. Every stamp in Timers is
// milliseconds since the tunnel's origin, so the whole state machine advances on the supplied
// clock alone -- the tests drive time deterministically and never touch a socket.
// ---------------------------------------------------------------------------

class Tunn::Impl {
public:
    explicit Impl(const Config& config)
        : clock(config.clock ? config.clock : std::function<std::uint64_t()>(process_clock_ms)),
          origin_ms(clock()),
          handshake(config.static_private, config.peer_static_public,
                    static_cast<std::uint32_t>(config.index << 8), config.preshared_key) {
        // Tunn::new (mod.rs:202): the ring's handshake index is seeded at index << 8.
        handshake.set_clock(clock);
        timers.is_initiator = false;
        timers.persistent_keepalive = config.persistent_keepalive;   // Timers::new (timers.rs:69)
        timers.should_reset_rr = true;                               // rate_limiter.is_none() (mod.rs:218)
        // Timers::new stamps every timestamp at the instant the tunnel is created, and every later
        // subtraction is saturating, so all of them read as "zero elapsed" at the start. Stamps in
        // this port are milliseconds RELATIVE to origin_ms (now() and timer_tick both store relative
        // values), so the creation instant is the relative zero -- NOT the absolute origin_ms, which
        // would make the first unsigned subtraction wrap and expire a real-clock tunnel on sight.
        for (std::uint64_t& stamp : timers.stamps) {
            stamp = 0;                                           // Timers::new (timers.rs:60)
        }
        for (std::uint64_t& stamp : timers.session_stamps) {
            stamp = 0;
        }
        timers.want_handshake = false;
        timers.want_keepalive = false;

        // The tunnel's own rate limiter (mod.rs:220): keyed by OUR static public, so an incoming
        // handshake's mac1 -- HASH("mac1----" || our public) -- validates.
        const Key local_public = public_from_private(config.static_private);
        rate_limiter.peer_public = local_public;
        rate_limiter.limit = peer_handshake_rate_limit;
        {
            std::array<std::uint8_t, 16> secret{};
            RAND_bytes(secret.data(), static_cast<int>(secret.size()));
            rate_limiter.secret = secret;
            Key nonce_key = random_key();
            rate_limiter.nonce_key = nonce_key;
        }
        rate_limiter.clock = clock;
        rate_limiter.origin_ms = origin_ms;
        rate_limiter.last_reset_ms = origin_ms;
        rate_limiter.build_keys();
    }

    std::function<std::uint64_t()> clock;
    std::uint64_t origin_ms;
    Handshake handshake;
    std::array<std::optional<Session>, n_sessions> sessions{};
    std::uint64_t current = 0;                 // mod.rs:66, the full local index in use
    std::deque<std::vector<std::uint8_t>> packet_queue;
    Timers timers;
    RateLimiterState rate_limiter;
    std::uint64_t tx_bytes = 0;
    std::uint64_t rx_bytes = 0;

    std::uint64_t now() const { return since(clock(), origin_ms); }

    std::optional<Session>& slot(std::uint64_t full_index) {
        return sessions[static_cast<std::size_t>(full_index % n_sessions)];
    }

    // timer_tick (timers.rs:112).
    void timer_tick(TimerName name) {
        switch (name) {
        case TimeLastPacketReceived:
            timers.want_keepalive = true;
            timers.want_handshake = false;
            break;
        case TimeLastPacketSent:
            timers.want_handshake = true;
            timers.want_keepalive = false;
            break;
        default:
            break;
        }
        timers.stamps[name] = timers.stamps[TimeCurrent];
    }

    // timer_tick_session_established (timers.rs:129).
    void timer_tick_session_established(bool is_initiator, std::uint64_t session_idx) {
        timer_tick(TimeSessionEstablished);
        timers.session_stamps[static_cast<std::size_t>(session_idx % n_sessions)] =
            timers.stamps[TimeCurrent];
        timers.is_initiator = is_initiator;
    }

    // set_current_session (mod.rs:390).
    void set_current_session(std::uint64_t new_idx) {
        const std::uint64_t cur_idx = current;
        if (cur_idx == new_idx) {
            return;
        }
        if (!slot(cur_idx).has_value() ||
            timers.session_stamps[static_cast<std::size_t>(new_idx % n_sessions)] >=
                timers.session_stamps[static_cast<std::size_t>(cur_idx % n_sessions)]) {
            current = new_idx;
        }
    }

    // clear_all (timers.rs:142).
    void clear_all() {
        for (auto& session : sessions) {
            session.reset();
        }
        packet_queue.clear();
        timers.clear(now());
    }

    // queue_packet / requeue_packet / dequeue_packet (mod.rs:523-541).
    void queue_packet(std::span<const std::uint8_t> packet) {
        if (packet_queue.size() < max_queue_depth) {
            packet_queue.emplace_back(packet.begin(), packet.end());
        }
    }
    void requeue_packet(std::vector<std::uint8_t> packet) {
        if (packet_queue.size() < max_queue_depth) {
            packet_queue.push_front(std::move(packet));
        }
    }

    TunnResult send_queued_packet() {
        if (!packet_queue.empty()) {
            std::vector<std::uint8_t> packet = std::move(packet_queue.front());
            packet_queue.pop_front();
            TunnResult result = encapsulate(packet);
            if (result.kind == TunnResult::Kind::Err) {
                requeue_packet(std::move(packet));
            }
            return result;
        }
        return TunnResult::done();
    }

    // validate_decapsulated_packet (mod.rs:464).
    TunnResult validate_decapsulated_packet(std::vector<std::uint8_t> plain) {
        if (plain.empty()) {
            return TunnResult::done();                                        // keepalive, :466
        }
        IpAddress src;
        std::size_t computed_len = 0;
        if ((plain[0] >> 4) == 4 && plain.size() >= 20) {                      // :467
            computed_len = read_u16_be(plain.data() + 2);
            src.v4 = true;
            std::copy_n(plain.begin() + 12, 4, src.bytes.begin() + 12);
        } else if ((plain[0] >> 4) == 6 && plain.size() >= 40) {               // :480
            computed_len = read_u16_be(plain.data() + 4) + 40;
            src.v4 = false;
            std::copy_n(plain.begin() + 8, 16, src.bytes.begin());
        } else {
            return TunnResult::err(WgError::InvalidPacket);                    // :493
        }
        if (computed_len > plain.size()) {
            return TunnResult::err(WgError::InvalidPacket);                    // :497
        }
        timer_tick(TimeLastDataPacketReceived);                                // :500
        rx_bytes += computed_len;
        plain.resize(computed_len);
        if (src.v4) {
            std::array<std::uint8_t, 4> addr{};
            std::copy_n(src.bytes.begin() + 12, 4, addr.begin());
            return TunnResult::to_tunnel_v4(std::move(plain), addr);
        }
        return TunnResult::to_tunnel_v6(std::move(plain), src.bytes);
    }

    TunnResult handle_handshake_init(const HandshakeInitiation& p) {            // mod.rs:318
        auto established = handshake.receive_initiation(p);
        if (!established) {
            return TunnResult::err(established.error());
        }
        const std::uint32_t index = established->session.local_index();
        slot(index) = std::move(established->session);
        timer_tick(TimeLastPacketReceived);
        timer_tick(TimeLastPacketSent);
        timer_tick_session_established(false, index);
        return TunnResult::to_network(std::move(established->message));
    }

    TunnResult handle_handshake_response(const HandshakeResponse& p) {          // mod.rs:343
        auto session = handshake.receive_response(p);
        if (!session) {
            return TunnResult::err(session.error());
        }
        auto keepalive = session->format_packet_data({});
        if (!keepalive) {
            return TunnResult::err(keepalive.error());
        }
        const std::uint32_t l_idx = session->local_index();
        slot(l_idx) = std::move(*session);
        timer_tick(TimeLastPacketReceived);
        timer_tick_session_established(true, l_idx);
        set_current_session(l_idx);
        return TunnResult::to_network(std::move(*keepalive));
    }

    TunnResult handle_cookie_reply(const CookieReply& p) {                      // mod.rs:371
        auto result = handshake.receive_cookie_reply(p);
        if (!result) {
            return TunnResult::err(result.error());
        }
        timer_tick(TimeLastPacketReceived);
        timer_tick(TimeCookieReceived);
        return TunnResult::done();
    }

    TunnResult handle_data(const TransportMessage& p) {                          // mod.rs:406
        const std::uint32_t r_idx = p.receiver_index;
        auto& candidate = slot(r_idx);
        if (!candidate) {
            return TunnResult::err(WgError::NoCurrentSession);                  // :419
        }
        auto plain = candidate->receive_packet_data(p);
        if (!plain) {
            return TunnResult::err(plain.error());
        }
        set_current_session(r_idx);
        timer_tick(TimeLastPacketReceived);
        return validate_decapsulated_packet(std::move(*plain));
    }

    TunnResult handle_verified_packet(Packet&& packet) {                        // mod.rs:304
        switch (packet.kind) {
        case PacketKind::HandshakeInit:
            return handle_handshake_init(packet.init);
        case PacketKind::HandshakeResponse:
            return handle_handshake_response(packet.response);
        case PacketKind::CookieReply:
            return handle_cookie_reply(packet.cookie);
        case PacketKind::Data:
            return handle_data(packet.data);
        }
        return TunnResult::err(WgError::InvalidPacket);
    }

    // format_handshake_initiation (mod.rs:433).
    TunnResult format_handshake_initiation(bool force_resend) {
        if (handshake.is_in_progress() && !force_resend) {
            return TunnResult::done();                                         // :438
        }
        if (handshake.is_expired()) {
            timers.clear(now());                                               // :443
        }
        const bool starting_new = !handshake.is_in_progress();                 // :446
        auto packet = handshake.format_initiation();                           // :448
        if (!packet) {
            return TunnResult::err(packet.error());
        }
        if (starting_new) {
            timer_tick(TimeLastHandshakeStarted);                              // :453
        }
        timer_tick(TimeLastPacketSent);                                        // :455
        return TunnResult::to_network(std::move(*packet));
    }

    // update_session_timers (timers.rs:152).
    void update_session_timers(std::uint64_t time_now) {
        for (std::size_t i = 0; i < n_sessions; ++i) {
            if (time_now - timers.session_stamps[i] > ms_of(180)) {            // REJECT_AFTER_TIME
                timers.session_stamps[i] = time_now;
                sessions[i].reset();
            }
        }
    }

    // update_timers (timers.rs:168).
    TunnResult update_timers() {
        bool handshake_initiation_required = false;
        bool keepalive_required = false;

        if (timers.should_reset_rr) {
            rate_limiter.reset_count();
        }
        const std::uint64_t now_ms = now();
        timers.stamps[TimeCurrent] = now_ms;
        update_session_timers(now_ms);

        const std::uint64_t session_established = timers.stamps[TimeSessionEstablished];
        const std::uint64_t handshake_started = timers.stamps[TimeLastHandshakeStarted];
        const std::uint64_t aut_packet_received = timers.stamps[TimeLastPacketReceived];
        const std::uint64_t aut_packet_sent = timers.stamps[TimeLastPacketSent];
        const std::uint64_t data_packet_received = timers.stamps[TimeLastDataPacketReceived];
        const std::uint64_t data_packet_sent = timers.stamps[TimeLastDataPacketSent];

        if (handshake.is_expired()) {
            return TunnResult::err(WgError::ConnectionExpired);                // :196
        }
        if (handshake.has_cookie() &&
            now_ms - timers.stamps[TimeCookieReceived] >= ms_of(120)) {        // :200 COOKIE_EXPIRATION
            handshake.clear_cookie();
        }
        if (now_ms - session_established >= ms_of(180) * 3) {                  // :208 REJECT_AFTER_TIME*3
            handshake.set_expired();
            clear_all();
            return TunnResult::err(WgError::ConnectionExpired);
        }

        const std::optional<std::uint64_t> initiation_age = handshake.initiation_age_ms();
        if (initiation_age) {                                                  // :215 handshake.timer()
            if (now_ms - handshake_started >= ms_of(90)) {                     // :217 REKEY_ATTEMPT_TIME
                handshake.set_expired();
                clear_all();
                return TunnResult::err(WgError::ConnectionExpired);
            }
            if (*initiation_age >= ms_of(5)) {                                 // :228 REKEY_TIMEOUT
                handshake_initiation_required = true;
            }
        } else {
            if (timers.is_initiator) {                                         // :238
                if (session_established < data_packet_sent &&
                    now_ms - session_established >= ms_of(120)) {              // :244 REKEY_AFTER_TIME
                    handshake_initiation_required = true;
                }
                // REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT = 165s (:255).
                if (session_established < data_packet_received &&
                    now_ms - session_established >= ms_of(180) - ms_of(10) - ms_of(5)) {
                    handshake_initiation_required = true;
                }
            }
            // KEEPALIVE + REKEY_TIMEOUT (:271).
            if (data_packet_sent > aut_packet_received &&
                now_ms - aut_packet_received >= ms_of(10) + ms_of(5) &&
                exchange_clear(timers.want_handshake)) {
                handshake_initiation_required = true;
            }
            if (!handshake_initiation_required) {
                // KEEPALIVE_TIMEOUT (:282).
                if (data_packet_received > aut_packet_sent &&
                    now_ms - aut_packet_sent >= ms_of(10) &&
                    exchange_clear(timers.want_keepalive)) {
                    keepalive_required = true;
                }
                // PERSISTENT_KEEPALIVE (:291).
                if (timers.persistent_keepalive > 0 &&
                    now_ms - timers.stamps[TimePersistentKeepalive] >=
                        ms_of(timers.persistent_keepalive)) {
                    timer_tick(TimePersistentKeepalive);
                    keepalive_required = true;
                }
            }
        }

        if (handshake_initiation_required) {
            return format_handshake_initiation(true);                          // :304
        }
        if (keepalive_required) {
            return encapsulate({});                                            // :308
        }
        return TunnResult::done();
    }

    TunnResult encapsulate(std::span<const std::uint8_t> src) {                // mod.rs:250
        auto& existing = slot(current);
        if (existing) {
            auto packet = existing->format_packet_data(src);
            if (!packet) {
                return TunnResult::err(packet.error());
            }
            timer_tick(TimeLastPacketSent);
            if (!src.empty()) {
                timer_tick(TimeLastDataPacketSent);
            }
            tx_bytes += src.size();
            return TunnResult::to_network(std::move(*packet));
        }
        queue_packet(src);
        return format_handshake_initiation(false);
    }

    TunnResult decapsulate(std::optional<IpAddress> src_addr,
                           std::span<const std::uint8_t> datagram) {           // mod.rs:276
        if (datagram.empty()) {
            return send_queued_packet();                                       // :282
        }
        VerifyOutcome outcome = rate_limiter.verify(src_addr, datagram);
        if (outcome.error) {
            return TunnResult::err(*outcome.error);                            // :297
        }
        if (!outcome.cookie_reply.empty()) {
            return TunnResult::to_network(std::move(outcome.cookie_reply));    // :293
        }
        if (!outcome.packet) {
            return TunnResult::err(WgError::InvalidPacket);
        }
        return handle_verified_packet(std::move(*outcome.packet));             // :301
    }

    static bool exchange_clear(bool& flag) {
        const bool previous = flag;
        flag = false;
        return previous;
    }
};

Tunn::Tunn(Config config) : impl_(std::make_unique<Impl>(config)) {}
Tunn::~Tunn() = default;
Tunn::Tunn(Tunn&&) noexcept = default;
Tunn& Tunn::operator=(Tunn&&) noexcept = default;

TunnResult Tunn::encapsulate(std::span<const std::uint8_t> src) {
    return impl_->encapsulate(src);
}

TunnResult Tunn::decapsulate(std::optional<IpAddress> src_addr,
                             std::span<const std::uint8_t> datagram) {
    return impl_->decapsulate(src_addr, datagram);
}

TunnResult Tunn::update_timers() { return impl_->update_timers(); }

TunnResult Tunn::format_handshake_initiation(bool force_resend) {
    return impl_->format_handshake_initiation(force_resend);
}

bool Tunn::is_expired() const { return impl_->handshake.is_expired(); }

std::optional<std::uint64_t> Tunn::time_since_last_handshake_ms() const {
    const std::uint64_t full = impl_->current;
    if (!impl_->slot(full).has_value()) {
        return std::nullopt;                                                   // timers.rs:322
    }
    return since(impl_->now(), impl_->timers.stamps[TimeSessionEstablished]);  // timers.rs:314
}

std::optional<std::uint16_t> Tunn::persistent_keepalive() const {
    if (impl_->timers.persistent_keepalive > 0) {
        return static_cast<std::uint16_t>(impl_->timers.persistent_keepalive); // timers.rs:326
    }
    return std::nullopt;
}

Session* Tunn::current_session() {
    auto& existing = impl_->slot(impl_->current);
    return existing ? &*existing : nullptr;
}

// ---------------------------------------------------------------------------
// The socket loop's hemeranoize call sites (wireguard.rs:243-264, :277-285, :573-575).

void send_data_packet(transport::UdpIo& sock, const SocketAddr& peer,
                      const hemeranoize::HemeraNoizeConfig& cfg,
                      std::span<const std::uint8_t> packet, bool& obfuscation_sent,
                      bool& post_handshake_junk_sent) {
    // wireguard.rs:248-255. The latch goes up before the curtain runs, which is what `*sent = true;
    // drop(sent);` before the await at :251-252 buys: a second packet that arrives while the first
    // is still sleeping does not start a second curtain. apply_obfuscation guards on is_enabled()
    // itself (hemeranoize.rs:318); the Rust guards twice, at :250 and there, and so does this.
    if (!obfuscation_sent && cfg.is_enabled()) {
        obfuscation_sent = true;
        hemeranoize::apply_obfuscation(sock, peer, cfg);
    }

    // wireguard.rs:257 `let _ = sock_w.send(&pkt_vec).await;` -- the tunnel's own packet, after the
    // noise it was wrapped in and before any junk that follows it. The result is dropped, as Rust's
    // is: a lost WG packet is a retransmit, which update_timers arranges for.
    (void)sock.send(peer, packet);

    // wireguard.rs:259-264, the comment of which is the rule: post-handshake junk once, not on
    // every data packet. The count test comes first, so a profile that wants none never takes the
    // second latch's branch at all.
    if (cfg.jc_after_hs > 0 && !post_handshake_junk_sent) {
        post_handshake_junk_sent = true;
        hemeranoize::send_post_handshake_junk(sock, peer, cfg);
    }
}

void send_timer_packet(transport::UdpIo& sock, const hemeranoize::HemeraNoizeConfig& cfg,
                       std::span<const std::uint8_t> packet) {
    // wireguard.rs:282-284: the junk first, then the keepalive. Behind it would be a cover story of
    // exactly nothing, and the Rust's order is the one the deep-packet box sees.
    if (cfg.is_enabled()) hemeranoize::send_keepalive_junk(sock, cfg);

    // wireguard.rs:285 `let _ = sock_t.send(&pkt_vec).await;`. The destination is unset because the
    // timer task has no peer to name -- wireguard.rs:271-272 moves only the tunnel and sock_t into
    // it -- and sock_t is the connected clone of :157, whose every write is send() and never
    // send_to(). bind_via_upstream's socket is connected at upstream.rs:622 before the loop starts.
    (void)sock.send(SocketAddr{}, packet);
}

void pre_handshake_obfuscation(transport::UdpIo& sock, const SocketAddr& peer,
                               const hemeranoize::HemeraNoizeConfig& cfg) {
    // wireguard.rs:573-575, verify_endpoint_keep_session: the curtain on a fresh socket, after
    // bind_via_upstream at :568 and before Tunn::new at :580, so the initiation packet that leaves at
    // :606 is the first thing behind the noise. It is a different call site from send_data_packet's
    // latch, which is why it has no latch: this function runs once per verification, on a socket that
    // has never carried anything. The is_enabled() test is the Rust's own (:573) and apply_obfuscation
    // repeats it (hemeranoize.rs:318); both stay.
    if (cfg.is_enabled()) hemeranoize::apply_obfuscation(sock, peer, cfg);
}

} // namespace hemera::core::wireguard
