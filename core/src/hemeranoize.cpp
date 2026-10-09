#include "hemeranoize.hpp"

#include "transport.hpp" // UdpIo, the socket the three senders below write through

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <random>
#include <span>
#include <string>
#include <thread>

namespace hemera::core::hemeranoize {
namespace {

std::mt19937_64& entropy() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

// Inclusive on both ends, exactly like the Rust core's `lo..=hi`.
std::size_t between(std::size_t lo, std::size_t hi) {
    return std::uniform_int_distribution<std::size_t>{lo, hi}(entropy());
}

std::uint8_t random_byte() {
    return static_cast<std::uint8_t>(entropy()() & 0xff);
}

void fill_bytes(std::vector<std::uint8_t>& bytes) {
    std::generate(bytes.begin(), bytes.end(), random_byte);
}

template <typename N>
void append_be(std::vector<std::uint8_t>& out, N value) {
    for (std::size_t i = 0; i < sizeof(N); ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * (sizeof(N) - 1 - i))));
    }
}

std::string_view trim(std::string_view text) {
    const auto space = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c;
    };
    while (!text.empty() && space(text.front())) text = text.substr(1);
    while (!text.empty() && space(text.back())) text = text.substr(0, text.size() - 1);
    return text;
}

// `text` as a size, or nothing when it is no run of digits. Past a megabyte the digits stop
// mattering; every caller caps the result anyway.
std::optional<std::size_t> size_of(std::string_view text) {
    text = trim(text);
    if (text.empty()) return std::nullopt;
    std::size_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + static_cast<std::size_t>(c - '0');
        if (value > 1'048'576) return value;
    }
    return value;
}

// `min-max` picks a size inside it, a plain number is that size, and anything else is none. No
// length above 2 KiB is ever asked for.
std::size_t parse_range(std::string_view data) {
    constexpr std::size_t cap = 2048;
    const std::size_t dash = data.find('-');
    if (dash != std::string_view::npos) {
        const std::optional<std::size_t> lo = size_of(data.substr(0, dash));
        const std::optional<std::size_t> hi = size_of(data.substr(dash + 1));
        const std::size_t min = lo.value_or(0);
        const std::size_t max = hi.value_or(0);
        if (max > min && min > 0) return std::min(between(min, max), cap);
    }
    return std::min(size_of(data).value_or(0), cap);
}

bool lower_letter(char c) {
    return c >= 'a' && c <= 'z';
}

// The bytes `hex` holds, with its whitespace and an `0x` gone, or nothing when hex::decode would
// have refused it.
std::optional<std::vector<std::uint8_t>> unhex(std::string_view hex) {
    std::string packed;
    for (const char c : hex) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != 0x0b && c != 0x0c) {
            packed += c;
        }
    }
    if (packed.starts_with("0x") || packed.starts_with("0X")) packed.erase(0, 2);
    if (packed.size() % 2 != 0) return std::nullopt;

    std::vector<std::uint8_t> out;
    out.reserve(packed.size() / 2);
    std::uint8_t byte = 0;
    for (std::size_t i = 0; i < packed.size(); ++i) {
        const char c = packed[i];
        std::uint8_t digit{};
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint8_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint8_t>(c - 'A' + 10);
        } else {
            return std::nullopt;
        }
        byte = static_cast<std::uint8_t>(byte << 4 | digit);
        if (i % 2 == 1) out.push_back(byte);
    }
    return out;
}

std::atomic<std::uint32_t> counter{1};

constexpr std::uint8_t IKE_HEADER[] = {0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04,
                                       0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0c,
                                       0x00, 0x00, 0x00, 0x00};

// ---------------------------------------------------------------------------
// The two rules the three senders share, kept apart so they read like hemeranoize.rs.

// hemeranoize.rs:313-315 -- `async fn send_connected(sock, pkt) { let _ = sock.send(pkt).await; }`.
// One write on the socket, its result dropped. Rust's sock.send() is the connected-socket write and
// there is no send_to anywhere in :313-400, so the destination cannot matter; WinUdp::send already
// makes that same choice internally (transport.cpp:249-259: a connected socket takes ::send and
// ignores the destination), so handing it `peer` is faithful to the arm Rust has and adds no second
// way of saying it. A dropped result means a failed send is a missing junk packet and nothing else
// -- junk never decides whether the tunnel comes up, and the Rust logs nothing here either.
void send_connected(transport::UdpIo& sock, const SocketAddr& peer,
                    const std::vector<std::uint8_t>& packet) {
    (void)sock.send(peer, std::span<const std::uint8_t>{packet});
}

// The `if !interval.is_zero() { sleep(interval) }` the loops repeat (hemeranoize.rs:334-336,
// 342-344, 370-372) and apply_obfuscation's closing handshake_delay shares (357-359). The pause
// comes after the send, the last packet of a run included, because that is how the Rust loop is
// written: the gap ahead of the caller's real packet is part of what the noise looks like.
void pause_between(std::chrono::milliseconds interval) {
    if (interval.count() != 0) std::this_thread::sleep_for(interval);
}

} // namespace

HemeraNoizeConfig HemeraNoizeConfig::off() {
    return {};
}

HemeraNoizeConfig HemeraNoizeConfig::light() {
    HemeraNoizeConfig cfg;
    cfg.i1 = std::string("<b 0d0a0d0a><t><r 20-32>");
    cfg.i2 = std::string("<rc 24-48>");
    cfg.jc = 4;
    cfg.jc_before_hs = 2;
    cfg.jc_after_i1 = 1;
    cfg.jc_after_hs = 1;
    cfg.jmin = 48;
    cfg.jmax = 190;
    cfg.junk_interval = std::chrono::milliseconds(3);
    cfg.handshake_delay = std::chrono::milliseconds(5);
    return cfg;
}

HemeraNoizeConfig HemeraNoizeConfig::balanced() {
    HemeraNoizeConfig cfg;
    cfg.i1 = std::string("<b 0d0a0d0a><t><rc 20-40>");
    cfg.i2 = std::string("<b 504f5354><rd 10-20><rc 20-30>");
    cfg.i3 = std::string("<r 30-50>");
    cfg.jc = 6;
    cfg.jc_before_hs = 3;
    cfg.jc_after_i1 = 2;
    cfg.jc_after_hs = 1;
    cfg.jmin = 64;
    cfg.jmax = 256;
    cfg.junk_interval = std::chrono::milliseconds(2);
    cfg.handshake_delay = std::chrono::milliseconds(8);
    return cfg;
}

HemeraNoizeConfig HemeraNoizeConfig::aggressive() {
    HemeraNoizeConfig cfg;
    cfg.i1 = std::string("<b 0d0a0d0a><t><rc 40-64>");
    cfg.i2 = std::string("<b 504f5354><t><rd 15-30><rc 30-50>");
    cfg.i3 = std::string("<b 474554><rc 40-60>");
    cfg.i4 = std::string("<r 60-100>");
    cfg.i5 = std::string("<c><rd 20-40>");
    cfg.jc = 10;
    cfg.jc_before_hs = 4;
    cfg.jc_after_i1 = 3;
    cfg.jc_after_hs = 3;
    cfg.jmin = 80;
    cfg.jmax = 384;
    cfg.junk_interval = std::chrono::milliseconds(1);
    cfg.handshake_delay = std::chrono::milliseconds(12);
    return cfg;
}

HemeraNoizeConfig HemeraNoizeConfig::firewall() {
    HemeraNoizeConfig cfg;
    cfg.i1 = std::string("<b 0d0a0d0a><t><rc 24-44>");
    cfg.i2 = std::string("<b 504f5354><c><rd 12-24><rc 24-36>");
    cfg.i3 = std::string("<b 474554><r 30-50>");
    cfg.jc = 7;
    cfg.jc_before_hs = 3;
    cfg.jc_after_i1 = 2;
    cfg.jc_after_hs = 2;
    cfg.jmin = 64;
    cfg.jmax = 300;
    cfg.junk_interval = std::chrono::milliseconds(2);
    cfg.handshake_delay = std::chrono::milliseconds(10);
    return cfg;
}

HemeraNoizeConfig HemeraNoizeConfig::gfw() {
    HemeraNoizeConfig cfg;
    cfg.i1 = std::string("<b 16030100><c><rc 48-72>");
    cfg.i2 = std::string("<b 0d0a0d0a><t><rd 20-40><rc 36-60>");
    cfg.i3 = std::string("<b 474554202f20485454502f312e31><rc 40-64>");
    cfg.i4 = std::string("<b 504f5354><c><r 64-110>");
    cfg.i5 = std::string("<rd 24-48><rc 32-56>");
    cfg.jc = 12;
    cfg.jc_before_hs = 5;
    cfg.jc_after_i1 = 3;
    cfg.jc_after_hs = 4;
    cfg.jmin = 96;
    cfg.jmax = 420;
    cfg.junk_interval = std::chrono::milliseconds(1);
    cfg.handshake_delay = std::chrono::milliseconds(16);
    cfg.allow_zero_size = true;
    return cfg;
}

bool HemeraNoizeConfig::is_enabled() const {
    return jc > 0 || i1.has_value();
}

HemeraNoizeConfig from_profile(std::string_view name) {
    const std::string wanted = [&] {
        std::string text(trim(name));
        std::ranges::transform(text, text.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return text;
    }();

    if (wanted == "off" || wanted == "none") return HemeraNoizeConfig::off();
    if (wanted == "light") return HemeraNoizeConfig::light();
    if (wanted == "firewall") return HemeraNoizeConfig::firewall();
    if (wanted == "gfw") return HemeraNoizeConfig::gfw();
    if (wanted == "aggressive" || wanted == "heavy") return HemeraNoizeConfig::aggressive();
    return HemeraNoizeConfig::balanced();
}

std::vector<std::uint8_t> parse_cps(std::string_view spec) {
    std::vector<std::uint8_t> out;

    for (std::size_t at = spec.find('<'); at != std::string_view::npos;
         at = spec.find('<', at + 1)) {
        std::size_t named = at + 1;
        while (named < spec.size() && lower_letter(spec[named])) ++named;
        if (named == at + 1) continue; // <([a-z]+)> wants a tag name
        const std::string_view tag = spec.substr(at + 1, named - at - 1);

        std::size_t data_at = named;
        while (data_at < spec.size() &&
               std::isspace(static_cast<unsigned char>(spec[data_at])) != 0) {
            ++data_at;
        }
        const std::size_t end = spec.find('>', data_at);
        if (end == std::string_view::npos) break; // [^>]*> wants it closed
        const std::string_view data = spec.substr(data_at, end - data_at);
        at = end;

        if (tag == "b") {
            if (auto bytes = unhex(data)) {
                out.insert(out.end(), bytes->begin(), bytes->end());
            }
        } else if (tag == "t") {
            const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch());
            append_be<std::uint32_t>(out, static_cast<std::uint32_t>(secs.count()));
        } else if (tag == "c") {
            append_be<std::uint32_t>(
                out, counter.fetch_add(1, std::memory_order_relaxed));
        } else if (tag == "r" || tag == "rc" || tag == "rd") {
            const std::size_t len = parse_range(data);
            if (len == 0) continue;
            std::vector<std::uint8_t> run(len);
            if (tag == "r") {
                fill_bytes(run);
            } else {
                std::string_view alphabet =
                    tag == "rc" ? std::string_view("abcdefghijklmnopqrstuvwxyz"
                                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                                : std::string_view("0123456789");
                for (std::uint8_t& c : run) {
                    c = static_cast<std::uint8_t>(alphabet[between(0, alphabet.size() - 1)]);
                }
            }
            out.insert(out.end(), run.begin(), run.end());
        }
    }

    return out;
}

std::vector<std::uint8_t> wrap_ikev2(std::span<const std::uint8_t> payload) {
    if (payload.empty()) return {};

    std::vector<std::uint8_t> header;
    header.reserve(28 + payload.size());

    if (payload.size() >= 8) {
        header.insert(header.end(), payload.begin(), payload.begin() + 8);
    } else {
        for (int i = 0; i < 8; ++i) header.push_back(random_byte());
    }
    for (int i = 0; i < 8; ++i) header.push_back(random_byte());

    header.insert(header.end(), {0x21, 0x20, 0x22, 0x08});
    header.insert(header.end(), {0x00, 0x00, 0x00, 0x00});
    append_be<std::uint32_t>(header, static_cast<std::uint32_t>(28 + 24 + payload.size()));
    header.insert(header.end(), {0x00, 0x00});
    append_be<std::uint16_t>(header,
                             static_cast<std::uint16_t>(static_cast<std::size_t>(24) +
                                                        payload.size()));
    header.insert(header.end(), IKE_HEADER, IKE_HEADER + std::size(IKE_HEADER));
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

std::vector<std::uint8_t> generate_junk(const HemeraNoizeConfig& cfg) {
    std::size_t min_size = cfg.jmin;
    std::size_t max_size = cfg.jmax;

    if (cfg.jmin == 0 && cfg.jmax == 0) {
        return cfg.allow_zero_size ? std::vector<std::uint8_t>{}
                                   : std::vector<std::uint8_t>{0x00};
    }
    if (cfg.jmax == 0) {
        min_size = max_size = std::max<std::size_t>(cfg.jmin, 1);
    } else if (!cfg.allow_zero_size) {
        min_size = std::max<std::size_t>(cfg.jmin, 1);
        max_size = std::max(cfg.jmax, min_size);
    } else {
        max_size = std::max(cfg.jmax, cfg.jmin);
    }

    const std::size_t size =
        max_size == min_size ? min_size : between(min_size, max_size);
    if (size == 0) {
        return cfg.allow_zero_size ? std::vector<std::uint8_t>{}
                                   : std::vector<std::uint8_t>{0x00};
    }

    std::vector<std::uint8_t> junk(size);
    fill_bytes(junk);
    return junk;
}

void apply_obfuscation(transport::UdpIo& sock, const SocketAddr& peer,
                       const HemeraNoizeConfig& cfg) {
    // hemeranoize.rs:318-320: an off profile neither sends nor sleeps nor says anything; it returns.
    if (!cfg.is_enabled()) return;

    // hemeranoize.rs:322-329: the i1 signature behind an IKE v2 header, and 2 ms after it. wrap_ikev2
    // of a payload is never empty when the payload is not, so the send is unconditional here.
    if (cfg.i1) {
        const std::vector<std::uint8_t> payload = parse_cps(*cfg.i1);
        if (!payload.empty()) {
            const std::vector<std::uint8_t> framed = wrap_ikev2(payload);
            send_connected(sock, peer, framed);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // hemeranoize.rs:331-337.
    for (std::size_t i = 0; i < cfg.jc_after_i1; ++i) {
        const std::vector<std::uint8_t> junk = generate_junk(cfg);
        send_connected(sock, peer, junk);
        pause_between(cfg.junk_interval);
    }

    // hemeranoize.rs:339-345. A second loop rather than one over jc_after_i1 + jc_before_hs, because
    // the Rust runs two and the counts come from different config fields.
    for (std::size_t i = 0; i < cfg.jc_before_hs; ++i) {
        const std::vector<std::uint8_t> junk = generate_junk(cfg);
        send_connected(sock, peer, junk);
        pause_between(cfg.junk_interval);
    }

    // hemeranoize.rs:347-355: i2, i3, i4, i5 in that order, 1 ms after each one that sends. A
    // signature that parses to nothing is skipped without the pause, as the Rust's `if !payload.is_
    // empty()` guard makes it.
    for (const auto* sig : {&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5}) {
        if (!*sig) continue;
        const std::vector<std::uint8_t> pkt = parse_cps(**sig);
        if (pkt.empty()) continue;
        send_connected(sock, peer, pkt);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // hemeranoize.rs:357-359: the caller's cue to start the real handshake is this pause.
    pause_between(cfg.handshake_delay);
}

void send_post_handshake_junk(transport::UdpIo& sock, const SocketAddr& peer,
                              const HemeraNoizeConfig& cfg) {
    // hemeranoize.rs:367-373. No is_enabled() guard, because hemeranoize.rs:362-366 has none: the
    // count decides on its own, and a zero jc_after_hs costs one empty loop.
    for (std::size_t i = 0; i < cfg.jc_after_hs; ++i) {
        const std::vector<std::uint8_t> junk = generate_junk(cfg);
        send_connected(sock, peer, junk);
        pause_between(cfg.junk_interval);
    }
}

void send_keepalive_junk(transport::UdpIo& sock, const HemeraNoizeConfig& cfg) {
    // hemeranoize.rs:377-379.
    if (!cfg.is_enabled()) return;

    // hemeranoize.rs:381-383. `0..=base` is inclusive on both ends, which is the port's `between`,
    // so the run is base+0 .. 2*base packets long -- never zero, never a fixed length.
    const std::size_t base = std::max<std::size_t>(cfg.jc_before_hs, 1);
    const std::size_t extra = between(0, base);
    const std::size_t count = base + extra;

    // hemeranoize.rs:385-399.
    for (std::size_t i = 0; i < count; ++i) {
        std::vector<std::uint8_t> junk = generate_junk(cfg);
        if (!junk.empty() && junk[0] >= 1 && junk[0] <= 4) {
            // The first byte is a WireGuard message type; + 0x40 keeps the packet's length and the
            // rest of its bytes but makes it no recognised type at all. wrapping_add on a u8 is the
            // truncating cast below.
            junk[0] = static_cast<std::uint8_t>(junk[0] + 0x40);
        }
        // The destination is an unset address, and that is the faithful reading: hemeranoize.rs:376
        // is given no peer to name, only the socket and the config, and its send() writes through a
        // socket that is already connected -- wireguard.rs:156-157 clones self.sock, which :107 got
        // from bind_via_upstream, and every write to it is send() and never send_to(). WinUdp takes
        // ::send and ignores the destination in that case, so nothing is aimed at nothing.
        send_connected(sock, SocketAddr{}, junk);

        // hemeranoize.rs:394-398: the gap is the profile's interval plus up to 8 ms, so the
        // keepalive rhythm is never a clock tick either.
        const std::size_t jitter = between(0, 8);
        pause_between(cfg.junk_interval + std::chrono::milliseconds(
                                             static_cast<long long>(jitter)));
    }
}

} // namespace hemera::core::hemeranoize
