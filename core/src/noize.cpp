#include "noize.hpp"

#include "transport.hpp" // transport::UdpIo, the seam noize.rs's &UdpSocket becomes here

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <random>
#include <string>
#include <thread>

namespace aether::core::noize {
namespace {

std::mt19937_64& entropy() {
    thread_local std::mt19937_64 generator{std::random_device{}()};
    return generator;
}

// Inclusive on both ends, exactly like the Rust core's `lo..=hi`.
std::size_t between(std::size_t lo, std::size_t hi) {
    return std::uniform_int_distribution<std::size_t>{lo, hi}(entropy());
}

void fill_random(std::vector<std::uint8_t>& bytes) {
    std::generate(bytes.begin(), bytes.end(), [] {
        return static_cast<std::uint8_t>(entropy()() & 0xff);
    });
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

// The bytes `hex` holds, or nothing when it is an odd number of them or carries a character
// that is no digit -- the way hex::decode refuses.
std::optional<std::vector<std::uint8_t>> unhex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    std::uint8_t byte = 0;
    for (std::size_t i = 0; i < hex.size(); ++i) {
        const char c = hex[i];
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

// ---------------------------------------------------------------------------
// The sender's three small rules, kept apart so pre_handshake below reads like noize.rs.

// noize.rs:171-173 and 193-195 -- `if !cfg.junk_interval.is_zero() { sleep(...) }`. The Rust
// sleeps after every junk packet of the loop, the last one included, and this is no place to be
// clever about it: the gap before the ClientHello is part of what the noise looks like.
void pause_between(std::chrono::milliseconds interval) {
    if (interval.count() != 0) std::this_thread::sleep_for(interval);
}

// The two lines every send in pre_handshake answers with: "{label} sent {n} bytes" at trace, or
// "{label} send failed: {e}" at debug. noize.rs writes these four pairs by hand (168-169,
// 180-181, 190-191, 202-203); one function means none of them can drift from the wording, and the
// error text is UdpIo's own -- "send: socket error 10065" and friends -- which is what Rust's {e}
// prints for an io::Error. Nothing here can name a key, a certificate or a token.
void report(const Note& note, const std::expected<std::size_t, std::string>& sent,
            std::string_view label) {
    if (!note) return;
    if (sent) {
        note(Level::Trace, std::string(label) + " sent " + std::to_string(*sent) + " bytes");
    } else {
        note(Level::Debug, std::string(label) + " send failed: " + sent.error());
    }
}

// noize.rs:151-154, the address send_to aims at. Rust reads it through local_addr(), which answers
// an error only for a socket that was never bound; here local() has no error to give and the unset
// SocketAddr is that same "no address known", which is when Rust falls back to the peer. A relay
// that is empty is the same fallback for a different reason: the detour table has no entry for
// this socket, so the intended peer is where the packet goes.
SocketAddr junk_target(transport::UdpIo& io, const SocketAddr& peer, const RelayTarget& relay) {
    if (!relay) return peer;
    const SocketAddr local = io.local();
    if (local.port == 0 && local.ip == IpAddress{}) return peer;
    return relay(local, peer);
}

} // namespace

NoizeConfig NoizeConfig::off() {
    return {};
}

NoizeConfig NoizeConfig::firewall() {
    NoizeConfig cfg;
    cfg.jc_before_hs = 2;
    cfg.jc_after_i1 = 2;
    cfg.jmin = 48;
    cfg.jmax = 190;
    cfg.i1 = std::string("<b 0d0a0d0a><t><r 24>");
    cfg.i2 = std::string("<r 48>");
    cfg.junk_interval = std::chrono::milliseconds(4);
    return cfg;
}

NoizeConfig NoizeConfig::light() {
    NoizeConfig cfg;
    cfg.jc_before_hs = 1;
    cfg.jc_after_i1 = 0;
    cfg.jmin = 32;
    cfg.jmax = 96;
    cfg.i1 = std::string("<b 0d0a0d0a><t><r 16>");
    cfg.junk_interval = std::chrono::milliseconds(3);
    return cfg;
}

NoizeConfig NoizeConfig::gfw() {
    NoizeConfig cfg;
    cfg.jc_before_hs = 2;
    cfg.jc_after_i1 = 1;
    cfg.jmin = 64;
    cfg.jmax = 256;
    cfg.i1 = std::string("<b 0d0a0d0a><t><r 24>");
    cfg.i2 = std::string("<r 32>");
    cfg.junk_interval = std::chrono::milliseconds(5);
    return cfg;
}

bool NoizeConfig::is_enabled() const {
    return jc_before_hs > 0 || jc_after_i1 > 0 || i1.has_value();
}

NoizeConfig from_profile(std::string_view name) {
    if (name == "off" || name == "none") return NoizeConfig::off();
    if (name == "light") return NoizeConfig::light();
    if (name == "gfw" || name == "aggressive" || name == "heavy") return NoizeConfig::gfw();
    return NoizeConfig::firewall();
}

std::vector<std::uint8_t> junk_packet(const NoizeConfig& cfg) {
    std::size_t lo = 40;
    std::size_t hi = 90;
    if (cfg.jmax > cfg.jmin && cfg.jmin > 0) {
        lo = cfg.jmin;
        hi = cfg.jmax;
    }
    std::vector<std::uint8_t> buf(between(lo, hi));
    fill_random(buf);
    return buf;
}

std::vector<std::uint8_t> parse_cps(std::string_view spec) {
    std::vector<std::uint8_t> out;
    std::size_t i = 0;
    while (i < spec.size()) {
        if (spec[i] != '<') {
            ++i;
            continue;
        }
        const std::size_t end = spec.find('>', i);
        if (end == std::string_view::npos) break;
        const std::string_view inner = trim(spec.substr(i + 1, end - i - 1));
        const std::size_t gap = inner.find_first_of(" \t\n\r\v\f");
        const std::string_view tag = gap == std::string_view::npos ? inner : inner.substr(0, gap);
        const std::string_view data =
            gap == std::string_view::npos ? std::string_view{} : trim(inner.substr(gap));

        if (tag == "b") {
            std::string packed;
            for (const char c : data) {
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != 0x0b && c != 0x0c) {
                    packed += c;
                }
            }
            if (auto bytes = unhex(packed)) out.insert(out.end(), bytes->begin(), bytes->end());
        } else if (tag == "t") {
            append_be<std::uint32_t>(
                out, static_cast<std::uint32_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count()));
        } else if (tag == "n") {
            append_be<std::uint64_t>(out, entropy()());
        } else if (tag == "r") {
            std::size_t len = 0;
            bool digits = !data.empty();
            for (const char c : data) {
                if (std::isdigit(static_cast<unsigned char>(c)) == 0) digits = false;
            }
            if (digits) {
                for (const char c : data) len = len * 10 + static_cast<std::size_t>(c - '0');
            }
            len = std::min<std::size_t>(len, 1024);
            if (len > 0) {
                std::vector<std::uint8_t> r(len);
                fill_random(r);
                out.insert(out.end(), r.begin(), r.end());
            }
        }

        i = end + 1;
    }
    return out;
}

std::expected<std::size_t, std::string>
send_junk(transport::UdpIo& io, const SocketAddr& peer, std::span<const std::uint8_t> packet,
          const RelayTarget& relay) {
    // noize.rs:147-156. Rust's two arms -- send() on a connected socket, send_to(relay_target) on
    // an unconnected one -- are the two branches of WinUdp::send (transport.cpp:249-259), so this
    // hands over the destination it would send_to and the socket decides which of the two it is.
    return io.send(junk_target(io, peer, relay), packet);
}

void pre_handshake(transport::UdpIo& io, const SocketAddr& peer, const NoizeConfig& cfg,
                   const RelayTarget& relay, const Note& note) {
    // noize.rs:159-161. An off profile is not "send nothing and say so": it is this return, with
    // no line and no sleep, which is why --noize off costs the handshake nothing.
    if (!cfg.is_enabled()) return;

    // noize.rs:163. The count is the profile's, and it is written before the first packet so a
    // host that filters trace away still sees the plan when it does not.
    if (note) {
        note(Level::Trace,
             "sending " + std::to_string(cfg.jc_before_hs) + " junk packets before handshake");
    }

    // noize.rs:165-174: the junk ahead of everything, each packet its own random size and bytes.
    for (std::size_t i = 0; i < cfg.jc_before_hs; ++i) {
        const std::vector<std::uint8_t> pkt = junk_packet(cfg);
        report(note, send_junk(io, peer, pkt, relay), "junk[" + std::to_string(i) + "]");
        pause_between(cfg.junk_interval);
    }

    // noize.rs:176-185: the signature, and only when it parses to bytes at all. A spec of nothing
    // -- an unknown tag, hex hex::decode refuses -- sends nothing and so takes no pause either,
    // exactly as Rust's `if !pkt.is_empty()` makes it.
    if (cfg.i1) {
        const std::vector<std::uint8_t> pkt = parse_cps(*cfg.i1);
        if (!pkt.empty()) {
            report(note, send_junk(io, peer, pkt, relay), "signature i1");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // noize.rs:187-196: the junk that follows the signature, labelled junk_after so the two runs
    // tell each other apart in a log even though they are the same junk_packet().
    for (std::size_t i = 0; i < cfg.jc_after_i1; ++i) {
        const std::vector<std::uint8_t> pkt = junk_packet(cfg);
        report(note, send_junk(io, peer, pkt, relay), "junk_after[" + std::to_string(i) + "]");
        pause_between(cfg.junk_interval);
    }

    // noize.rs:198-206: and the tail signature, which gets no pause after it because the Rust
    // gives it none -- the ClientHello is meant to follow straight on.
    if (cfg.i2) {
        const std::vector<std::uint8_t> pkt = parse_cps(*cfg.i2);
        if (!pkt.empty()) {
            report(note, send_junk(io, peer, pkt, relay), "signature i2");
        }
    }

    // noize.rs:208.
    if (note) note(Level::Trace, "obfuscation pre-handshake complete");
}

} // namespace aether::core::noize
