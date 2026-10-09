#include "sniff.hpp"

#include "dns.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iterator>
#include <string_view>

namespace aether::core {
namespace {

    constexpr std::uint8_t TLS_HANDSHAKE = 0x16;
    constexpr std::uint8_t TLS_CLIENT_HELLO = 0x01;
    constexpr std::uint16_t EXT_SERVER_NAME = 0x0000;
    constexpr std::uint8_t SNI_HOST_NAME = 0x00;

    constexpr std::size_t MAX_HOST_LEN = 253;

    // The number `width` bytes at `at` hold, in network order; nothing when they are not there.
    std::optional<std::size_t> read_be(std::span<const std::uint8_t> buf, std::size_t at,
                                       std::size_t width) {
        if (at > buf.size() || width > buf.size() - at) return std::nullopt;
        std::size_t value = 0;
        for (std::size_t i = 0; i < width; ++i) value = (value << 8) | buf[at + i];
        return value;
    }

    std::optional<std::size_t> read_be16(std::span<const std::uint8_t> buf, std::size_t at) {
        return read_be(buf, at, 2);
    }

    // `at + width`, or nothing when it does not fit -- the way the arithmetic is checked in Rust.
    std::optional<std::size_t> after(std::size_t at, std::size_t width) {
        if (width > SIZE_MAX - at) return std::nullopt;
        return at + width;
    }

    bool space(std::uint8_t c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == 0x0c;
    }

    bool host_char(std::uint8_t c) {
        return std::isalnum(c) != 0 || c == '-' || c == '.' || c == '_';
    }

    std::string lowered(std::string_view text) {
        std::string out(text);
        for (char& c : out) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return out;
    }

    std::string_view trim_space(std::string_view text) {
        while (!text.empty() && space(static_cast<std::uint8_t>(text.front()))) {
            text = text.substr(1);
        }
        while (!text.empty() && space(static_cast<std::uint8_t>(text.back()))) {
            text = text.substr(0, text.size() - 1);
        }
        return text;
    }

    std::span<const std::uint8_t> bytes_of(std::string_view text) {
        return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
    }

    std::optional<std::string> first_server_name(std::span<const std::uint8_t> data) {
        const auto list_len = read_be16(data, 0);
        if (!list_len) return std::nullopt;
        const auto listed = after(2, *list_len);
        if (!listed) return std::nullopt;
        const std::size_t list_end = std::min(*listed, data.size());

        std::size_t at = 2;
        while (at + 3 <= list_end) {
            const std::uint8_t kind = data[at];
            const auto length = read_be16(data, at + 1);
            if (!length) return std::nullopt;
            const std::size_t start = at + 3;
            const auto end = after(start, *length);
            if (!end) return std::nullopt;
            if (*end > list_end) return std::nullopt;
            if (kind == SNI_HOST_NAME) return plausible_host(data.subspan(start, *end - start));
            at = *end;
        }
        return std::nullopt;
    }

    bool looks_like_http(std::string_view line) {
        constexpr std::string_view methods[] = {"GET ",   "POST ",  "PUT ",   "HEAD ",  "DELETE ",
                                               "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "};
        return std::any_of(std::begin(methods), std::end(methods),
                           [line](std::string_view method) { return line.starts_with(method); }) &&
               line.contains("HTTP/");
    }

} // namespace

std::optional<std::string> plausible_host(std::span<const std::uint8_t> raw) {
    if (raw.empty() || raw.size() > MAX_HOST_LEN) return std::nullopt;

    std::size_t begin = 0;
    std::size_t end = raw.size();
    while (begin < end && space(raw[begin])) ++begin;
    while (end > begin && space(raw[end - 1])) --end;
    while (end > begin && raw[end - 1] == '.') --end;
    const std::string_view name{reinterpret_cast<const char*>(raw.data()) + begin, end - begin};
    if (name.empty() || name.size() > MAX_HOST_LEN) return std::nullopt;

    if (!std::all_of(name.begin(), name.end(),
                     [](char c) { return host_char(static_cast<std::uint8_t>(c)); })) {
        return std::nullopt;
    }
    if (!name.contains('.')) return std::nullopt;
    // An address in a Server Name is no name to match a rule against.
    if (ip_literal(name)) return std::nullopt;

    return lowered(name);
}

std::optional<std::string> tls_sni(std::span<const std::uint8_t> buf) {
    if (buf.empty() || buf[0] != TLS_HANDSHAKE) return std::nullopt;

    const auto record_len = read_be16(buf, 3);
    if (!record_len) return std::nullopt;
    const auto record_end = after(5, *record_len);
    if (!record_end || *record_end < 5) return std::nullopt;
    const std::span<const std::uint8_t> body =
        buf.subspan(5, std::min(*record_end, buf.size()) - 5);
    if (body.empty() || body[0] != TLS_CLIENT_HELLO) return std::nullopt;

    const auto hello_len = read_be(body, 1, 3);
    if (!hello_len) return std::nullopt;
    const auto hello_end = after(4, *hello_len);
    if (!hello_end || *hello_end < 4) return std::nullopt;
    const std::span<const std::uint8_t> hello =
        body.subspan(4, std::min(*hello_end, body.size()) - 4);

    std::size_t at = 2 + 32;
    if (at >= hello.size()) return std::nullopt;

    const auto advanced = after(at, 1 + hello[at]);
    if (!advanced) return std::nullopt;
    at = *advanced;

    const auto cipher_len = read_be16(hello, at);
    if (!cipher_len) return std::nullopt;
    const auto past_ciphers = after(at, 2 + *cipher_len);
    if (!past_ciphers) return std::nullopt;
    at = *past_ciphers;

    if (at >= hello.size()) return std::nullopt;
    const auto past_compression = after(at, 1 + hello[at]);
    if (!past_compression) return std::nullopt;
    at = *past_compression;

    const auto extensions_len = read_be16(hello, at);
    if (!extensions_len) return std::nullopt;
    const auto extensions_at = after(at, 2);
    if (!extensions_at) return std::nullopt;
    const auto listed = after(*extensions_at, *extensions_len);
    if (!listed) return std::nullopt;
    const std::size_t extensions_end = std::min(*listed, hello.size());

    at = *extensions_at;
    while (at + 4 <= extensions_end) {
        const auto kind = read_be16(hello, at);
        if (!kind) return std::nullopt;
        const auto length = read_be16(hello, at + 2);
        if (!length) return std::nullopt;
        const std::size_t data_start = at + 4;
        const auto data_end = after(data_start, *length);
        if (!data_end) return std::nullopt;
        if (*data_end > extensions_end) return std::nullopt;
        if (*kind == EXT_SERVER_NAME) {
            return first_server_name(hello.subspan(data_start, *data_end - data_start));
        }
        at = *data_end;
    }
    return std::nullopt;
}

std::optional<std::string> http_host(std::span<const std::uint8_t> buf) {
    const std::string_view head{reinterpret_cast<const char*>(buf.data()),
                                 std::min(buf.size(), PEEK_BUDGET)};
    std::size_t at = 0;

    // The next segment of `head` split on "\r\n", as Rust's split yields them: a trailing
    // separator has an empty segment after it, and a last line with no separator at all is
    // still a line. Nothing once the text runs out.
    auto next_line = [&]() -> std::optional<std::string_view> {
        if (at > head.size()) return std::nullopt;
        const std::size_t cut = head.find("\r\n", at);
        if (cut == std::string_view::npos) {
            const std::string_view line = head.substr(at);
            at = head.size() + 1;
            return line;
        }
        const std::string_view line = head.substr(at, cut - at);
        at = cut + 2;
        return line;
    };

    const auto request_line = next_line();
    if (!request_line || !looks_like_http(*request_line)) return std::nullopt;

    for (auto line = next_line(); line; line = next_line()) {
        if (line->empty()) break;
        const std::size_t colon = line->find(':');
        if (colon == std::string_view::npos) continue;
        const std::string_view name = trim_space(line->substr(0, colon));
        std::string_view value = trim_space(line->substr(colon + 1));
        if (lowered(name) != "host") continue;

        const std::size_t last = value.rfind(':');
        if (last != std::string_view::npos &&
            std::all_of(value.begin() + static_cast<std::ptrdiff_t>(last) + 1, value.end(),
                        [](char c) { return c >= '0' && c <= '9'; })) {
            value = value.substr(0, last);
        }
        return plausible_host(bytes_of(value));
    }
    return std::nullopt;
}

std::optional<std::string> sniff_hostname(std::span<const std::uint8_t> buf) {
    if (auto name = tls_sni(buf)) return name;
    return http_host(buf);
}

} // namespace aether::core
