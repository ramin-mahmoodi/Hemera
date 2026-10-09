#include "https.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <limits>

namespace hemera::core {
namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string_view trim(std::string_view text) {
    const std::size_t begin = text.find_first_not_of(" \t\r\n\v\f");
    if (begin == std::string_view::npos) return {};
    const std::size_t end = text.find_last_not_of(" \t\r\n\v\f");
    return text.substr(begin, end - begin + 1);
}

// Rust's `str::parse::<usize>()`: digits only, with a leading `+` from_chars refuses, and an
// overflow that is no value rather than a wrapped one.
std::optional<std::size_t> parse_size(std::string_view text) {
    if (text.starts_with('+')) text.remove_prefix(1);
    if (text.empty()) return std::nullopt;
    std::size_t value = 0;
    const auto read = std::from_chars(text.data(), text.data() + text.size(), value);
    if (read.ec != std::errc{} || read.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

// Rust's `usize::from_str_radix(size, 16)`: no sign, at least one digit, and nothing past the
// width of the machine.
std::optional<std::size_t> parse_hex(std::string_view text) {
    if (text.empty()) return std::nullopt;
    std::size_t value = 0;
    for (const char c : text) {
        std::size_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::size_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::size_t>(c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::size_t>(c - 'A') + 10;
        } else {
            return std::nullopt;
        }
        if (value > (std::numeric_limits<std::size_t>::max() - digit) / 16) return std::nullopt;
        value = value * 16 + digit;
    }
    return value;
}

std::string_view as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::size_t find_sequence(std::span<const std::uint8_t> haystack, std::string_view needle) {
    if (haystack.size() < needle.size()) return std::string_view::npos;
    const auto* data = reinterpret_cast<const char*>(haystack.data());
    const std::size_t limit = haystack.size() - needle.size() + 1;
    for (std::size_t at = 0; at < limit; ++at) {
        if (std::memcmp(data + at, needle.data(), needle.size()) == 0) return at;
    }
    return std::string_view::npos;
}

void push_text(std::vector<std::uint8_t>& into, std::string_view text) {
    into.insert(into.end(), text.begin(), text.end());
}

std::vector<std::string_view> split_on(std::string_view text, std::string_view separator) {
    std::vector<std::string_view> pieces;
    std::size_t at = 0;
    for (;;) {
        const std::size_t next = text.find(separator, at);
        if (next == std::string_view::npos) {
            pieces.push_back(text.substr(at));
            break;
        }
        pieces.push_back(text.substr(at, next - at));
        at = next + separator.size();
    }
    return pieces;
}

// The second whitespace-separated token of a status line, which is where the status is.
std::optional<std::uint16_t> status_of(std::string_view line) {
    std::size_t at = 0;
    for (int token = 0; token < 2; ++token) {
        at = line.find_first_not_of(" \t\r\n\v\f", at);
        if (at == std::string_view::npos) return std::nullopt;
        const std::size_t end = line.find_first_of(" \t\r\n\v\f", at);
        const std::string_view piece =
            line.substr(at, end == std::string_view::npos ? std::string_view::npos : end - at);
        if (token == 1) {
            unsigned value = 0;
            const auto read = std::from_chars(piece.data(), piece.data() + piece.size(), value);
            if (read.ec != std::errc{} || read.ptr != piece.data() + piece.size()) {
                return std::nullopt;
            }
            if (value > std::numeric_limits<std::uint16_t>::max()) return std::nullopt;
            return static_cast<std::uint16_t>(value);
        }
        if (end == std::string_view::npos) return std::nullopt;
        at = end;
    }
    return std::nullopt;
}

} // namespace

std::string authority(std::string_view host, std::uint16_t port) {
    std::string text = host.contains(':') ? "[" + std::string(host) + "]" : std::string(host);
    if (port != 443) text += ":" + std::to_string(port);
    return text;
}

std::vector<std::uint8_t> http1_request(std::string_view method, std::string_view host,
                                        std::uint16_t port, std::string_view path,
                                        const std::vector<std::pair<std::string, std::string>>& headers,
                                        std::optional<std::span<const std::uint8_t>> body) {
    std::vector<std::uint8_t> wire;
    push_text(wire, method);
    push_text(wire, " ");
    push_text(wire, path);
    push_text(wire, " HTTP/1.1\r\nHost: ");
    push_text(wire, authority(host, port));
    push_text(wire, "\r\n");
    for (const auto& [name, value] : headers) {
        push_text(wire, name);
        push_text(wire, ": ");
        push_text(wire, value);
        push_text(wire, "\r\n");
    }
    if (body) push_text(wire, "Content-Length: " + std::to_string(body->size()) + "\r\n");
    push_text(wire, "Connection: close\r\n\r\n");
    if (body) wire.insert(wire.end(), body->begin(), body->end());
    return wire;
}

std::string h2_uri(std::string_view host, std::uint16_t port, std::string_view path) {
    return "https://" + authority(host, port) + std::string(path);
}

std::expected<std::pair<std::uint16_t, std::vector<std::pair<std::string, std::string>>>,
              std::string>
http1_head(std::span<const std::uint8_t> head) {
    const std::string_view text = as_text(head);
    const std::vector<std::string_view> lines = split_on(text, "\r\n");
    const std::string_view status_line = lines.empty() ? std::string_view{} : lines.front();
    const std::optional<std::uint16_t> status = status_of(status_line);
    if (!status) {
        return std::unexpected("bad status line: " + std::string(status_line));
    }

    std::vector<std::pair<std::string, std::string>> fields;
    for (std::size_t line = 1; line < lines.size(); ++line) {
        const std::string_view text_line = lines[line];
        const std::size_t colon = text_line.find(':');
        if (colon == std::string_view::npos) continue;
        fields.emplace_back(std::string(trim(text_line.substr(0, colon))),
                            std::string(trim(text_line.substr(colon + 1))));
    }
    return std::pair{*status, std::move(fields)};
}

std::expected<std::pair<FramingKind, std::size_t>, std::string>
framing(std::uint16_t status, const std::vector<std::pair<std::string, std::string>>& fields) {
    if (status == 204 || status == 304) {
        return std::pair{FramingKind::Length, std::size_t{0}};
    }

    const auto wanted = [&fields](std::string_view name) -> const std::string* {
        for (const auto& [field, value] : fields) {
            if (lowered(field) == name) return &value;
        }
        return nullptr;
    };

    if (const std::string* encoding = wanted("transfer-encoding")) {
        if (lowered(*encoding).contains("chunked")) {
            return std::pair{FramingKind::Chunked, std::size_t{0}};
        }
    }

    if (const std::string* length = wanted("content-length")) {
        // The value as the caller wrote it, spaces and all, is what the error names.
        const std::optional<std::size_t> bytes = parse_size(trim(*length));
        if (!bytes) return std::unexpected("bad Content-Length: " + *length);
        return std::pair{FramingKind::Length, *bytes};
    }
    return std::pair{FramingKind::Close, std::size_t{0}};
}

std::expected<bool, std::string> Dechunker::advance(std::span<const std::uint8_t> body) {
    const auto malformed = [](std::string_view what) {
        return std::unexpected("a chunked answer with " + std::string(what));
    };

    while (!done_) {
        if (have_size_) {
            // The chunk's data, then CRLF.
            // Rust's two checked_adds: a chunk whose end cannot be named is refused, not wrapped.
            if (size_ > std::numeric_limits<std::size_t>::max() - at_ - 2) {
                return malformed("a chunk too large");
            }
            const std::size_t end = at_ + size_ + 2;
            if (body.size() < end) return false;
            if (body[end - 2] != '\r' || body[end - 1] != '\n') {
                return malformed("no line end after a chunk");
            }
            joined_.insert(joined_.end(), body.begin() + static_cast<std::ptrdiff_t>(at_),
                           body.begin() + static_cast<std::ptrdiff_t>(end - 2));
            at_ = end;
            searched_ = end;
            have_size_ = false;
            continue;
        }

        // A line: a chunk size, or a field of the trailer.
        const std::size_t from = std::max(at_, searched_ == 0 ? 0 : searched_ - 1);
        const std::span<const std::uint8_t> tail(body.data() + from, body.size() - from);
        const std::size_t offset = find_sequence(tail, "\r\n");
        if (offset == std::string_view::npos) {
            if (body.size() - at_ > MAX_LINE) return malformed("a line too long");
            searched_ = body.size();
            return false;
        }
        const std::size_t end = from + offset;
        const std::span<const std::uint8_t> line(body.data() + at_, end - at_);
        at_ = end + 2;
        searched_ = at_;

        if (trailer_) {
            done_ = line.empty();
            continue;
        }
        const std::string_view whole = as_text(line);
        const std::string_view size_text = trim(split_on(whole, ";").front());
        const std::optional<std::size_t> size = parse_hex(size_text);
        if (!size) return malformed("a bad chunk size");
        if (*size == 0) {
            trailer_ = true;
        } else {
            size_ = *size;
            have_size_ = true;
        }
    }
    return true;
}

std::expected<std::vector<std::uint8_t>, std::string> Dechunker::finish() const {
    if (done_) return joined_;
    return std::unexpected("the chunked answer ended before its last chunk");
}

std::expected<bool, std::string> Http1Answer::push(std::span<const std::uint8_t> bytes) {
    raw_.insert(raw_.end(), bytes.begin(), bytes.end());
    if (raw_.size() > MAX_BODY) return std::unexpected("the answer is too large");

    while (!head_) {
        const std::size_t from = std::max(head_start_, searched_ >= 3 ? searched_ - 3 : 0);
        const std::span<const std::uint8_t> tail(raw_.data() + from, raw_.size() - from);
        const std::size_t offset = find_sequence(tail, "\r\n\r\n");
        if (offset == std::string_view::npos) {
            searched_ = raw_.size();
            return false;
        }
        const std::size_t end = from + offset;
        auto parsed =
            http1_head(std::span<const std::uint8_t>(raw_.data() + head_start_, end - head_start_));
        if (!parsed) return std::unexpected(parsed.error());

        const std::uint16_t status = parsed->first;
        if (status >= 100 && status < 200 && status != 101) {
            // An interim answer, before the answer itself.
            head_start_ = end + 4;
            searched_ = head_start_;
            continue;
        }
        auto where = framing(status, parsed->second);
        if (!where) return std::unexpected(where.error());

        Head head;
        head.status = status;
        head.fields = std::move(parsed->second);
        head.body_start = end + 4;
        head.framing = where->first;
        head.length = where->second;
        head_ = std::move(head);
    }

    Head& head = *head_;
    const std::span<const std::uint8_t> body(raw_.data() + head.body_start,
                                             raw_.size() - head.body_start);
    switch (head.framing) {
        case FramingKind::Length:
            return body.size() >= head.length;
        case FramingKind::Chunked:
            return head.dechunker.advance(body);
        case FramingKind::Close:
            return false;
    }
    return false;
}

std::expected<Http1Answer::Answer, std::string> Http1Answer::finish() const {
    if (!head_) {
        return std::unexpected(raw_.empty() ? "empty response" : "truncated response head");
    }
    const Head& head = *head_;
    const std::span<const std::uint8_t> body(raw_.data() + head.body_start,
                                             raw_.size() - head.body_start);
    std::vector<std::uint8_t> whole;
    switch (head.framing) {
        case FramingKind::Length:
            if (body.size() < head.length) {
                return std::unexpected("the answer ended after " + std::to_string(body.size()) +
                                       " of its " + std::to_string(head.length) + " bytes");
            }
            whole.assign(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(head.length));
            break;
        case FramingKind::Chunked: {
            auto joined = head.dechunker.finish();
            if (!joined) return std::unexpected(joined.error());
            whole = std::move(*joined);
            break;
        }
        case FramingKind::Close:
            whole.assign(body.begin(), body.end());
            break;
    }
    return Answer{head.status, head.fields, std::move(whole)};
}

namespace https {

std::pair<std::string_view, std::uint16_t> target(const Request& request) {
    return request.address.value_or(std::pair{request.host, request.port});
}

std::string_view server_name(const Request& request) {
    return request.sni.empty() ? request.host : request.sni;
}

std::vector<std::pair<std::string, std::string>> request_fields(const Request& request) {
    // The URI https.rs hands http::Request::builder(), taken apart the way the h2 encoder puts it
    // back together: the scheme, the authority and the path, before the caller's fields.
    const std::string uri = h2_uri(request.host, request.port, request.path);
    std::string_view rest = uri;
    rest.remove_prefix(std::string_view("https://").size());
    const std::size_t slash = rest.find('/');
    const std::string_view authority_part = rest.substr(0, slash);
    const std::string_view path_part =
        slash == std::string_view::npos ? std::string_view{} : rest.substr(slash);

    std::vector<std::pair<std::string, std::string>> fields = {
        {":method", std::string(request.method)},
        {":scheme", "https"},
        {":authority", std::string(authority_part)},
        {":path", std::string(path_part)},
    };
    for (const auto& [name, value] : request.headers) fields.emplace_back(name, value);
    // http::header::CONTENT_LENGTH, which is the field's name in the case http stores it in.
    if (request.body) {
        fields.emplace_back("content-length", std::to_string(request.body->size()));
    }
    return fields;
}

bool chose_http2(std::string_view selected) { return selected == "h2"; }

} // namespace https

} // namespace hemera::core
