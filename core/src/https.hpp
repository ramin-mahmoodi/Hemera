#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aether::core {

// Port of aether/src/https.rs. This header holds the half that decides things rather than sends
// them: the shape of a request, and the reading of an HTTP/1.1 answer as its bytes arrive. The
// handshake, the socket and the h2 stream are https_runtime.hpp, which sends them. What is here is
// the answer's grammar, which is where a truncated or malformed response is told apart from a whole
// one, and the request shapes both carriers put on the wire.

// The most of an answer that is read.
inline constexpr std::size_t MAX_BODY = 512 * 1024;
// The largest header list an HTTP/2 answer may have: Chrome's.
inline constexpr std::uint32_t MAX_HEADER_LIST = 256 * 1024;
// The longest line of a chunked body, a chunk size or a field of its trailer, that is read.
inline constexpr std::size_t MAX_LINE = 8 * 1024;

// ALPN: HTTP/2, then HTTP/1.1, as Chrome offers them, in wire format.
inline constexpr std::uint8_t ALPN_H2_HTTP1[] = {0x02, 'h', '2', 0x08,
                                                 'h',  't', 't', 'p', '/', '1', '.', '1'};

// `host`:`port` as a URL writes it: an IPv6 address in brackets, and the port left out when it is
// 443.
[[nodiscard]] std::string authority(std::string_view host, std::uint16_t port);

// The body of an HTTP/1.1 request, exactly as over_http1 writes it: the request line, Host, the
// caller's fields, Content-Length when there is a body -- even an empty one, which is a body the
// server is told to expect -- Connection: close, and the body.
[[nodiscard]] std::vector<std::uint8_t> http1_request(
    std::string_view method, std::string_view host, std::uint16_t port, std::string_view path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::optional<std::span<const std::uint8_t>> body);

// The URI an h2 request carries: `https://{authority}{path}`.
[[nodiscard]] std::string h2_uri(std::string_view host, std::uint16_t port, std::string_view path);

// Where the body of an answer ends (RFC 9112, 6.3).
enum class FramingKind {
    Length, // after this many bytes
    Chunked, // at its last chunk and the end of its trailer
    Close, // with the connection
};

// A chunked body (RFC 9112, 7.1), joined as it comes in, each byte looked at about once.
class Dechunker {
public:
    // Goes on with `body`, the whole body so far, and says whether its last chunk and its trailer
    // have come; an error for what is no chunked body.
    [[nodiscard]] std::expected<bool, std::string> advance(std::span<const std::uint8_t> body);
    // The body, joined; an error unless its last chunk and its trailer have come.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> finish() const;

private:
    std::size_t at_ = 0;      // where the next piece of the body starts
    std::size_t searched_ = 0; // how far the search for the end of that line has looked
    std::size_t size_ = 0;    // the chunk whose data comes next
    bool have_size_ = false;
    bool trailer_ = false; // the last chunk has come, so the trailer comes next
    bool done_ = false;
    std::vector<std::uint8_t> joined_;
};

// An HTTP/1.1 answer as it comes in: its head, past any interim (1xx) answers before it, then its
// body, which ends as its head says.
class Http1Answer {
public:
    struct Head {
        std::uint16_t status = 0;
        std::vector<std::pair<std::string, std::string>> fields;
        std::size_t body_start = 0;
        FramingKind framing = FramingKind::Close;
        std::size_t length = 0;
        Dechunker dechunker;
    };

    struct Answer {
        std::uint16_t status = 0;
        std::vector<std::pair<std::string, std::string>> fields;
        std::vector<std::uint8_t> body;
    };

    // Takes `bytes`, the next of the answer, and says whether the answer is whole.
    [[nodiscard]] std::expected<bool, std::string> push(std::span<const std::uint8_t> bytes);

    // The answer once the connection has ended; an error when the connection ended before the
    // answer did.
    [[nodiscard]] std::expected<Answer, std::string> finish() const;

private:
    std::vector<std::uint8_t> raw_;
    std::size_t head_start_ = 0;
    std::size_t searched_ = 0;
    std::optional<Head> head_;
};

// The status and the header fields of `head`, the head of an answer without its last CRLF.
[[nodiscard]] std::expected<std::pair<std::uint16_t,
                                      std::vector<std::pair<std::string, std::string>>>,
                     std::string>
http1_head(std::span<const std::uint8_t> head);

// Where the body of an answer with `status` and header `fields` ends: chunked goes before any
// Content-Length.
[[nodiscard]] std::expected<std::pair<FramingKind, std::size_t>, std::string>
framing(std::uint16_t status, const std::vector<std::pair<std::string, std::string>>& fields);

// The live half -- the socket, the handshake, the ECH loop, the h2 stream and the HTTP/1.1 write
// and read -- is in https_runtime.hpp, which builds on the shapes below.

namespace https {

// A request: https.rs's `Request`. `host` is the HTTP host, of Host or :authority, a name or an IP
// address, an IPv6 one without brackets, on `port`, which Host and :authority leave out when it is
// 443, and `path` the path with its query. The connection goes to `host` on `port`, and the
// ClientHello names `host`, unless `address` and `sni` name others; offering ECH, the name goes
// inside the encrypted ClientHello.
struct Request {
    std::string_view method;
    std::string_view host;
    std::uint16_t port = 443;
    // Where the connection goes instead of `host` on `port`: a name or an IP address, and its port.
    std::optional<std::pair<std::string_view, std::uint16_t>> address;
    // The server name of the ClientHello instead of `host`; empty means `host`.
    std::string_view sni;
    std::string_view path;
    // The caller's header fields, in the order they go on the wire.
    std::span<const std::pair<std::string, std::string>> headers;
    std::optional<std::span<const std::uint8_t>> body;
};

// An answer, read to its end. `headers` keeps the case the server wrote, which every reader here
// matches case-insensitively; `protocol` is the one ALPN picked, "h2" or "http/1.1".
struct Response {
    std::uint16_t status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
    std::string_view protocol;
};

// Where the connection goes: `address` when it is given, `host` on `port` when it is not.
[[nodiscard]] std::pair<std::string_view, std::uint16_t> target(const Request& request);

// The server name of the ClientHello: `sni` when it is given, `host` when it is not.
[[nodiscard]] std::string_view server_name(const Request& request);

// The header block an h2 request carries: the pseudo headers `h2_uri`'s absolute URI decomposes
// into -- :method, :scheme, :authority, :path, in that order -- then the caller's fields in their
// order, then content-length when there is a body. This is what http::Request::builder() is handed
// and what the h2 encoder puts on the wire; over_http2 gives it to nghttp2 as it comes back.
[[nodiscard]] std::vector<std::pair<std::string, std::string>> request_fields(const Request& request);

// Whether `selected`, the protocol ALPN chose, is HTTP/2: the one decision that picks between
// over_http2 and over_http1. Anything else, the empty selection included, is HTTP/1.1, as https.rs
// has it.
[[nodiscard]] bool chose_http2(std::string_view selected);

} // namespace https

} // namespace aether::core
