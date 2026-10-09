// default_ech_transport: the socket half dns.hpp leaves to the engine, the way https_runtime
// is the socket half https.hpp leaves. Blocking, like the rest of this port.

#include "ech_transport.hpp"

#include "access_http.hpp"
#include "https_runtime.hpp"
#include "socks.hpp"
#include "tls.hpp"

#include <chrono>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

namespace aether::core {

namespace {

constexpr std::chrono::milliseconds kDirectTimeout{5000};
constexpr std::chrono::milliseconds kDohTimeout{10000};

[[nodiscard]] bool wait_readable(SOCKET sock, std::chrono::milliseconds budget) {
    fd_set read;
    FD_ZERO(&read);
    FD_SET(sock, &read);
    timeval slice{};
    const auto ms = std::min<std::chrono::milliseconds>(budget, std::chrono::milliseconds(50));
    slice.tv_sec = static_cast<long>(ms.count() / 1000);
    slice.tv_usec = static_cast<long>((ms.count() % 1000) * 1000);
    return ::select(0, &read, nullptr, nullptr, &slice) > 0;
}

[[nodiscard]] int fill_address(const SocketAddr& addr, sockaddr_storage& storage) {
    std::memset(&storage, 0, sizeof storage);
    if (addr.ip.v4) {
        auto& v4 = reinterpret_cast<sockaddr_in&>(storage);
        v4.sin_family = AF_INET;
        v4.sin_port = htons(addr.port);
        std::memcpy(&v4.sin_addr.s_addr, addr.ip.bytes.data() + 12, 4);
        return sizeof sockaddr_in;
    }
    auto& v6 = reinterpret_cast<sockaddr_in6&>(storage);
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons(addr.port);
    std::memcpy(&v6.sin6_addr, addr.ip.bytes.data(), 16);
    return sizeof sockaddr_in6;
}

// A connected TCP socket with a 5 s connect budget: non-blocking connect + select, the way the
// rest of this tree bounds its connects.
[[nodiscard]] std::expected<SOCKET, std::string> dial_tcp(const SocketAddr& peer) {
    const SOCKET sock =
        ::socket(peer.ip.v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return std::unexpected(std::string("socket failed"));
    u_long nonblock = 1;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    sockaddr_storage storage{};
    const int length = fill_address(peer, storage);
    if (::connect(sock, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
        const int code = WSAGetLastError();
        if (code != WSAEWOULDBLOCK && code != WSAEINPROGRESS && code != WSAEINVAL) {
            closesocket(sock);
            return std::unexpected("connect failed (" + std::to_string(code) + ")");
        }
        fd_set write;
        FD_ZERO(&write);
        FD_SET(sock, &write);
        timeval budget{};
        budget.tv_sec = 5;
        if (::select(0, nullptr, &write, nullptr, &budget) <= 0) {
            closesocket(sock);
            return std::unexpected(std::string("connect timed out"));
        }
        int failed = 0;
        int size = sizeof failed;
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&failed), &size);
        if (failed != 0) {
            closesocket(sock);
            return std::unexpected("connect failed (" + std::to_string(failed) + ")");
        }
    }
    nonblock = 0;
    ::ioctlsocket(sock, FIONBIO, &nonblock);
    return sock;
}

[[nodiscard]] bool send_all(SOCKET sock, std::span<const std::uint8_t> bytes,
                            const std::chrono::steady_clock::time_point& finish) {
    std::size_t sent = 0;
    while (sent < bytes.size()) {
        if (std::chrono::steady_clock::now() >= finish) return false;
        const int wrote =
            ::send(sock, reinterpret_cast<const char*>(bytes.data() + sent),
                   static_cast<int>(bytes.size() - sent), 0);
        if (wrote <= 0) return false;
        sent += static_cast<std::size_t>(wrote);
    }
    return true;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> recv_exact(
    SOCKET sock, std::size_t want, const std::chrono::steady_clock::time_point& finish) {
    std::vector<std::uint8_t> out;
    out.reserve(want);
    std::vector<std::uint8_t> chunk(2048);
    while (out.size() < want) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            finish - std::chrono::steady_clock::now());
        if (left.count() <= 0 || !wait_readable(sock, left)) return std::nullopt;
        const int got = ::recv(sock, reinterpret_cast<char*>(chunk.data()),
                               static_cast<int>(std::min<std::size_t>(chunk.size(),
                                                                     want - out.size())),
                               0);
        if (got <= 0) return std::nullopt;
        out.insert(out.end(), chunk.begin(), chunk.begin() + got);
    }
    return out;
}

[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> ask_direct(
    const EchDns& dns, std::string_view domain) {
    const auto target = parse_address(dns.host);
    if (!target.has_value()) return std::unexpected(std::string("bad resolver address"));
    const SocketAddr peer{*target, dns.port == 0 ? std::uint16_t{53} : dns.port};
    const auto [query, id] = new_query(domain, RR_HTTPS);
    const auto finish = std::chrono::steady_clock::now() + kDirectTimeout;

    if (dns.kind == EchDns::Kind::Udp) {
        const SOCKET sock = ::socket(peer.ip.v4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return std::unexpected(std::string("socket failed"));
        u_long nonblock = 1;
        ::ioctlsocket(sock, FIONBIO, &nonblock);
        sockaddr_storage storage{};
        const int length = fill_address(peer, storage);
        std::vector<std::uint8_t> answer(4096);
        std::expected<std::vector<std::uint8_t>, std::string> result =
            std::unexpected(std::string{});
        auto last_send = std::chrono::steady_clock::now() - std::chrono::seconds(2);
        while (std::chrono::steady_clock::now() < finish) {
            // One query a second while nothing answers: a retry without a storm.
            if (std::chrono::steady_clock::now() - last_send >= std::chrono::seconds(1)) {
                (void)::sendto(sock, reinterpret_cast<const char*>(query.data()),
                               static_cast<int>(query.size()), 0,
                               reinterpret_cast<sockaddr*>(&storage), length);
                last_send = std::chrono::steady_clock::now();
            }
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                finish - std::chrono::steady_clock::now());
            if (left.count() <= 0 || !wait_readable(sock, left)) break;
            const int got = ::recvfrom(sock, reinterpret_cast<char*>(answer.data()),
                                       static_cast<int>(answer.size()), 0, nullptr, nullptr);
            if (got <= 0) continue;
            const std::span<const std::uint8_t> message(answer.data(),
                                                       static_cast<std::size_t>(got));
            if (!response_matches(message, id, domain, RR_HTTPS)) continue;
            result = answer_ech(message, domain);
            break;
        }
        closesocket(sock);
        return result;
    }

    auto dialed = dial_tcp(peer);
    if (!dialed.has_value()) return std::unexpected(dialed.error());
    const SOCKET sock = *dialed;
    const std::vector<std::uint8_t> framed = tcp_message(query);
    std::expected<std::vector<std::uint8_t>, std::string> result =
        std::unexpected(std::string{});
    if (send_all(sock, framed, finish)) {
        if (auto head = recv_exact(sock, 2, finish)) {
            const std::size_t want = (static_cast<std::size_t>((*head)[0]) << 8) | (*head)[1];
            if (want > 0 && want <= 65535) {
                if (auto body = recv_exact(sock, want, finish)) {
                    const std::span<const std::uint8_t> message(body->data(), body->size());
                    if (response_matches(message, id, domain, RR_HTTPS)) {
                        result = answer_ech(message, domain);
                    }
                }
            }
        }
    }
    closesocket(sock);
    return result;
}

[[nodiscard]] std::expected<std::vector<std::uint8_t>, std::string> ask_doh(
    const Settings& settings, const EchDns& dns, std::string_view domain) {
    // RFC 8484 POST: the wire query as the body, no base64url round trip.
    auto split = split_url(dns.endpoint.url);
    if (!split.has_value()) return std::unexpected(split.error());
    const auto [query, id] = new_query(domain, RR_HTTPS);

    https::Request outgoing;
    outgoing.method = "POST";
    outgoing.host = split->host;
    outgoing.port = split->port;
    std::optional<std::pair<std::string, std::uint16_t>> dest_storage;
    if (dns.endpoint.address.has_value()) {
        dest_storage = host_and_port(*dns.endpoint.address, split->port);
        if (dest_storage.has_value()) {
            outgoing.address =
                std::pair<std::string_view, std::uint16_t>{dest_storage->first,
                                                           dest_storage->second};
        }
    }
    if (dns.endpoint.sni.has_value()) outgoing.sni = *dns.endpoint.sni;
    outgoing.path = split->path;
    const std::vector<std::pair<std::string, std::string>> fields{
        {"Accept", "application/dns-message"},
        {"Content-Type", "application/dns-message"},
    };
    outgoing.headers = fields;
    outgoing.body = std::span<const std::uint8_t>(query);

    const Fingerprint fingerprint = Fingerprint::configured(settings);
    https::Call call;
    call.settings = &settings;
    auto answered = https::send(outgoing, fingerprint, nullptr, kDohTimeout, call);
    if (!answered.has_value()) return std::unexpected(answered.error());
    const std::span<const std::uint8_t> message(answered->body.data(), answered->body.size());
    if (answered->status < 200 || answered->status > 299) {
        return std::unexpected("doh status " + std::to_string(answered->status));
    }
    if (!response_matches(message, id, domain, RR_HTTPS)) {
        return std::unexpected(std::string{});
    }
    return answer_ech(message, domain);
}

} // namespace

EchTransport default_ech_transport(const Settings& settings) {
    return [&settings](const EchDns& dns, std::string_view domain)
               -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (dns.kind == EchDns::Kind::Https) return ask_doh(settings, dns, domain);
        return ask_direct(dns, domain);
    };
}

} // namespace aether::core
