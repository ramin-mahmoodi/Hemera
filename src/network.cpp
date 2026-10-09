#include "network.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <charconv>

#pragma comment(lib, "ws2_32.lib")

namespace aether::network {

namespace {
bool g_wsa_initialized = false;
}

void init() {
    if (!g_wsa_initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
            g_wsa_initialized = true;
        }
    }
}

void shutdown() {
    if (g_wsa_initialized) {
        WSACleanup();
        g_wsa_initialized = false;
    }
}

bool parse_address(std::string_view addr_str, std::string& host, uint16_t& port) {
    if (addr_str.empty()) return false;
    size_t colon = addr_str.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon == addr_str.size() - 1) {
        return false;
    }

    std::string_view host_part = addr_str.substr(0, colon);
    std::string_view port_part = addr_str.substr(colon + 1);

    // Strip brackets if IPv6
    if (host_part.front() == '[' && host_part.back() == ']') {
        host_part = host_part.substr(1, host_part.size() - 2);
    }

    int port_num = 0;
    auto [ptr, ec] = std::from_chars(port_part.data(), port_part.data() + port_part.size(), port_num);
    if (ec != std::errc() || port_num <= 0 || port_num > 65535) {
        return false;
    }

    host = std::string(host_part);
    port = static_cast<uint16_t>(port_num);
    return true;
}

bool port_is_live(std::string_view addr_str, std::chrono::milliseconds timeout) {
    init();

    std::string host;
    uint16_t port = 0;
    if (!parse_address(addr_str, host, port)) {
        return false;
    }

    // When configured to listen on 0.0.0.0, we probe localhost
    if (host == "0.0.0.0" || host == "::") {
        host = "127.0.0.1";
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port);
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

    bool success = false;
    for (addrinfo* ptr = res; ptr != nullptr; ptr = ptr->ai_next) {
        SOCKET s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (s == INVALID_SOCKET) continue;

        // Set non-blocking mode
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);

        int conn_res = connect(s, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen));
        if (conn_res == 0) {
            success = true;
            closesocket(s);
            break;
        }

        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set write_fds;
            fd_set except_fds;
            FD_ZERO(&write_fds);
            FD_ZERO(&except_fds);
            FD_SET(s, &write_fds);
            FD_SET(s, &except_fds);

            timeval tv{};
            tv.tv_sec = static_cast<long>(timeout.count() / 1000);
            tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

            int sel = select(0, nullptr, &write_fds, &except_fds, &tv);
            if (sel > 0 && FD_ISSET(s, &write_fds) && !FD_ISSET(s, &except_fds)) {
                int err = 0;
                int err_len = sizeof(err);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len) == 0 && err == 0) {
                    success = true;
                }
            }
        }

        closesocket(s);
        if (success) break;
    }

    freeaddrinfo(res);
    return success;
}

} // namespace aether::network
