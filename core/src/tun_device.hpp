#pragma once

#include "dns.hpp"

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace hemera::core::tun {

struct TunConfig {
    std::string adapter_name = "Hemera";
    std::string tunnel_type = "HemeraTunnel";
    std::string ipv4;               // e.g. "172.16.0.2" or "172.16.0.2/32"
    std::string ipv6;               // optional e.g. "2606:4700:110:8867:a595:bb0a:85c9:6df1/128"
    SocketAddr peer_endpoint{};     // remote peer address and port for bypass route
    std::string dns = "1.1.1.1";
    uint32_t ring_capacity = 0x400000; // 4 MB ring buffer capacity
    uint32_t mtu = 1280;               // Tunnel MTU (1280 for WireGuard/QUIC, 1500 for H2)
};

class TunDevice {
public:
    virtual ~TunDevice() = default;

    // Factory method: loads wintun.dll, creates adapter, assigns IP, installs bypass & default routes
    [[nodiscard]] static std::expected<std::unique_ptr<TunDevice>, std::string> create(
        const TunConfig& config);

    // Write decrypted packet from remote tunnel to local Windows network stack
    virtual bool write_packet(std::span<const uint8_t> packet) = 0;

    // Read packet sent by Windows applications to be forwarded into the tunnel
    // If wait_ms > 0, waits on Wintun read wait event up to wait_ms before reading
    virtual std::vector<uint8_t> read_packet(uint32_t wait_ms = 0) = 0;

    // Drains up to max_packets available in the ring buffer into the provided sink function
    // Returns the number of packets processed
    virtual size_t drain_read_packets(
        size_t max_packets,
        const std::function<void(std::span<const uint8_t>)>& on_packet) = 0;

    // Event handle signaled by Wintun when packets are ready to be read
    [[nodiscard]] virtual void* read_wait_event() const = 0;

    // Check if wintun.dll can be located and loaded
    [[nodiscard]] static bool is_wintun_available();

    // Check if the current process runs with Administrator privileges
    [[nodiscard]] static bool is_elevated();

    // Cleanup any stale adapters/routes from previous crashes or ungraceful terminations
    static void cleanup_stale_adapter(const std::string& name = "Hemera");
};

} // namespace hemera::core::tun
