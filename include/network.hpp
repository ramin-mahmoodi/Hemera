#pragma once

#include <string_view>
#include <chrono>

namespace aether::network {

// Initialize and cleanup network subsystem (Winsock)
void init();
void shutdown();

// Check if a TCP port is actively accepting connections
// If host is 0.0.0.0 or unspecified, probes 127.0.0.1
bool port_is_live(std::string_view addr_str, std::chrono::milliseconds timeout = std::chrono::milliseconds(300));

// Parse host and port from address string (e.g., "127.0.0.1:1819")
bool parse_address(std::string_view addr_str, std::string& host, uint16_t& port);

} // namespace aether::network
