#pragma once

#include <string>
#include <filesystem>

namespace aether::sysproxy {

// Formats proxy server string to include HTTP, HTTPS, and SOCKS
std::string format_proxy_string(std::string_view addr, std::string_view socks_addr = "");

// Applies OS-wide proxy setting and creates a backup of previous settings
bool apply(const std::string& addr, const std::filesystem::path& backup_file, const std::string& socks_addr = "");

// Restores OS-wide proxy setting from backup if it was applied by this session
void restore(const std::filesystem::path& backup_file);

// Restores OS-wide proxy setting left by a prior crashed session
void restore_stale(const std::filesystem::path& backup_file);

// Returns true if proxy is currently actively managed by this process
bool is_applied() noexcept;

} // namespace aether::sysproxy
