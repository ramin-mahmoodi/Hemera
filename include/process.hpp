#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <memory>
#include <atomic>
#include <expected>

namespace aether::process {

struct SpawnResult {
    bool success = false;
    uint32_t pid = 0;
    std::string error_message;
};

// Locate Aether binary in priority candidate directories
std::expected<std::filesystem::path, std::string> resolve_binary();

// Locate tun2socks binary in priority candidate directories
std::expected<std::filesystem::path, std::string> resolve_tun2socks();

// Write or clear PID file
void write_pid_file(const std::filesystem::path& data_dir, uint32_t pid, std::string_view filename = "aether.pid");
void clear_pid_file(const std::filesystem::path& data_dir, std::string_view filename = "aether.pid");

// Reaps any leftover Aether or tun2socks process from an earlier crash
void reap_orphan(const std::filesystem::path& data_dir);

// Kill a process tree (by PID)
void kill_process_tree(uint32_t pid);

// Runs a command line hidden and waits for it; true only on exit code 0
bool run_and_wait(std::wstring_view command_line, uint32_t timeout_ms = 10000);

class ProcessSession {
public:
    using LogCallback = std::function<void(std::string_view line)>;

    ProcessSession();
    ~ProcessSession();

    ProcessSession(const ProcessSession&) = delete;
    ProcessSession& operator=(const ProcessSession&) = delete;

    // Spawns aether.exe with redirected pipes and assigned Job Object
    SpawnResult spawn(
        const std::filesystem::path& binary_path,
        const std::filesystem::path& work_dir,
        const ConnectionProfile& profile,
        LogCallback log_cb
    );

    // Spawns arbitrary command with redirected pipes and assigned Job Object
    SpawnResult spawn_command(
        const std::filesystem::path& binary_path,
        const std::vector<std::string>& args,
        const std::filesystem::path& work_dir,
        LogCallback log_cb
    );

    [[nodiscard]] uint32_t pid() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::optional<uint32_t> exit_code() const noexcept;

    // Checks state indicators detected from log stream
    [[nodiscard]] bool engine_started() const noexcept;
    [[nodiscard]] bool access_code_required() const noexcept;
    [[nodiscard]] std::optional<uint32_t> scan_budget_secs() const noexcept;

    // Interaction endpoints
    void send_ctrl_c();
    bool send_access_code(std::string_view code);
    void kill();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace aether::process
