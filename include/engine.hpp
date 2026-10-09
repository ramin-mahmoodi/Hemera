#pragma once

#include "types.hpp"
#include "json.hpp"
#include "sysproxy.hpp"
#include "inproc_core.hpp"
#include <memory>
#include <mutex>
#include <functional>
#include <filesystem>
#include <thread>
#include <expected>

namespace hemera {

struct LiveStats {
    uint64_t up = 0;
    uint64_t down = 0;
    uint64_t uptime = 0;
};

class HemeraEngine {
public:
    using StateCallback = std::function<void(const ConnectionState& state)>;
    using LogCallback = std::function<void(const LogLine& log)>;
    using BudgetCallback = std::function<void(uint32_t budget_secs)>;
    using AccessCodeCallback = std::function<void()>;
    using StatsCallback = std::function<void(const LiveStats& stats)>;

    HemeraEngine();
    ~HemeraEngine();

    HemeraEngine(const HemeraEngine&) = delete;
    HemeraEngine& operator=(const HemeraEngine&) = delete;

    // Callbacks registration
    void set_on_state_changed(StateCallback cb);
    void set_on_log(LogCallback cb);
    void set_on_scan_budget(BudgetCallback cb);
    void set_on_access_code_requested(AccessCodeCallback cb);
    void set_on_stats(StatsCallback cb);

    // Profile & Settings storage
    [[nodiscard]] std::filesystem::path app_data_dir() const;
    [[nodiscard]] ConnectionProfile load_profile() const;
    void save_profile(const ConnectionProfile& profile) const;
    void set_active_profile(const ConnectionProfile& profile);
    [[nodiscard]] AppSettings load_settings() const;
    void save_settings(const AppSettings& settings) const;

    // State inspection
    [[nodiscard]] ConnectionState current_state() const;
    [[nodiscard]] ConnectionProfile active_profile() const;
    [[nodiscard]] LiveStats current_stats() const;

    // Connection Control
    std::expected<void, std::string> connect(std::optional<ConnectionProfile> custom_profile = std::nullopt);
    std::expected<void, std::string> disconnect();
    std::expected<void, std::string> submit_access_code(std::string_view code);

    // App Startup / Shutdown helpers
    void startup_cleanup();
    void shutdown_blocking();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace hemera
