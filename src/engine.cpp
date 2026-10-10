#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "engine.hpp"
#include "network.hpp"
#include "sysproxy.hpp"
#include "inproc_core.hpp"
#include "tun_device.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <malloc.h>
#include <shlobj.h>
#include <fstream>
#include <iostream>
#include <format>
#include <chrono>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

namespace hemera {

namespace {

std::filesystem::path get_roaming_appdata_dir() {
    std::filesystem::path base;
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
        base = path;
        CoTaskMemFree(path);
    } else {
        wchar_t* env_appdata = nullptr;
        size_t len = 0;
        if (_wdupenv_s(&env_appdata, &len, L"APPDATA") == 0 && env_appdata) {
            base = env_appdata;
            free(env_appdata);
        } else {
            base = std::filesystem::temp_directory_path();
        }
    }

    std::filesystem::path hemera_dir = base / "Hemera";
    std::filesystem::path old_hemera_dir = base / "Hemera";

    // Smooth migration: copy existing configuration if Hemera directory is fresh
    if (!std::filesystem::exists(hemera_dir) && std::filesystem::exists(old_hemera_dir)) {
        std::error_code ec;
        std::filesystem::create_directories(hemera_dir, ec);
        std::filesystem::copy(old_hemera_dir, hemera_dir, std::filesystem::copy_options::recursive | std::filesystem::copy_options::skip_existing, ec);
    }

    return hemera_dir;
}

} // namespace

struct HemeraEngine::Impl {
    mutable std::recursive_mutex mutex;
    ConnectionState state;
    ConnectionProfile profile;
    LiveStats stats;
    hemera::core::Cancel cancel_token;
    std::unique_ptr<std::thread> core_thread;

    StateCallback on_state_changed;
    LogCallback on_log;
    BudgetCallback on_scan_budget;
    AccessCodeCallback on_access_code_requested;
    StatsCallback on_stats;

    std::filesystem::path data_dir;
    std::filesystem::path backup_file;
    std::filesystem::path profile_file;
    std::filesystem::path settings_file;

    Impl() {
        data_dir = get_roaming_appdata_dir();
        std::error_code ec;
        std::filesystem::create_directories(data_dir, ec);

        backup_file = data_dir / "sysproxy-backup.json";
        profile_file = data_dir / "profile.json";
        settings_file = data_dir / "settings.json";

        state.kind = StateKind::Idle;

        if (std::filesystem::exists(profile_file)) {
            std::ifstream in(profile_file);
            if (in.is_open()) {
                std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                auto val = json::parse(content);
                if (val) {
                    profile = json::profile_from_json(*val);
                }
            }
        }
    }

    ~Impl() {
        stop_core_thread();
    }

    void stop_core_thread() {
        cancel_token.cancel();
        if (core_thread && core_thread->joinable()) {
            if (core_thread->get_id() != std::this_thread::get_id()) {
                core_thread->join();
            } else {
                core_thread->detach();
            }
        }
        core_thread.reset();
    }

    void emit_state(const ConnectionState& new_state) {
        std::ofstream f("hemera_engine.log", std::ios::app);
        f << "[STATE] kind=" << static_cast<int>(new_state.kind) << " err=" << new_state.error_message << std::endl;
        StateCallback cb;
        {
            std::lock_guard lock(mutex);
            state = new_state;
            cb = on_state_changed;
        }
        if (cb) {
            cb(new_state);
        }
    }

    void emit_log(std::string_view line) {
        std::ofstream f("hemera_engine.log", std::ios::app);
        f << "[LOG] " << line << std::endl;
        LogCallback cb;
        {
            std::lock_guard lock(mutex);
            cb = on_log;
        }
        if (cb) {
            cb({.line = std::string(line), .timestamp_ms = current_time_ms()});
        }
    }
};

HemeraEngine::HemeraEngine() : impl_(std::make_unique<Impl>()) {
    network::init();
}

HemeraEngine::~HemeraEngine() {
    shutdown_blocking();
    network::shutdown();
}

void HemeraEngine::set_on_state_changed(StateCallback cb) {
    std::lock_guard lock(impl_->mutex);
    impl_->on_state_changed = std::move(cb);
}

void HemeraEngine::set_on_log(LogCallback cb) {
    std::lock_guard lock(impl_->mutex);
    impl_->on_log = std::move(cb);
}

void HemeraEngine::set_on_scan_budget(BudgetCallback cb) {
    std::lock_guard lock(impl_->mutex);
    impl_->on_scan_budget = std::move(cb);
}

void HemeraEngine::set_on_access_code_requested(AccessCodeCallback cb) {
    std::lock_guard lock(impl_->mutex);
    impl_->on_access_code_requested = std::move(cb);
}

void HemeraEngine::set_on_stats(StatsCallback cb) {
    std::lock_guard lock(impl_->mutex);
    impl_->on_stats = std::move(cb);
}

std::filesystem::path HemeraEngine::app_data_dir() const {
    return impl_->data_dir;
}

ConnectionProfile HemeraEngine::load_profile() const {
    if (std::filesystem::exists(impl_->profile_file)) {
        std::ifstream in(impl_->profile_file);
        if (in.is_open()) {
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto val = json::parse(content);
            if (val) {
                return json::profile_from_json(*val);
            }
        }
    }
    return ConnectionProfile{};
}

void HemeraEngine::save_profile(const ConnectionProfile& profile) const {
    {
        std::lock_guard lock(impl_->mutex);
        impl_->profile = profile;
    }
    auto json_val = json::profile_to_json(profile, true);
    std::error_code ec;
    std::filesystem::create_directories(impl_->data_dir, ec);
    std::ofstream out(impl_->profile_file);
    if (out.is_open()) {
        out << json_val.dump(2);
    }
}

void HemeraEngine::set_active_profile(const ConnectionProfile& profile) {
    save_profile(profile);
}

AppSettings HemeraEngine::load_settings() const {
    if (std::filesystem::exists(impl_->settings_file)) {
        std::ifstream in(impl_->settings_file);
        if (in.is_open()) {
            std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto val = json::parse(content);
            if (val) {
                return json::settings_from_json(*val);
            }
        }
    }
    return AppSettings{};
}

void HemeraEngine::save_settings(const AppSettings& settings) const {
    auto json_val = json::settings_to_json(settings);
    std::error_code ec;
    std::filesystem::create_directories(impl_->data_dir, ec);
    std::ofstream out(impl_->settings_file);
    if (out.is_open()) {
        out << json_val.dump(2);
    }
}

ConnectionState HemeraEngine::current_state() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->state;
}

ConnectionProfile HemeraEngine::active_profile() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->profile;
}

LiveStats HemeraEngine::current_stats() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->stats;
}

std::expected<void, std::string> HemeraEngine::connect(std::optional<ConnectionProfile> custom_profile) {
    std::lock_guard lock(impl_->mutex);

    if (impl_->state.kind == StateKind::Connected || impl_->state.kind == StateKind::Connecting) {
        return std::unexpected("Already connected or connecting");
    }

    ConnectionProfile prof = custom_profile.value_or(load_profile());
    if (prof.tun_mode && !hemera::core::tun::TunDevice::is_elevated()) {
        impl_->emit_state({
            .kind = StateKind::Error,
            .error_message = "TUN mode requires Administrator privileges. Please restart Hemera as Administrator."
        });
        return std::unexpected("TUN mode requires Administrator privileges");
    }

    impl_->profile = prof;
    impl_->cancel_token = hemera::core::Cancel();

    // Clean up any old thread
    if (impl_->core_thread && impl_->core_thread->joinable()) {
        impl_->core_thread->detach();
    }

    impl_->emit_state({.kind = StateKind::Connecting});

    impl_->core_thread = std::make_unique<std::thread>([this, prof, cancel = impl_->cancel_token]() mutable {
        std::vector<std::string> args = prof.as_args();
        std::map<std::string, std::string> env;
        if (prof.tun_mode) env["HEMERA_TUN_MODE"] = "1";
        if (prof.masque_http2) env["HEMERA_MASQUE_HTTP2"] = "1";
        if (prof.fragment) {
            env["HEMERA_MASQUE_H2_FRAGMENT"] = "1";
            env["HEMERA_MASQUE_H2_FRAGMENT_SNI"] = "1";
        }
        if (prof.ech) env["HEMERA_ECH"] = "auto";
        if (!prof.exit_loc.empty()) env["HEMERA_EXIT_LOC"] = prof.exit_loc;
        if (!prof.dns.empty()) env["HEMERA_DNS"] = prof.dns;
        if (!prof.route_direct.empty()) env["HEMERA_ROUTE_DIRECT"] = prof.route_direct;
        if (prof.protocol == Protocol::Wireguard || prof.protocol == Protocol::Gool || prof.protocol == Protocol::WarpInWarp) {
            env["HEMERA_NOIZE"] = std::string(to_string(prof.wg_noize));
        } else {
            env["HEMERA_NOIZE"] = std::string(to_string(prof.masque_noize));
        }
        if (prof.protocol == Protocol::WarpInWarp) env["HEMERA_GOOL_MODE"] = "classic";
        if (!prof.access_email.empty()) env["HEMERA_ACCESS_EMAIL"] = prof.access_email;
        if (!prof.access_client_id.empty()) env["HEMERA_ACCESS_CLIENT_ID"] = prof.access_client_id;
        if (!prof.access_client_secret.empty()) env["HEMERA_ACCESS_CLIENT_SECRET"] = prof.access_client_secret;
        if (!prof.access_token.empty()) env["HEMERA_ACCESS_TOKEN"] = prof.access_token;

        hemera::core::InprocCallbacks cbs;
        cbs.on_log = [this](std::string_view l) {
            impl_->emit_log(l);
        };
        cbs.on_stats = [this](uint64_t up, uint64_t down, uint64_t uptime) {
            LiveStats st{.up = up, .down = down, .uptime = uptime};
            StatsCallback scb;
            {
                std::lock_guard lk(impl_->mutex);
                impl_->stats = st;
                scb = impl_->on_stats;
            }
            if (scb) scb(st);
        };
        cbs.on_state_changed = [this, prof, cancel](const std::string& st) {
            if (st == "Connected") {
                if (cancel.is_cancelled()) return;
                impl_->emit_state({
                    .kind = StateKind::Connected,
                    .socks_addr = prof.primary_addr(),
                    .connected_at_ms = current_time_ms()
                });
                if (!prof.tun_mode && prof.system_proxy) {
                    auto http_front = prof.http_front();
                    std::string front = http_front.value_or("127.0.0.1:1819");
                    sysproxy::apply(front, impl_->backup_file, prof.primary_addr());
                }
            } else if (st == "Connecting") {
                impl_->emit_state({.kind = StateKind::Connecting});
            } else if (st == "Error") {
                if (prof.system_proxy) sysproxy::restore(impl_->backup_file);
                impl_->emit_state({.kind = StateKind::Error, .error_message = "Connection encountered an error"});
            } else if (st == "Disconnected") {
                if (prof.system_proxy) sysproxy::restore(impl_->backup_file);
                impl_->emit_state({.kind = StateKind::Idle});
            }
        };

        {
            std::ofstream f("hemera_engine.log", std::ios::app);
            f << "[CONNECT] Starting run_inproc with args:";
            for (const auto& a : args) f << " " << a;
            f << std::endl;
        }

        int rc = hemera::core::run_inproc(args, env, cancel, cbs);

        {
            std::ofstream f("hemera_engine.log", std::ios::app);
            f << "[CONNECT] run_inproc finished with rc=" << rc << " cancelled=" << cancel.is_cancelled() << std::endl;
        }

        if (rc != 0 && !cancel.is_cancelled()) {
            if (prof.system_proxy) sysproxy::restore(impl_->backup_file);
            impl_->emit_state({
                .kind = StateKind::Error,
                .error_message = std::format("Core exited with status {}", rc)
            });
        } else {
            if (prof.system_proxy) sysproxy::restore(impl_->backup_file);
            impl_->emit_state({
                .kind = StateKind::Idle
            });
        }

        // Reclaim network stack, crypto contexts, and CRT heap buffers on disconnect
        _heapmin();
        SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    });

    return {};
}

std::expected<void, std::string> HemeraEngine::disconnect() {
    impl_->emit_state({.kind = StateKind::Disconnecting});
    impl_->cancel_token.cancel();

    bool sys_prox = false;
    {
        std::lock_guard lock(impl_->mutex);
        sys_prox = impl_->profile.system_proxy;
    }
    if (sys_prox) {
        sysproxy::restore(impl_->backup_file);
    }

    impl_->emit_state({.kind = StateKind::Idle});
    _heapmin();
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    return {};
}

std::expected<void, std::string> HemeraEngine::submit_access_code(std::string_view /*code*/) {
    return {};
}

void HemeraEngine::startup_cleanup() {
    sysproxy::restore_stale(impl_->backup_file);
    hemera::core::tun::TunDevice::cleanup_stale_adapter("Hemera");
}

void HemeraEngine::shutdown_blocking() {
    (void)disconnect();
    impl_->stop_core_thread();
    sysproxy::restore(impl_->backup_file);
}

} // namespace hemera
