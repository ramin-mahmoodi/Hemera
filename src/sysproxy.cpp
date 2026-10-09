#include "sysproxy.hpp"
#include "json.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#include <atomic>
#include <fstream>
#include <iostream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

namespace aether::sysproxy {

namespace {

constexpr const wchar_t* REG_KEY_INTERNET_SETTINGS = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
std::atomic<bool> g_applied{false};

void notify_system() {
    // INTERNET_OPTION_SETTINGS_CHANGED (39)
    InternetSetOptionW(nullptr, 39, nullptr, 0);
    // INTERNET_OPTION_REFRESH (37)
    InternetSetOptionW(nullptr, 37, nullptr, 0);
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size);
    return out;
}

std::string to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::optional<DWORD> read_reg_dword(HKEY hKey, const wchar_t* value_name) {
    DWORD val = 0;
    DWORD val_size = sizeof(val);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &val_size) == ERROR_SUCCESS && type == REG_DWORD) {
        return val;
    }
    return std::nullopt;
}

std::optional<std::string> read_reg_string(HKEY hKey, const wchar_t* value_name) {
    DWORD size = 0;
    DWORD type = 0;
    if (RegQueryValueExW(hKey, value_name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS || type != REG_SZ) {
        return std::nullopt;
    }
    std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, 0);
    if (RegQueryValueExW(hKey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &size) == ERROR_SUCCESS) {
        return to_utf8(buf.data());
    }
    return std::nullopt;
}

void set_wininet_proxy(bool enable, const std::wstring& server = L"", const std::wstring& bypass = L"<local>") {
    INTERNET_PER_CONN_OPTION_LISTW list{};
    INTERNET_PER_CONN_OPTIONW options[3]{};

    list.dwSize = sizeof(list);
    list.pszConnection = nullptr; // LAN connection
    list.dwOptionError = 0;
    list.pOptions = options;

    options[0].dwOption = INTERNET_PER_CONN_FLAGS;
    options[0].Value.dwValue = enable ? (PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY) : PROXY_TYPE_DIRECT;

    if (enable || !server.empty()) {
        list.dwOptionCount = 3;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[1].Value.pszValue = const_cast<wchar_t*>(server.c_str());

        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        options[2].Value.pszValue = const_cast<wchar_t*>(bypass.c_str());
    } else {
        list.dwOptionCount = 1;
    }

    InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    notify_system();
}

void restore_internal(const std::filesystem::path& backup_file) {
    if (!std::filesystem::exists(backup_file)) return;

    std::ifstream file(backup_file);
    if (!file.is_open()) return;

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    auto json_val = json::parse(content);
    if (!json_val || !json_val->is_object()) return;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_KEY_INTERNET_SETTINGS, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return;
    }

    DWORD enable = 0;
    std::wstring ws_server;
    std::wstring ws_override = L"<local>";

    if (json_val->contains("enable")) {
        enable = static_cast<DWORD>(json_val->get("enable").as_int(0));
        RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&enable), sizeof(enable));
    }

    if (json_val->contains("server")) {
        std::string s = json_val->get("server").as_string();
        if (s.empty()) {
            RegDeleteValueW(hKey, L"ProxyServer");
        } else {
            ws_server = to_wide(s);
            RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, reinterpret_cast<const BYTE*>(ws_server.c_str()), static_cast<DWORD>((ws_server.size() + 1) * sizeof(wchar_t)));
        }
    }

    if (json_val->contains("override")) {
        std::string s = json_val->get("override").as_string();
        if (s.empty()) {
            RegDeleteValueW(hKey, L"ProxyOverride");
        } else {
            ws_override = to_wide(s);
            RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, reinterpret_cast<const BYTE*>(ws_override.c_str()), static_cast<DWORD>((ws_override.size() + 1) * sizeof(wchar_t)));
        }
    }

    RegCloseKey(hKey);

    // Restore WinINet per-connection options
    set_wininet_proxy(enable != 0, ws_server, ws_override);
}

} // namespace

std::string format_proxy_string(std::string_view addr, std::string_view socks_addr) {
    if (addr.find('=') != std::string_view::npos) {
        return std::string(addr);
    }
    auto strip_scheme = [](std::string_view s) -> std::string_view {
        if (s.starts_with("http://")) return s.substr(7);
        if (s.starts_with("https://")) return s.substr(8);
        if (s.starts_with("socks5://")) return s.substr(9);
        if (s.starts_with("socks://")) return s.substr(8);
        return s;
    };
    std::string_view clean_addr = strip_scheme(addr);
    if (clean_addr.empty()) {
        clean_addr = "127.0.0.1:1822";
    }
    std::string_view clean_socks = strip_scheme(socks_addr);
    if (clean_socks.empty()) {
        clean_socks = "127.0.0.1:1819";
    }
    return std::format("http={};https={};socks={}", clean_addr, clean_addr, clean_socks);
}

bool apply(const std::string& addr, const std::filesystem::path& backup_file, const std::string& socks_addr) {
    if (std::filesystem::exists(backup_file)) {
        restore_internal(backup_file);
        std::error_code ec;
        std::filesystem::remove(backup_file, ec);
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_KEY_INTERNET_SETTINGS, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    // Read current settings to backup
    json::Object backup_obj;
    auto cur_enable = read_reg_dword(hKey, L"ProxyEnable");
    backup_obj["enable"] = cur_enable.has_value() ? static_cast<int>(*cur_enable) : 0;

    auto cur_server = read_reg_string(hKey, L"ProxyServer");
    backup_obj["server"] = cur_server.value_or("");

    auto cur_override = read_reg_string(hKey, L"ProxyOverride");
    backup_obj["override"] = cur_override.value_or("");

    json::Value backup_val(std::move(backup_obj));

    // Ensure parent directory exists
    if (backup_file.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(backup_file.parent_path(), ec);
    }

    std::ofstream out(backup_file);
    if (!out.is_open()) {
        RegCloseKey(hKey);
        return false;
    }
    out << backup_val.dump(2);
    out.close();

    // Format comprehensive proxy string (HTTP, HTTPS, SOCKS)
    std::string proxy_str = format_proxy_string(addr, socks_addr);
    std::wstring ws_server = to_wide(proxy_str);
    std::wstring ws_override = L"<local>";
    DWORD enable = 1;

    RegSetValueExW(hKey, L"ProxyServer", 0, REG_SZ, reinterpret_cast<const BYTE*>(ws_server.c_str()), static_cast<DWORD>((ws_server.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(hKey, L"ProxyOverride", 0, REG_SZ, reinterpret_cast<const BYTE*>(ws_override.c_str()), static_cast<DWORD>((ws_override.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&enable), sizeof(enable));

    RegCloseKey(hKey);

    // Apply WinINet per-connection options
    set_wininet_proxy(true, ws_server, ws_override);
    g_applied.store(true, std::memory_order_relaxed);
    return true;
}

void restore(const std::filesystem::path& backup_file) {
    if (g_applied.exchange(false, std::memory_order_relaxed)) {
        restore_internal(backup_file);
        std::error_code ec;
        std::filesystem::remove(backup_file, ec);
    }
}

void restore_stale(const std::filesystem::path& backup_file) {
    if (std::filesystem::exists(backup_file)) {
        restore_internal(backup_file);
        std::error_code ec;
        std::filesystem::remove(backup_file, ec);
    }
    g_applied.store(false, std::memory_order_relaxed);
}

bool is_applied() noexcept {
    return g_applied.load(std::memory_order_relaxed);
}

} // namespace aether::sysproxy
