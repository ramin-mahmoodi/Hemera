#include "autostart.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>

namespace aether::autostart {

namespace {

constexpr const wchar_t* REG_KEY_RUN = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr const wchar_t* APP_NAME = L"Hemera";

std::wstring get_current_exe_path() {
    std::vector<wchar_t> buffer(MAX_PATH);
    DWORD length = 0;
    while (true) {
        length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) break;
        buffer.resize(buffer.size() * 2);
    }
    return std::wstring(buffer.data(), length);
}

} // namespace

bool is_enabled() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_KEY_RUN, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD size = 0;
    LONG res = RegQueryValueExW(hKey, APP_NAME, nullptr, &type, nullptr, &size);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool set_enabled(bool enable) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_KEY_RUN, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    bool ok = false;
    if (enable) {
        std::wstring exe_path = get_current_exe_path();
        if (!exe_path.empty()) {
            std::wstring cmd = L"\"" + exe_path + L"\" --minimized";
            LONG res = RegSetValueExW(
                hKey,
                APP_NAME,
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(cmd.c_str()),
                static_cast<DWORD>((cmd.size() + 1) * sizeof(wchar_t))
            );
            ok = (res == ERROR_SUCCESS);
        }
    } else {
        LONG res = RegDeleteValueW(hKey, APP_NAME);
        ok = (res == ERROR_SUCCESS || res == ERROR_FILE_NOT_FOUND);
    }

    RegCloseKey(hKey);
    return ok;
}

} // namespace aether::autostart
