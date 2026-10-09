#include "inproc_core.hpp"
#include "settings.hpp"
#include <iostream>
#include <vector>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

namespace {

[[nodiscard]] std::string to_utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), need,
                        nullptr, nullptr);
    return out;
}

[[nodiscard]] std::vector<std::string> command_line_args() {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr || argc <= 1) {
        if (argv != nullptr) LocalFree(argv);
        return {};
    }
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc - 1));
    for (int i = 1; i < argc; ++i) args.push_back(to_utf8(argv[i]));
    LocalFree(argv);
    return args;
}

const hemera::core::Cancel* g_cli_cancel = nullptr;

BOOL WINAPI cli_ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT ||
        type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        if (g_cli_cancel != nullptr) g_cli_cancel->cancel();
        return TRUE;
    }
    return FALSE;
}

} // namespace

int main(int, char**) {
    const std::vector<std::string> args = command_line_args();
    hemera::core::Cancel cancel;
    g_cli_cancel = &cancel;
    SetConsoleCtrlHandler(cli_ctrl_handler, TRUE);

    return hemera::core::run_inproc(args, {}, cancel, {});
}
