#include "gui.hpp"
#include "engine.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mmsystem.h>
#include <timeapi.h>
#include <commctrl.h>
#include <string_view>
#include <memory>

#pragma comment(lib, "winmm.lib")

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, PWSTR pCmdLine, int /*nCmdShow*/) {
    // High-DPI Awareness v2
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // Single-instance check
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Local\\Hemera_SingleInstance_Native_Mutex");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        // App is already running — find and restore existing window
        HWND hExisting = FindWindowW(L"HemeraMainWindowClass", L"Hemera");
        if (hExisting) {
            ShowWindow(hExisting, SW_RESTORE);
            SetForegroundWindow(hExisting);
        }
        CloseHandle(hMutex);
        return 0;
    }

    // Check for --minimized command line argument
    std::wstring_view cmd_line = pCmdLine ? pCmdLine : L"";
    bool start_minimized = (cmd_line.find(L"--minimized") != std::wstring_view::npos);

    // Initialize core engine
    auto engine = std::make_shared<aether::AetherEngine>();

    // Clean up orphans & stale proxy from previous crash
    engine->startup_cleanup();

    // Launch UI
    aether::gui::MainWindow window(hInstance, engine, start_minimized);
    if (!window.create()) {
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    timeBeginPeriod(1);
    int result = window.run_message_loop();
    timeEndPeriod(1);

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return result;
}
