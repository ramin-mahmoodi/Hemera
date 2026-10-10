#include "gui.hpp"
#include "engine.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>
#include <mmsystem.h>
#include <timeapi.h>
#include <commctrl.h>
#include <string_view>
#include <memory>
#include <fstream>
#include <chrono>

#pragma comment(lib, "winmm.lib")

// Tell NVIDIA and AMD graphics drivers to strictly use low-power integrated GPU (Intel Iris Xe)
// This completely avoids waking up the dGPU (NVIDIA RTX 3050) from D3-Cold state, eliminating the 2-second startup hitch!
extern "C" {
    __declspec(dllexport) DWORD NvOptimusEnablement = 0x00000000;
    __declspec(dllexport) int AmdPowerXpressRequestHighPerformance = 0;
}

static void LogCrashDirect(EXCEPTION_POINTERS* ep) {
    HANDLE h = CreateFileW(L"crash_report.txt", GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, nullptr, FILE_END);
        char buf[512];
        DWORD wr = 0;
        if (ep && ep->ExceptionRecord) {
            HMODULE hMod = nullptr;
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &hMod);
            char modName[MAX_PATH] = "Unknown";
            if (hMod) GetModuleFileNameA(hMod, modName, sizeof(modName));
            uintptr_t offset = hMod ? (reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) - reinterpret_cast<uintptr_t>(hMod)) : 0;
            snprintf(buf, sizeof(buf), "CRASH: Code=0x%lx Addr=0x%p Mod=%s+0x%llx\r\n",
                     ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress, modName, static_cast<unsigned long long>(offset));
        } else {
            snprintf(buf, sizeof(buf), "CRASH: Unknown\r\n");
        }
        WriteFile(h, buf, static_cast<DWORD>(strlen(buf)), &wr, nullptr);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

static LONG WINAPI VectoredHandler(EXCEPTION_POINTERS* ep) {
    if (ep && ep->ExceptionRecord) {
        DWORD code = ep->ExceptionRecord->ExceptionCode;
        // Ignore normal debugging / RPC / C++ exceptions
        if (code == 0xE06D7363 || code == 0x406D1388 || code == 0x000006BA) {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_ILLEGAL_INSTRUCTION ||
            code == EXCEPTION_STACK_OVERFLOW || code == 0xC0000409 /* FAST_FAIL */) {
            LogCrashDirect(ep);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, PWSTR pCmdLine, int /*nCmdShow*/) {
    AddVectoredExceptionHandler(1, VectoredHandler);
    SetUnhandledExceptionFilter([](EXCEPTION_POINTERS* ep) -> LONG {
        LogCrashDirect(ep);
        return EXCEPTION_CONTINUE_SEARCH;
    });

    // Initialize COM for Direct2D, DirectWrite, WIC, and Shell
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    // High-DPI Awareness v2
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

#ifndef PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
#define PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION 0x00000004
#endif

    // Disable Windows 11 EcoQoS (Power Throttling) and preserve 1ms timer resolution in background/tray
    PROCESS_POWER_THROTTLING_STATE power_throttling{};
    power_throttling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    power_throttling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    power_throttling.StateMask = 0;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power_throttling, sizeof(power_throttling));

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // Single-instance check
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Local\\Hemera_SingleInstance_Native_Mutex");
    DWORD mutex_err = GetLastError();
    if (hMutex && mutex_err == ERROR_ALREADY_EXISTS) {
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
    auto engine = std::make_shared<hemera::HemeraEngine>();

    // Clean up orphans & stale proxy from previous crash
    engine->startup_cleanup();

    // Launch UI
    hemera::gui::MainWindow window(hInstance, engine, start_minimized);

    if (!window.create()) {
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    timeBeginPeriod(1);
    int result = 0;
    try {
        result = window.run_message_loop();
    } catch (const std::exception& e) {
        (void)e;
        result = 2;
    } catch (...) {
        result = 3;
    }
    timeEndPeriod(1);

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return result;
}
