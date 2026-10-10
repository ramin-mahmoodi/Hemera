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

    std::ofstream lf("startup.log", std::ios::app);
    lf << "wWinMain started, PID=" << GetCurrentProcessId() << std::endl;

    // Initialize COM for Direct2D, DirectWrite, WIC, and Shell
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    // High-DPI Awareness v2
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // Single-instance check
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"Local\\Hemera_SingleInstance_Native_Mutex");
    DWORD mutex_err = GetLastError();
    lf << "Mutex created, err=" << mutex_err << std::endl;
    if (hMutex && mutex_err == ERROR_ALREADY_EXISTS) {
        lf << "ERROR_ALREADY_EXISTS -> exiting" << std::endl;
        HWND hExisting = FindWindowW(L"HemeraMainWindowClass", L"Hemera");
        if (hExisting) {
            ShowWindow(hExisting, SW_RESTORE);
            SetForegroundWindow(hExisting);
        }
        CloseHandle(hMutex);
        return 0;
    }
    lf << "Single instance check passed" << std::endl;

    // Check for --minimized command line argument
    std::wstring_view cmd_line = pCmdLine ? pCmdLine : L"";
    bool start_minimized = (cmd_line.find(L"--minimized") != std::wstring_view::npos);

    // Initialize core engine
    auto engine = std::make_shared<hemera::HemeraEngine>();

    // Clean up orphans & stale proxy from previous crash
    engine->startup_cleanup();

    // Launch UI
    lf << "Creating window..." << std::endl;
    hemera::gui::MainWindow window(hInstance, engine, start_minimized);

    if (!window.create()) {
        lf << "window.create() FAILED!" << std::endl;
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }
    lf << "window.create() succeeded, entering message loop" << std::endl;

    timeBeginPeriod(1);
    int result = 0;
    try {
        result = window.run_message_loop();
        lf << "run_message_loop returned with code=" << result << std::endl;
    } catch (const std::exception& e) {
        lf << "FATAL EXCEPTION in run_message_loop: " << e.what() << std::endl;
        result = 2;
    } catch (...) {
        lf << "FATAL UNKNOWN EXCEPTION in run_message_loop!" << std::endl;
        result = 3;
    }
    timeEndPeriod(1);
    lf.flush();

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return result;
}
