#pragma once

#include "engine.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <memory>

namespace aether::gui {

// Custom Windows Messages for Thread-safe UI updates
inline constexpr UINT WM_HEMERA_STATE_CHANGE = WM_USER + 101;
inline constexpr UINT WM_HEMERA_LOG          = WM_USER + 102;
inline constexpr UINT WM_HEMERA_BUDGET       = WM_USER + 103;
inline constexpr UINT WM_HEMERA_ACCESS_CODE  = WM_USER + 104;
inline constexpr UINT WM_HEMERA_TRAY         = WM_USER + 105;
inline constexpr UINT WM_AETHER_STATE_CHANGE = WM_HEMERA_STATE_CHANGE;
inline constexpr UINT WM_AETHER_LOG          = WM_HEMERA_LOG;
inline constexpr UINT WM_AETHER_BUDGET       = WM_HEMERA_BUDGET;
inline constexpr UINT WM_AETHER_ACCESS_CODE  = WM_HEMERA_ACCESS_CODE;
inline constexpr UINT WM_AETHER_TRAY         = WM_HEMERA_TRAY;

class MainWindow {
public:
    struct Impl;
    MainWindow(HINSTANCE hInstance, std::shared_ptr<AetherEngine> engine, bool start_minimized);
    ~MainWindow();

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    bool create();
    int run_message_loop();

    void show(int nCmdShow = SW_SHOW);
    void hide();

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace aether::gui
