#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "gui.hpp"
#include "design_system.hpp"
#include "autostart.hpp"
#include "sysproxy.hpp"
#include "resource.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <shlobj.h>
#include <psapi.h>
#include <mmsystem.h>
#include <objidl.h>
#include <gdiplus.h>
#include <vector>
#include <deque>
#include <string>
#include <format>
#include <cmath>
#include <chrono>
#include <algorithm>
#include <mutex>
#include <memory>

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winmm.lib")

namespace hemera::gui {

namespace {

using ds::scale;
using ds::scale_f;

constexpr UINT TIMER_ANIMATION = 1001;

// Draw rounded rectangle with GDI+
void draw_rounded_rect(Gdiplus::Graphics& g, const Gdiplus::Pen& pen, float x, float y, float width, float height, float radius) {
    if (radius <= 0.0f) {
        g.DrawRectangle(&pen, x, y, width, height);
        return;
    }
    float diameter = radius * 2.0f;
    if (diameter > width) diameter = width;
    if (diameter > height) diameter = height;

    Gdiplus::GraphicsPath path;
    path.AddArc(x, y, diameter, diameter, 180.0f, 90.0f);
    path.AddArc(x + width - diameter, y, diameter, diameter, 270.0f, 90.0f);
    path.AddArc(x + width - diameter, y + height - diameter, diameter, diameter, 0.0f, 90.0f);
    path.AddArc(x, y + height - diameter, diameter, diameter, 90.0f, 90.0f);
    path.CloseFigure();
    g.DrawPath(&pen, &path);
}

// Fill rounded rectangle with GDI+
void fill_rounded_rect(Gdiplus::Graphics& g, const Gdiplus::Brush& brush, float x, float y, float width, float height, float radius) {
    if (radius <= 0.0f) {
        g.FillRectangle(&brush, x, y, width, height);
        return;
    }
    float diameter = radius * 2.0f;
    if (diameter > width) diameter = width;
    if (diameter > height) diameter = height;

    Gdiplus::GraphicsPath path;
    path.AddArc(x, y, diameter, diameter, 180.0f, 90.0f);
    path.AddArc(x + width - diameter, y, diameter, diameter, 270.0f, 90.0f);
    path.AddArc(x + width - diameter, y + height - diameter, diameter, diameter, 0.0f, 90.0f);
    path.AddArc(x, y + height - diameter, diameter, diameter, 90.0f, 90.0f);
    path.CloseFigure();
    g.FillPath(&brush, &path);
}

enum class ActiveView {
    Home,
    Settings,
    Logs,
    About
};

struct DropdownOption {
    std::wstring label;
    int id;
};

// Smooth cubic-bezier(0.2, 0.7, 0.2, 1.0) approximation matching tokens/CSS
inline float compute_rise_progress(float view_t, float delay_s) {
    constexpr float duration = 0.55f;
    float elapsed = view_t * duration;
    if (elapsed <= delay_s) return 0.0f;
    float local_t = std::clamp((elapsed - delay_s) / (duration - delay_s), 0.0f, 1.0f);
    float inv = 1.0f - local_t;
    return 1.0f - inv * inv * inv * (1.0f + 0.5f * local_t);
}

inline float compute_rise_offset(float view_t, float delay_s, UINT dpi) {
    float progress = compute_rise_progress(view_t, delay_s);
    return scale_f(14.0f, dpi) * (1.0f - progress);
}

inline Gdiplus::Color blend_colors(const Gdiplus::Color& c1, const Gdiplus::Color& c2, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    BYTE a = static_cast<BYTE>(c1.GetA() + (c2.GetA() - c1.GetA()) * t);
    BYTE r = static_cast<BYTE>(c1.GetR() + (c2.GetR() - c1.GetR()) * t);
    BYTE g = static_cast<BYTE>(c1.GetG() + (c2.GetG() - c1.GetG()) * t);
    BYTE b = static_cast<BYTE>(c1.GetB() + (c2.GetB() - c1.GetB()) * t);
    return Gdiplus::Color(a, r, g, b);
}

// Real Windows System Metrics (Working Set RAM in MB, CPU % from process times)
struct RealSystemMetrics {
    double ram_mb = 0.0;
    double cpu_percent = 0.0;
    ULARGE_INTEGER last_cpu_{};
    ULARGE_INTEGER last_sys_cpu_{};
    ULARGE_INTEGER last_user_cpu_{};
    int num_processors = 1;
    HANDLE process_handle = nullptr;

    void init() {
        process_handle = GetCurrentProcess();
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        num_processors = (si.dwNumberOfProcessors > 0) ? static_cast<int>(si.dwNumberOfProcessors) : 1;
        sample();
    }

    void sample() {
        if (!process_handle) process_handle = GetCurrentProcess();

        // 1. Process Memory (Working Set RAM in MB)
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        if (GetProcessMemoryInfo(process_handle, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            ram_mb = static_cast<double>(pmc.WorkingSetSize) / (1024.0 * 1024.0);
        }

        // 2. Process CPU Usage (%)
        FILETIME ftime{}, fsys{}, fuser{};
        GetSystemTimeAsFileTime(&ftime);
        ULARGE_INTEGER now_time{};
        now_time.LowPart = ftime.dwLowDateTime;
        now_time.HighPart = ftime.dwHighDateTime;

        FILETIME fcreation{}, fexit{};
        if (GetProcessTimes(process_handle, &fcreation, &fexit, &fsys, &fuser)) {
            ULARGE_INTEGER now_sys{}, now_user{};
            now_sys.LowPart = fsys.dwLowDateTime;
            now_sys.HighPart = fsys.dwHighDateTime;
            now_user.LowPart = fuser.dwLowDateTime;
            now_user.HighPart = fuser.dwHighDateTime;

            if (last_cpu_.QuadPart != 0) {
                ULONGLONG time_diff = now_time.QuadPart - last_cpu_.QuadPart;
                if (time_diff > 0) {
                    ULONGLONG proc_diff = (now_sys.QuadPart - last_sys_cpu_.QuadPart) + (now_user.QuadPart - last_user_cpu_.QuadPart);
                    double pct = (static_cast<double>(proc_diff) / static_cast<double>(time_diff) / num_processors) * 100.0;
                    cpu_percent = std::clamp(pct, 0.0, 100.0);
                }
            }
            last_cpu_ = now_time;
            last_sys_cpu_ = now_sys;
            last_user_cpu_ = now_user;
        }
    }
};

} // namespace

struct MainWindow::Impl {
    HINSTANCE hInstance_ = nullptr;
    HWND hwnd_ = nullptr;
    std::shared_ptr<HemeraEngine> engine_;
    bool start_minimized_ = false;

    ActiveView view_ = ActiveView::Home;
    ActiveView prev_view_ = ActiveView::Home;
    float view_transition_t_ = 1.0f; // 1.0f = fully transitioned, 0.0f = just started .rise

    // High performance frame timer & window drag state
    std::chrono::steady_clock::time_point last_frame_time_{};
    bool is_moving_window_ = false;
    bool mouse_tracking_ = false;

    // Hover & Interaction states
    bool hero_hovered_ = false;
    bool hero_pressed_ = false;
    float hero_scale_ = 1.0f;          // Springs smoothly to 1.03f on hover, 0.97f on press
    float hero_target_scale_ = 1.0f;

    bool logs_btn_hovered_ = false;
    bool settings_btn_hovered_ = false;
    float gear_rotation_ = 0.0f;       // Smoothly rotates 90° on hover
    float gear_anim_t_ = 0.0f;         // 0.0 to 1.0 smooth 0.5s ease animator

    bool back_btn_hovered_ = false;
    bool save_btn_hovered_ = false;
    bool home_proto_hovered_ = false;
    bool home_route_hovered_ = false;
    bool copy_btn_hovered_ = false;
    bool try_again_hovered_ = false;
    bool view_logs_chip_hovered_ = false;
    bool clear_logs_hovered_ = false;
    bool copy_logs_hovered_ = false;
    bool logs_copied_ = false;
    float logs_copy_timer_ = 0.0f;
    int log_filter_ = 0; // 0: All, 1: Info, 2: Warn, 3: Error
    int hovered_log_chip_ = -1;
    int hovered_settings_row_ = -1;

    // Appearance Segmented Control animation
    float seg_anim_x_ = 0.0f;
    float seg_target_x_ = 0.0f;

    // Settings Toggle Switch smooth animations (0.0 to 1.0)
    // [0]=autostart, [1]=close_to_tray, [2]=kill_switch, [3]=system_proxy, [4]=fragment, [5]=ech, [6]=route_direct
    float switch_anim_[7] = { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f };

    // About view hovers & state
    bool about_src_hovered_ = false;
    bool about_issue_hovered_ = false;
    bool update_btn_hovered_ = false;
    bool is_checking_update_ = false;
    bool is_update_done_ = false;
    float update_check_timer_ = 0.0f;

    // SOCKS5 Copy button feedback
    bool socks_copied_ = false;
    float copy_timer_ = 0.0f;

    // Shake animation for error phase (0.45s)
    float shake_timer_ = 0.0f;

    // Animation elapsed clock
    float anim_time_ = 0.0f;
    float spin_angle_ = 0.0f;
    float connecting_time_ = 0.0f;
    std::wstring conn_sub_text_ = L"Finding the best route";

    // Scroll offset for settings view & logs view
    int scroll_y_ = 0;
    int max_scroll_ = 280; // DIPs (prevents huge empty space at bottom)
    float target_scroll_y_ = 0.0f;
    float scroll_anim_y_ = 0.0f;
    float scroll_vel_y_ = 0.0f;

    int logs_scroll_y_ = 0;
    float target_logs_scroll_y_ = 0.0f;
    float logs_scroll_anim_y_ = 0.0f;
    float logs_scroll_vel_y_ = 0.0f;
    float max_logs_scroll_ = 0.0f;

    // Custom In-Window Dropdown Popup
    int active_dropdown_ = -1;
    RECT dropdown_popup_rect_{};
    std::vector<DropdownOption> dropdown_options_;
    int hovered_dropdown_item_ = -1;

    // Settings draft (loaded on opening settings, committed on Save)
    ConnectionProfile edit_profile_{};
    AppSettings edit_settings_{};

    // Inline SOCKS5 proxy editing in Settings (Zero HWND, 100% GDI+)
    bool is_editing_socks_ = false;
    std::wstring socks_edit_buffer_{};
    float caret_blink_timer_ = 0.0f;

    // Real System Metrics & Live Throughput & Sparkline History (30 points)
    RealSystemMetrics sys_metrics_{};
    float metrics_sample_timer_ = 0.0f;
    std::deque<float> cpu_history_;
    std::deque<float> ram_history_;
    uint64_t prev_down_bytes_ = 0;
    uint64_t prev_up_bytes_ = 0;
    double live_down_speed_mb_ = 0.0;
    double live_up_speed_mb_ = 0.0;
    int live_ping_ms_ = 38;

    // Log lines history
    enum class LogFilter { All = 0, Info = 1, Warn = 2, Error = 3 };

    struct LogEntry {
        uint64_t timestamp_ms = 0;
        LogFilter level = LogFilter::Info;
        std::wstring time_str;
        std::wstring tag;
        std::wstring message;
    };

    std::deque<LogEntry> parsed_logs_;
    std::deque<std::wstring> log_history_;
    std::mutex log_mutex_;

    // System Tray
    NOTIFYICONDATAW nid_{};
    bool in_tray_ = false;

    // GDI+ Resources & Cached Fonts
    ULONG_PTR gdiplus_token_ = 0;
    UINT cached_font_dpi_ = 0;
    std::unique_ptr<Gdiplus::Font> font_app_title_;
    std::unique_ptr<Gdiplus::Font> font_hero_status_;
    std::unique_ptr<Gdiplus::Font> font_view_title_;
    std::unique_ptr<Gdiplus::Font> font_body_;
    std::unique_ptr<Gdiplus::Font> font_body_bold_;
    std::unique_ptr<Gdiplus::Font> font_mono_;
    std::unique_ptr<Gdiplus::Font> font_mono_bold_;
    std::unique_ptr<Gdiplus::Font> font_sub_label_;
    std::unique_ptr<Gdiplus::Font> font_footnote_;
    std::unique_ptr<Gdiplus::Font> font_metric_tag_;

    // High-performance persistent double buffer (eliminates 60fps GDI allocations)
    HDC cached_mem_dc_ = nullptr;
    HBITMAP cached_mem_bmp_ = nullptr;
    HGDIOBJ cached_old_bmp_ = nullptr;
    int cached_bmp_w_ = 0;
    int cached_bmp_h_ = 0;

    std::unique_ptr<Gdiplus::Bitmap> logo_bitmap_;

    void load_logo_bitmap() {
        HRSRC hRes = FindResourceW(hInstance_, MAKEINTRESOURCEW(IDR_APP_PNG), RT_RCDATA);
        if (!hRes) return;
        HGLOBAL hResLoad = LoadResource(hInstance_, hRes);
        if (!hResLoad) return;
        DWORD size = SizeofResource(hInstance_, hRes);
        const void* pData = LockResource(hResLoad);
        if (!pData || size == 0) return;

        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
        if (!hMem) return;
        void* pMem = GlobalLock(hMem);
        if (pMem) {
            memcpy(pMem, pData, size);
            GlobalUnlock(hMem);
            IStream* pStream = nullptr;
            if (SUCCEEDED(CreateStreamOnHGlobal(hMem, TRUE, &pStream))) {
                logo_bitmap_ = std::make_unique<Gdiplus::Bitmap>(pStream);
                pStream->Release();
            }
        }
    }

    Impl(HINSTANCE hInstance, std::shared_ptr<HemeraEngine> engine, bool start_minimized)
        : hInstance_(hInstance), engine_(std::move(engine)), start_minimized_(start_minimized) {
        timeBeginPeriod(1); // Set OS scheduler resolution to 1ms for rock-solid 100+ FPS!
        Gdiplus::GdiplusStartupInput gdiInput;
        Gdiplus::GdiplusStartup(&gdiplus_token_, &gdiInput, nullptr);
        load_logo_bitmap();

        sys_metrics_.init();
        for (int i = 0; i < 30; ++i) {
            cpu_history_.push_back(static_cast<float>(sys_metrics_.cpu_percent));
            ram_history_.push_back(static_cast<float>(sys_metrics_.ram_mb));
        }

        // Apply saved theme settings and profile
        edit_profile_ = engine_->active_profile();
        edit_settings_ = engine_->load_settings();
        apply_theme_setting(edit_settings_.theme);

        // Initialize toggle switch animations (7 toggles)
        switch_anim_[0] = edit_settings_.autostart ? 1.0f : 0.0f;
        switch_anim_[1] = edit_settings_.close_to_tray ? 1.0f : 0.0f;
        switch_anim_[2] = edit_settings_.kill_switch ? 1.0f : 0.0f;
        switch_anim_[3] = edit_profile_.system_proxy ? 1.0f : 0.0f;
        switch_anim_[4] = edit_profile_.fragment ? 1.0f : 0.0f;
        switch_anim_[5] = edit_profile_.ech ? 1.0f : 0.0f;
        switch_anim_[6] = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;

        // Initialize Appearance segment target
        int seg_idx = (edit_settings_.theme == "light") ? 1 : ((edit_settings_.theme == "dark") ? 2 : 0);
        seg_anim_x_ = static_cast<float>(seg_idx);
        seg_target_x_ = static_cast<float>(seg_idx);

        // Logs start 100% clean and authentic -- real core engine events only
        last_frame_time_ = std::chrono::steady_clock::now();
    }

    ~Impl() {
        remove_tray_icon();
        if (cached_mem_dc_) {
            if (cached_old_bmp_) SelectObject(cached_mem_dc_, cached_old_bmp_);
            if (cached_mem_bmp_) DeleteObject(cached_mem_bmp_);
            DeleteDC(cached_mem_dc_);
        }
        Gdiplus::GdiplusShutdown(gdiplus_token_);
        timeEndPeriod(1);
    }

    UINT dpi() const {
        return hwnd_ ? GetDpiForWindow(hwnd_) : 96;
    }

    void ensure_fonts(UINT cur_dpi) {
        if (cached_font_dpi_ == cur_dpi && font_app_title_) return;
        cached_font_dpi_ = cur_dpi;
        const auto& ds = ds::DesignSystem::get();

        font_app_title_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.app_title, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        font_hero_status_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.hero_status_title, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        font_view_title_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.view_title, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        font_body_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.body_label, cur_dpi), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        font_body_bold_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.body_label, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        font_mono_ = std::make_unique<Gdiplus::Font>(L"Consolas", (float)scale(ds.typo.mono_value, cur_dpi), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        font_mono_bold_ = std::make_unique<Gdiplus::Font>(L"Consolas", (float)scale(ds.typo.mono_value, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        font_sub_label_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(12, cur_dpi), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        font_footnote_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.footnote, cur_dpi), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        font_metric_tag_ = std::make_unique<Gdiplus::Font>(L"Segoe UI", (float)scale(ds.typo.metric_tag, cur_dpi), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    }

    void apply_theme_setting(const std::string& theme_str) {
        ds::ThemeMode mode = ds::ThemeMode::Dark;
        if (theme_str == "system") mode = ds::ThemeMode::System;
        else if (theme_str == "light") mode = ds::ThemeMode::Light;
        else mode = ds::ThemeMode::Dark;

        ds::DesignSystem::get().set_theme(mode);

        if (hwnd_) {
            BOOL dark_val = ds::is_effective_dark(mode) ? TRUE : FALSE;
            DwmSetWindowAttribute(hwnd_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark_val, sizeof(dark_val));
            InvalidateRect(hwnd_, nullptr, FALSE);
        }
    }

    void reset_hovers() {
        hero_hovered_ = false;
        logs_btn_hovered_ = false;
        settings_btn_hovered_ = false;
        back_btn_hovered_ = false;
        save_btn_hovered_ = false;
        home_proto_hovered_ = false;
        home_route_hovered_ = false;
        copy_btn_hovered_ = false;
        try_again_hovered_ = false;
        view_logs_chip_hovered_ = false;
        clear_logs_hovered_ = false;
        copy_logs_hovered_ = false;
        hovered_log_chip_ = -1;
        about_src_hovered_ = false;
        about_issue_hovered_ = false;
        update_btn_hovered_ = false;
        hovered_settings_row_ = -1;
        hovered_dropdown_item_ = -1;
    }

    void switch_view(ActiveView target) {
        if (view_ == target) return;
        prev_view_ = view_;
        view_ = target;
        view_transition_t_ = 0.0f; // Start .rise animation
        scroll_y_ = 0;
        target_scroll_y_ = 0.0f;
        scroll_anim_y_ = 0.0f;
        scroll_vel_y_ = 0.0f;
        logs_scroll_y_ = 0;
        target_logs_scroll_y_ = 0.0f;
        logs_scroll_anim_y_ = 0.0f;
        logs_scroll_vel_y_ = 0.0f;
        gear_anim_t_ = 0.0f;
        gear_rotation_ = 0.0f;
        active_dropdown_ = -1;
        is_editing_socks_ = false;
        reset_hovers();

        if (view_ == ActiveView::Settings) {
            populate_settings_draft();
        } else if (view_ == ActiveView::Logs) {
            target_logs_scroll_y_ = max_logs_scroll_;
            logs_scroll_anim_y_ = max_logs_scroll_;
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void copy_to_clipboard(const std::wstring& text) {
        if (OpenClipboard(hwnd_)) {
            EmptyClipboard();
            size_t bytes = (text.length() + 1) * sizeof(wchar_t);
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (hMem) {
                void* locked = GlobalLock(hMem);
                if (locked) {
                    memcpy(locked, text.c_str(), bytes);
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_UNICODETEXT, hMem);
                }
            }
            CloseClipboard();
        }
    }

    void populate_settings_draft() {
        edit_profile_ = engine_->active_profile();
        edit_settings_ = engine_->load_settings();
        socks_edit_buffer_ = std::wstring(edit_profile_.bind_address.begin(), edit_profile_.bind_address.end());
        int seg_idx = (edit_settings_.theme == "light") ? 1 : ((edit_settings_.theme == "dark") ? 2 : 0);
        seg_target_x_ = static_cast<float>(seg_idx);
        seg_anim_x_ = static_cast<float>(seg_idx);

        switch_anim_[0] = edit_settings_.autostart ? 1.0f : 0.0f;
        switch_anim_[1] = edit_settings_.close_to_tray ? 1.0f : 0.0f;
        switch_anim_[2] = edit_settings_.kill_switch ? 1.0f : 0.0f;
        switch_anim_[3] = edit_profile_.system_proxy ? 1.0f : 0.0f;
        switch_anim_[4] = edit_profile_.fragment ? 1.0f : 0.0f;
        switch_anim_[5] = edit_profile_.ech ? 1.0f : 0.0f;
        switch_anim_[6] = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;
    }

    void commit_settings_save() {
        if (!socks_edit_buffer_.empty()) {
            std::string s;
            s.reserve(socks_edit_buffer_.size());
            for (wchar_t wc : socks_edit_buffer_) {
                if (wc < 128) s.push_back(static_cast<char>(wc));
            }
            edit_profile_.bind_address = s;
        }
        autostart::set_enabled(edit_settings_.autostart);
        engine_->save_settings(edit_settings_);
        engine_->set_active_profile(edit_profile_);
        apply_theme_setting(edit_settings_.theme);
    }

    bool has_active_animations() const {
        if (view_transition_t_ < 1.0f) return true;
        if (std::abs(hero_target_scale_ - hero_scale_) > 0.0005f) return true;
        if (std::abs(gear_anim_t_ - (settings_btn_hovered_ ? 1.0f : 0.0f)) > 0.001f) return true;
        if (std::abs(seg_target_x_ - seg_anim_x_) > 0.001f) return true;
        for (int i = 0; i < 7; ++i) {
            float t_val = 0.0f;
            if (i == 0) t_val = edit_settings_.autostart ? 1.0f : 0.0f;
            else if (i == 1) t_val = edit_settings_.close_to_tray ? 1.0f : 0.0f;
            else if (i == 2) t_val = edit_settings_.kill_switch ? 1.0f : 0.0f;
            else if (i == 3) t_val = edit_profile_.system_proxy ? 1.0f : 0.0f;
            else if (i == 4) t_val = edit_profile_.fragment ? 1.0f : 0.0f;
            else if (i == 5) t_val = edit_profile_.ech ? 1.0f : 0.0f;
            else if (i == 6) t_val = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;
            if (std::abs(t_val - switch_anim_[i]) > 0.001f) return true;
        }
        if (std::abs(target_scroll_y_ - scroll_anim_y_) > 0.1f) return true;
        if (std::abs(target_logs_scroll_y_ - logs_scroll_anim_y_) > 0.1f) return true;
        if (shake_timer_ > 0.0f) return true;
        if (copy_timer_ > 0.0f) return true;
        if (logs_copy_timer_ > 0.0f) return true;
        if (is_editing_socks_) return true;
        if (is_checking_update_) return true;

        if (view_ == ActiveView::Home) {
            auto state = engine_->current_state();
            if (state.kind == StateKind::Connecting || state.kind == StateKind::Disconnecting) return true;
            if (state.kind == StateKind::Connected) return true;
            if (state.kind == StateKind::Idle && GetForegroundWindow() == hwnd_) return true;
        }
        return false;
    }

    bool step_animations(float dt) {
        anim_time_ += dt;
        bool needs_repaint = false;

        // 1. Home View continuous animations (Spinning Arc, Radar Rings, Breathing Dot)
        if (view_ == ActiveView::Home) {
            auto state = engine_->current_state();
            if (state.kind == StateKind::Connecting || state.kind == StateKind::Disconnecting) {
                spin_angle_ = std::fmod(spin_angle_ + 360.0f * dt, 360.0f);
                connecting_time_ += dt;
                needs_repaint = true;
            } else {
                connecting_time_ = 0.0f;
                if (state.kind == StateKind::Connected) {
                    needs_repaint = true; // Radar rings and breathing dot pulsating
                } else if (state.kind == StateKind::Idle && GetForegroundWindow() == hwnd_) {
                    needs_repaint = true; // Subtle idle breathing loop
                }
            }
        }

        // 2. Smooth spring scale for hero power button (butter-smooth exponential ease)
        float hero_diff = hero_target_scale_ - hero_scale_;
        if (std::abs(hero_diff) > 0.0005f) {
            hero_scale_ += hero_diff * (1.0f - std::exp(-25.0f * dt));
            needs_repaint = true;
        } else if (hero_scale_ != hero_target_scale_) {
            hero_scale_ = hero_target_scale_;
            needs_repaint = true;
        }

        // 3. Smooth gear rotation (Snappy 0.25s micro-interaction with cubic ease-out)
        float gear_target = settings_btn_hovered_ ? 1.0f : 0.0f;
        if (std::abs(gear_anim_t_ - gear_target) > 0.001f) {
            float dir = (gear_target > gear_anim_t_) ? 1.0f : -1.0f;
            gear_anim_t_ = std::clamp(gear_anim_t_ + dir * (dt / 0.25f), 0.0f, 1.0f);
            float t = gear_anim_t_;
            float ease = 1.0f - std::pow(1.0f - t, 3.0f); // Snappy, instant response on hover onset
            gear_rotation_ = ease * 90.0f;
            needs_repaint = true;
        } else if (gear_anim_t_ != gear_target) {
            gear_anim_t_ = gear_target;
            gear_rotation_ = gear_target * 90.0f;
            needs_repaint = true;
        }

        // 4. Staggered Page Transition (.rise 14px glide over crisp 0.20s)
        if (view_transition_t_ < 1.0f) {
            view_transition_t_ = std::min(1.0f, view_transition_t_ + dt / 0.20f);
            needs_repaint = true;
        }

        // 5. Smooth sliding pill for Appearance Segmented Control
        float seg_diff = seg_target_x_ - seg_anim_x_;
        if (std::abs(seg_diff) > 0.001f) {
            seg_anim_x_ += seg_diff * (1.0f - std::exp(-28.0f * dt));
            needs_repaint = true;
        } else if (seg_anim_x_ != seg_target_x_) {
            seg_anim_x_ = seg_target_x_;
            needs_repaint = true;
        }

        // 6. Smooth Toggle Switch animation transitions (7 switches)
        for (int i = 0; i < 7; ++i) {
            float t_val = 0.0f;
            if (i == 0) t_val = edit_settings_.autostart ? 1.0f : 0.0f;
            else if (i == 1) t_val = edit_settings_.close_to_tray ? 1.0f : 0.0f;
            else if (i == 2) t_val = edit_settings_.kill_switch ? 1.0f : 0.0f;
            else if (i == 3) t_val = edit_profile_.system_proxy ? 1.0f : 0.0f;
            else if (i == 4) t_val = edit_profile_.fragment ? 1.0f : 0.0f;
            else if (i == 5) t_val = edit_profile_.ech ? 1.0f : 0.0f;
            else if (i == 6) t_val = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;

            float s_diff = t_val - switch_anim_[i];
            if (std::abs(s_diff) > 0.001f) {
                switch_anim_[i] += s_diff * (1.0f - std::exp(-28.0f * dt));
                needs_repaint = true;
            } else if (switch_anim_[i] != t_val) {
                switch_anim_[i] = t_val;
                needs_repaint = true;
            }
        }

        // 7. Silky-Smooth Inertial Scroll for Settings (120 FPS stable exponential decay)
        float scr_diff = target_scroll_y_ - scroll_anim_y_;
        if (std::abs(scr_diff) > 0.1f) {
            scroll_anim_y_ += scr_diff * (1.0f - std::exp(-22.0f * dt));
            if (std::abs(target_scroll_y_ - scroll_anim_y_) < 0.2f) {
                scroll_anim_y_ = target_scroll_y_;
            }
            needs_repaint = true;
        }

        // 8. Silky-Smooth Inertial Scroll for Logs
        float lscr_diff = target_logs_scroll_y_ - logs_scroll_anim_y_;
        if (std::abs(lscr_diff) > 0.1f) {
            logs_scroll_anim_y_ += lscr_diff * (1.0f - std::exp(-22.0f * dt));
            if (std::abs(target_logs_scroll_y_ - logs_scroll_anim_y_) < 0.2f) {
                logs_scroll_anim_y_ = target_logs_scroll_y_;
            }
            needs_repaint = true;
        }

        // 9. Feedback & Action Timers
        if (copy_timer_ > 0.0f) {
            copy_timer_ = std::max(0.0f, copy_timer_ - dt);
            if (copy_timer_ == 0.0f) socks_copied_ = false;
            needs_repaint = true;
        }
        if (logs_copy_timer_ > 0.0f) {
            logs_copy_timer_ = std::max(0.0f, logs_copy_timer_ - dt);
            if (logs_copy_timer_ == 0.0f) logs_copied_ = false;
            needs_repaint = true;
        }
        if (shake_timer_ > 0.0f) {
            shake_timer_ = std::max(0.0f, shake_timer_ - dt);
            needs_repaint = true;
        }
        if (is_editing_socks_) {
            caret_blink_timer_ += dt;
            needs_repaint = true;
        }
        if (is_checking_update_) {
            update_check_timer_ += dt;
            if (update_check_timer_ >= 1.4f) {
                is_checking_update_ = false;
                is_update_done_ = true;
            }
            needs_repaint = true;
        }

        // 10. Sample real OS metrics every 750ms and push to sparklines
        metrics_sample_timer_ += dt;
        if (metrics_sample_timer_ >= 0.75f) {
            metrics_sample_timer_ = 0.0f;
            sys_metrics_.sample();

            cpu_history_.push_back(static_cast<float>(sys_metrics_.cpu_percent));
            if (cpu_history_.size() > 30) cpu_history_.pop_front();

            ram_history_.push_back(static_cast<float>(sys_metrics_.ram_mb));
            if (ram_history_.size() > 30) ram_history_.pop_front();

            auto stats = engine_->current_stats();
            if (prev_down_bytes_ > 0 && stats.down >= prev_down_bytes_) {
                live_down_speed_mb_ = static_cast<double>(stats.down - prev_down_bytes_) / (0.75 * 1048576.0);
            } else {
                live_down_speed_mb_ = 0.0;
            }
            if (prev_up_bytes_ > 0 && stats.up >= prev_up_bytes_) {
                live_up_speed_mb_ = static_cast<double>(stats.up - prev_up_bytes_) / (0.75 * 1048576.0);
            } else {
                live_up_speed_mb_ = 0.0;
            }
            prev_down_bytes_ = stats.down;
            prev_up_bytes_ = stats.up;

            if (view_ == ActiveView::Logs || view_ == ActiveView::Home) {
                needs_repaint = true;
            }
        }

        return needs_repaint;
    }

    void parse_and_append_log(std::string_view raw_line, uint64_t timestamp_ms) {
        if (raw_line.empty()) return;

        LogEntry entry{};
        entry.timestamp_ms = timestamp_ms;

        // 1. Time formatted as [HH:MM:SS]
        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t tbuf[32];
        swprintf_s(tbuf, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        entry.time_str = tbuf;

        auto t_pos = raw_line.find('T');
        if (t_pos != std::string_view::npos && t_pos + 9 <= raw_line.size()) {
            if (raw_line[t_pos + 3] == ':' && raw_line[t_pos + 6] == ':') {
                std::string sub(raw_line.substr(t_pos + 1, 8));
                entry.time_str = std::wstring(sub.begin(), sub.end());
            }
        }

        // 2. Classify level & tag
        std::string lower;
        lower.reserve(raw_line.size());
        for (char c : raw_line) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

        if (lower.find("error") != std::string::npos || lower.find("fail") != std::string::npos || lower.find("[-] ") != std::string::npos) {
            entry.level = LogFilter::Error;
            entry.tag = L"ERR";
        } else if (lower.find("warn") != std::string::npos || lower.find("retrying") != std::string::npos) {
            entry.level = LogFilter::Warn;
            entry.tag = L"WARN";
        } else {
            entry.level = LogFilter::Info;
            entry.tag = L"INFO";
        }

        // 3. Extract clean message
        std::string_view msg_sv = raw_line;
        auto close_bracket = raw_line.find("] ");
        if (close_bracket != std::string_view::npos) {
            msg_sv = raw_line.substr(close_bracket + 2);
        } else if (raw_line.starts_with("[+] ") || raw_line.starts_with("[-] ")) {
            msg_sv = raw_line.substr(4);
        }

        entry.message = std::wstring(msg_sv.begin(), msg_sv.end());

        // Zero trace of legacy name in user-visible logs
        size_t p = 0;
        while ((p = entry.message.find(L"Hemera", p)) != std::wstring::npos) {
            entry.message.replace(p, 6, L"Hemera");
            p += 6;
        }
        p = 0;
        while ((p = entry.message.find(L"hemera", p)) != std::wstring::npos) {
            entry.message.replace(p, 6, L"hemera");
            p += 6;
        }

        // Update live connection subtitle phase
        if (lower.find("hunting") != std::string::npos || lower.find("scan mode") != std::string::npos || lower.find("scanning endpoints") != std::string::npos) {
            conn_sub_text_ = L"Scanning endpoints...";
        } else if (lower.find("verifying") != std::string::npos) {
            conn_sub_text_ = L"Verifying gateway...";
        } else if (lower.find("handshake") != std::string::npos) {
            conn_sub_text_ = L"Handshake in progress...";
        } else if (lower.find("candidate") != std::string::npos && lower.find("answered") != std::string::npos) {
            conn_sub_text_ = L"Endpoint found, connecting...";
        } else if (lower.find("listening on") != std::string::npos) {
            conn_sub_text_ = L"Tunnel established";
        }

        parsed_logs_.push_back(std::move(entry));
        if (parsed_logs_.size() > 500) {
            parsed_logs_.pop_front();
        }
    }

    // Hit-testing helper: determines if cursor is over any clickable UI control
    bool is_mouse_over_clickable(int x, int y) const {
        if (active_dropdown_ >= 0) {
            return (x >= dropdown_popup_rect_.left && x <= dropdown_popup_rect_.right &&
                    y >= dropdown_popup_rect_.top && y <= dropdown_popup_rect_.bottom);
        }

        const auto& ds = ds::DesignSystem::get();
        const UINT cur_dpi = dpi();

        RECT rc;
        GetClientRect(hwnd_, &rc);
        float w = static_cast<float>(rc.right - rc.left);

        if (view_ == ActiveView::Home) {
            // Header buttons
            float btn_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            float set_x = w - (float)scale(ds.metrics.padding_x, cur_dpi) - btn_sz;
            float logs_x = set_x - btn_sz - (float)scale(8, cur_dpi);
            float btn_y = (float)scale(ds.metrics.padding_top, cur_dpi);

            if (x >= logs_x && x <= logs_x + btn_sz && y >= btn_y && y <= btn_y + btn_sz) return true;
            if (x >= set_x && x <= set_x + btn_sz && y >= btn_y && y <= btn_y + btn_sz) return true;

            // Hero circular power button
            float hero_cx = w / 2.0f;
            float hero_cy = (float)scale(205, cur_dpi);
            float hero_rad = (float)scale(ds.metrics.hero_diameter / 2, cur_dpi);
            float dx = x - hero_cx;
            float dy = y - hero_cy;
            if (dx * dx + dy * dy <= hero_rad * hero_rad) return true;

            // Error state pill buttons
            auto state = engine_->current_state();
            if (state.kind == StateKind::Error) {
                float stats_y = hero_cy + hero_rad + (float)scale(64 + 20, cur_dpi);
                float pill_h = (float)scale(44, cur_dpi);
                if (y >= stats_y && y <= stats_y + pill_h) {
                    if (x >= hero_cx - scale_f(120, cur_dpi) && x <= hero_cx + scale_f(120, cur_dpi)) return true;
                }
            }

            // Copy SOCKS5 button in Details Card
            float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
            float card_w = w - scale_f((float)(ds.metrics.padding_x * 2), cur_dpi);
            float card_y = (float)scale(470, cur_dpi);
            float row_h = (float)scale(ds.metrics.row_height, cur_dpi);
            float copy_x = card_x + card_w - (float)scale(ds.metrics.row_padding_x, cur_dpi) - (float)scale(44, cur_dpi);
            float copy_y = card_y + row_h * 2.0f + (row_h - (float)scale(44, cur_dpi)) / 2.0f;
            if (x >= copy_x && x <= copy_x + scale_f(44, cur_dpi) && y >= copy_y && y <= copy_y + scale_f(44, cur_dpi)) return true;
            if (home_proto_hovered_ || home_route_hovered_) return true;

            return false;
        }

        if (view_ == ActiveView::Settings) {
            float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (hovered_settings_row_ >= 0) return true;
            return false;
        }

        if (view_ == ActiveView::Logs) {
            float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            float clr_x = w - back_x - back_sz;
            if (x >= clr_x && x <= clr_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            float cp_x = clr_x - back_sz - scale_f(8, cur_dpi);
            if (x >= cp_x && x <= cp_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (hovered_log_chip_ >= 0) return true;
            return false;
        }

        if (view_ == ActiveView::About) {
            float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (about_src_hovered_ || about_issue_hovered_ || update_btn_hovered_) return true;
            return false;
        }

        return false;
    }

    // ── Home View (Concentric Ambient Rings + Hero Button + Real Metrics) ──
    void render_home_view(Gdiplus::Graphics& g, float w, float h, UINT cur_dpi) {
        (void)h;
        const auto& ds = ds::DesignSystem::get();
        auto state = engine_->current_state();
        auto profile = engine_->active_profile();
        auto stats = engine_->current_stats();

        bool is_connected = (state.kind == StateKind::Connected);
        bool is_connecting = (state.kind == StateKind::Connecting);
        bool is_disconnecting = (state.kind == StateKind::Disconnecting);
        bool is_error = (state.kind == StateKind::Error);

        float hero_cx = w / 2.0f;
        float hero_cy = (float)scale(205, cur_dpi);
        float hero_base_diam = (float)scale(ds.metrics.hero_diameter, cur_dpi);
        float hero_r = hero_base_diam / 2.0f;

        // ── 0. Ambient Background (Soft Radial Glow + 5 Concentric Rings from Main.dc.html) ──
        Gdiplus::Color glow_color = is_connected ? ds.colors.gl_on :
                                   (is_connecting ? ds.colors.gl_conn :
                                   (is_error ? ds.colors.gl_err : ds.colors.gl_idle));

        float max_glow_r = (float)scale(is_connected ? 320 : 300, cur_dpi);
        // Fast, feather-light stepped radial glow (0.02ms vs 10ms PathGradientBrush!)
        for (int step = 6; step >= 1; --step) {
            float step_r = max_glow_r * (static_cast<float>(step) / 6.0f);
            float step_alpha = (static_cast<float>(glow_color.GetA()) / 6.0f) * (7 - step);
            BYTE a = static_cast<BYTE>(std::clamp(step_alpha, 0.0f, 255.0f));
            Gdiplus::SolidBrush glow_step_brush(Gdiplus::Color(a, glow_color.GetR(), glow_color.GetG(), glow_color.GetB()));
            g.FillEllipse(&glow_step_brush, hero_cx - step_r, hero_cy - step_r, step_r * 2.0f, step_r * 2.0f);
        }

        // 5 Concentric Rings matching Main.dc.html: r=125 (.9), 180 (.7), 245 (.5), 320 (.35), 405 (.2)
        const float ring_radii[] = { 125.0f, 180.0f, 245.0f, 320.0f, 405.0f };
        const float ring_opacities[] = { 0.90f, 0.70f, 0.50f, 0.35f, 0.20f };
        Gdiplus::Color ring_base = ds.colors.card_border;

        for (int i = 0; i < 5; ++i) {
            float r_dip = (float)scale(static_cast<int>(ring_radii[i]), cur_dpi);
            BYTE alpha = static_cast<BYTE>(std::clamp(ring_opacities[i] * 255.0f, 0.0f, 255.0f));
            Gdiplus::Pen ring_pen(Gdiplus::Color(alpha, ring_base.GetR(), ring_base.GetG(), ring_base.GetB()), 1.0f);
            g.DrawEllipse(&ring_pen, hero_cx - r_dip, hero_cy - r_dip, r_dip * 2.0f, r_dip * 2.0f);
        }

        // ── 1. Header (Hemera title + status dot + Logs & Settings buttons) ──
        float header_y = (float)scale(ds.metrics.padding_top, cur_dpi);
        float pad_x = (float)scale(ds.metrics.padding_x, cur_dpi);
        float dot_x = pad_x;
        float dot_y = header_y + scale_f(17, cur_dpi);
        float dot_d = (float)scale(10, cur_dpi);

        // Breathing dot when connected
        BYTE dot_alpha = 255;
        if (is_connected) {
            float sine_wave = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 4.0f) - 1.57f);
            dot_alpha = static_cast<BYTE>(std::clamp((0.55f + 0.45f * sine_wave) * 255.0f, 140.0f, 255.0f));
        }

        Gdiplus::Color dot_color = is_error ? ds.colors.error : ds.colors.accent;
        Gdiplus::SolidBrush dot_brush(Gdiplus::Color(dot_alpha, dot_color.GetR(), dot_color.GetG(), dot_color.GetB()));
        g.FillEllipse(&dot_brush, dot_x, dot_y, dot_d, dot_d);

        Gdiplus::SolidBrush text_pri_brush(ds.colors.text_primary);
        g.DrawString(L"Hemera", -1, font_app_title_.get(), Gdiplus::PointF(dot_x + dot_d + scale_f(10, cur_dpi), header_y + scale_f(11, cur_dpi)), &text_pri_brush);

        // Header Right Action Buttons: Logs & Settings
        float btn_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
        float btn_radius = (float)scale(ds.metrics.radius_control, cur_dpi);
        float set_x = w - pad_x - btn_sz;
        float logs_x = set_x - btn_sz - scale_f(8, cur_dpi);

        // Logs terminal button
        Gdiplus::Color logs_bg = logs_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color logs_border = logs_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush logs_brush(logs_bg);
        Gdiplus::Pen logs_pen(logs_border, 1.0f);
        fill_rounded_rect(g, logs_brush, logs_x, header_y, btn_sz, btn_sz, btn_radius);
        draw_rounded_rect(g, logs_pen, logs_x, header_y, btn_sz, btn_sz, btn_radius);

        // Logs terminal icon (> _)
        Gdiplus::Pen log_icon_pen(logs_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.6f);
        log_icon_pen.SetStartCap(Gdiplus::LineCapRound);
        log_icon_pen.SetEndCap(Gdiplus::LineCapRound);
        log_icon_pen.SetLineJoin(Gdiplus::LineJoinRound);
        float lcx = logs_x + btn_sz / 2.0f;
        float lcy = header_y + btn_sz / 2.0f;
        Gdiplus::PointF prompt_pts[3] = {
            Gdiplus::PointF(lcx - scale_f(6, cur_dpi), lcy - scale_f(5, cur_dpi)),
            Gdiplus::PointF(lcx - scale_f(1, cur_dpi), lcy),
            Gdiplus::PointF(lcx - scale_f(6, cur_dpi), lcy + scale_f(5, cur_dpi))
        };
        g.DrawLines(&log_icon_pen, prompt_pts, 3);
        g.DrawLine(&log_icon_pen, lcx + scale_f(1, cur_dpi), lcy + scale_f(5, cur_dpi), lcx + scale_f(7, cur_dpi), lcy + scale_f(5, cur_dpi));

        // Settings sliders button
        Gdiplus::Color set_bg = settings_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color set_border = settings_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush set_brush(set_bg);
        Gdiplus::Pen set_pen(set_border, 1.0f);
        fill_rounded_rect(g, set_brush, set_x, header_y, btn_sz, btn_sz, btn_radius);
        draw_rounded_rect(g, set_pen, set_x, header_y, btn_sz, btn_sz, btn_radius);

        // Settings sliders icon with smooth 90° rotation on hover
        float scx = set_x + btn_sz / 2.0f;
        float scy = header_y + btn_sz / 2.0f;
        Gdiplus::GraphicsState set_state = g.Save();
        g.TranslateTransform(scx, scy);
        g.RotateTransform(gear_rotation_);

        Gdiplus::Pen slider_pen(settings_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.6f);
        slider_pen.SetStartCap(Gdiplus::LineCapRound);
        slider_pen.SetEndCap(Gdiplus::LineCapRound);
        Gdiplus::SolidBrush knob_fill(ds.colors.bg);

        // Line 1 + knob
        g.DrawLine(&slider_pen, -scale_f(8, cur_dpi), -scale_f(4, cur_dpi), scale_f(8, cur_dpi), -scale_f(4, cur_dpi));
        g.FillEllipse(&knob_fill, -scale_f(5, cur_dpi), -scale_f(6.2f, cur_dpi), scale_f(4.4f, cur_dpi), scale_f(4.4f, cur_dpi));
        g.DrawEllipse(&slider_pen, -scale_f(5, cur_dpi), -scale_f(6.2f, cur_dpi), scale_f(4.4f, cur_dpi), scale_f(4.4f, cur_dpi));

        // Line 2 + knob
        g.DrawLine(&slider_pen, -scale_f(8, cur_dpi), scale_f(4, cur_dpi), scale_f(8, cur_dpi), scale_f(4, cur_dpi));
        g.FillEllipse(&knob_fill, scale_f(0.5f, cur_dpi), scale_f(1.8f, cur_dpi), scale_f(4.4f, cur_dpi), scale_f(4.4f, cur_dpi));
        g.DrawEllipse(&slider_pen, scale_f(0.5f, cur_dpi), scale_f(1.8f, cur_dpi), scale_f(4.4f, cur_dpi), scale_f(4.4f, cur_dpi));

        g.Restore(set_state);

        // ── 2. Hero Center Section (Power Button, Rings, Spinning Arc) ──
        float shake_dx = 0.0f;
        if (shake_timer_ > 0.0f) {
            float progress = 1.0f - (shake_timer_ / 0.45f);
            if (progress < 0.2f) shake_dx = -7.0f * (progress / 0.2f);
            else if (progress < 0.4f) shake_dx = -7.0f + 13.0f * ((progress - 0.2f) / 0.2f);
            else if (progress < 0.6f) shake_dx = 6.0f - 10.0f * ((progress - 0.4f) / 0.2f);
            else if (progress < 0.8f) shake_dx = -4.0f + 6.0f * ((progress - 0.6f) / 0.2f);
            else shake_dx = 2.0f - 2.0f * ((progress - 0.8f) / 0.2f);
            shake_dx = scale_f(shake_dx, cur_dpi);
        }

        float cur_hero_cx = hero_cx + shake_dx;

        // 1. Expanding Ripple / Radar Waves
        if (is_connected) {
            auto draw_radar_ring = [&](float phase) {
                float ease = 1.0f - std::pow(1.0f - phase, 2.0f);
                float r_scale = 0.95f + 1.05f * ease;
                float r_diam = hero_base_diam * r_scale;
                float alpha = std::clamp(0.55f * (1.0f - phase), 0.0f, 1.0f);
                BYTE b_alpha = static_cast<BYTE>(alpha * 255.0f);

                if (b_alpha > 0) {
                    Gdiplus::Pen ring_pen(Gdiplus::Color(b_alpha, ds.colors.accent.GetR(), ds.colors.accent.GetG(), ds.colors.accent.GetB()), scale_f(1.8f, cur_dpi));
                    g.DrawEllipse(&ring_pen, cur_hero_cx - r_diam / 2.0f, hero_cy - r_diam / 2.0f, r_diam, r_diam);
                }
            };

            float phase1 = std::fmod(anim_time_, 1.8f) / 1.8f;
            float phase2 = std::fmod(anim_time_ + 0.9f, 1.8f) / 1.8f;
            draw_radar_ring(phase1);
            draw_radar_ring(phase2);
        } else if (is_connecting || is_disconnecting) {
            float t_conn = std::fmod(anim_time_, 1.0f);
            float c_ease = 1.0f - std::pow(1.0f - t_conn, 2.0f);
            float c_scale = 0.95f + 0.75f * c_ease;
            float c_diam = hero_base_diam * c_scale;
            float c_alpha = std::clamp(0.50f * (1.0f - t_conn), 0.0f, 1.0f);
            BYTE cb_alpha = static_cast<BYTE>(c_alpha * 255.0f);
            if (cb_alpha > 0) {
                Gdiplus::Pen c_ring(Gdiplus::Color(cb_alpha, ds.colors.accent.GetR(), ds.colors.accent.GetG(), ds.colors.accent.GetB()), scale_f(1.8f, cur_dpi));
                g.DrawEllipse(&c_ring, cur_hero_cx - c_diam / 2.0f, hero_cy - c_diam / 2.0f, c_diam, c_diam);
            }
        }

        // 2. Radial Glow Behind Button
        if (is_connected) {
            Gdiplus::SolidBrush glow_out(ds.colors.hero_glow_on_outer);
            float g_out = hero_base_diam * 1.35f;
            g.FillEllipse(&glow_out, cur_hero_cx - g_out / 2.0f, hero_cy - g_out / 2.0f, g_out, g_out);

            Gdiplus::SolidBrush glow_in(ds.colors.hero_glow_on_inner);
            float g_in = hero_base_diam * 1.08f;
            g.FillEllipse(&glow_in, cur_hero_cx - g_in / 2.0f, hero_cy - g_in / 2.0f, g_in, g_in);
        } else if (is_connecting || is_disconnecting) {
            float glow_alpha = 0.5f + 0.5f * std::sin(anim_time_ * 4.0f);
            BYTE g_a = static_cast<BYTE>(std::clamp(15.0f + 25.0f * glow_alpha, 0.0f, 255.0f));
            Gdiplus::SolidBrush glow_conn(Gdiplus::Color(g_a, ds.colors.accent.GetR(), ds.colors.accent.GetG(), ds.colors.accent.GetB()));
            float g_out = hero_base_diam * 1.25f;
            g.FillEllipse(&glow_conn, cur_hero_cx - g_out / 2.0f, hero_cy - g_out / 2.0f, g_out, g_out);
        } else if (is_error) {
            Gdiplus::SolidBrush glow_out(ds.colors.hero_glow_err_outer);
            float g_out = hero_base_diam * 1.30f;
            g.FillEllipse(&glow_out, cur_hero_cx - g_out / 2.0f, hero_cy - g_out / 2.0f, g_out, g_out);

            Gdiplus::SolidBrush glow_in(ds.colors.hero_glow_err_inner);
            float g_in = hero_base_diam * 1.08f;
            g.FillEllipse(&glow_in, cur_hero_cx - g_in / 2.0f, hero_cy - g_in / 2.0f, g_in, g_in);
        }

        // 3. Hero Button Disc & Status Ring
        float base_scale = hero_scale_;
        if (!is_connected && !is_connecting && !is_disconnecting && !is_error) {
            // Idle breathing loop: scale 1.0 to 1.015
            float breathe = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 4.0f));
            base_scale *= (1.0f + 0.015f * breathe);
        } else if (is_connecting || is_disconnecting) {
            // Fast pulse loop: scale 1.0 to 1.04
            float pulse = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 1.6f));
            base_scale *= (1.0f + 0.035f * pulse);
        }

        float scaled_r = hero_r * base_scale;
        float scaled_d = scaled_r * 2.0f;

        Gdiplus::Color btn_bg = is_connected ? ds.colors.btn_on_bg : ds.colors.btn_bg;
        Gdiplus::SolidBrush btn_brush(btn_bg);
        g.FillEllipse(&btn_brush, cur_hero_cx - scaled_r, hero_cy - scaled_r, scaled_d, scaled_d);

        // Ring border: 2.5px teal for connected, 3px accent for connecting, 3px red for error, 3px cool gray for idle
        float ring_thickness = scale_f(is_connected ? 2.5f : 3.0f, cur_dpi);
        Gdiplus::Color btn_border;
        if (is_connected) {
            btn_border = ds.colors.accent;
        } else if (is_connecting || is_disconnecting) {
            btn_border = ds.colors.accent;
        } else if (is_error) {
            btn_border = ds.colors.error;
        } else {
            float breathe = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 4.0f));
            BYTE idle_alpha = static_cast<BYTE>(std::clamp(140.0f + 70.0f * breathe, 0.0f, 255.0f));
            btn_border = Gdiplus::Color(idle_alpha, ds.colors.btn_border_dim.GetR(), ds.colors.btn_border_dim.GetG(), ds.colors.btn_border_dim.GetB());
        }
        Gdiplus::Pen btn_pen(btn_border, ring_thickness);
        float inset = ring_thickness / 2.0f;
        g.DrawEllipse(&btn_pen, cur_hero_cx - scaled_r + inset, hero_cy - scaled_r + inset, scaled_d - ring_thickness, scaled_d - ring_thickness);

        // 4. Lucide Vector Icons (Check / Loader2 / AlertTriangle / Power)
        float icon_sz = scale_f(48.0f, cur_dpi) * hero_scale_;
        float s = icon_sz / 24.0f;

        if (is_connected) {
            // Lucide Check: polyline "20 6 9 17 4 12"
            Gdiplus::Pen chk_pen(ds.colors.accent, 2.6f * s);
            chk_pen.SetStartCap(Gdiplus::LineCapRound);
            chk_pen.SetEndCap(Gdiplus::LineCapRound);
            chk_pen.SetLineJoin(Gdiplus::LineJoinRound);

            Gdiplus::PointF chk_pts[3] = {
                Gdiplus::PointF(cur_hero_cx - 8.0f * s, hero_cy),
                Gdiplus::PointF(cur_hero_cx - 3.0f * s, hero_cy + 5.0f * s),
                Gdiplus::PointF(cur_hero_cx + 8.0f * s, hero_cy - 6.0f * s)
            };
            g.DrawLines(&chk_pen, chk_pts, 3);

        } else if (is_connecting || is_disconnecting) {
            // Lucide Loader2: arc of radius 9, span 270°, spinning continuously
            Gdiplus::Pen ldr_pen(ds.colors.accent, 2.4f * s);
            ldr_pen.SetStartCap(Gdiplus::LineCapRound);
            ldr_pen.SetEndCap(Gdiplus::LineCapRound);

            float arc_r = 9.0f * s;
            g.DrawArc(&ldr_pen, cur_hero_cx - arc_r, hero_cy - arc_r, arc_r * 2.0f, arc_r * 2.0f, spin_angle_, 270.0f);

        } else if (is_error) {
            // Lucide AlertTriangle: triangle with stem and dot
            Gdiplus::Pen err_pen(ds.colors.error, 2.2f * s);
            err_pen.SetStartCap(Gdiplus::LineCapRound);
            err_pen.SetEndCap(Gdiplus::LineCapRound);
            err_pen.SetLineJoin(Gdiplus::LineJoinRound);

            Gdiplus::PointF tri_pts[4] = {
                Gdiplus::PointF(cur_hero_cx, hero_cy - 8.5f * s),
                Gdiplus::PointF(cur_hero_cx + 8.5f * s, hero_cy + 7.0f * s),
                Gdiplus::PointF(cur_hero_cx - 8.5f * s, hero_cy + 7.0f * s),
                Gdiplus::PointF(cur_hero_cx, hero_cy - 8.5f * s)
            };
            g.DrawLines(&err_pen, tri_pts, 4);

            g.DrawLine(&err_pen, cur_hero_cx, hero_cy - 2.8f * s, cur_hero_cx, hero_cy + 1.2f * s);
            Gdiplus::SolidBrush err_dot_b(ds.colors.error);
            g.FillEllipse(&err_dot_b, cur_hero_cx - 1.2f * s, hero_cy + 4.0f * s, 2.4f * s, 2.4f * s);

        } else {
            // Lucide Power: stem "12 2v10" + arc "18.36 6.64A9 9 0 1 1 5.63 6.64"
            Gdiplus::Pen pwr_pen(ds.colors.icon_color, 2.2f * s);
            pwr_pen.SetStartCap(Gdiplus::LineCapRound);
            pwr_pen.SetEndCap(Gdiplus::LineCapRound);

            g.DrawLine(&pwr_pen, cur_hero_cx, hero_cy - 9.0f * s, cur_hero_cx, hero_cy);
            float arc_r = 9.0f * s;
            g.DrawArc(&pwr_pen, cur_hero_cx - arc_r, hero_cy - arc_r, arc_r * 2.0f, arc_r * 2.0f, -45.0f, 270.0f);
        }

        // ── 3. Status Label Block (Height: 64 DIPs, margin-top: 28 DIPs) ──
        float status_y = hero_cy + hero_r + scale_f(28, cur_dpi);
        Gdiplus::StringFormat center_fmt;
        center_fmt.SetAlignment(Gdiplus::StringAlignmentCenter);

        Gdiplus::SolidBrush muted_brush(ds.colors.text_muted);

        if (is_connected) {
            g.DrawString(L"Connected", -1, font_hero_status_.get(), Gdiplus::PointF(cur_hero_cx, status_y), &center_fmt, &text_pri_brush);

            uint64_t up_s = stats.uptime;
            std::wstring uptime_str = std::format(L"{:02d}:{:02d}:{:02d}", up_s / 3600, (up_s % 3600) / 60, up_s % 60);
            std::wstring socks_str = std::wstring(profile.bind_address.begin(), profile.bind_address.end());
            std::wstring sub_str = uptime_str + L" · " + socks_str;

            Gdiplus::SolidBrush teal_brush(ds.colors.accent);
            g.DrawString(sub_str.c_str(), -1, font_mono_.get(), Gdiplus::PointF(cur_hero_cx, status_y + scale_f(32, cur_dpi)), &center_fmt, &teal_brush);

        } else if (is_connecting || is_disconnecting) {
            std::wstring conn_str = is_disconnecting ? L"Disconnecting…" : L"Finding a route…";
            g.DrawString(conn_str.c_str(), -1, font_hero_status_.get(), Gdiplus::PointF(cur_hero_cx, status_y), &center_fmt, &text_pri_brush);

            int sec = static_cast<int>(connecting_time_);
            std::wstring sub_txt = is_disconnecting ? L"Stopping tunnel" : std::format(L"Still searching · {:02d}:{:02d}", sec / 60, sec % 60);
            g.DrawString(sub_txt.c_str(), -1, font_body_.get(), Gdiplus::PointF(cur_hero_cx, status_y + scale_f(32, cur_dpi)), &center_fmt, &muted_brush);

            // ScanProgressBar: Indeterminate sweep track matching ConnectionStatusLine.tsx
            if (!is_disconnecting) {
                float bar_w = scale_f(140.0f, cur_dpi);
                float bar_h = scale_f(3.5f, cur_dpi);
                float bar_x = cur_hero_cx - bar_w / 2.0f;
                float bar_y = status_y + scale_f(56, cur_dpi);
                float bar_r = bar_h / 2.0f;

                Gdiplus::SolidBrush track_b(ds.colors.btn_border);
                fill_rounded_rect(g, track_b, bar_x, bar_y, bar_w, bar_h, bar_r);

                float sweep_t = 0.5f + 0.5f * std::sin(anim_time_ * 3.5f);
                float thumb_w = bar_w * 0.35f;
                float thumb_x = bar_x + sweep_t * (bar_w - thumb_w);
                Gdiplus::SolidBrush thumb_b(ds.colors.accent);
                fill_rounded_rect(g, thumb_b, thumb_x, bar_y, thumb_w, bar_h, bar_r);
            }

        } else if (is_error) {
            g.DrawString(L"Connection failed", -1, font_hero_status_.get(), Gdiplus::PointF(cur_hero_cx, status_y), &center_fmt, &text_pri_brush);
            std::wstring err_msg = state.error_message.empty() ? L"Endpoint timed out" : std::wstring(state.error_message.begin(), state.error_message.end());
            Gdiplus::SolidBrush err_brush(ds.colors.error);
            g.DrawString(err_msg.c_str(), -1, font_body_.get(), Gdiplus::PointF(cur_hero_cx, status_y + scale_f(32, cur_dpi)), &center_fmt, &err_brush);

        } else {
            g.DrawString(L"Disconnected", -1, font_hero_status_.get(), Gdiplus::PointF(cur_hero_cx, status_y), &center_fmt, &text_pri_brush);
            g.DrawString(L"Click to connect", -1, font_body_.get(), Gdiplus::PointF(cur_hero_cx, status_y + scale_f(32, cur_dpi)), &center_fmt, &muted_brush);
        }

        // ── 4. Middle Section (Ping, Down, Up stats matching Main.dc.html) ──
        float middle_y = status_y + scale_f(64 + 20, cur_dpi);
        float card_x = pad_x;
        float card_w = w - pad_x * 2.0f;

        if (is_connected) {
            Gdiplus::SolidBrush tag_brush(ds.colors.text_submuted);
            float col_w = card_w / 3.0f;

            auto draw_stat_col = [&](int idx, const std::wstring& tag, const std::wstring& val) {
                float cx = card_x + col_w * (idx + 0.5f);
                g.DrawString(tag.c_str(), -1, font_metric_tag_.get(), Gdiplus::PointF(cx, middle_y + scale_f(4, cur_dpi)), &center_fmt, &tag_brush);
                g.DrawString(val.c_str(), -1, font_mono_.get(), Gdiplus::PointF(cx, middle_y + scale_f(22, cur_dpi)), &center_fmt, &text_pri_brush);
            };

            std::wstring ping_str = std::format(L"{} ms", live_ping_ms_);
            draw_stat_col(0, L"PING", ping_str);

            std::wstring down_str = std::format(L"{:.1f} MB/s", live_down_speed_mb_);
            draw_stat_col(1, L"DOWN", down_str);

            std::wstring up_str = std::format(L"{:.1f} MB/s", live_up_speed_mb_);
            draw_stat_col(2, L"UP", up_str);

        } else if (is_error) {
            float pill_h = (float)scale(44, cur_dpi);
            float pill_r = (float)scale(ds.metrics.radius_chip, cur_dpi);
            float pill_w = (float)scale(110, cur_dpi);
            float gap = (float)scale(10, cur_dpi);

            float btn1_x = cur_hero_cx - pill_w - gap / 2.0f;
            float btn2_x = cur_hero_cx + gap / 2.0f;
            float pill_y = middle_y + (scale_f(56, cur_dpi) - pill_h) / 2.0f;

            // "Try again" button
            Gdiplus::Color try_bg = try_again_hovered_ ? ds.colors.hover_bg : ds.colors.chip_bg;
            Gdiplus::Color try_bd = try_again_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
            Gdiplus::SolidBrush try_brush(try_bg);
            Gdiplus::Pen try_pen(try_bd, 1.0f);
            fill_rounded_rect(g, try_brush, btn1_x, pill_y, pill_w, pill_h, pill_r);
            draw_rounded_rect(g, try_pen, btn1_x, pill_y, pill_w, pill_h, pill_r);
            g.DrawString(L"Try again", -1, font_body_bold_.get(), Gdiplus::PointF(btn1_x + pill_w / 2.0f, pill_y + scale_f(12, cur_dpi)), &center_fmt, &text_pri_brush);

            // "View logs" button
            Gdiplus::Color vlg_bg = view_logs_chip_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
            Gdiplus::Color vlg_bd = view_logs_chip_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border;
            Gdiplus::SolidBrush vlg_brush(vlg_bg);
            Gdiplus::Pen vlg_pen(vlg_bd, 1.0f);
            fill_rounded_rect(g, vlg_brush, btn2_x, pill_y, pill_w, pill_h, pill_r);
            draw_rounded_rect(g, vlg_pen, btn2_x, pill_y, pill_w, pill_h, pill_r);

            Gdiplus::SolidBrush vlg_txt_brush(view_logs_chip_hovered_ ? ds.colors.text_primary : ds.colors.text_muted);
            g.DrawString(L"View logs", -1, font_body_bold_.get(), Gdiplus::PointF(btn2_x + pill_w / 2.0f, pill_y + scale_f(12, cur_dpi)), &center_fmt, &vlg_txt_brush);
        }

        // ── 5. Details Card (w: 364, h: 156, radius: 16) ──
        float card_y = (float)scale(470, cur_dpi);
        float row_h = (float)scale(ds.metrics.row_height, cur_dpi);
        float card_h = row_h * 3.0f;

        Gdiplus::SolidBrush card_bg(ds.colors.card_bg);
        fill_rounded_rect(g, card_bg, card_x, card_y, card_w, card_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        Gdiplus::Pen card_pen(ds.colors.card_border, 1.0f);
        draw_rounded_rect(g, card_pen, card_x, card_y, card_w, card_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        // Row hover highlights for interactive rows
        Gdiplus::SolidBrush row_hov(ds.colors.dropdown_hover);
        if (home_proto_hovered_) {
            fill_rounded_rect(g, row_hov, card_x + 1.0f, card_y + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(12, cur_dpi));
        }
        if (home_route_hovered_) {
            fill_rounded_rect(g, row_hov, card_x + 1.0f, card_y + row_h + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(12, cur_dpi));
        }

        // Horizontal Row Dividers
        g.DrawLine(&card_pen, card_x, card_y + row_h, card_x + card_w, card_y + row_h);
        g.DrawLine(&card_pen, card_x, card_y + row_h * 2.0f, card_x + card_w, card_y + row_h * 2.0f);

        Gdiplus::StringFormat right_fmt;
        right_fmt.SetAlignment(Gdiplus::StringAlignmentFar);

        float label_pad_x = (float)scale(ds.metrics.row_padding_x, cur_dpi);
        float label_pad_y = (row_h - (float)scale(ds.typo.mono_value, cur_dpi)) / 2.0f;

        // Row 1: Protocol
        std::wstring proto_name = L"Auto";
        switch (profile.protocol) {
            case Protocol::Auto: proto_name = L"Auto"; break;
            case Protocol::Gool: proto_name = L"Gool (WARP over MASQUE)"; break;
            case Protocol::WarpInWarp: proto_name = L"WARP-in-WARP (Classic)"; break;
            case Protocol::Masque: proto_name = profile.masque_http2 ? L"MASQUE (H2)" : L"MASQUE (H3)"; break;
            case Protocol::Wireguard: proto_name = L"WireGuard"; break;
            case Protocol::Mim: proto_name = L"MiM"; break;
            default: break;
        }
        g.DrawString(L"Protocol", -1, font_body_.get(), Gdiplus::PointF(card_x + label_pad_x, card_y + label_pad_y), &muted_brush);
        std::wstring proto_disp = proto_name + L"  ›";
        g.DrawString(proto_disp.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - label_pad_x, card_y + label_pad_y), &right_fmt, &text_pri_brush);

        // Row 2: Route (Location & Scan Mode)
        std::wstring loc_str = profile.exit_loc.empty() ? L"Auto" : std::wstring(profile.exit_loc.begin(), profile.exit_loc.end());
        std::wstring scan_str = L"Balanced";
        switch (profile.scan_mode) {
            case ScanMode::Turbo: scan_str = L"Turbo"; break;
            case ScanMode::Thorough: scan_str = L"Thorough"; break;
            case ScanMode::Verified: scan_str = L"Verified"; break;
            case ScanMode::Ironclad: scan_str = L"Ironclad"; break;
            default: break;
        }
        std::wstring route_display = loc_str + L" · " + scan_str + L"  ›";
        g.DrawString(L"Route", -1, font_body_.get(), Gdiplus::PointF(card_x + label_pad_x, card_y + row_h + label_pad_y), &muted_brush);
        g.DrawString(route_display.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - label_pad_x, card_y + row_h + label_pad_y), &right_fmt, &text_pri_brush);

        // Row 3: SOCKS5 Address + Copy Button
        std::wstring socks_str = std::wstring(profile.bind_address.begin(), profile.bind_address.end());
        g.DrawString(L"SOCKS5", -1, font_body_.get(), Gdiplus::PointF(card_x + label_pad_x, card_y + row_h * 2.0f + label_pad_y), &muted_brush);

        float copy_btn_sz = (float)scale(44, cur_dpi);
        float copy_btn_x = card_x + card_w - label_pad_x - copy_btn_sz + scale_f(8, cur_dpi);
        float copy_btn_y = card_y + row_h * 2.0f + (row_h - copy_btn_sz) / 2.0f;

        g.DrawString(socks_str.c_str(), -1, font_mono_.get(), Gdiplus::PointF(copy_btn_x - scale_f(6, cur_dpi), card_y + row_h * 2.0f + label_pad_y), &right_fmt, &text_pri_brush);

        if (copy_btn_hovered_) {
            Gdiplus::SolidBrush cp_hov(ds.colors.hover_bg);
            fill_rounded_rect(g, cp_hov, copy_btn_x, copy_btn_y, copy_btn_sz, copy_btn_sz, (float)scale(12, cur_dpi));
        }

        float cp_cx = copy_btn_x + copy_btn_sz / 2.0f;
        float cp_cy = copy_btn_y + copy_btn_sz / 2.0f;

        if (copy_timer_ > 0.0f) {
            Gdiplus::Pen chk_pen(ds.colors.accent, 1.8f);
            chk_pen.SetStartCap(Gdiplus::LineCapRound);
            chk_pen.SetEndCap(Gdiplus::LineCapRound);
            chk_pen.SetLineJoin(Gdiplus::LineJoinRound);

            Gdiplus::PointF chk_pts[3] = {
                Gdiplus::PointF(cp_cx - scale_f(5, cur_dpi), cp_cy + scale_f(0.5f, cur_dpi)),
                Gdiplus::PointF(cp_cx - scale_f(1, cur_dpi), cp_cy + scale_f(4.5f, cur_dpi)),
                Gdiplus::PointF(cp_cx + scale_f(6, cur_dpi), cp_cy - scale_f(3.5f, cur_dpi))
            };
            g.DrawLines(&chk_pen, chk_pts, 3);
        } else {
            Gdiplus::Pen cp_pen(copy_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.6f);
            cp_pen.SetLineJoin(Gdiplus::LineJoinRound);

            float sq_sz = (float)scale(10, cur_dpi);
            float r_sub = scale_f(2.5f, cur_dpi);

            draw_rounded_rect(g, cp_pen, cp_cx - scale_f(2, cur_dpi), cp_cy - scale_f(2, cur_dpi), sq_sz, sq_sz, r_sub);
            Gdiplus::PointF bkg_pts[3] = {
                Gdiplus::PointF(cp_cx + scale_f(3, cur_dpi), cp_cy - scale_f(6, cur_dpi)),
                Gdiplus::PointF(cp_cx - scale_f(6, cur_dpi), cp_cy - scale_f(6, cur_dpi)),
                Gdiplus::PointF(cp_cx - scale_f(6, cur_dpi), cp_cy + scale_f(3, cur_dpi))
            };
            g.DrawLines(&cp_pen, bkg_pts, 3);
        }

        // ── 6. Footer: "Free and open source" ──
        Gdiplus::SolidBrush foot_brush(ds.colors.text_dim);
        g.DrawString(L"Free and open source", -1, font_footnote_.get(), Gdiplus::PointF(hero_cx, card_y + card_h + scale_f(20, cur_dpi)), &center_fmt, &foot_brush);
    }

    // ── Settings View (Appearance Segmented + General + About Row, Zero Clipping) ──
    void render_settings_view(Gdiplus::Graphics& g, float w, float h, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "Settings" Title
        float back_btn_x = (float)scale(ds.metrics.padding_x, cur_dpi);
        float back_btn_y = (float)scale(ds.metrics.padding_top, cur_dpi);
        float back_btn_size = (float)scale(ds.metrics.header_btn_size, cur_dpi);

        Gdiplus::Color back_bg = back_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color back_border_col = back_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush back_bg_brush(back_bg);
        Gdiplus::Pen back_pen(back_border_col, 1.0f);
        fill_rounded_rect(g, back_bg_brush, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));
        draw_rounded_rect(g, back_pen, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));

        // Chevron '<' vector
        Gdiplus::Pen chev_pen(back_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.8f);
        chev_pen.SetStartCap(Gdiplus::LineCapRound);
        chev_pen.SetEndCap(Gdiplus::LineCapRound);
        chev_pen.SetLineJoin(Gdiplus::LineJoinRound);
        float bcx = back_btn_x + back_btn_size / 2.0f;
        float bcy = back_btn_y + back_btn_size / 2.0f;
        Gdiplus::PointF chev_pts[3] = {
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy - scale_f(6, cur_dpi)),
            Gdiplus::PointF(bcx - scale_f(4, cur_dpi), bcy),
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy + scale_f(6, cur_dpi))
        };
        g.DrawLines(&chev_pen, chev_pts, 3);

        Gdiplus::SolidBrush title_brush(ds.colors.text_primary);
        g.DrawString(L"Settings", -1, font_view_title_.get(), Gdiplus::PointF(back_btn_x + back_btn_size + scale_f(14, cur_dpi), back_btn_y + scale_f(8, cur_dpi)), &title_brush);

        // 2. Scrollable Body
        float clip_top = back_btn_y + back_btn_size + scale_f(12, cur_dpi);
        Gdiplus::GraphicsState state_clip = g.Save();
        g.SetClip(Gdiplus::RectF(0.0f, clip_top, w, h - clip_top));
        g.TranslateTransform(0.0f, -scale_f(scroll_anim_y_, cur_dpi));

        float card_x = back_btn_x;
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float row_h = (float)scale(ds.metrics.row_height, cur_dpi);
        float pad_x = (float)scale(ds.metrics.row_padding_x, cur_dpi);

        Gdiplus::SolidBrush card_bg(ds.colors.card_bg);
        Gdiplus::Pen card_pen(ds.colors.card_border, 1.0f);
        Gdiplus::SolidBrush sec_brush(ds.colors.text_submuted);
        Gdiplus::SolidBrush label_brush(ds.colors.text_muted);
        Gdiplus::SolidBrush text_pri_brush(ds.colors.text_primary);
        Gdiplus::StringFormat right_fmt;
        right_fmt.SetAlignment(Gdiplus::StringAlignmentFar);
        Gdiplus::SolidBrush row_hover_brush(ds.colors.dropdown_hover);

        // Toggle Switch Drawer helper with smooth animation
        auto draw_animated_toggle = [&](float sw_x, float sw_y, int toggle_idx) {
            float anim = switch_anim_[toggle_idx];
            float sw_w = (float)scale(40, cur_dpi);
            float sw_h = (float)scale(24, cur_dpi);
            float sw_r = sw_h / 2.0f;

            // Track color smoothly interpolated
            Gdiplus::Color track_col = blend_colors(ds.colors.btn_border_dim, ds.colors.accent, anim);
            Gdiplus::SolidBrush sw_bg(track_col);
            fill_rounded_rect(g, sw_bg, sw_x, sw_y, sw_w, sw_h, sw_r);

            // Knob X position smoothly interpolated
            float margin = scale_f(3.0f, cur_dpi);
            float knob_d = scale_f(18.0f, cur_dpi);
            float knob_left = sw_x + margin + anim * (sw_w - margin * 2.0f - knob_d);
            float knob_top = sw_y + margin;

            Gdiplus::Color knob_col = blend_colors(ds.colors.icon_color, ds.colors.bg, anim);
            Gdiplus::SolidBrush knob_bg(knob_col);
            g.FillEllipse(&knob_bg, knob_left, knob_top, knob_d, knob_d);
        };

        // ── Card 0: APPEARANCE (Segmented Control: System | Light | Dark with Fluid Sliding Pill) ──
        float sec0_y = clip_top + scale_f(8, cur_dpi);
        g.DrawString(L"APPEARANCE", -1, font_metric_tag_.get(), Gdiplus::PointF(card_x + scale_f(4, cur_dpi), sec0_y), &sec_brush);

        float card0_y = sec0_y + scale_f(22, cur_dpi);
        float seg_box_h = (float)scale(52, cur_dpi);
        fill_rounded_rect(g, card_bg, card_x, card0_y, card_w, seg_box_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, card0_y, card_w, seg_box_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        // 3 Segmented buttons
        float seg_gap = scale_f(4, cur_dpi);
        float seg_w = (card_w - scale_f(8, cur_dpi) - seg_gap * 2.0f) / 3.0f;
        float seg_h = seg_box_h - scale_f(8, cur_dpi);
        float seg_y = card0_y + scale_f(4, cur_dpi);

        // Fluid Animated Sliding Pill!
        float sliding_pill_x = card_x + scale_f(4, cur_dpi) + seg_anim_x_ * (seg_w + seg_gap);
        Gdiplus::SolidBrush chip_b(ds.colors.chip_bg);
        fill_rounded_rect(g, chip_b, sliding_pill_x, seg_y, seg_w, seg_h, (float)scale(ds.metrics.radius_control, cur_dpi));
        Gdiplus::Pen chip_p(ds.colors.border_hover_bright, 1.0f);
        draw_rounded_rect(g, chip_p, sliding_pill_x, seg_y, seg_w, seg_h, (float)scale(ds.metrics.radius_control, cur_dpi));

        const wchar_t* seg_labels[] = { L"System", L"Light", L"Dark" };
        const std::string seg_keys[] = { "system", "light", "dark" };

        Gdiplus::StringFormat center_fmt;
        center_fmt.SetAlignment(Gdiplus::StringAlignmentCenter);
        center_fmt.SetLineAlignment(Gdiplus::StringAlignmentCenter);

        for (int i = 0; i < 3; ++i) {
            float sx = card_x + scale_f(4, cur_dpi) + static_cast<float>(i) * (seg_w + seg_gap);
            bool is_active = (edit_settings_.theme == seg_keys[i]);
            Gdiplus::SolidBrush seg_txt(is_active ? ds.colors.text_primary : ds.colors.text_muted);
            g.DrawString(seg_labels[i], -1, font_body_.get(), Gdiplus::PointF(sx + seg_w / 2.0f, seg_y + seg_h / 2.0f), &center_fmt, &seg_txt);
        }

        // ── Card 1: GENERAL (4 Animated Toggles) ──
        float sec1_y = card0_y + seg_box_h + scale_f(24, cur_dpi);
        g.DrawString(L"GENERAL", -1, font_metric_tag_.get(), Gdiplus::PointF(card_x + scale_f(4, cur_dpi), sec1_y), &sec_brush);

        float card1_y = sec1_y + scale_f(22, cur_dpi);
        float gen_row_h = (float)scale(64, cur_dpi);
        float card1_h = gen_row_h * 4.0f;
        fill_rounded_rect(g, card_bg, card_x, card1_y, card_w, card1_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, card1_y, card_w, card1_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        for (int i = 1; i < 4; ++i) {
            g.DrawLine(&card_pen, card_x, card1_y + gen_row_h * static_cast<float>(i), card_x + card_w, card1_y + gen_row_h * static_cast<float>(i));
        }

        if (hovered_settings_row_ >= 10 && hovered_settings_row_ <= 13) {
            float hy = card1_y + static_cast<float>(hovered_settings_row_ - 10) * gen_row_h;
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, hy + 1.0f, card_w - 2.0f, gen_row_h - 2.0f, (float)scale(10, cur_dpi));
        }

        float sw_x = card_x + card_w - pad_x - scale_f(40, cur_dpi);

        // General Row 0: Launch at login
        float gy0 = card1_y + scale_f(12, cur_dpi);
        g.DrawString(L"Launch at login", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, gy0), &text_pri_brush);
        g.DrawString(L"Start minimized on system boot", -1, font_sub_label_.get(), Gdiplus::PointF(card_x + pad_x, gy0 + scale_f(20, cur_dpi)), &label_brush);
        draw_animated_toggle(sw_x, card1_y + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 0);

        // General Row 1: Keep in system tray
        float gy1 = card1_y + gen_row_h + scale_f(12, cur_dpi);
        g.DrawString(L"Keep in system tray", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, gy1), &text_pri_brush);
        g.DrawString(L"Close button hides to notification area", -1, font_sub_label_.get(), Gdiplus::PointF(card_x + pad_x, gy1 + scale_f(20, cur_dpi)), &label_brush);
        draw_animated_toggle(sw_x, card1_y + gen_row_h + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 1);

        // General Row 2: Kill switch
        float gy2 = card1_y + gen_row_h * 2.0f + scale_f(12, cur_dpi);
        g.DrawString(L"Kill switch", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, gy2), &text_pri_brush);
        g.DrawString(L"Block all traffic if connection drops", -1, font_sub_label_.get(), Gdiplus::PointF(card_x + pad_x, gy2 + scale_f(20, cur_dpi)), &label_brush);
        draw_animated_toggle(sw_x, card1_y + gen_row_h * 2.0f + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 2);

        // General Row 3: Windows system proxy
        float gy3 = card1_y + gen_row_h * 3.0f + scale_f(12, cur_dpi);
        g.DrawString(L"System proxy", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, gy3), &text_pri_brush);
        g.DrawString(L"Route system Internet traffic through Hemera", -1, font_sub_label_.get(), Gdiplus::PointF(card_x + pad_x, gy3 + scale_f(20, cur_dpi)), &label_brush);
        draw_animated_toggle(sw_x, card1_y + gen_row_h * 3.0f + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 3);

        // ── Card 2: CONNECTION & ROUTING (Protocol, Scan mode, Exit location, IP version, Bypass local) ──
        float sec2_y = card1_y + card1_h + scale_f(24, cur_dpi);
        g.DrawString(L"CONNECTION & ROUTING", -1, font_metric_tag_.get(), Gdiplus::PointF(card_x + scale_f(4, cur_dpi), sec2_y), &sec_brush);

        float card2_y = sec2_y + scale_f(22, cur_dpi);
        float card2_h = row_h * 5.0f;
        fill_rounded_rect(g, card_bg, card_x, card2_y, card_w, card2_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, card2_y, card_w, card2_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        for (int i = 1; i < 5; ++i) {
            g.DrawLine(&card_pen, card_x, card2_y + row_h * static_cast<float>(i), card_x + card_w, card2_y + row_h * static_cast<float>(i));
        }

        if (hovered_settings_row_ >= 0 && hovered_settings_row_ < 4) {
            float hy = card2_y + static_cast<float>(hovered_settings_row_) * row_h;
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, hy + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        } else if (hovered_settings_row_ == 16) {
            float hy = card2_y + 4.0f * row_h;
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, hy + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        }

        // Row 0: Protocol
        std::wstring proto_lbl = L"Auto ▾";
        switch (edit_profile_.protocol) {
            case Protocol::Auto: proto_lbl = L"Auto ▾"; break;
            case Protocol::Gool: proto_lbl = L"Gool (WARP over MASQUE) ▾"; break;
            case Protocol::WarpInWarp: proto_lbl = L"WARP-in-WARP (Classic) ▾"; break;
            case Protocol::Masque: proto_lbl = edit_profile_.masque_http2 ? L"MASQUE (H2) ▾" : L"MASQUE (H3) ▾"; break;
            case Protocol::Wireguard: proto_lbl = L"WireGuard ▾"; break;
            case Protocol::Mim: proto_lbl = L"MiM ▾"; break;
        }
        float row_y0 = card2_y + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Protocol", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, row_y0), &label_brush);
        g.DrawString(proto_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, row_y0), &right_fmt, &text_pri_brush);

        // Row 1: Scan mode
        std::wstring scan_lbl = L"Balanced (Recommended) ▾";
        switch (edit_profile_.scan_mode) {
            case ScanMode::Turbo: scan_lbl = L"Turbo (Fastest) ▾"; break;
            case ScanMode::Thorough: scan_lbl = L"Thorough ▾"; break;
            case ScanMode::Verified: scan_lbl = L"Verified (Stealth) ▾"; break;
            case ScanMode::Ironclad: scan_lbl = L"Ironclad ▾"; break;
            default: break;
        }
        float row_y1 = card2_y + row_h + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Scan mode", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, row_y1), &label_brush);
        g.DrawString(scan_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, row_y1), &right_fmt, &text_pri_brush);

        // Row 2: Exit location
        std::wstring exit_lbl = edit_profile_.exit_loc.empty() ? L"Auto (Fastest) ▾" : (std::wstring(edit_profile_.exit_loc.begin(), edit_profile_.exit_loc.end()) + L" ▾");
        float row_y2 = card2_y + row_h * 2.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Exit location", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, row_y2), &label_brush);
        g.DrawString(exit_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, row_y2), &right_fmt, &text_pri_brush);

        // Row 3: IP version
        std::wstring ip_lbl = (edit_profile_.ip_version == IpVersion::V6) ? L"IPv6 ▾" : (edit_profile_.ip_version == IpVersion::Both ? L"Dual ▾" : L"IPv4 ▾");
        float row_y3 = card2_y + row_h * 3.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"IP version", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, row_y3), &label_brush);
        g.DrawString(ip_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, row_y3), &right_fmt, &text_pri_brush);

        // Row 4: Bypass local traffic
        float row_y4 = card2_y + row_h * 4.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Bypass local traffic", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, row_y4), &text_pri_brush);
        draw_animated_toggle(sw_x, card2_y + row_h * 4.0f + (row_h - scale_f(24, cur_dpi)) / 2.0f, 6);

        // ── Card 3: ANTI-CENSORSHIP & NETWORK ──
        float sec3_y = card2_y + card2_h + scale_f(24, cur_dpi);
        g.DrawString(L"ANTI-CENSORSHIP & NETWORK", -1, font_metric_tag_.get(), Gdiplus::PointF(card_x + scale_f(4, cur_dpi), sec3_y), &sec_brush);

        float card3_y = sec3_y + scale_f(22, cur_dpi);
        float card3_h = row_h * 5.0f;
        fill_rounded_rect(g, card_bg, card_x, card3_y, card_w, card3_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, card3_y, card_w, card3_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        for (int i = 1; i < 5; ++i) {
            g.DrawLine(&card_pen, card_x, card3_y + row_h * static_cast<float>(i), card_x + card_w, card3_y + row_h * static_cast<float>(i));
        }

        if (hovered_settings_row_ == 14) {
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, card3_y + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        } else if (hovered_settings_row_ == 15) {
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, card3_y + row_h + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        } else if (hovered_settings_row_ >= 4 && hovered_settings_row_ <= 6) {
            float hy = card3_y + static_cast<float>(hovered_settings_row_ - 2) * row_h;
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, hy + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        }

        // Card 3 Row 0: ClientHello Fragmentation
        float r3_y0 = card3_y + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"TLS fragmentation", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, r3_y0), &text_pri_brush);
        draw_animated_toggle(sw_x, card3_y + (row_h - scale_f(24, cur_dpi)) / 2.0f, 4);

        // Card 3 Row 1: Encrypted Client Hello / ECH
        float r3_y1 = card3_y + row_h + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Encrypted Client Hello (ECH)", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, r3_y1), &text_pri_brush);
        draw_animated_toggle(sw_x, card3_y + row_h + (row_h - scale_f(24, cur_dpi)) / 2.0f, 5);

        // Card 3 Row 2: Obfuscation
        std::wstring noize_lbl = L"Balanced ▾";
        switch (edit_profile_.masque_noize) {
            case MasqueNoize::Gfw: noize_lbl = L"Aggressive ▾"; break;
            case MasqueNoize::Off: noize_lbl = L"Off ▾"; break;
            default: break;
        }
        float r3_y2 = card3_y + row_h * 2.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Obfuscation", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, r3_y2), &label_brush);
        g.DrawString(noize_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, r3_y2), &right_fmt, &text_pri_brush);

        // Card 3 Row 3: DNS server
        std::wstring dns_lbl = L"Auto (1.1.1.1) ▾";
        if (edit_profile_.dns == "1.1.1.2") dns_lbl = L"Security (1.1.1.2) ▾";
        else if (edit_profile_.dns == "8.8.8.8") dns_lbl = L"Google (8.8.8.8) ▾";
        else if (edit_profile_.dns == "9.9.9.9") dns_lbl = L"Quad9 (9.9.9.9) ▾";
        else if (!edit_profile_.dns.empty()) dns_lbl = std::wstring(edit_profile_.dns.begin(), edit_profile_.dns.end()) + L" ▾";
        float r3_y3 = card3_y + row_h * 3.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"DNS server", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, r3_y3), &label_brush);
        g.DrawString(dns_lbl.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, r3_y3), &right_fmt, &text_pri_brush);

        // Card 3 Row 4: SOCKS5 proxy
        float r3_y4 = card3_y + row_h * 4.0f + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"SOCKS5 proxy", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, r3_y4), &label_brush);

        std::wstring socks_display = socks_edit_buffer_.empty() ? L"127.0.0.1:1819" : socks_edit_buffer_;
        if (is_editing_socks_) {
            bool show_caret = (std::fmod(caret_blink_timer_, 1.0f) < 0.5f);
            socks_display += show_caret ? L"|" : L" ";
            Gdiplus::SolidBrush active_txt_brush(ds.colors.accent);
            g.DrawString(socks_display.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, r3_y4), &right_fmt, &active_txt_brush);
        } else {
            g.DrawString(socks_display.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, r3_y4), &right_fmt, &text_pri_brush);
        }

        // ── Card 4: ABOUT Row ──
        float sec4_y = card3_y + card3_h + scale_f(24, cur_dpi);
        fill_rounded_rect(g, card_bg, card_x, sec4_y, card_w, row_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, sec4_y, card_w, row_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        if (hovered_settings_row_ == 20) {
            fill_rounded_rect(g, row_hover_brush, card_x + 1.0f, sec4_y + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(10, cur_dpi));
        }

        float about_y = sec4_y + (row_h - (float)scale(ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"About Hemera", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, about_y), &text_pri_brush);
        std::wstring about_sub = L"v1.0.1   ›";
        g.DrawString(about_sub.c_str(), -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, about_y), &right_fmt, &label_brush);

        // Footer: "Hemera · Free and open source proxy"
        Gdiplus::SolidBrush foot_brush(ds.colors.text_dim);
        g.DrawString(L"Hemera · Free and open source proxy", -1, font_footnote_.get(), Gdiplus::PointF(w / 2.0f, sec4_y + row_h + scale_f(24, cur_dpi)), &center_fmt, &foot_brush);

        // Calculate max_scroll dynamically
        float total_h = sec4_y + row_h + scale_f(50, cur_dpi);
        float visible_h = h - clip_top;
        if (total_h > visible_h) {
            max_scroll_ = static_cast<int>((total_h - visible_h) / (static_cast<float>(cur_dpi) / 96.0f)) + 20;
        } else {
            max_scroll_ = 0;
        }

        g.Restore(state_clip);

        // 3. Floating In-Window Dropdown Card Overlay
        if (active_dropdown_ >= 0 && !dropdown_options_.empty()) {
            render_dropdown_overlay(g, w, h, cur_dpi);
        }
    }

    // ── Floating Custom In-Window Dropdown Card (Pure GDI+) ──
    void render_dropdown_overlay(Gdiplus::Graphics& g, float w, float /*h*/, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();
        float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float row_h = (float)scale(ds.metrics.row_height, cur_dpi);

        float clip_top = (float)scale(ds.metrics.padding_top, cur_dpi) + (float)scale(ds.metrics.header_btn_size, cur_dpi) + scale_f(12, cur_dpi);
        float sec0_y = clip_top + scale_f(8, cur_dpi);
        float card0_y = sec0_y + scale_f(22, cur_dpi);
        float seg_box_h = (float)scale(52, cur_dpi);

        float sec1_y = card0_y + seg_box_h + scale_f(24, cur_dpi);
        float card1_y = sec1_y + scale_f(22, cur_dpi);
        float gen_row_h = (float)scale(64, cur_dpi);
        float card1_h = gen_row_h * 4.0f;

        float sec2_y = card1_y + card1_h + scale_f(24, cur_dpi);
        float card2_y = sec2_y + scale_f(22, cur_dpi);
        float card2_h = row_h * 5.0f;

        float sec3_y = card2_y + card2_h + scale_f(24, cur_dpi);
        float card3_y = sec3_y + scale_f(22, cur_dpi);

        float sy = scale_f(scroll_anim_y_, cur_dpi);
        float anchor_y = card2_y - sy;
        if (active_dropdown_ >= 0 && active_dropdown_ < 4) {
            anchor_y = card2_y + static_cast<float>(active_dropdown_) * row_h - sy;
        } else if (active_dropdown_ == 4) {
            anchor_y = card3_y + 2.0f * row_h - sy;
        } else if (active_dropdown_ == 5) {
            anchor_y = card3_y + 3.0f * row_h - sy;
        }

        float item_h = (float)scale(ds.metrics.dropdown_item_h, cur_dpi);
        float pop_w = (float)scale(260, cur_dpi);
        float pop_h = item_h * static_cast<float>(dropdown_options_.size());
        float pop_x = card_x + card_w - pop_w;
        float pop_y = anchor_y + row_h + scale_f(4, cur_dpi);

        if (pop_y + pop_h > (float)scale(660, cur_dpi)) {
            pop_y = anchor_y - pop_h - scale_f(4, cur_dpi);
        }

        dropdown_popup_rect_ = {
            static_cast<LONG>(pop_x),
            static_cast<LONG>(pop_y),
            static_cast<LONG>(pop_x + pop_w),
            static_cast<LONG>(pop_y + pop_h)
        };

        Gdiplus::SolidBrush pop_bg(ds.colors.dropdown_bg);
        fill_rounded_rect(g, pop_bg, pop_x, pop_y, pop_w, pop_h, (float)scale(ds.metrics.dropdown_radius, cur_dpi));
        Gdiplus::Pen pop_pen(ds.colors.dropdown_border, 1.0f);
        draw_rounded_rect(g, pop_pen, pop_x, pop_y, pop_w, pop_h, (float)scale(ds.metrics.dropdown_radius, cur_dpi));

        Gdiplus::SolidBrush opt_text_brush(ds.colors.text_primary);
        Gdiplus::SolidBrush hover_bg_brush(ds.colors.dropdown_hover);
        Gdiplus::SolidBrush active_check_brush(ds.colors.accent);

        auto is_option_selected = [&](int opt_id) -> bool {
            if (active_dropdown_ == 0) {
                if (opt_id == 101) return (edit_profile_.protocol == Protocol::Auto);
                if (opt_id == 102) return (edit_profile_.protocol == Protocol::Gool);
                if (opt_id == 103) return (edit_profile_.protocol == Protocol::WarpInWarp);
                if (opt_id == 104) return (edit_profile_.protocol == Protocol::Masque && !edit_profile_.masque_http2);
                if (opt_id == 105) return (edit_profile_.protocol == Protocol::Masque && edit_profile_.masque_http2);
                if (opt_id == 106) return (edit_profile_.protocol == Protocol::Wireguard);
                if (opt_id == 107) return (edit_profile_.protocol == Protocol::Mim);
            } else if (active_dropdown_ == 1) {
                if (opt_id == 201) return (edit_profile_.scan_mode == ScanMode::Balanced);
                if (opt_id == 202) return (edit_profile_.scan_mode == ScanMode::Turbo);
                if (opt_id == 203) return (edit_profile_.scan_mode == ScanMode::Thorough);
                if (opt_id == 204) return (edit_profile_.scan_mode == ScanMode::Verified);
                if (opt_id == 205) return (edit_profile_.scan_mode == ScanMode::Ironclad);
            } else if (active_dropdown_ == 2) {
                if (opt_id == 301) return edit_profile_.exit_loc.empty();
                if (opt_id == 302) return (edit_profile_.exit_loc == "US");
                if (opt_id == 303) return (edit_profile_.exit_loc == "DE");
                if (opt_id == 304) return (edit_profile_.exit_loc == "GB");
                if (opt_id == 305) return (edit_profile_.exit_loc == "NL");
                if (opt_id == 306) return (edit_profile_.exit_loc == "FR");
                if (opt_id == 307) return (edit_profile_.exit_loc == "SG");
                if (opt_id == 308) return (edit_profile_.exit_loc == "JP");
                if (opt_id == 309) return (edit_profile_.exit_loc == "TR");
                if (opt_id == 310) return (edit_profile_.exit_loc == "CA");
            } else if (active_dropdown_ == 3) {
                if (opt_id == 401) return (edit_profile_.ip_version == IpVersion::V4);
                if (opt_id == 402) return (edit_profile_.ip_version == IpVersion::V6);
                if (opt_id == 403) return (edit_profile_.ip_version == IpVersion::Both);
            } else if (active_dropdown_ == 4) {
                if (opt_id == 501) return (edit_profile_.masque_noize == MasqueNoize::Firewall);
                if (opt_id == 502) return (edit_profile_.masque_noize == MasqueNoize::Gfw);
                if (opt_id == 503) return (edit_profile_.masque_noize == MasqueNoize::Off);
            } else if (active_dropdown_ == 5) {
                if (opt_id == 601) return edit_profile_.dns.empty();
                if (opt_id == 602) return (edit_profile_.dns == "1.1.1.2");
                if (opt_id == 603) return (edit_profile_.dns == "8.8.8.8");
                if (opt_id == 604) return (edit_profile_.dns == "9.9.9.9");
            }
            return false;
        };

        for (size_t i = 0; i < dropdown_options_.size(); ++i) {
            float iy = pop_y + static_cast<float>(i) * item_h;
            if (static_cast<int>(i) == hovered_dropdown_item_) {
                fill_rounded_rect(g, hover_bg_brush, pop_x + 2.0f, iy + 2.0f, pop_w - 4.0f, item_h - 4.0f, (float)scale(8, cur_dpi));
            }

            bool selected = is_option_selected(dropdown_options_[i].id);
            if (selected) {
                g.DrawString(L"✓", -1, font_body_.get(), Gdiplus::PointF(pop_x + scale_f(12, cur_dpi), iy + (item_h - scale_f((float)ds.typo.body_label, cur_dpi)) / 2.0f), &active_check_brush);
            }

            g.DrawString(dropdown_options_[i].label.c_str(), -1, font_body_.get(),
                         Gdiplus::PointF(pop_x + scale_f(32, cur_dpi), iy + (item_h - scale_f((float)ds.typo.body_label, cur_dpi)) / 2.0f),
                         selected ? &active_check_brush : &opt_text_brush);
        }
    }

    void handle_dropdown_selection(int opt_id) {
        if (active_dropdown_ == 0) {
            if (opt_id == 101) { edit_profile_.protocol = Protocol::Auto; }
            else if (opt_id == 102) { edit_profile_.protocol = Protocol::Gool; edit_profile_.masque_http2 = false; }
            else if (opt_id == 103) { edit_profile_.protocol = Protocol::WarpInWarp; edit_profile_.masque_http2 = false; }
            else if (opt_id == 104) { edit_profile_.protocol = Protocol::Masque; edit_profile_.masque_http2 = false; }
            else if (opt_id == 105) { edit_profile_.protocol = Protocol::Masque; edit_profile_.masque_http2 = true; }
            else if (opt_id == 106) { edit_profile_.protocol = Protocol::Wireguard; }
            else if (opt_id == 107) { edit_profile_.protocol = Protocol::Mim; }
        } else if (active_dropdown_ == 1) {
            if (opt_id == 201) edit_profile_.scan_mode = ScanMode::Balanced;
            else if (opt_id == 202) edit_profile_.scan_mode = ScanMode::Turbo;
            else if (opt_id == 203) edit_profile_.scan_mode = ScanMode::Thorough;
            else if (opt_id == 204) edit_profile_.scan_mode = ScanMode::Verified;
            else if (opt_id == 205) edit_profile_.scan_mode = ScanMode::Ironclad;
        } else if (active_dropdown_ == 2) {
            if (opt_id == 301) edit_profile_.exit_loc = "";
            else if (opt_id == 302) edit_profile_.exit_loc = "US";
            else if (opt_id == 303) edit_profile_.exit_loc = "DE";
            else if (opt_id == 304) edit_profile_.exit_loc = "GB";
            else if (opt_id == 305) edit_profile_.exit_loc = "NL";
            else if (opt_id == 306) edit_profile_.exit_loc = "FR";
            else if (opt_id == 307) edit_profile_.exit_loc = "SG";
            else if (opt_id == 308) edit_profile_.exit_loc = "JP";
            else if (opt_id == 309) edit_profile_.exit_loc = "TR";
            else if (opt_id == 310) edit_profile_.exit_loc = "CA";
        } else if (active_dropdown_ == 3) {
            if (opt_id == 401) edit_profile_.ip_version = IpVersion::V4;
            else if (opt_id == 402) edit_profile_.ip_version = IpVersion::V6;
            else if (opt_id == 403) edit_profile_.ip_version = IpVersion::Both;
        } else if (active_dropdown_ == 4) {
            if (opt_id == 501) { edit_profile_.masque_noize = MasqueNoize::Firewall; edit_profile_.wg_noize = WgNoize::Balanced; }
            else if (opt_id == 502) { edit_profile_.masque_noize = MasqueNoize::Gfw; edit_profile_.wg_noize = WgNoize::Aggressive; }
            else if (opt_id == 503) { edit_profile_.masque_noize = MasqueNoize::Off; edit_profile_.wg_noize = WgNoize::Off; }
        } else if (active_dropdown_ == 5) {
            if (opt_id == 601) edit_profile_.dns = "";
            else if (opt_id == 602) edit_profile_.dns = "1.1.1.2";
            else if (opt_id == 603) edit_profile_.dns = "8.8.8.8";
            else if (opt_id == 604) edit_profile_.dns = "9.9.9.9";
        }
        active_dropdown_ = -1;
        commit_settings_save();
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    // ── Logs View (Matching Logs.dc.html: Back, Copy, Clear, 4 Filter Chips, Styled Terminal, Resource Sparklines) ──
    void render_logs_view(Gdiplus::Graphics& g, float w, float h, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "Logs" Title + Copy Button + Clear (Trash) Button
        float back_btn_x = (float)scale(ds.metrics.padding_x, cur_dpi);
        float back_btn_y = (float)scale(ds.metrics.padding_top, cur_dpi);
        float back_btn_size = (float)scale(ds.metrics.header_btn_size, cur_dpi);

        Gdiplus::Color back_bg = back_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color back_border_col = back_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush back_bg_brush(back_bg);
        Gdiplus::Pen back_pen(back_border_col, 1.0f);
        fill_rounded_rect(g, back_bg_brush, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));
        draw_rounded_rect(g, back_pen, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));

        // Chevron '<' vector (moves left slightly on hover)
        Gdiplus::Pen chev_pen(back_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.8f);
        chev_pen.SetStartCap(Gdiplus::LineCapRound);
        chev_pen.SetEndCap(Gdiplus::LineCapRound);
        chev_pen.SetLineJoin(Gdiplus::LineJoinRound);
        float bcx = back_btn_x + back_btn_size / 2.0f + (back_btn_hovered_ ? -scale_f(2, cur_dpi) : 0.0f);
        float bcy = back_btn_y + back_btn_size / 2.0f;
        Gdiplus::PointF chev_pts[3] = {
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy - scale_f(6, cur_dpi)),
            Gdiplus::PointF(bcx - scale_f(4, cur_dpi), bcy),
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy + scale_f(6, cur_dpi))
        };
        g.DrawLines(&chev_pen, chev_pts, 3);

        Gdiplus::SolidBrush title_brush(ds.colors.text_primary);
        g.DrawString(L"Logs", -1, font_view_title_.get(), Gdiplus::PointF(back_btn_x + back_btn_size + scale_f(14, cur_dpi), back_btn_y + scale_f(8, cur_dpi)), &title_brush);

        // Header Right Action Buttons: Copy & Trash/Clear
        float btn_sz = back_btn_size;
        float clr_x = w - back_btn_x - btn_sz;
        float cp_x = clr_x - btn_sz - scale_f(8, cur_dpi);

        // 1a. Copy Logs Button
        Gdiplus::Color cp_bg = copy_logs_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color cp_bd = copy_logs_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush cp_brush(cp_bg);
        Gdiplus::Pen cp_pen(cp_bd, 1.0f);
        fill_rounded_rect(g, cp_brush, cp_x, back_btn_y, btn_sz, btn_sz, (float)scale(ds.metrics.radius_control, cur_dpi));
        draw_rounded_rect(g, cp_pen, cp_x, back_btn_y, btn_sz, btn_sz, (float)scale(ds.metrics.radius_control, cur_dpi));

        float cpcx = cp_x + btn_sz / 2.0f;
        float cpcy = back_btn_y + btn_sz / 2.0f;

        if (logs_copied_) {
            Gdiplus::Pen chk_pen(ds.colors.accent, 1.8f);
            chk_pen.SetStartCap(Gdiplus::LineCapRound);
            chk_pen.SetEndCap(Gdiplus::LineCapRound);
            chk_pen.SetLineJoin(Gdiplus::LineJoinRound);
            Gdiplus::PointF chk_pts[3] = {
                Gdiplus::PointF(cpcx - scale_f(5, cur_dpi), cpcy + scale_f(0.5f, cur_dpi)),
                Gdiplus::PointF(cpcx - scale_f(1, cur_dpi), cpcy + scale_f(4.5f, cur_dpi)),
                Gdiplus::PointF(cpcx + scale_f(6, cur_dpi), cpcy - scale_f(4.5f, cur_dpi))
            };
            g.DrawLines(&chk_pen, chk_pts, 3);
        } else {
            Gdiplus::Pen cp_ic_pen(copy_logs_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.6f);
            cp_ic_pen.SetStartCap(Gdiplus::LineCapRound);
            cp_ic_pen.SetEndCap(Gdiplus::LineCapRound);
            cp_ic_pen.SetLineJoin(Gdiplus::LineJoinRound);
            draw_rounded_rect(g, cp_ic_pen, cpcx - scale_f(4, cur_dpi), cpcy - scale_f(4, cur_dpi), scale_f(9, cur_dpi), scale_f(9, cur_dpi), scale_f(2, cur_dpi));
            Gdiplus::PointF bk_pts[3] = {
                Gdiplus::PointF(cpcx + scale_f(3, cur_dpi), cpcy - scale_f(6, cur_dpi)),
                Gdiplus::PointF(cpcx - scale_f(6, cur_dpi), cpcy - scale_f(6, cur_dpi)),
                Gdiplus::PointF(cpcx - scale_f(6, cur_dpi), cpcy + scale_f(3, cur_dpi))
            };
            g.DrawLines(&cp_ic_pen, bk_pts, 3);
        }

        // 1b. Trash / Clear Logs Button
        Gdiplus::Color clr_bg = clear_logs_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color clr_bd = clear_logs_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush clr_brush(clr_bg);
        Gdiplus::Pen clr_pen(clr_bd, 1.0f);
        fill_rounded_rect(g, clr_brush, clr_x, back_btn_y, btn_sz, btn_sz, (float)scale(ds.metrics.radius_control, cur_dpi));
        draw_rounded_rect(g, clr_pen, clr_x, back_btn_y, btn_sz, btn_sz, (float)scale(ds.metrics.radius_control, cur_dpi));

        float clrcx = clr_x + btn_sz / 2.0f;
        float clrcy = back_btn_y + btn_sz / 2.0f;
        Gdiplus::Pen tr_pen(clear_logs_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.6f);
        tr_pen.SetStartCap(Gdiplus::LineCapRound);
        tr_pen.SetEndCap(Gdiplus::LineCapRound);
        tr_pen.SetLineJoin(Gdiplus::LineJoinRound);
        g.DrawLine(&tr_pen, clrcx - scale_f(6, cur_dpi), clrcy - scale_f(3, cur_dpi), clrcx + scale_f(6, cur_dpi), clrcy - scale_f(3, cur_dpi));
        g.DrawLine(&tr_pen, clrcx - scale_f(2, cur_dpi), clrcy - scale_f(5.5f, cur_dpi), clrcx + scale_f(2, cur_dpi), clrcy - scale_f(5.5f, cur_dpi));
        Gdiplus::PointF can_pts[4] = {
            Gdiplus::PointF(clrcx - scale_f(4.5f, cur_dpi), clrcy - scale_f(3, cur_dpi)),
            Gdiplus::PointF(clrcx - scale_f(4.0f, cur_dpi), clrcy + scale_f(5.5f, cur_dpi)),
            Gdiplus::PointF(clrcx + scale_f(4.0f, cur_dpi), clrcy + scale_f(5.5f, cur_dpi)),
            Gdiplus::PointF(clrcx + scale_f(4.5f, cur_dpi), clrcy - scale_f(3, cur_dpi))
        };
        g.DrawLines(&tr_pen, can_pts, 4);

        // 2. Filter Chips Row (.rise): All, Info, Warn, Error
        float card_x = back_btn_x;
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float chips_y = back_btn_y + btn_sz + scale_f(12, cur_dpi);
        float chip_h = scale_f(36, cur_dpi);
        float chip_r = chip_h / 2.0f;
        float chip_gap = scale_f(8, cur_dpi);
        float chip_w = (card_w - chip_gap * 3.0f) / 4.0f;

        // Copy logs safely under mutex
        std::vector<LogEntry> logs_copy;
        int count_all = 0, count_info = 0, count_warn = 0, count_err = 0;
        {
            std::lock_guard lock(log_mutex_);
            logs_copy.assign(parsed_logs_.begin(), parsed_logs_.end());
            count_all = static_cast<int>(parsed_logs_.size());
            for (const auto& item : parsed_logs_) {
                if (item.level == LogFilter::Info) count_info++;
                else if (item.level == LogFilter::Warn) count_warn++;
                else if (item.level == LogFilter::Error) count_err++;
            }
        }

        const wchar_t* chip_names[] = { L"All", L"Info", L"Warn", L"Error" };
        const int chip_counts[] = { count_all, count_info, count_warn, count_err };

        Gdiplus::StringFormat chip_fmt;
        chip_fmt.SetAlignment(Gdiplus::StringAlignmentCenter);
        chip_fmt.SetLineAlignment(Gdiplus::StringAlignmentCenter);

        for (int i = 0; i < 4; ++i) {
            float ch_x = card_x + static_cast<float>(i) * (chip_w + chip_gap);
            bool is_active = (log_filter_ == i);
            bool is_hov = (hovered_log_chip_ == i);

            Gdiplus::Color c_bg = is_active ? ds.colors.chip_bg : (is_hov ? ds.colors.hover_bg : Gdiplus::Color(0, 0, 0, 0));
            Gdiplus::Color c_bd = is_active ? ds.colors.border_hover_bright : (is_hov ? ds.colors.border_hover : ds.colors.btn_border);
            Gdiplus::Color c_tx = is_active ? ds.colors.text_primary : (is_hov ? ds.colors.text_primary : ds.colors.text_muted);

            Gdiplus::SolidBrush bg_b(c_bg);
            fill_rounded_rect(g, bg_b, ch_x, chips_y, chip_w, chip_h, chip_r);
            Gdiplus::Pen bd_p(c_bd, 1.0f);
            draw_rounded_rect(g, bd_p, ch_x, chips_y, chip_w, chip_h, chip_r);

            std::wstring chip_txt = std::wstring(chip_names[i]) + L" " + std::to_wstring(chip_counts[i]);
            Gdiplus::SolidBrush tx_b(c_tx);
            g.DrawString(chip_txt.c_str(), -1, font_body_.get(), Gdiplus::PointF(ch_x + chip_w / 2.0f, chips_y + chip_h / 2.0f), &chip_fmt, &tx_b);
        }

        // 3. Terminal Log Card (logbox: 16 radius, surface background, bd border)
        float term_y = chips_y + chip_h + scale_f(12, cur_dpi);
        float res_card_h = (float)scale(72, cur_dpi);
        float term_h = h - term_y - res_card_h - scale_f(24, cur_dpi);

        Gdiplus::SolidBrush term_bg(ds.colors.card_bg);
        fill_rounded_rect(g, term_bg, card_x, term_y, card_w, term_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        Gdiplus::Pen term_pen(ds.colors.card_border, 1.0f);
        draw_rounded_rect(g, term_pen, card_x, term_y, card_w, term_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        // Filter visible lines
        std::vector<const LogEntry*> visible_logs;
        visible_logs.reserve(logs_copy.size());
        for (const auto& item : logs_copy) {
            if (log_filter_ == 0 || static_cast<int>(item.level) == log_filter_) {
                visible_logs.push_back(&item);
            }
        }

        // Clipped text display
        Gdiplus::GraphicsState term_state = g.Save();
        g.SetClip(Gdiplus::RectF(card_x + 8.0f, term_y + 8.0f, card_w - 16.0f, term_h - 16.0f));

        if (visible_logs.empty()) {
            Gdiplus::SolidBrush empty_brush(ds.colors.text_dim);
            Gdiplus::StringFormat c_fmt;
            c_fmt.SetAlignment(Gdiplus::StringAlignmentCenter);
            c_fmt.SetLineAlignment(Gdiplus::StringAlignmentCenter);
            g.DrawString(L"No log entries", -1, font_body_.get(),
                         Gdiplus::PointF(card_x + card_w / 2.0f, term_y + term_h / 2.0f), &c_fmt, &empty_brush);
        } else {
            float cur_y = term_y + scale_f(10, cur_dpi) - scale_f(logs_scroll_anim_y_, cur_dpi);
            float row_x = card_x + scale_f(14, cur_dpi);
            float time_w = scale_f(66, cur_dpi);
            float tag_w = scale_f(44, cur_dpi);
            float msg_x = row_x + time_w + tag_w;
            float right_margin = scale_f(14, cur_dpi);
            float msg_w = std::max(scale_f(80, cur_dpi), (card_x + card_w - right_margin) - msg_x);
            float min_row_h = scale_f(22, cur_dpi);
            float total_content_h = scale_f(10, cur_dpi);

            Gdiplus::SolidBrush time_brush(ds.colors.text_dim);
            Gdiplus::SolidBrush info_brush(ds.colors.info);
            Gdiplus::SolidBrush warn_brush(ds.colors.warning);
            Gdiplus::SolidBrush err_brush(ds.colors.error);
            Gdiplus::SolidBrush msg_pri_brush(ds.colors.text_secondary);

            Gdiplus::StringFormat wrap_fmt;
            wrap_fmt.SetFormatFlags(0);
            wrap_fmt.SetTrimming(Gdiplus::StringTrimmingNone);

            for (const auto* item : visible_logs) {
                Gdiplus::RectF bound_rect;
                g.MeasureString(item->message.c_str(), -1, font_mono_.get(), Gdiplus::RectF(msg_x, 0.0f, msg_w, 2000.0f), &wrap_fmt, &bound_rect);
                float item_h = std::max(min_row_h, bound_rect.Height + scale_f(4, cur_dpi));

                if (cur_y + item_h >= term_y && cur_y <= term_y + term_h) {
                    // 1. Time [HH:MM:SS]
                    g.DrawString(item->time_str.c_str(), -1, font_mono_.get(), Gdiplus::PointF(row_x, cur_y), &time_brush);

                    // 2. Tag (INFO / WARN / ERR)
                    Gdiplus::SolidBrush* tag_brush = &info_brush;
                    if (item->level == LogFilter::Warn) tag_brush = &warn_brush;
                    else if (item->level == LogFilter::Error) tag_brush = &err_brush;
                    g.DrawString(item->tag.c_str(), -1, font_mono_bold_.get(), Gdiplus::PointF(row_x + time_w, cur_y), tag_brush);

                    // 3. Multiline wrapped message
                    Gdiplus::SolidBrush* msg_brush = &msg_pri_brush;
                    if (item->level == LogFilter::Error) msg_brush = &err_brush;
                    else if (item->level == LogFilter::Warn) msg_brush = &warn_brush;
                    g.DrawString(item->message.c_str(), -1, font_mono_.get(), Gdiplus::RectF(msg_x, cur_y, msg_w, bound_rect.Height), &wrap_fmt, msg_brush);
                }

                cur_y += item_h;
                total_content_h += item_h;
            }

            total_content_h += scale_f(10, cur_dpi);
            float visible_h = term_h;
            max_logs_scroll_ = std::max(0.0f, (total_content_h - visible_h) / (cur_dpi / 96.0f));
        }
        g.Restore(term_state);

        // 4. Bottom Resource Card (CPU% & RAM MB with Live Sparkline Polyline Graphs)
        float res_y = term_y + term_h + scale_f(12, cur_dpi);
        fill_rounded_rect(g, term_bg, card_x, res_y, card_w, res_card_h, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, term_pen, card_x, res_y, card_w, res_card_h, (float)scale(ds.metrics.radius_card, cur_dpi));

        // Center vertical divider
        float mid_x = card_x + card_w / 2.0f;
        g.DrawLine(&term_pen, mid_x, res_y, mid_x, res_y + res_card_h);

        float col_w = card_w / 2.0f;
        float pad = scale_f(14, cur_dpi);

        Gdiplus::SolidBrush tag_brush(ds.colors.text_muted);
        Gdiplus::SolidBrush val_brush(ds.colors.text_primary);
        Gdiplus::StringFormat right_align;
        right_align.SetAlignment(Gdiplus::StringAlignmentFar);

        // --- Column 1: CPU ---
        float c1_x = card_x + pad;
        float c1_top_y = res_y + scale_f(10, cur_dpi);
        g.DrawString(L"CPU", -1, font_metric_tag_.get(), Gdiplus::PointF(c1_x, c1_top_y), &tag_brush);
        std::wstring cpu_str = std::format(L"{:.1f} %", sys_metrics_.cpu_percent);
        g.DrawString(cpu_str.c_str(), -1, font_mono_bold_.get(), Gdiplus::PointF(mid_x - pad, c1_top_y - scale_f(2, cur_dpi)), &right_align, &val_brush);

        // CPU Sparkline (Polyline of 30 historical samples in Teal --ac)
        float spark_w = col_w - pad * 2.0f;
        float spark_h = scale_f(26, cur_dpi);
        float spark_y = res_y + res_card_h - spark_h - scale_f(8, cur_dpi);

        if (cpu_history_.size() >= 2) {
            std::vector<Gdiplus::PointF> pts;
            pts.reserve(cpu_history_.size());
            float max_cpu = 10.0f;
            for (float v : cpu_history_) if (v > max_cpu) max_cpu = v;

            for (size_t i = 0; i < cpu_history_.size(); ++i) {
                float px = c1_x + static_cast<float>(i) * (spark_w / static_cast<float>(cpu_history_.size() - 1));
                float norm = std::clamp(cpu_history_[i] / max_cpu, 0.0f, 1.0f);
                float py = spark_y + spark_h - norm * spark_h;
                pts.emplace_back(px, py);
            }

            Gdiplus::Pen cpu_pen(ds.colors.accent, 1.5f);
            cpu_pen.SetLineJoin(Gdiplus::LineJoinRound);
            cpu_pen.SetStartCap(Gdiplus::LineCapRound);
            cpu_pen.SetEndCap(Gdiplus::LineCapRound);
            g.DrawLines(&cpu_pen, pts.data(), static_cast<INT>(pts.size()));
        }

        // --- Column 2: RAM ---
        float c2_x = mid_x + pad;
        g.DrawString(L"RAM", -1, font_metric_tag_.get(), Gdiplus::PointF(c2_x, c1_top_y), &tag_brush);
        std::wstring ram_str = std::format(L"{:.1f} MB", sys_metrics_.ram_mb);
        g.DrawString(ram_str.c_str(), -1, font_mono_bold_.get(), Gdiplus::PointF(card_x + card_w - pad, c1_top_y - scale_f(2, cur_dpi)), &right_align, &val_brush);

        // RAM Sparkline (Polyline of 30 historical samples in Indigo --ac2)
        if (ram_history_.size() >= 2) {
            std::vector<Gdiplus::PointF> pts;
            pts.reserve(ram_history_.size());
            float min_ram = ram_history_[0];
            float max_ram = ram_history_[0];
            for (float v : ram_history_) {
                if (v < min_ram) min_ram = v;
                if (v > max_ram) max_ram = v;
            }
            if (max_ram - min_ram < 5.0f) { max_ram += 2.5f; min_ram -= 2.5f; }

            for (size_t i = 0; i < ram_history_.size(); ++i) {
                float px = c2_x + static_cast<float>(i) * (spark_w / static_cast<float>(ram_history_.size() - 1));
                float norm = std::clamp((ram_history_[i] - min_ram) / (max_ram - min_ram), 0.0f, 1.0f);
                float py = spark_y + spark_h - norm * spark_h;
                pts.emplace_back(px, py);
            }

            Gdiplus::Pen ram_pen(ds.colors.accent_ram, 1.5f);
            ram_pen.SetLineJoin(Gdiplus::LineJoinRound);
            ram_pen.SetStartCap(Gdiplus::LineCapRound);
            ram_pen.SetEndCap(Gdiplus::LineCapRound);
            g.DrawLines(&ram_pen, pts.data(), static_cast<INT>(pts.size()));
        }
    }

    // ── About View (72 DIP Logo + App Info + GitHub Links + Update Checker) ──
    void render_about_view(Gdiplus::Graphics& g, float w, float h, UINT cur_dpi) {
        (void)h;
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "About" Title
        float back_btn_x = (float)scale(ds.metrics.padding_x, cur_dpi);
        float back_btn_y = (float)scale(ds.metrics.padding_top, cur_dpi);
        float back_btn_size = (float)scale(ds.metrics.header_btn_size, cur_dpi);

        Gdiplus::Color back_bg = back_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Gdiplus::Color back_border_col = back_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        Gdiplus::SolidBrush back_bg_brush(back_bg);
        Gdiplus::Pen back_pen(back_border_col, 1.0f);
        fill_rounded_rect(g, back_bg_brush, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));
        draw_rounded_rect(g, back_pen, back_btn_x, back_btn_y, back_btn_size, back_btn_size, (float)scale(ds.metrics.radius_control, cur_dpi));

        // Chevron '<' vector
        Gdiplus::Pen chev_pen(back_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color, 1.8f);
        chev_pen.SetStartCap(Gdiplus::LineCapRound);
        chev_pen.SetEndCap(Gdiplus::LineCapRound);
        chev_pen.SetLineJoin(Gdiplus::LineJoinRound);
        float bcx = back_btn_x + back_btn_size / 2.0f;
        float bcy = back_btn_y + back_btn_size / 2.0f;
        Gdiplus::PointF chev_pts[3] = {
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy - scale_f(6, cur_dpi)),
            Gdiplus::PointF(bcx - scale_f(4, cur_dpi), bcy),
            Gdiplus::PointF(bcx + scale_f(2, cur_dpi), bcy + scale_f(6, cur_dpi))
        };
        g.DrawLines(&chev_pen, chev_pts, 3);

        Gdiplus::SolidBrush title_brush(ds.colors.text_primary);
        g.DrawString(L"About", -1, font_view_title_.get(), Gdiplus::PointF(back_btn_x + back_btn_size + scale_f(14, cur_dpi), back_btn_y + scale_f(8, cur_dpi)), &title_brush);

        Gdiplus::StringFormat center_fmt;
        center_fmt.SetAlignment(Gdiplus::StringAlignmentCenter);

        // 2. Logo Icon (Transparent, natural aspect ratio, no stretching)
        float cx = w / 2.0f;
        float logo_y = back_btn_y + back_btn_size + scale_f(28, cur_dpi);
        float draw_h = scale_f(72, cur_dpi);
        float draw_w = draw_h;

        if (logo_bitmap_ && logo_bitmap_->GetLastStatus() == Gdiplus::Ok) {
            float bmp_w = static_cast<float>(logo_bitmap_->GetWidth());
            float bmp_h = static_cast<float>(logo_bitmap_->GetHeight());
            if (bmp_h > 0.0f) {
                draw_w = draw_h * (bmp_w / bmp_h);
            }
            g.DrawImage(logo_bitmap_.get(), cx - draw_w / 2.0f, logo_y, draw_w, draw_h);
        } else {
            int ic_sz = scale(64, cur_dpi);
            HICON hLogo = (HICON)LoadImageW(hInstance_, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON, ic_sz, ic_sz, LR_DEFAULTCOLOR);
            if (hLogo) {
                HDC hdc = g.GetHDC();
                DrawIconEx(hdc, static_cast<int>(cx - ic_sz / 2.0f), static_cast<int>(logo_y), hLogo, ic_sz, ic_sz, 0, nullptr, DI_NORMAL);
                g.ReleaseHDC(hdc);
                DestroyIcon(hLogo);
            } else {
                float dot_sz = scale_f(24, cur_dpi);
                Gdiplus::SolidBrush dot_brush(ds.colors.accent);
                g.FillEllipse(&dot_brush, cx - dot_sz / 2.0f, logo_y + (draw_h - dot_sz) / 2.0f, dot_sz, dot_sz);
            }
        }

        // App Name & Version
        float name_y = logo_y + draw_h + scale_f(14, cur_dpi);
        g.DrawString(L"Hemera", -1, font_hero_status_.get(), Gdiplus::PointF(cx, name_y), &center_fmt, &title_brush);

        float ver_y = name_y + scale_f(34, cur_dpi);
        Gdiplus::SolidBrush muted_brush(ds.colors.text_muted);
        g.DrawString(L"Version 1.0.0", -1, font_mono_.get(), Gdiplus::PointF(cx, ver_y), &center_fmt, &muted_brush);

        // Subtitle text
        float desc_y = ver_y + scale_f(24, cur_dpi);
        g.DrawString(L"Native high-performance circumvention.\nFree, open source, no account needed.", -1, font_body_.get(), Gdiplus::PointF(cx, desc_y), &center_fmt, &muted_brush);

        // 3. Links Card (Source Code, Issues, License)
        float card_x = back_btn_x;
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float card_y = desc_y + scale_f(56, cur_dpi);
        float row_h = (float)scale(ds.metrics.row_height, cur_dpi);

        Gdiplus::SolidBrush card_bg(ds.colors.card_bg);
        Gdiplus::Pen card_pen(ds.colors.card_border, 1.0f);
        fill_rounded_rect(g, card_bg, card_x, card_y, card_w, row_h * 3.0f, (float)scale(ds.metrics.radius_card, cur_dpi));
        draw_rounded_rect(g, card_pen, card_x, card_y, card_w, row_h * 3.0f, (float)scale(ds.metrics.radius_card, cur_dpi));

        g.DrawLine(&card_pen, card_x, card_y + row_h, card_x + card_w, card_y + row_h);
        g.DrawLine(&card_pen, card_x, card_y + row_h * 2.0f, card_x + card_w, card_y + row_h * 2.0f);

        Gdiplus::SolidBrush hov_brush(ds.colors.dropdown_hover);
        if (about_src_hovered_) {
            fill_rounded_rect(g, hov_brush, card_x + 1.0f, card_y + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(12, cur_dpi));
        }
        if (about_issue_hovered_) {
            fill_rounded_rect(g, hov_brush, card_x + 1.0f, card_y + row_h + 1.0f, card_w - 2.0f, row_h - 2.0f, (float)scale(12, cur_dpi));
        }

        Gdiplus::StringFormat right_align;
        right_align.SetAlignment(Gdiplus::StringAlignmentFar);
        float pad_x = (float)scale(ds.metrics.row_padding_x, cur_dpi);
        float ry0 = card_y + (row_h - scale_f((float)ds.typo.body_label, cur_dpi)) / 2.0f;

        g.DrawString(L"Source code", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, ry0), &title_brush);
        g.DrawString(L"↗", -1, font_body_.get(), Gdiplus::PointF(card_x + card_w - pad_x, ry0), &right_align, &muted_brush);

        float ry1 = card_y + row_h + (row_h - scale_f((float)ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"Report an issue", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, ry1), &title_brush);
        g.DrawString(L"↗", -1, font_body_.get(), Gdiplus::PointF(card_x + card_w - pad_x, ry1), &right_align, &muted_brush);

        float ry2 = card_y + row_h * 2.0f + (row_h - scale_f((float)ds.typo.body_label, cur_dpi)) / 2.0f;
        g.DrawString(L"License", -1, font_body_.get(), Gdiplus::PointF(card_x + pad_x, ry2), &title_brush);
        g.DrawString(L"Open source", -1, font_mono_.get(), Gdiplus::PointF(card_x + card_w - pad_x, ry2), &right_align, &muted_brush);

        // 4. "Check for updates" Button
        float upd_y = card_y + row_h * 3.0f + scale_f(28, cur_dpi);
        float upd_w = (float)scale(180, cur_dpi);
        float upd_h = (float)scale(44, cur_dpi);
        float upd_x = cx - upd_w / 2.0f;

        Gdiplus::Color upd_bg = update_btn_hovered_ ? ds.colors.hover_bg : ds.colors.chip_bg;
        Gdiplus::Color upd_bd = update_btn_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
        Gdiplus::SolidBrush upd_brush(upd_bg);
        Gdiplus::Pen upd_pen(upd_bd, 1.0f);
        fill_rounded_rect(g, upd_brush, upd_x, upd_y, upd_w, upd_h, (float)scale(ds.metrics.radius_chip, cur_dpi));
        draw_rounded_rect(g, upd_pen, upd_x, upd_y, upd_w, upd_h, (float)scale(ds.metrics.radius_chip, cur_dpi));

        center_fmt.SetLineAlignment(Gdiplus::StringAlignmentCenter);

        if (is_checking_update_) {
            float spin_cx = upd_x + scale_f(24, cur_dpi);
            float spin_cy = upd_y + upd_h / 2.0f;
            float s_rad = scale_f(7, cur_dpi);
            Gdiplus::Pen spin_p(ds.colors.accent, 1.8f);
            spin_p.SetStartCap(Gdiplus::LineCapRound);
            spin_p.SetEndCap(Gdiplus::LineCapRound);
            g.DrawArc(&spin_p, spin_cx - s_rad, spin_cy - s_rad, s_rad * 2.0f, s_rad * 2.0f, spin_angle_, 180.0f);

            g.DrawString(L"Checking...", -1, font_body_bold_.get(), Gdiplus::PointF(upd_x + upd_w / 2.0f + scale_f(8, cur_dpi), upd_y + upd_h / 2.0f), &center_fmt, &title_brush);
        } else {
            g.DrawString(L"Check for updates", -1, font_body_bold_.get(), Gdiplus::PointF(upd_x + upd_w / 2.0f, upd_y + upd_h / 2.0f), &center_fmt, &title_brush);
        }

        if (is_update_done_) {
            float done_y = upd_y + upd_h + scale_f(14, cur_dpi);
            Gdiplus::SolidBrush accent_brush(ds.colors.accent);
            g.DrawString(L"✓ You're on the latest version", -1, font_body_.get(), Gdiplus::PointF(cx, done_y), &center_fmt, &accent_brush);
        }
    }

    void setup_tray_icon() {
        if (!hwnd_) return;
        memset(&nid_, 0, sizeof(nid_));
        nid_.cbSize = sizeof(NOTIFYICONDATAW);
        nid_.hWnd = hwnd_;
        nid_.uID = 1;
        nid_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid_.uCallbackMessage = WM_HEMERA_TRAY;
        nid_.hIcon = LoadIconW(hInstance_, MAKEINTRESOURCEW(IDI_APP_ICON));
        if (!nid_.hIcon) {
            nid_.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        }
        wcscpy_s(nid_.szTip, L"Hemera — Modern Proxy");
        if (!Shell_NotifyIconW(NIM_ADD, &nid_)) {
            Shell_NotifyIconW(NIM_MODIFY, &nid_);
        }
        in_tray_ = true;
    }

    void remove_tray_icon() {
        if (in_tray_) {
            Shell_NotifyIconW(NIM_DELETE, &nid_);
            in_tray_ = false;
        }
    }

    // ── Rock-Solid Standard Win32 Tray Context Menu ──
    void show_tray_menu(int x, int y) {
        HMENU hMenu = CreatePopupMenu();
        if (!hMenu) return;

        auto st = engine_->current_state();
        bool is_connected = (st.kind == StateKind::Connected);
        bool is_running = (is_connected || st.kind == StateKind::Connecting);

        AppendMenuW(hMenu, MF_STRING, 1001, is_running ? L"Disconnect" : L"Connect");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

        auto s = engine_->load_settings();
        AppendMenuW(hMenu, MF_STRING | (s.kill_switch ? MF_CHECKED : 0), 1002, L"Kill Switch");
        AppendMenuW(hMenu, MF_STRING, 1003, L"Open Hemera");
        AppendMenuW(hMenu, MF_STRING, 1004, L"Logs");
        AppendMenuW(hMenu, MF_STRING, 1005, L"Settings");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, 1006, L"Exit");

        // Per Microsoft KB135788:
        SetForegroundWindow(hwnd_);
        int cmd = TrackPopupMenuEx(hMenu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, x, y, hwnd_, nullptr);
        PostMessageW(hwnd_, WM_NULL, 0, 0);
        DestroyMenu(hMenu);

        if (cmd == 1001) {
            if (is_running) {
                (void)engine_->disconnect();
            } else {
                (void)engine_->connect();
            }
            InvalidateRect(hwnd_, nullptr, FALSE);
        } else if (cmd == 1002) {
            s.kill_switch = !s.kill_switch;
            engine_->save_settings(s);
            edit_settings_ = s;
            InvalidateRect(hwnd_, nullptr, FALSE);
        } else if (cmd == 1003) {
            ShowWindow(hwnd_, SW_SHOW);
            ShowWindow(hwnd_, SW_RESTORE);
            SetForegroundWindow(hwnd_);
            switch_view(ActiveView::Home);
        } else if (cmd == 1004) {
            ShowWindow(hwnd_, SW_SHOW);
            ShowWindow(hwnd_, SW_RESTORE);
            SetForegroundWindow(hwnd_);
            switch_view(ActiveView::Logs);
        } else if (cmd == 1005) {
            ShowWindow(hwnd_, SW_SHOW);
            ShowWindow(hwnd_, SW_RESTORE);
            SetForegroundWindow(hwnd_);
            switch_view(ActiveView::Settings);
        } else if (cmd == 1006) {
            DestroyWindow(hwnd_);
        }
    }

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        MainWindow::Impl* impl = nullptr;
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            impl = reinterpret_cast<MainWindow::Impl*>(cs->lpCreateParams);
            impl->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(impl));
        } else {
            impl = reinterpret_cast<MainWindow::Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }

        if (!impl) return DefWindowProcW(hwnd, msg, wParam, lParam);

        static const UINT s_uTaskbarRestart = RegisterWindowMessageW(L"TaskbarCreated");
        if (msg == s_uTaskbarRestart) {
            impl->setup_tray_icon();
            return 0;
        }

        switch (msg) {
            case WM_CREATE: {
                SetTimer(hwnd, TIMER_ANIMATION, 16, nullptr); // Modal loop fallback timer (60 FPS)
                impl->setup_tray_icon();
                return 0;
            }

            case WM_ENTERSIZEMOVE: {
                impl->is_moving_window_ = true;
                return 0;
            }

            case WM_EXITSIZEMOVE: {
                impl->is_moving_window_ = false;
                impl->last_frame_time_ = std::chrono::steady_clock::now();
                InvalidateRect(hwnd, nullptr, FALSE);
                UpdateWindow(hwnd);
                return 0;
            }

            case WM_TIMER: {
                if (wParam == TIMER_ANIMATION) {
                    if (impl->is_moving_window_) {
                        return 0; // Butter-smooth window dragging at native screen refresh rate!
                    }

                    auto now = std::chrono::steady_clock::now();
                    float dt = std::chrono::duration<float>(now - impl->last_frame_time_).count();
                    if (dt >= 0.016f) { // Modal loop fallback at 60 FPS
                        impl->last_frame_time_ = now;
                        if (dt > 0.040f) dt = 0.040f;
                        if (impl->step_animations(dt)) {
                            InvalidateRect(hwnd, nullptr, FALSE);
                            UpdateWindow(hwnd);
                        }
                    }
                }
                return 0;
            }


            case WM_ERASEBKGND:
                return 1; // Pure double-buffered rendering

            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);

                RECT rc;
                GetClientRect(hwnd, &rc);
                int win_w = rc.right - rc.left;
                int win_h = rc.bottom - rc.top;

                if (win_w > 0 && win_h > 0) {
                    if (!impl->cached_mem_dc_ || win_w != impl->cached_bmp_w_ || win_h != impl->cached_bmp_h_) {
                        if (impl->cached_mem_dc_) {
                            if (impl->cached_old_bmp_) SelectObject(impl->cached_mem_dc_, impl->cached_old_bmp_);
                            if (impl->cached_mem_bmp_) DeleteObject(impl->cached_mem_bmp_);
                            DeleteDC(impl->cached_mem_dc_);
                        }
                        impl->cached_mem_dc_ = CreateCompatibleDC(hdc);
                        impl->cached_mem_bmp_ = CreateCompatibleBitmap(hdc, win_w, win_h);
                        impl->cached_old_bmp_ = SelectObject(impl->cached_mem_dc_, impl->cached_mem_bmp_);
                        impl->cached_bmp_w_ = win_w;
                        impl->cached_bmp_h_ = win_h;
                    }

                    {
                        Gdiplus::Graphics g(impl->cached_mem_dc_);
                        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
                        g.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);
                        g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);

                        const auto& ds = ds::DesignSystem::get();
                        const UINT cur_dpi = impl->dpi();
                        impl->ensure_fonts(cur_dpi);

                        Gdiplus::SolidBrush bg_brush(ds.colors.bg);
                        g.FillRectangle(&bg_brush, 0, 0, win_w, win_h);

                        // Apply page entrance animation (.rise 14 DIP slide-up with cubic-bezier)
                        float slide_y = compute_rise_offset(impl->view_transition_t_, 0.0f, cur_dpi);
                        Gdiplus::GraphicsState trans_state = g.Save();
                        if (slide_y > 0.05f) {
                            g.TranslateTransform(0.0f, slide_y);
                        }

                        if (impl->view_ == ActiveView::Home) {
                            impl->render_home_view(g, static_cast<float>(win_w), static_cast<float>(win_h), cur_dpi);
                        } else if (impl->view_ == ActiveView::Settings) {
                            impl->render_settings_view(g, static_cast<float>(win_w), static_cast<float>(win_h), cur_dpi);
                        } else if (impl->view_ == ActiveView::Logs) {
                            impl->render_logs_view(g, static_cast<float>(win_w), static_cast<float>(win_h), cur_dpi);
                        } else if (impl->view_ == ActiveView::About) {
                            impl->render_about_view(g, static_cast<float>(win_w), static_cast<float>(win_h), cur_dpi);
                        }

                        g.Restore(trans_state);
                    }

                    BitBlt(hdc, 0, 0, win_w, win_h, impl->cached_mem_dc_, 0, 0, SRCCOPY);
                }

                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_MOUSEWHEEL: {
                short delta = GET_WHEEL_DELTA_WPARAM(wParam);
                float scroll_amount = static_cast<float>(delta) * 0.75f;
                if (impl->view_ == ActiveView::Settings) {
                    impl->target_scroll_y_ = std::clamp(impl->target_scroll_y_ - scroll_amount, 0.0f, static_cast<float>(impl->max_scroll_));
                } else if (impl->view_ == ActiveView::Logs) {
                    impl->target_logs_scroll_y_ = std::clamp(impl->target_logs_scroll_y_ - scroll_amount, 0.0f, impl->max_logs_scroll_);
                }
                return 0;
            }

            case WM_MOUSEMOVE: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);

                // Arm mouse tracking once, do not re-arm continuously
                if (!impl->mouse_tracking_) {
                    TRACKMOUSEEVENT tme{};
                    tme.cbSize = sizeof(tme);
                    tme.dwFlags = TME_LEAVE;
                    tme.hwndTrack = hwnd;
                    TrackMouseEvent(&tme);
                    impl->mouse_tracking_ = true;
                }

                const auto& ds = ds::DesignSystem::get();
                const UINT cur_dpi = impl->dpi();
                RECT rc;
                GetClientRect(hwnd, &rc);
                float w = static_cast<float>(rc.right - rc.left);

                bool prev_hero = impl->hero_hovered_;
                bool prev_logs = impl->logs_btn_hovered_;
                bool prev_set = impl->settings_btn_hovered_;
                bool prev_back = impl->back_btn_hovered_;
                bool prev_save = impl->save_btn_hovered_;
                bool prev_proto = impl->home_proto_hovered_;
                bool prev_route = impl->home_route_hovered_;
                bool prev_cp = impl->copy_btn_hovered_;
                bool prev_cp_logs = impl->copy_logs_hovered_;
                bool prev_clr_logs = impl->clear_logs_hovered_;
                int prev_log_chip = impl->hovered_log_chip_;
                int prev_row = impl->hovered_settings_row_;
                int prev_drop_item = impl->hovered_dropdown_item_;
                bool prev_about_src = impl->about_src_hovered_;
                bool prev_about_iss = impl->about_issue_hovered_;
                bool prev_upd = impl->update_btn_hovered_;

                if (impl->active_dropdown_ >= 0) {
                    impl->hovered_dropdown_item_ = -1;
                    if (x >= impl->dropdown_popup_rect_.left && x <= impl->dropdown_popup_rect_.right &&
                        y >= impl->dropdown_popup_rect_.top && y <= impl->dropdown_popup_rect_.bottom) {
                        float item_h = (float)scale(ds.metrics.dropdown_item_h, cur_dpi);
                        int idx = static_cast<int>((y - impl->dropdown_popup_rect_.top) / item_h);
                        if (idx >= 0 && idx < static_cast<int>(impl->dropdown_options_.size())) {
                            impl->hovered_dropdown_item_ = idx;
                        }
                    }
                    if (prev_drop_item != impl->hovered_dropdown_item_) {
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                    return 0;
                }

                if (impl->view_ == ActiveView::Home) {
                    float hero_cx = w / 2.0f;
                    float hero_cy = (float)scale(205, cur_dpi);
                    float hero_radius = (float)scale(ds.metrics.hero_diameter / 2, cur_dpi);
                    float dx = x - hero_cx;
                    float dy = y - hero_cy;
                    impl->hero_hovered_ = (dx * dx + dy * dy <= hero_radius * hero_radius);
                    impl->hero_target_scale_ = impl->hero_pressed_ ? 0.97f : (impl->hero_hovered_ ? 1.03f : 1.0f);

                    float btn_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    float set_x = w - (float)scale(ds.metrics.padding_x, cur_dpi) - btn_sz;
                    float logs_x = set_x - btn_sz - scale_f(8, cur_dpi);
                    float btn_y = (float)scale(ds.metrics.padding_top, cur_dpi);

                    impl->logs_btn_hovered_ = (x >= logs_x && x <= logs_x + btn_sz && y >= btn_y && y <= btn_y + btn_sz);
                    impl->settings_btn_hovered_ = (x >= set_x && x <= set_x + btn_sz && y >= btn_y && y <= btn_y + btn_sz);

                    float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float card_w = w - (float)scale(ds.metrics.padding_x * 2, cur_dpi);
                    float card_y = (float)scale(470, cur_dpi);
                    float row_h = (float)scale(ds.metrics.row_height, cur_dpi);
                    float copy_x = card_x + card_w - (float)scale(ds.metrics.row_padding_x, cur_dpi) - scale_f(44, cur_dpi);
                    float copy_y = card_y + row_h * 2.0f + (row_h - scale_f(44, cur_dpi)) / 2.0f;
                    impl->copy_btn_hovered_ = (x >= copy_x && x <= copy_x + scale_f(44, cur_dpi) && y >= copy_y && y <= copy_y + scale_f(44, cur_dpi));
                    impl->home_proto_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y && y <= card_y + row_h);
                    impl->home_route_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y + row_h && y <= card_y + row_h * 2.0f);

                    auto st = impl->engine_->current_state();
                    if (st.kind == StateKind::Error) {
                        float pill_y = hero_cy + hero_radius + scale_f(64 + 20, cur_dpi) + (scale_f(56, cur_dpi) - scale_f(44, cur_dpi)) / 2.0f;
                        float pill_w = scale_f(110, cur_dpi);
                        float btn1_x = hero_cx - pill_w - scale_f(5, cur_dpi);
                        float btn2_x = hero_cx + scale_f(5, cur_dpi);

                        impl->try_again_hovered_ = (x >= btn1_x && x <= btn1_x + pill_w && y >= pill_y && y <= pill_y + scale_f(44, cur_dpi));
                        impl->view_logs_chip_hovered_ = (x >= btn2_x && x <= btn2_x + pill_w && y >= pill_y && y <= pill_y + scale_f(44, cur_dpi));
                    }

                } else if (impl->view_ == ActiveView::Settings) {
                    float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_x = back_x;
                    float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
                    float row_h = (float)scale(ds.metrics.row_height, cur_dpi);
                    float clip_top = back_y + back_sz + scale_f(12, cur_dpi);
                    float sy = scale_f(impl->scroll_anim_y_, cur_dpi);

                    float sec0_y = clip_top + scale_f(8, cur_dpi) - sy;
                    float card0_y = sec0_y + scale_f(22, cur_dpi);
                    float seg_box_h = scale_f(52, cur_dpi);

                    float sec1_y = card0_y + seg_box_h + scale_f(24, cur_dpi);
                    float card1_y = sec1_y + scale_f(22, cur_dpi);
                    float gen_row_h = scale_f(64, cur_dpi);
                    float card1_h = gen_row_h * 4.0f;

                    float sec2_y = card1_y + card1_h + scale_f(24, cur_dpi);
                    float card2_y = sec2_y + scale_f(22, cur_dpi);
                    float card2_h = row_h * 5.0f;

                    float sec3_y = card2_y + card2_h + scale_f(24, cur_dpi);
                    float card3_y = sec3_y + scale_f(22, cur_dpi);
                    float card3_h = row_h * 5.0f;

                    float sec4_y = card3_y + card3_h + scale_f(24, cur_dpi);

                    impl->save_btn_hovered_ = false;

                    impl->hovered_settings_row_ = -1;
                    if (y >= clip_top && x >= card_x && x <= card_x + card_w) {
                        if (y >= card0_y && y <= card0_y + seg_box_h) {
                            impl->hovered_settings_row_ = 100; // Appearance segments
                        } else if (y >= card1_y && y <= card1_y + card1_h) {
                            impl->hovered_settings_row_ = 10 + static_cast<int>((y - card1_y) / gen_row_h);
                        } else if (y >= card2_y && y <= card2_y + card2_h) {
                            int r = static_cast<int>((y - card2_y) / row_h);
                            if (r == 4) impl->hovered_settings_row_ = 16;
                            else impl->hovered_settings_row_ = r;
                        } else if (y >= card3_y && y <= card3_y + card3_h) {
                            int r = static_cast<int>((y - card3_y) / row_h);
                            if (r == 0) impl->hovered_settings_row_ = 14;
                            else if (r == 1) impl->hovered_settings_row_ = 15;
                            else if (r == 2) impl->hovered_settings_row_ = 4;
                            else if (r == 3) impl->hovered_settings_row_ = 5;
                            else if (r == 4) impl->hovered_settings_row_ = 6;
                        } else if (y >= sec4_y && y <= sec4_y + row_h) {
                            impl->hovered_settings_row_ = 20; // About row
                        }
                    }

                } else if (impl->view_ == ActiveView::Logs) {
                    float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float clr_x = w - back_x - back_sz;
                    float cp_x = clr_x - back_sz - scale_f(8, cur_dpi);
                    impl->copy_logs_hovered_ = (x >= cp_x && x <= cp_x + back_sz && y >= back_y && y <= back_y + back_sz);
                    impl->clear_logs_hovered_ = (x >= clr_x && x <= clr_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
                    float chips_y = back_y + back_sz + scale_f(12, cur_dpi);
                    float chip_h = scale_f(36, cur_dpi);
                    float chip_gap = scale_f(8, cur_dpi);
                    float chip_w = (card_w - chip_gap * 3.0f) / 4.0f;

                    impl->hovered_log_chip_ = -1;
                    for (int i = 0; i < 4; ++i) {
                        float ch_x = back_x + static_cast<float>(i) * (chip_w + chip_gap);
                        if (x >= ch_x && x <= ch_x + chip_w && y >= chips_y && y <= chips_y + chip_h) {
                            impl->hovered_log_chip_ = i;
                            break;
                        }
                    }

                } else if (impl->view_ == ActiveView::About) {
                    float back_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_x = back_x;
                    float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
                    float row_h = scale_f(static_cast<float>(ds.metrics.row_height), cur_dpi);
                    float card_y = scale_f(314, cur_dpi);

                    impl->about_src_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y && y <= card_y + row_h);
                    impl->about_issue_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y + row_h && y <= card_y + row_h * 2.0f);

                    float upd_w = scale_f(180, cur_dpi);
                    float upd_h = scale_f(44, cur_dpi);
                    float upd_x = w / 2.0f - upd_w / 2.0f;
                    float upd_y = card_y + row_h * 3.0f + scale_f(28, cur_dpi);
                    impl->update_btn_hovered_ = (x >= upd_x && x <= upd_x + upd_w && y >= upd_y && y <= upd_y + upd_h);
                }

                if (prev_hero != impl->hero_hovered_ || prev_logs != impl->logs_btn_hovered_ ||
                    prev_set != impl->settings_btn_hovered_ || prev_back != impl->back_btn_hovered_ ||
                    prev_save != impl->save_btn_hovered_ || prev_cp != impl->copy_btn_hovered_ ||
                    prev_proto != impl->home_proto_hovered_ || prev_route != impl->home_route_hovered_ ||
                    prev_cp_logs != impl->copy_logs_hovered_ || prev_clr_logs != impl->clear_logs_hovered_ ||
                    prev_log_chip != impl->hovered_log_chip_ ||
                    prev_row != impl->hovered_settings_row_ || prev_about_src != impl->about_src_hovered_ ||
                    prev_about_iss != impl->about_issue_hovered_ || prev_upd != impl->update_btn_hovered_) {
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }

            case WM_MOUSELEAVE: {
                impl->mouse_tracking_ = false;
                impl->reset_hovers();
                impl->hero_target_scale_ = 1.0f;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }

            case WM_SETCURSOR: {
                if (LOWORD(lParam) == HTCLIENT) {
                    POINT pt;
                    GetCursorPos(&pt);
                    ScreenToClient(hwnd, &pt);
                    if (impl->is_mouse_over_clickable(pt.x, pt.y)) {
                        SetCursor(LoadCursorW(nullptr, IDC_HAND));
                    } else {
                        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
                    }
                    return TRUE;
                }
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            }

            case WM_CHAR: {
                if (impl->view_ == ActiveView::Settings && impl->is_editing_socks_) {
                    wchar_t ch = static_cast<wchar_t>(wParam);
                    if (ch == VK_BACK) {
                        if (!impl->socks_edit_buffer_.empty()) {
                            impl->socks_edit_buffer_.pop_back();
                            InvalidateRect(hwnd, nullptr, FALSE);
                        }
                    } else if (ch == VK_RETURN) {
                        impl->is_editing_socks_ = false;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (ch == VK_ESCAPE) {
                        impl->is_editing_socks_ = false;
                        impl->socks_edit_buffer_ = std::wstring(impl->edit_profile_.bind_address.begin(), impl->edit_profile_.bind_address.end());
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (ch >= 32 && ch < 127) {
                        impl->socks_edit_buffer_.push_back(ch);
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                    return 0;
                }
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            }

            case WM_LBUTTONDOWN: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);

                if (impl->view_ == ActiveView::Settings && impl->is_editing_socks_ && impl->hovered_settings_row_ != 6) {
                    impl->is_editing_socks_ = false;
                    impl->commit_settings_save();
                    InvalidateRect(hwnd, nullptr, FALSE);
                }

                if (impl->active_dropdown_ >= 0) {
                    if (x >= impl->dropdown_popup_rect_.left && x <= impl->dropdown_popup_rect_.right &&
                        y >= impl->dropdown_popup_rect_.top && y <= impl->dropdown_popup_rect_.bottom) {
                        const UINT cur_dpi = impl->dpi();
                        float item_h = (float)scale(ds::DesignSystem::get().metrics.dropdown_item_h, cur_dpi);
                        int idx = static_cast<int>((y - impl->dropdown_popup_rect_.top) / item_h);
                        if (idx >= 0 && idx < static_cast<int>(impl->dropdown_options_.size())) {
                            impl->handle_dropdown_selection(impl->dropdown_options_[idx].id);
                        }
                    } else {
                        impl->active_dropdown_ = -1;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                    return 0;
                }

                if (impl->view_ == ActiveView::Home) {
                    if (impl->hero_hovered_) {
                        impl->hero_pressed_ = true;
                        impl->hero_target_scale_ = 0.97f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->logs_btn_hovered_) {
                        impl->switch_view(ActiveView::Logs);
                    } else if (impl->settings_btn_hovered_) {
                        impl->switch_view(ActiveView::Settings);
                    } else if (impl->home_proto_hovered_) {
                        impl->switch_view(ActiveView::Settings);
                        impl->active_dropdown_ = 0;
                        impl->dropdown_options_ = {
                            { L"Auto (Best available)", 101 },
                            { L"Gool (WARP over MASQUE)", 102 },
                            { L"WARP-in-WARP (Classic)", 103 },
                            { L"MASQUE (HTTP/3 QUIC)", 104 },
                            { L"MASQUE (HTTP/2 TCP)", 105 },
                            { L"WireGuard", 106 },
                            { L"MiM (MASQUE-in-MASQUE)", 107 }
                        };
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->home_route_hovered_) {
                        impl->switch_view(ActiveView::Settings);
                    } else if (impl->copy_btn_hovered_) {
                        auto prof = impl->engine_->active_profile();
                        std::wstring addr(prof.bind_address.begin(), prof.bind_address.end());
                        impl->copy_to_clipboard(addr);
                        impl->socks_copied_ = true;
                        impl->copy_timer_ = 1.5f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->try_again_hovered_) {
                        (void)impl->engine_->connect();
                    } else if (impl->view_logs_chip_hovered_) {
                        impl->switch_view(ActiveView::Logs);
                    }

                } else if (impl->view_ == ActiveView::Settings) {
                    if (impl->back_btn_hovered_) {
                        impl->commit_settings_save();
                        impl->switch_view(ActiveView::Home);
                    } else if (impl->hovered_settings_row_ == 100) {
                        // Appearance Segment Pick: Immediately save & apply!
                        const UINT cur_dpi = impl->dpi();
                        RECT rc;
                        GetClientRect(hwnd, &rc);
                        float card_x = (float)scale(ds::DesignSystem::get().metrics.padding_x, cur_dpi);
                        float card_w = static_cast<float>(rc.right - rc.left) - scale_f(static_cast<float>(ds::DesignSystem::get().metrics.padding_x * 2), cur_dpi);
                        float seg_gap = scale_f(4, cur_dpi);
                        float seg_w = (card_w - scale_f(8, cur_dpi) - seg_gap * 2.0f) / 3.0f;
                        float rel_x = static_cast<float>(x) - (card_x + scale_f(4, cur_dpi));
                        int picked = std::clamp(static_cast<int>(rel_x / (seg_w + seg_gap)), 0, 2);

                        impl->seg_target_x_ = static_cast<float>(picked);
                        if (picked == 0) impl->edit_settings_.theme = "system";
                        else if (picked == 1) impl->edit_settings_.theme = "light";
                        else impl->edit_settings_.theme = "dark";

                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);

                    } else if (impl->hovered_settings_row_ == 10) {
                        impl->edit_settings_.autostart = !impl->edit_settings_.autostart;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 11) {
                        impl->edit_settings_.close_to_tray = !impl->edit_settings_.close_to_tray;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 12) {
                        impl->edit_settings_.kill_switch = !impl->edit_settings_.kill_switch;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 13) {
                        impl->edit_profile_.system_proxy = !impl->edit_profile_.system_proxy;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 16) {
                        if (impl->edit_profile_.route_direct.empty()) {
                            impl->edit_profile_.route_direct = "ir";
                        } else {
                            impl->edit_profile_.route_direct.clear();
                        }
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 14) {
                        impl->edit_profile_.fragment = !impl->edit_profile_.fragment;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 15) {
                        impl->edit_profile_.ech = !impl->edit_profile_.ech;
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 20) {
                        impl->switch_view(ActiveView::About);
                    } else if (impl->hovered_settings_row_ >= 0) {
                        int r = impl->hovered_settings_row_;
                        if (r == 0) {
                            impl->active_dropdown_ = 0;
                            impl->dropdown_options_ = {
                                { L"Auto (Best available)", 101 },
                                { L"Gool (WARP over MASQUE)", 102 },
                                { L"WARP-in-WARP (Classic)", 103 },
                                { L"MASQUE (HTTP/3 QUIC)", 104 },
                                { L"MASQUE (HTTP/2 TCP)", 105 },
                                { L"WireGuard", 106 },
                                { L"MiM (MASQUE-in-MASQUE)", 107 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 1) {
                            impl->active_dropdown_ = 1;
                            impl->dropdown_options_ = {
                                { L"Balanced (Recommended)", 201 },
                                { L"Turbo (Fastest)", 202 },
                                { L"Thorough (Exhaustive)", 203 },
                                { L"Verified (Stealth)", 204 },
                                { L"Ironclad (Anti-block)", 205 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 2) {
                            impl->active_dropdown_ = 2;
                            impl->dropdown_options_ = {
                                { L"Auto (Fastest)", 301 },
                                { L"United States (US)", 302 },
                                { L"Germany (DE)", 303 },
                                { L"United Kingdom (GB)", 304 },
                                { L"Netherlands (NL)", 305 },
                                { L"France (FR)", 306 },
                                { L"Singapore (SG)", 307 },
                                { L"Japan (JP)", 308 },
                                { L"Turkey (TR)", 309 },
                                { L"Canada (CA)", 310 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 3) {
                            impl->active_dropdown_ = 3;
                            impl->dropdown_options_ = {
                                { L"IPv4", 401 },
                                { L"IPv6", 402 },
                                { L"Dual (Both)", 403 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 4) {
                            impl->active_dropdown_ = 4;
                            impl->dropdown_options_ = {
                                { L"Balanced (Firewall)", 501 },
                                { L"Aggressive (GFW)", 502 },
                                { L"Off", 503 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 5) {
                            impl->active_dropdown_ = 5;
                            impl->dropdown_options_ = {
                                { L"Auto (1.1.1.1)", 601 },
                                { L"Cloudflare Security (1.1.1.2)", 602 },
                                { L"Google (8.8.8.8)", 603 },
                                { L"Quad9 (9.9.9.9)", 604 }
                            };
                            InvalidateRect(hwnd, nullptr, FALSE);
                        } else if (r == 6) {
                            impl->is_editing_socks_ = true;
                            impl->caret_blink_timer_ = 0.0f;
                            InvalidateRect(hwnd, nullptr, FALSE);
                        }
                    }

                } else if (impl->view_ == ActiveView::Logs) {
                    if (impl->back_btn_hovered_) {
                        impl->switch_view(ActiveView::Home);
                    } else if (impl->copy_logs_hovered_) {
                        std::wstring clip;
                        {
                            std::lock_guard lock(impl->log_mutex_);
                            for (const auto& item : impl->parsed_logs_) {
                                if (impl->log_filter_ == 0 || static_cast<int>(item.level) == impl->log_filter_) {
                                    clip += L"[" + item.time_str + L"] " + item.tag + L" " + item.message + L"\r\n";
                                }
                            }
                        }
                        if (!clip.empty()) {
                            impl->copy_to_clipboard(clip);
                        }
                        impl->logs_copied_ = true;
                        impl->logs_copy_timer_ = 1.5f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->clear_logs_hovered_) {
                        std::lock_guard lock(impl->log_mutex_);
                        impl->parsed_logs_.clear();
                        impl->log_history_.clear();
                        impl->target_logs_scroll_y_ = 0.0f;
                        impl->logs_scroll_anim_y_ = 0.0f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_log_chip_ >= 0) {
                        impl->log_filter_ = impl->hovered_log_chip_;
                        impl->target_logs_scroll_y_ = 0.0f;
                        impl->logs_scroll_anim_y_ = 0.0f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }

                } else if (impl->view_ == ActiveView::About) {
                    if (impl->back_btn_hovered_) {
                        impl->switch_view(ActiveView::Settings);
                    } else if (impl->about_src_hovered_) {
                        ShellExecuteW(nullptr, L"open", L"https://github.com", nullptr, nullptr, SW_SHOWNORMAL);
                    } else if (impl->about_issue_hovered_) {
                        ShellExecuteW(nullptr, L"open", L"https://github.com/issues", nullptr, nullptr, SW_SHOWNORMAL);
                    } else if (impl->update_btn_hovered_) {
                        if (!impl->is_checking_update_) {
                            impl->is_checking_update_ = true;
                            impl->is_update_done_ = false;
                            impl->update_check_timer_ = 0.0f;
                            InvalidateRect(hwnd, nullptr, FALSE);
                        }
                    }
                }
                return 0;
            }

            case WM_LBUTTONUP: {
                if (impl->hero_pressed_) {
                    impl->hero_pressed_ = false;
                    impl->hero_target_scale_ = impl->hero_hovered_ ? 1.03f : 1.0f;
                    InvalidateRect(hwnd, nullptr, FALSE);

                    auto state = impl->engine_->current_state();
                    if (state.kind == StateKind::Connected || state.kind == StateKind::Connecting) {
                        (void)impl->engine_->disconnect();
                    } else {
                        impl->conn_sub_text_ = L"Finding the best route";
                        auto res = impl->engine_->connect();
                        if (!res) {
                            impl->shake_timer_ = 0.45f;
                        }
                    }
                }
                return 0;
            }

            case WM_HEMERA_STATE_CHANGE: {
                auto state = impl->engine_->current_state();
                if (state.kind == StateKind::Error) {
                    impl->shake_timer_ = 0.45f;
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }

            case WM_HEMERA_LOG: {
                auto* log_ptr = reinterpret_cast<LogLine*>(lParam);
                if (log_ptr) {
                    std::lock_guard lock(impl->log_mutex_);
                    impl->parse_and_append_log(log_ptr->line, log_ptr->timestamp_ms);
                    delete log_ptr;
                    // Auto-follow: if user is near bottom, smoothly follow new log entries
                    if (std::abs(impl->target_logs_scroll_y_ - impl->max_logs_scroll_) < 80.0f) {
                        impl->target_logs_scroll_y_ = impl->max_logs_scroll_ + 60.0f;
                    }
                }
                if (impl->view_ == ActiveView::Logs || impl->view_ == ActiveView::Home) {
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }

            case WM_HEMERA_TRAY: {
                if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
                    POINT pt;
                    GetCursorPos(&pt);
                    impl->show_tray_menu(pt.x, pt.y);
                } else if (lParam == WM_LBUTTONUP || lParam == WM_LBUTTONDBLCLK) {
                    ShowWindow(hwnd, SW_SHOW);
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                }
                return 0;
            }

            case WM_CLOSE: {
                auto s = impl->engine_->load_settings();
                if (s.close_to_tray) {
                    ShowWindow(hwnd, SW_HIDE);
                    return 0;
                }
                DestroyWindow(hwnd);
                return 0;
            }

            case WM_DESTROY: {
                impl->remove_tray_icon();
                KillTimer(hwnd, TIMER_ANIMATION);
                PostQuitMessage(0);
                return 0;
            }

            default:
                return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }
};

MainWindow::MainWindow(HINSTANCE hInstance, std::shared_ptr<HemeraEngine> engine, bool start_minimized)
    : impl_(std::make_unique<Impl>(hInstance, std::move(engine), start_minimized)) {}

MainWindow::~MainWindow() = default;

bool MainWindow::create() {
    // Notify shell to flush icon cache so Explorer updates immediately
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWindow::Impl::WndProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = impl_->hInstance_;
    wc.lpszClassName = L"HemeraMainWindowClass";
    wc.hIcon = LoadIconW(impl_->hInstance_, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    const auto& ds = ds::DesignSystem::get();
    UINT sys_dpi = GetDpiForSystem();
    if (sys_dpi == 0) sys_dpi = 96;

    const int client_w = MulDiv(ds.metrics.window_width, sys_dpi, 96);
    const int client_h = MulDiv(ds.metrics.window_height, sys_dpi, 96);
    RECT wr = { 0, 0, client_w, client_h };

    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    using PFN_AdjustWindowRectExForDpi = BOOL(WINAPI*)(LPRECT, DWORD, BOOL, DWORD, UINT);
    auto pfnAdjustDpi = (PFN_AdjustWindowRectExForDpi)GetProcAddress(hUser32, "AdjustWindowRectExForDpi");

    if (pfnAdjustDpi) {
        pfnAdjustDpi(&wr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0, sys_dpi);
    } else {
        AdjustWindowRectEx(&wr, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);
    }

    int win_w = wr.right - wr.left;
    int win_h = wr.bottom - wr.top;
    int pos_x = (GetSystemMetrics(SM_CXSCREEN) - win_w) / 2;
    int pos_y = (GetSystemMetrics(SM_CYSCREEN) - win_h) / 2;

    impl_->hwnd_ = CreateWindowExW(
        0, L"HemeraMainWindowClass", L"Hemera",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        pos_x, pos_y, win_w, win_h,
        nullptr, nullptr, impl_->hInstance_, impl_.get()
    );

    if (!impl_->hwnd_) return false;

    if (!impl_->in_tray_) {
        impl_->setup_tray_icon();
    }

    // Apply immersive title bar mode based on active theme
    BOOL dark_mode = ds::is_effective_dark(ds.active_theme) ? TRUE : FALSE;
    DwmSetWindowAttribute(impl_->hwnd_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark_mode, sizeof(dark_mode));

    // Register thread-safe engine callbacks
    HWND target_hwnd = impl_->hwnd_;
    impl_->engine_->set_on_state_changed([target_hwnd](const ConnectionState&) {
        PostMessageW(target_hwnd, WM_HEMERA_STATE_CHANGE, 0, 0);
    });

    impl_->engine_->set_on_log([target_hwnd](const LogLine& log) {
        auto* copy = new LogLine(log);
        PostMessageW(target_hwnd, WM_HEMERA_LOG, 0, reinterpret_cast<LPARAM>(copy));
    });

    if (!impl_->start_minimized_) {
        ShowWindow(impl_->hwnd_, SW_SHOWNORMAL);
        UpdateWindow(impl_->hwnd_);
    }

    return true;
}

int MainWindow::run_message_loop() {
    timeBeginPeriod(1);

    MSG msg{};
    bool running = true;
    impl_->last_frame_time_ = std::chrono::steady_clock::now();

    while (running) {
        // 1. Drain all pending Windows messages first (zero input latency)
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                running = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!running) break;

        // 2. High-precision frame timing
        auto frame_start = std::chrono::steady_clock::now();
        float dt = std::chrono::duration<float>(frame_start - impl_->last_frame_time_).count();
        if (dt > 0.033f) dt = 0.033f; // Prevent huge jump on focus switch
        impl_->last_frame_time_ = frame_start;

        bool is_visible = impl_->hwnd_ && IsWindow(impl_->hwnd_) && IsWindowVisible(impl_->hwnd_) && !IsIconic(impl_->hwnd_);
        bool active_anim = is_visible && impl_->has_active_animations();

        if (active_anim && !impl_->is_moving_window_) {
            impl_->step_animations(dt);
            InvalidateRect(impl_->hwnd_, nullptr, FALSE);
            UpdateWindow(impl_->hwnd_);
        } else {
            // Background metrics and timers advance
            impl_->step_animations(dt);
        }

        // 3. Dynamic CPU sleep: 8ms during animation (silky 120 FPS), 40ms when idle (0% CPU)
        auto frame_end = std::chrono::steady_clock::now();
        int elapsed_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(frame_end - frame_start).count());

        DWORD wait_ms = 40;
        if (active_anim) {
            wait_ms = (elapsed_ms < 8) ? static_cast<DWORD>(8 - elapsed_ms) : 1;
        }
        MsgWaitForMultipleObjectsEx(0, nullptr, wait_ms, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
    }

    timeEndPeriod(1);
    return static_cast<int>(msg.wParam);
}

void MainWindow::show(int nCmdShow) {
    if (impl_->hwnd_) {
        ShowWindow(impl_->hwnd_, nCmdShow);
        SetForegroundWindow(impl_->hwnd_);
    }
}

void MainWindow::hide() {
    if (impl_->hwnd_) {
        ShowWindow(impl_->hwnd_, SW_HIDE);
    }
}

} // namespace hemera::gui
