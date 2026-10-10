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
#include <malloc.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <shlobj.h>
#include <psapi.h>
#include <mmsystem.h>
#include <objidl.h>
#include <d2d1.h>
#include <d2d1helper.h>
#include <dwrite.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <vector>
#include <deque>
#include <string>
#include <format>
#include <cmath>
#include <chrono>
#include <algorithm>
#include <mutex>
#include <memory>
#include <fstream>

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
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace hemera::gui {

namespace {

using ds::scale;
using ds::scale_f;
using Color = ds::Color;

constexpr UINT TIMER_ANIMATION = 1001;

// Native Direct2D primitives used in MainWindow::Impl

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

// Smooth cubic-bezier(0.2, 0.7, 0.2, 1.0) approximation matching tokens/CSS .rise
inline float compute_rise_progress(float view_t) {
    float local_t = std::clamp(view_t, 0.0f, 1.0f);
    float inv = 1.0f - local_t;
    return 1.0f - inv * inv * inv * (1.0f + 0.5f * local_t);
}

inline Color blend_colors(const Color& c1, const Color& c2, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    return Color(
        c1.r + (c2.r - c1.r) * t,
        c1.g + (c2.g - c1.g) * t,
        c1.b + (c2.b - c1.b) * t,
        c1.a + (c2.a - c1.a) * t
    );
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
    float back_chevron_anim_x_ = 0.0f; // Smooth -3px micro-interaction on hover (.iconbtn.bk)
    bool min_btn_hovered_ = false;
    bool min_btn_pressed_ = false;
    bool close_btn_hovered_ = false;
    bool close_btn_pressed_ = false;
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
    // [0]=autostart, [1]=close_to_tray, [2]=kill_switch, [3]=system_proxy, [4]=fragment, [5]=ech, [6]=route_direct, [7]=tun_mode
    float switch_anim_[8] = { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f };

    // About view hovers & state
    bool about_src_hovered_ = false;
    bool about_issue_hovered_ = false;
    bool about_releases_hovered_ = false;
    bool about_license_hovered_ = false;
    float about_card_y_ = 0.0f;
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
    int max_scroll_ = 0;
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

    // Direct2D & DirectWrite Resources
    ULONG_PTR gdiplus_token_ = 0;
    Microsoft::WRL::ComPtr<ID2D1Factory> d2d_factory_;
    Microsoft::WRL::ComPtr<IDWriteFactory> dwrite_factory_;
    Microsoft::WRL::ComPtr<ID2D1HwndRenderTarget> render_target_;
    Microsoft::WRL::ComPtr<ID2D1SolidColorBrush> brush_;
    Microsoft::WRL::ComPtr<ID2D1StrokeStyle> stroke_round_;

    // DirectWrite Typography Formats
    UINT cached_font_dpi_ = 0;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_app_title_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_hero_status_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_view_title_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_body_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_body_bold_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_mono_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_mono_bold_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_mono_wrap_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_sub_label_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_footnote_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_metric_tag_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_tray_title_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_tray_sub_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_tray_btn_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt_tray_item_;

    // Logo & Visual Layer Resources
    Microsoft::WRL::ComPtr<ID2D1Bitmap> logo_d2d_bitmap_;

    bool custom_loop_active_ = false;
    int cached_bmp_w_ = 0;
    int cached_bmp_h_ = 0;
    bool need_full_bg_copy_ = false;

    // Interactive Scrollbar State
    bool scrollbar_hovered_ = false;
    bool scrollbar_dragging_ = false;
    float scrollbar_drag_start_y_ = 0.0f;
    float scrollbar_drag_start_scroll_ = 0.0f;
    RECT settings_sb_thumb_rect_{};
    RECT settings_sb_track_rect_{};

    ConnectionState cached_engine_state_{};
    ConnectionProfile cached_engine_profile_{};
    LiveStats cached_engine_stats_{};
    float stats_refresh_timer_ = 0.0f;

    // Custom Direct2D Tray Flyout Menu (matches aether-ui-complete)
    HWND tray_hwnd_ = nullptr;
    Microsoft::WRL::ComPtr<ID2D1HwndRenderTarget> tray_rt_;
    Microsoft::WRL::ComPtr<ID2D1SolidColorBrush> tray_brush_;
    int tray_hovered_item_ = -1;
    int tray_pressed_item_ = -1;

    void create_logo_d2d_bitmap() {
        if (!render_target_ || logo_d2d_bitmap_) return;

        HRSRC hRes = FindResourceW(hInstance_, MAKEINTRESOURCEW(IDR_APP_PNG), RT_RCDATA);
        if (!hRes) return;
        HGLOBAL hResLoad = LoadResource(hInstance_, hRes);
        if (!hResLoad) return;
        DWORD size = SizeofResource(hInstance_, hRes);
        const void* pData = LockResource(hResLoad);
        if (!pData || size == 0) return;

        Microsoft::WRL::ComPtr<IWICImagingFactory> wic_factory;
        HRESULT hr = CoCreateInstance(
            CLSID_WICImagingFactory,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&wic_factory)
        );
        if (FAILED(hr)) return;

        Microsoft::WRL::ComPtr<IWICStream> wic_stream;
        hr = wic_factory->CreateStream(&wic_stream);
        if (FAILED(hr)) return;

        hr = wic_stream->InitializeFromMemory(
            reinterpret_cast<BYTE*>(const_cast<void*>(pData)),
            size
        );
        if (FAILED(hr)) return;

        Microsoft::WRL::ComPtr<IWICBitmapDecoder> decoder;
        hr = wic_factory->CreateDecoderFromStream(
            wic_stream.Get(),
            nullptr,
            WICDecodeMetadataCacheOnLoad,
            &decoder
        );
        if (FAILED(hr)) return;

        Microsoft::WRL::ComPtr<IWICBitmapFrameDecode> frame;
        hr = decoder->GetFrame(0, &frame);
        if (FAILED(hr)) return;

        Microsoft::WRL::ComPtr<IWICFormatConverter> converter;
        hr = wic_factory->CreateFormatConverter(&converter);
        if (FAILED(hr)) return;

        hr = converter->Initialize(
            frame.Get(),
            GUID_WICPixelFormat32bppPBGRA,
            WICBitmapDitherTypeNone,
            nullptr,
            0.0f,
            WICBitmapPaletteTypeMedianCut
        );
        if (FAILED(hr)) return;

        render_target_->CreateBitmapFromWicBitmap(
            converter.Get(),
            nullptr,
            &logo_d2d_bitmap_
        );
    }

    HRESULT ensure_device_resources() {
        if (render_target_) return S_OK;
        if (!hwnd_ || !d2d_factory_) return E_FAIL;

        RECT rc;
        GetClientRect(hwnd_, &rc);
        D2D1_SIZE_U size = D2D1::SizeU(
            std::max(1L, rc.right - rc.left),
            std::max(1L, rc.bottom - rc.top)
        );

        D2D1_RENDER_TARGET_PROPERTIES rt_props = D2D1::RenderTargetProperties(
            D2D1_RENDER_TARGET_TYPE_SOFTWARE,
            D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_IGNORE),
            96.0f, 96.0f,
            D2D1_RENDER_TARGET_USAGE_NONE,
            D2D1_FEATURE_LEVEL_DEFAULT
        );

        D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_props = D2D1::HwndRenderTargetProperties(
            hwnd_,
            size,
            D2D1_PRESENT_OPTIONS_IMMEDIATELY
        );

        HRESULT hr = d2d_factory_->CreateHwndRenderTarget(rt_props, hwnd_props, &render_target_);
        if (FAILED(hr)) return hr;

        render_target_->SetDpi(96.0f, 96.0f);
        render_target_->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        render_target_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);

        hr = render_target_->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &brush_);
        if (FAILED(hr)) return hr;

        create_logo_d2d_bitmap();
        return S_OK;
    }

    void discard_device_resources() {
        logo_d2d_bitmap_.Reset();
        brush_.Reset();
        render_target_.Reset();
    }

    // Direct2D High-Performance Drawing Helpers
    void set_color(const Color& c) {
        if (brush_) brush_->SetColor(c);
    }
    void set_color(const Color& c, float alpha_mult) {
        if (brush_) brush_->SetColor(ds::to_d2d_alpha(c, alpha_mult));
    }
    void set_color(D2D1_COLOR_F c) {
        if (brush_) brush_->SetColor(c);
    }

    void fill_rect(float x, float y, float w, float h, const Color& c) {
        set_color(c);
        render_target_->FillRectangle(D2D1::RectF(x, y, x + w, y + h), brush_.Get());
    }

    void draw_rect(float x, float y, float w, float h, const Color& c, float stroke = 1.0f) {
        set_color(c);
        render_target_->DrawRectangle(D2D1::RectF(x, y, x + w, y + h), brush_.Get(), stroke);
    }

    void fill_rounded_rect(float x, float y, float w, float h, float radius, const Color& c) {
        if (radius <= 0.0f) { fill_rect(x, y, w, h, c); return; }
        set_color(c);
        render_target_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x, y, x + w, y + h), radius, radius), brush_.Get());
    }

    void fill_rounded_rect(float x, float y, float w, float h, float radius, D2D1_COLOR_F c) {
        set_color(c);
        render_target_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x, y, x + w, y + h), radius, radius), brush_.Get());
    }

    void draw_rounded_rect(float x, float y, float w, float h, float radius, const Color& c, float stroke = 1.0f) {
        if (radius <= 0.0f) { draw_rect(x, y, w, h, c, stroke); return; }
        set_color(c);
        render_target_->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(x, y, x + w, y + h), radius, radius), brush_.Get(), stroke);
    }

    void fill_card_row_hover(float card_x, float row_y, float card_w, float row_h, float radius, int row_idx, int total_rows, const Color& c) {
        if (!render_target_) return;
        if (radius <= 0.0f) {
            fill_rect(card_x, row_y, card_w, row_h, c);
            return;
        }
        if (total_rows <= 1) {
            fill_rounded_rect(card_x, row_y, card_w, row_h, radius, c);
        } else if (row_idx == 0) {
            render_target_->PushAxisAlignedClip(D2D1::RectF(card_x - 4.0f, row_y - 4.0f, card_x + card_w + 4.0f, row_y + row_h), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
            fill_rounded_rect(card_x, row_y, card_w, row_h + radius, radius, c);
            render_target_->PopAxisAlignedClip();
        } else if (row_idx == total_rows - 1) {
            render_target_->PushAxisAlignedClip(D2D1::RectF(card_x - 4.0f, row_y, card_x + card_w + 4.0f, row_y + row_h + 4.0f), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
            fill_rounded_rect(card_x, row_y - radius, card_w, row_h + radius, radius, c);
            render_target_->PopAxisAlignedClip();
        } else {
            fill_rect(card_x, row_y, card_w, row_h, c);
        }
    }

    void draw_line(float x1, float y1, float x2, float y2, const Color& c, float stroke = 1.0f, bool round_caps = false) {
        set_color(c);
        render_target_->DrawLine(D2D1::Point2F(x1, y1), D2D1::Point2F(x2, y2), brush_.Get(), stroke, round_caps ? stroke_round_.Get() : nullptr);
    }

    void draw_lines(const D2D1_POINT_2F* pts, UINT32 count, const Color& c, float stroke = 1.0f, bool round_caps = true) {
        if (!pts || count < 2) return;
        set_color(c);
        for (UINT32 i = 0; i < count - 1; ++i) {
            render_target_->DrawLine(pts[i], pts[i + 1], brush_.Get(), stroke, round_caps ? stroke_round_.Get() : nullptr);
        }
    }

    void fill_ellipse(float cx, float cy, float rx, float ry, const Color& c) {
        set_color(c);
        render_target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), rx, ry), brush_.Get());
    }

    void fill_ellipse(float cx, float cy, float r, const Color& c) {
        fill_ellipse(cx, cy, r, r, c);
    }

    void fill_ellipse(float cx, float cy, float r, D2D1_COLOR_F c) {
        set_color(c);
        render_target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), r, r), brush_.Get());
    }

    void draw_ellipse(float cx, float cy, float rx, float ry, const Color& c, float stroke = 1.0f, float alpha_mult = 1.0f) {
        set_color(c, alpha_mult);
        render_target_->DrawEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), rx, ry), brush_.Get(), stroke);
    }

    void draw_ellipse(float cx, float cy, float r, const Color& c, float stroke = 1.0f, float alpha_mult = 1.0f) {
        draw_ellipse(cx, cy, r, r, c, stroke, alpha_mult);
    }

    void draw_arc(float cx, float cy, float r, float start_deg, float sweep_deg, const Color& c, float stroke = 1.0f) {
        if (r <= 0.0f || std::abs(sweep_deg) < 0.1f) return;
        float start_rad = start_deg * (3.14159265f / 180.0f);
        float end_rad = (start_deg + sweep_deg) * (3.14159265f / 180.0f);

        D2D1_POINT_2F p_start = D2D1::Point2F(cx + r * std::cos(start_rad), cy + r * std::sin(start_rad));
        D2D1_POINT_2F p_end = D2D1::Point2F(cx + r * std::cos(end_rad), cy + r * std::sin(end_rad));

        Microsoft::WRL::ComPtr<ID2D1PathGeometry> path;
        if (FAILED(d2d_factory_->CreatePathGeometry(&path))) return;
        Microsoft::WRL::ComPtr<ID2D1GeometrySink> sink;
        if (FAILED(path->Open(&sink))) return;

        sink->BeginFigure(p_start, D2D1_FIGURE_BEGIN_HOLLOW);
        D2D1_ARC_SIZE arc_size = (std::abs(sweep_deg) >= 180.0f) ? D2D1_ARC_SIZE_LARGE : D2D1_ARC_SIZE_SMALL;
        D2D1_SWEEP_DIRECTION dir = (sweep_deg >= 0.0f) ? D2D1_SWEEP_DIRECTION_CLOCKWISE : D2D1_SWEEP_DIRECTION_COUNTER_CLOCKWISE;
        sink->AddArc(D2D1::ArcSegment(p_end, D2D1::SizeF(r, r), 0.0f, dir, arc_size));
        sink->EndFigure(D2D1_FIGURE_END_OPEN);
        sink->Close();

        set_color(c);
        render_target_->DrawGeometry(path.Get(), brush_.Get(), stroke, stroke_round_.Get());
    }

    void fill_radial_glow(float cx, float cy, float r, const Color& glow_color) {
        if (r <= 0.0f || !render_target_) return;
        D2D1_GRADIENT_STOP stops[2];
        stops[0].color = glow_color;
        stops[0].position = 0.0f;
        stops[1].color = D2D1::ColorF(glow_color.r, glow_color.g, glow_color.b, 0.0f);
        stops[1].position = 1.0f;

        Microsoft::WRL::ComPtr<ID2D1GradientStopCollection> stop_coll;
        if (FAILED(render_target_->CreateGradientStopCollection(stops, 2, &stop_coll))) return;

        D2D1_RADIAL_GRADIENT_BRUSH_PROPERTIES radial_props = D2D1::RadialGradientBrushProperties(
            D2D1::Point2F(cx, cy),
            D2D1::Point2F(0.0f, 0.0f),
            r, r
        );
        Microsoft::WRL::ComPtr<ID2D1RadialGradientBrush> radial_brush;
        if (FAILED(render_target_->CreateRadialGradientBrush(radial_props, stop_coll.Get(), &radial_brush))) return;

        render_target_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), r, r), radial_brush.Get());
    }

    void draw_text(const std::wstring_view text, IDWriteTextFormat* fmt, float x, float y, const Color& c) {
        if (text.empty() || !fmt || !render_target_) return;
        set_color(c);
        fmt->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        fmt->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        D2D1_RECT_F r = D2D1::RectF(x, y, x + 2000.0f, y + 200.0f);
        render_target_->DrawText(text.data(), static_cast<UINT32>(text.length()), fmt, r, brush_.Get());
    }

    void draw_text_center(const std::wstring_view text, IDWriteTextFormat* fmt, float cx, float y, const Color& c) {
        if (text.empty() || !fmt || !render_target_) return;
        set_color(c);
        fmt->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        fmt->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        D2D1_RECT_F r = D2D1::RectF(cx - 1000.0f, y, cx + 1000.0f, y + 200.0f);
        render_target_->DrawText(text.data(), static_cast<UINT32>(text.length()), fmt, r, brush_.Get());
    }

    void draw_text_right(const std::wstring_view text, IDWriteTextFormat* fmt, float rx, float y, const Color& c) {
        if (text.empty() || !fmt || !render_target_) return;
        set_color(c);
        fmt->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_TRAILING);
        fmt->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        D2D1_RECT_F r = D2D1::RectF(rx - 2000.0f, y, rx, y + 200.0f);
        render_target_->DrawText(text.data(), static_cast<UINT32>(text.length()), fmt, r, brush_.Get());
    }

    void draw_text_rect(const std::wstring_view text, IDWriteTextFormat* fmt, float x, float y, float w, float h, const Color& c,
                        DWRITE_TEXT_ALIGNMENT align_h = DWRITE_TEXT_ALIGNMENT_LEADING,
                        DWRITE_PARAGRAPH_ALIGNMENT align_v = DWRITE_PARAGRAPH_ALIGNMENT_NEAR) {
        if (text.empty() || !fmt || !render_target_) return;
        set_color(c);
        fmt->SetTextAlignment(align_h);
        fmt->SetParagraphAlignment(align_v);
        D2D1_RECT_F r = D2D1::RectF(x, y, x + w, y + h);
        render_target_->DrawText(text.data(), static_cast<UINT32>(text.length()), fmt, r, brush_.Get());
    }

    float measure_text_height(const std::wstring_view text, IDWriteTextFormat* fmt, float max_width) {
        if (text.empty() || !fmt || !dwrite_factory_) return 0.0f;
        Microsoft::WRL::ComPtr<IDWriteTextLayout> layout;
        if (FAILED(dwrite_factory_->CreateTextLayout(text.data(), static_cast<UINT32>(text.length()), fmt, max_width, 10000.0f, &layout))) return 0.0f;
        DWRITE_TEXT_METRICS tm{};
        layout->GetMetrics(&tm);
        return tm.height;
    }

    // Modern Header Back Button matching web reference .iconbtn.bk exactly
    void draw_back_button(float back_x, float back_y, float back_sz, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();
        if (back_btn_hovered_) {
            fill_rounded_rect(back_x, back_y, back_sz, back_sz, scale_f(12.0f, cur_dpi), ds.colors.hover_bg);
        }

        // Chevron animated shift: -3px on hover matching web .bk:hover svg { transform: translateX(-3px); }
        float bcx = back_x + back_sz / 2.0f + scale_f(back_chevron_anim_x_, cur_dpi);
        float bcy = back_y + back_sz / 2.0f;
        Color chev_col = back_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
        D2D1_POINT_2F chev_pts[3] = {
            D2D1::Point2F(bcx + scale_f(2.5f, cur_dpi), bcy - scale_f(6.5f, cur_dpi)),
            D2D1::Point2F(bcx - scale_f(3.5f, cur_dpi), bcy),
            D2D1::Point2F(bcx + scale_f(2.5f, cur_dpi), bcy + scale_f(6.5f, cur_dpi))
        };
        draw_lines(chev_pts, 3, chev_col, scale_f(1.6f, cur_dpi), true);
    }

    // Chrome-style Custom Titlebar Caption Buttons (Minimize & Close)
    void draw_caption_buttons(float win_w, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();
        float btn_w = scale_f(46.0f, cur_dpi);
        float btn_h = scale_f(30.0f, cur_dpi);
        float close_x = win_w - btn_w;
        float min_x = close_x - btn_w;

        // 1. Minimize Button (Chrome-exact light & dark hover colors)
        bool is_dark = ds::is_effective_dark(ds.active_theme);
        Color min_bg;
        if (min_btn_pressed_) {
            min_bg = is_dark ? Color{ 255, 48, 50, 58 } : Color{ 255, 218, 220, 224 };
        } else if (min_btn_hovered_) {
            min_bg = is_dark ? Color{ 255, 36, 38, 44 } : Color{ 255, 232, 234, 237 };
        } else {
            min_bg = Color{ 0, 0, 0, 0 };
        }
        if (min_bg.a > 0.0f) {
            fill_rect(min_x, 0.0f, btn_w, btn_h, min_bg);
        }
        Color min_icon_col = min_btn_hovered_ ? ds.colors.text_primary : ds.colors.text_muted;
        float min_cx = min_x + btn_w / 2.0f;
        float min_cy = btn_h / 2.0f;
        float min_line_w = scale_f(10.0f, cur_dpi);
        draw_line(min_cx - min_line_w / 2.0f, min_cy, min_cx + min_line_w / 2.0f, min_cy, min_icon_col, 1.2f, false);

        // 2. Close Button (Google Chrome signature red hover)
        Color close_bg = close_btn_pressed_ ? Color{ 255, 196, 43, 28 } : // #C42B1C
                         (close_btn_hovered_ ? Color{ 255, 232, 17, 35 } : Color{ 0, 0, 0, 0 }); // #E81123
        if (close_bg.a > 0.0f) {
            fill_rect(close_x, 0.0f, btn_w, btn_h, close_bg);
        }
        Color close_icon_col = (close_btn_hovered_ || close_btn_pressed_) ? Color{ 255, 255, 255, 255 } : ds.colors.text_muted;
        float close_cx = close_x + btn_w / 2.0f;
        float close_cy = btn_h / 2.0f;
        float cr = scale_f(4.8f, cur_dpi);
        draw_line(close_cx - cr, close_cy - cr, close_cx + cr, close_cy + cr, close_icon_col, 1.2f, false);
        draw_line(close_cx + cr, close_cy - cr, close_cx - cr, close_cy + cr, close_icon_col, 1.2f, false);
    }

    Impl(HINSTANCE hInstance, std::shared_ptr<HemeraEngine> engine, bool start_minimized)
        : hInstance_(hInstance), engine_(std::move(engine)), start_minimized_(start_minimized) {
        timeBeginPeriod(1); // Set OS scheduler resolution to 1ms for rock-solid 100+ FPS!

        D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, d2d_factory_.GetAddressOf());
        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown**>(dwrite_factory_.GetAddressOf()));

        if (d2d_factory_) {
            D2D1_STROKE_STYLE_PROPERTIES stroke_props = D2D1::StrokeStyleProperties(
                D2D1_CAP_STYLE_ROUND,
                D2D1_CAP_STYLE_ROUND,
                D2D1_CAP_STYLE_ROUND,
                D2D1_LINE_JOIN_ROUND
            );
            d2d_factory_->CreateStrokeStyle(stroke_props, nullptr, 0, &stroke_round_);
        }

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
        switch_anim_[7] = edit_profile_.tun_mode ? 1.0f : 0.0f;

        // Initialize Appearance segment target
        int seg_idx = (edit_settings_.theme == "light") ? 1 : ((edit_settings_.theme == "dark") ? 2 : 0);
        seg_anim_x_ = static_cast<float>(seg_idx);
        seg_target_x_ = static_cast<float>(seg_idx);

        // Logs start 100% clean and authentic -- real core engine events only
        last_frame_time_ = std::chrono::steady_clock::now();
    }

    ~Impl() {
        remove_tray_icon();
        discard_device_resources();
        stroke_round_.Reset();
        dwrite_factory_.Reset();
        d2d_factory_.Reset();
        timeEndPeriod(1);
    }

    UINT dpi() const {
        return hwnd_ ? GetDpiForWindow(hwnd_) : 96;
    }

    void ensure_fonts(UINT cur_dpi) {
        if (cached_font_dpi_ == cur_dpi && fmt_app_title_) return;
        cached_font_dpi_ = cur_dpi;

        auto create_best_fmt = [&](const std::vector<const WCHAR*>& families, float size_px, DWRITE_FONT_WEIGHT weight, Microsoft::WRL::ComPtr<IDWriteTextFormat>& out_fmt) {
            out_fmt.Reset();
            for (const WCHAR* fam : families) {
                Microsoft::WRL::ComPtr<IDWriteTextFormat> fmt;
                HRESULT hr = dwrite_factory_->CreateTextFormat(
                    fam,
                    nullptr,
                    weight,
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    size_px,
                    L"en-us",
                    &fmt
                );
                if (SUCCEEDED(hr) && fmt) {
                    WCHAR actual[128] = {0};
                    fmt->GetFontFamilyName(actual, 128);
                    if (_wcsicmp(actual, fam) == 0) {
                        out_fmt = fmt;
                        out_fmt->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
                        return;
                    }
                }
            }
            dwrite_factory_->CreateTextFormat(
                families.back(),
                nullptr,
                weight,
                DWRITE_FONT_STYLE_NORMAL,
                DWRITE_FONT_STRETCH_NORMAL,
                size_px,
                L"en-us",
                &out_fmt
            );
            if (out_fmt) out_fmt->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
        };

        const std::vector<const WCHAR*> ui_fonts = { L"Geist", L"Segoe UI Variable Text", L"Segoe UI Variable Display", L"Segoe UI" };
        const std::vector<const WCHAR*> mono_fonts = { L"Geist Mono", L"Cascadia Code", L"Cascadia Mono", L"Consolas" };

        create_best_fmt(ui_fonts, scale_f(15.0f, cur_dpi), DWRITE_FONT_WEIGHT_MEDIUM, fmt_app_title_);
        create_best_fmt(ui_fonts, scale_f(26.0f, cur_dpi), DWRITE_FONT_WEIGHT_SEMI_BOLD, fmt_hero_status_);
        create_best_fmt(ui_fonts, scale_f(20.0f, cur_dpi), DWRITE_FONT_WEIGHT_MEDIUM, fmt_view_title_);
        create_best_fmt(ui_fonts, scale_f(14.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_body_);
        create_best_fmt(ui_fonts, scale_f(14.0f, cur_dpi), DWRITE_FONT_WEIGHT_SEMI_BOLD, fmt_body_bold_);
        create_best_fmt(mono_fonts, scale_f(13.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_mono_);
        create_best_fmt(mono_fonts, scale_f(13.0f, cur_dpi), DWRITE_FONT_WEIGHT_SEMI_BOLD, fmt_mono_bold_);
        create_best_fmt(ui_fonts, scale_f(12.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_sub_label_);
        create_best_fmt(ui_fonts, scale_f(12.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_footnote_);
        create_best_fmt(ui_fonts, scale_f(11.0f, cur_dpi), DWRITE_FONT_WEIGHT_MEDIUM, fmt_metric_tag_);

        // Compact & refined typography for system tray flyout
        create_best_fmt(ui_fonts, scale_f(12.5f, cur_dpi), DWRITE_FONT_WEIGHT_SEMI_BOLD, fmt_tray_title_);
        create_best_fmt(mono_fonts, scale_f(11.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_tray_sub_);
        create_best_fmt(ui_fonts, scale_f(12.0f, cur_dpi), DWRITE_FONT_WEIGHT_SEMI_BOLD, fmt_tray_btn_);
        create_best_fmt(ui_fonts, scale_f(11.5f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_tray_item_);

        fmt_mono_wrap_.Reset();
        create_best_fmt(mono_fonts, scale_f(12.0f, cur_dpi), DWRITE_FONT_WEIGHT_REGULAR, fmt_mono_wrap_);
        if (fmt_mono_wrap_) fmt_mono_wrap_->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
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
            COLORREF caption_col = dark_val ? RGB(11, 11, 13) : RGB(246, 246, 247);
            DwmSetWindowAttribute(hwnd_, 35 /* DWMWA_CAPTION_COLOR */, &caption_col, sizeof(caption_col));
            COLORREF caption_txt = dark_val ? RGB(237, 237, 237) : RGB(24, 24, 27);
            DwmSetWindowAttribute(hwnd_, 36 /* DWMWA_TEXT_COLOR */, &caption_txt, sizeof(caption_txt));
            InvalidateRect(hwnd_, nullptr, FALSE);
        }
    }

    void reset_hovers() {
        min_btn_hovered_ = false;
        min_btn_pressed_ = false;
        close_btn_hovered_ = false;
        close_btn_pressed_ = false;
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
        about_releases_hovered_ = false;
        about_license_hovered_ = false;
        update_btn_hovered_ = false;
        hovered_settings_row_ = -1;
        hovered_dropdown_item_ = -1;
        scrollbar_hovered_ = false;
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
        switch_anim_[7] = edit_profile_.tun_mode ? 1.0f : 0.0f;
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
        if (std::abs(back_chevron_anim_x_ - (back_btn_hovered_ ? -3.0f : 0.0f)) > 0.01f) return true;
        if (std::abs(hero_target_scale_ - hero_scale_) > 0.0005f) return true;
        if (std::abs(gear_anim_t_ - (settings_btn_hovered_ ? 1.0f : 0.0f)) > 0.001f) return true;
        if (std::abs(seg_target_x_ - seg_anim_x_) > 0.001f) return true;
        for (int i = 0; i < 8; ++i) {
            float t_val = 0.0f;
            if (i == 0) t_val = edit_settings_.autostart ? 1.0f : 0.0f;
            else if (i == 1) t_val = edit_settings_.close_to_tray ? 1.0f : 0.0f;
            else if (i == 2) t_val = edit_settings_.kill_switch ? 1.0f : 0.0f;
            else if (i == 3) t_val = edit_profile_.system_proxy ? 1.0f : 0.0f;
            else if (i == 4) t_val = edit_profile_.fragment ? 1.0f : 0.0f;
            else if (i == 5) t_val = edit_profile_.ech ? 1.0f : 0.0f;
            else if (i == 6) t_val = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;
            else if (i == 7) t_val = edit_profile_.tun_mode ? 1.0f : 0.0f;
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

        // 4. Staggered Page Transition (.rise 14px glide + opacity fade over 0.28s)
        if (view_transition_t_ < 1.0f) {
            view_transition_t_ = std::min(1.0f, view_transition_t_ + dt / 0.28f);
            needs_repaint = true;
        }

        // 5. Back button chevron glide (-3px on hover matching web .bk:hover svg)
        float bk_target = back_btn_hovered_ ? -3.0f : 0.0f;
        float bk_diff = bk_target - back_chevron_anim_x_;
        if (std::abs(bk_diff) > 0.01f) {
            back_chevron_anim_x_ += bk_diff * (1.0f - std::exp(-22.0f * dt));
            needs_repaint = true;
        } else if (back_chevron_anim_x_ != bk_target) {
            back_chevron_anim_x_ = bk_target;
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

        // 6. Smooth Toggle Switch animation transitions (8 switches)
        for (int i = 0; i < 8; ++i) {
            float t_val = 0.0f;
            if (i == 0) t_val = edit_settings_.autostart ? 1.0f : 0.0f;
            else if (i == 1) t_val = edit_settings_.close_to_tray ? 1.0f : 0.0f;
            else if (i == 2) t_val = edit_settings_.kill_switch ? 1.0f : 0.0f;
            else if (i == 3) t_val = edit_profile_.system_proxy ? 1.0f : 0.0f;
            else if (i == 4) t_val = edit_profile_.fragment ? 1.0f : 0.0f;
            else if (i == 5) t_val = edit_profile_.ech ? 1.0f : 0.0f;
            else if (i == 6) t_val = (!edit_profile_.route_direct.empty()) ? 1.0f : 0.0f;
            else if (i == 7) t_val = edit_profile_.tun_mode ? 1.0f : 0.0f;

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

        float cap_w = scale_f(46.0f, cur_dpi);
        float cap_h = scale_f(30.0f, cur_dpi);
        if (y >= 0 && y <= cap_h && x >= w - cap_w * 2.0f && x <= w) {
            return true;
        }

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
            float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (hovered_settings_row_ >= 0) return true;
            return false;
        }

        if (view_ == ActiveView::Logs) {
            float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
            float clr_x = w - card_x - back_sz;
            if (x >= clr_x && x <= clr_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            float cp_x = clr_x - back_sz - scale_f(8, cur_dpi);
            if (x >= cp_x && x <= cp_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (hovered_log_chip_ >= 0) return true;
            return false;
        }

        if (view_ == ActiveView::About) {
            float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
            float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
            float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
            if (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz) return true;

            if (about_src_hovered_ || about_issue_hovered_ || update_btn_hovered_) return true;
            return false;
        }

        return false;
    }

    // ── Home View (Concentric Ambient Rings + Hero Button + Real Metrics) ──
        // ── Home View (Direct2D Hardware-Accelerated) ──
    void render_home_view(float w, float h, UINT cur_dpi) {
        (void)h;
        const auto& ds = ds::DesignSystem::get();
        const auto& state = cached_engine_state_;
        const auto& profile = cached_engine_profile_;
        const auto& stats = cached_engine_stats_;

        bool is_connected = (state.kind == StateKind::Connected);
        bool is_connecting = (state.kind == StateKind::Connecting);
        bool is_disconnecting = (state.kind == StateKind::Disconnecting);
        bool is_error = (state.kind == StateKind::Error);

        float hero_cx = w / 2.0f;
        float hero_cy = static_cast<float>(scale(210, cur_dpi));
        float hero_base_diam = static_cast<float>(scale(ds.metrics.hero_diameter, cur_dpi));
        float hero_r = hero_base_diam / 2.0f;

        // ── 0. Ambient Background (Soft Radial Glow + 5 Concentric Rings) ──
        Color glow_color = is_connected ? ds.colors.gl_on :
                           (is_connecting ? ds.colors.gl_conn :
                           (is_error ? ds.colors.gl_err : ds.colors.gl_idle));
        float max_glow_r = static_cast<float>(scale(is_connected ? 340 : 300, cur_dpi));
        fill_radial_glow(hero_cx, hero_cy, max_glow_r, glow_color);

        bool is_dark = ds::is_effective_dark(ds.active_theme);
        Color ring_col = is_dark ? Color{ 255, 45, 45, 54 } : Color{ 255, 215, 215, 222 };
        const float ring_radii[] = { 125.0f, 180.0f, 245.0f, 320.0f, 405.0f };
        const float ring_opacities[] = { 0.70f, 0.50f, 0.35f, 0.22f, 0.12f };
        for (int i = 0; i < 5; ++i) {
            float r_dip = scale_f(ring_radii[i], cur_dpi);
            draw_ellipse(hero_cx, hero_cy, r_dip, ring_col, 1.0f, ring_opacities[i]);
        }

        // ── 1. Header (Brand title + breathing status dot + Logs & Settings buttons) ──
        float header_y = static_cast<float>(scale(ds.metrics.padding_top, cur_dpi));
        float pad_x = static_cast<float>(scale(ds.metrics.padding_x, cur_dpi));
        float dot_x = pad_x;
        float dot_y = header_y + scale_f(17, cur_dpi);
        float dot_d = static_cast<float>(scale(10, cur_dpi));

        float dot_alpha = 1.0f;
        if (is_connected) {
            float sine_wave = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 4.0f) - 1.57f);
            dot_alpha = std::clamp(0.55f + 0.45f * sine_wave, 0.55f, 1.0f);
        }

        Color dot_color = is_error ? ds.colors.error : ds.colors.accent;
        fill_ellipse(dot_x + dot_d / 2.0f, dot_y + dot_d / 2.0f, dot_d / 2.0f, ds::to_d2d_alpha(dot_color, dot_alpha));

        draw_text(L"Hemera", fmt_app_title_.Get(), dot_x + dot_d + scale_f(10, cur_dpi), header_y + scale_f(11, cur_dpi), ds.colors.text_primary);

        // Header Right Action Buttons: Logs & Settings
        float btn_sz = static_cast<float>(scale(ds.metrics.header_btn_size, cur_dpi));
        float btn_radius = static_cast<float>(scale(ds.metrics.radius_control, cur_dpi));
        float set_x = w - pad_x - btn_sz;
        float logs_x = set_x - btn_sz - scale_f(8, cur_dpi);

        // Logs terminal button
        Color logs_bg = logs_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Color logs_border = logs_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        fill_rounded_rect(logs_x, header_y, btn_sz, btn_sz, btn_radius, logs_bg);
        draw_rounded_rect(logs_x, header_y, btn_sz, btn_sz, btn_radius, logs_border, 1.0f);

        // Logs terminal icon (> _)
        Color log_icon_col = logs_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
        float lcx = logs_x + btn_sz / 2.0f;
        float lcy = header_y + btn_sz / 2.0f;
        D2D1_POINT_2F prompt_pts[3] = {
            D2D1::Point2F(lcx - scale_f(6, cur_dpi), lcy - scale_f(5, cur_dpi)),
            D2D1::Point2F(lcx - scale_f(1, cur_dpi), lcy),
            D2D1::Point2F(lcx - scale_f(6, cur_dpi), lcy + scale_f(5, cur_dpi))
        };
        draw_lines(prompt_pts, 3, log_icon_col, 1.6f, true);
        draw_line(lcx + scale_f(1, cur_dpi), lcy + scale_f(5, cur_dpi), lcx + scale_f(7, cur_dpi), lcy + scale_f(5, cur_dpi), log_icon_col, 1.6f, true);

        // Settings sliders button
        Color set_bg = settings_btn_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Color set_border = settings_btn_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        fill_rounded_rect(set_x, header_y, btn_sz, btn_sz, btn_radius, set_bg);
        draw_rounded_rect(set_x, header_y, btn_sz, btn_sz, btn_radius, set_border, 1.0f);

        // Settings sliders icon with smooth rotation on hover
        float scx = set_x + btn_sz / 2.0f;
        float scy = header_y + btn_sz / 2.0f;

        D2D1_MATRIX_3X2_F cur_mat;
        render_target_->GetTransform(&cur_mat);
        render_target_->SetTransform(D2D1::Matrix3x2F::Rotation(gear_rotation_, D2D1::Point2F(scx, scy)) * cur_mat);

        Color slider_col = settings_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
        draw_line(scx - scale_f(8, cur_dpi), scy - scale_f(4, cur_dpi), scx + scale_f(8, cur_dpi), scy - scale_f(4, cur_dpi), slider_col, 1.6f, true);
        fill_ellipse(scx - scale_f(2.8f, cur_dpi), scy - scale_f(4, cur_dpi), scale_f(2.2f, cur_dpi), ds.colors.bg);
        draw_ellipse(scx - scale_f(2.8f, cur_dpi), scy - scale_f(4, cur_dpi), scale_f(2.2f, cur_dpi), slider_col, 1.6f);

        draw_line(scx - scale_f(8, cur_dpi), scy + scale_f(4, cur_dpi), scx + scale_f(8, cur_dpi), scy + scale_f(4, cur_dpi), slider_col, 1.6f, true);
        fill_ellipse(scx + scale_f(2.7f, cur_dpi), scy + scale_f(4, cur_dpi), scale_f(2.2f, cur_dpi), ds.colors.bg);
        draw_ellipse(scx + scale_f(2.7f, cur_dpi), scy + scale_f(4, cur_dpi), scale_f(2.2f, cur_dpi), slider_col, 1.6f);

        render_target_->SetTransform(cur_mat);

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

        // Button scale with smooth breathing / pulsing
        float base_scale = hero_scale_;
        if (!is_connected && !is_connecting && !is_disconnecting && !is_error) {
            float breathe = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 4.0f));
            base_scale *= (1.0f + 0.012f * breathe);
        } else if (is_connecting || is_disconnecting) {
            float pulse = 0.5f + 0.5f * std::sin(anim_time_ * (2.0f * 3.14159f / 1.6f));
            base_scale *= (1.0f + 0.025f * pulse);
        }
        float scaled_r = hero_r * base_scale;

        // 2A. Halo & Animated Outer Waves
        if (is_connected) {
            // Double expanding radar ripple rings (Period 2.8s, Ring 2 offset by 1.4s)
            for (int r_i = 0; r_i < 2; ++r_i) {
                float offset = r_i * 1.4f;
                float t = std::fmod(anim_time_ + offset, 2.8f) / 2.8f;
                float pulse_r = scaled_r * (1.0f + 0.55f * t);
                float alpha = 0.45f * (1.0f - t);
                if (alpha > 0.01f) {
                    draw_ellipse(cur_hero_cx, hero_cy, pulse_r, ds.colors.accent, scale_f(1.5f, cur_dpi), alpha);
                }
            }
            // 60px soft radial glow behind the button
            fill_radial_glow(cur_hero_cx, hero_cy, scaled_r + scale_f(55.0f, cur_dpi), Color(55, 94, 234, 212));
            // 8px halo
            fill_ellipse(cur_hero_cx, hero_cy, scaled_r + scale_f(8.0f, cur_dpi), Color(25, 94, 234, 212));
        } else if (is_connecting || is_disconnecting) {
            // Connecting: Orbital spinning arc ring (Period 1.1s, sweep 78 deg)
            float orbit_r = scaled_r + scale_f(10.0f, cur_dpi);
            // Faint 360-deg guide track
            draw_ellipse(cur_hero_cx, hero_cy, orbit_r, ds.colors.accent, scale_f(1.5f, cur_dpi), 0.12f);
            // Spinning arc with round caps
            float spin_deg = std::fmod(anim_time_ * (360.0f / 1.1f), 360.0f);
            draw_arc(cur_hero_cx, hero_cy, orbit_r, spin_deg, 78.0f, ds.colors.accent, scale_f(2.0f, cur_dpi));
            // Subtle 8px halo
            fill_ellipse(cur_hero_cx, hero_cy, scaled_r + scale_f(8.0f, cur_dpi), Color(15, 94, 234, 212));
        } else if (is_error) {
            // Error glow
            fill_radial_glow(cur_hero_cx, hero_cy, scaled_r + scale_f(45.0f, cur_dpi), Color(45, 248, 113, 113));
            fill_ellipse(cur_hero_cx, hero_cy, scaled_r + scale_f(8.0f, cur_dpi), Color(20, 248, 113, 113));
        } else {
            // Idle 8px outer halo
            fill_ellipse(cur_hero_cx, hero_cy, scaled_r + scale_f(8.0f, cur_dpi), Color(6, 255, 255, 255));
        }

        // 2B. Button Disc
        Color btn_bg = is_connected ? ds.colors.btn_on_bg : ds.colors.btn_bg;
        fill_ellipse(cur_hero_cx, hero_cy, scaled_r, btn_bg);

        // 2C. Button Border
        Color btn_border = ds.colors.btn_border_dim;
        float border_thickness = scale_f(1.0f, cur_dpi);
        if (is_connected) {
            btn_border = ds.colors.accent;
            border_thickness = scale_f(1.5f, cur_dpi);
        } else if (is_connecting || is_disconnecting) {
            btn_border = ds.colors.btn_border;
            border_thickness = scale_f(1.0f, cur_dpi);
        } else if (is_error) {
            btn_border = ds.colors.error;
            border_thickness = scale_f(1.5f, cur_dpi);
        } else {
            btn_border = ds.colors.btn_border_dim;
            border_thickness = scale_f(1.0f, cur_dpi);
        }
        draw_ellipse(cur_hero_cx, hero_cy, scaled_r, btn_border, border_thickness);

        // 2D. Power Icon (ALWAYS the crisp power icon across all states!)
        Color pwr_col = ds.colors.text_muted;
        if (is_connected || is_connecting || is_disconnecting) {
            pwr_col = ds.colors.accent;
        } else if (is_error) {
            pwr_col = ds.colors.error;
        }

        float pwr_sz = scale_f(52.0f, cur_dpi) * hero_scale_;
        float s = pwr_sz / 24.0f;
        float pwr_stroke = scale_f(3.0f, cur_dpi) * hero_scale_;
        // Vertical stem from (12, 3) to (12, 11) in 24x24 box:
        draw_line(cur_hero_cx, hero_cy - 9.0f * s, cur_hero_cx, hero_cy - 1.0f * s, pwr_col, pwr_stroke, true);
        // Circular arc centered at hero_cy with radius 8.2 * s:
        draw_arc(cur_hero_cx, hero_cy, 8.2f * s, -40.0f, 260.0f, pwr_col, pwr_stroke);

        // ── 3. Status Label Block ──
        float status_y = hero_cy + hero_r + scale_f(28, cur_dpi);

        if (is_connected) {
            draw_text_center(L"Connected", fmt_hero_status_.Get(), cur_hero_cx, status_y, ds.colors.text_primary);
            uint64_t up_s = stats.uptime;
            std::wstring uptime_str = std::format(L"{:02d}:{:02d}:{:02d}", up_s / 3600, (up_s % 3600) / 60, up_s % 60);
            draw_text_center(uptime_str, fmt_mono_.Get(), cur_hero_cx, status_y + scale_f(32, cur_dpi), ds.colors.accent);
        } else if (is_connecting || is_disconnecting) {
            std::wstring conn_title = L"Connecting";
            if (!is_disconnecting) {
                float dot_c = std::fmod(anim_time_, 1.2f);
                if (dot_c < 0.4f) conn_title += L".";
                else if (dot_c < 0.8f) conn_title += L"..";
                else conn_title += L"...";
            } else {
                conn_title = L"Disconnecting…";
            }
            draw_text_center(conn_title, fmt_hero_status_.Get(), cur_hero_cx, status_y, ds.colors.text_primary);
            std::wstring sub_txt = is_disconnecting ? L"Stopping tunnel" : L"Finding the best route";
            draw_text_center(sub_txt, fmt_body_.Get(), cur_hero_cx, status_y + scale_f(32, cur_dpi), ds.colors.text_muted);
        } else if (is_error) {
            draw_text_center(L"Couldn't connect", fmt_hero_status_.Get(), cur_hero_cx, status_y, ds.colors.text_primary);
            std::wstring err_msg = state.error_message.empty() ? L"Endpoint timed out" : std::wstring(state.error_message.begin(), state.error_message.end());
            draw_text_center(err_msg, fmt_body_.Get(), cur_hero_cx, status_y + scale_f(32, cur_dpi), ds.colors.error);
        } else {
            draw_text_center(L"Not connected", fmt_hero_status_.Get(), cur_hero_cx, status_y, ds.colors.text_primary);
            draw_text_center(L"Tap the button to connect", fmt_body_.Get(), cur_hero_cx, status_y + scale_f(32, cur_dpi), ds.colors.text_muted);
        }

        // ── 4. Middle Section (Ping, Down, Up stats when connected) ──
        float middle_y = status_y + scale_f(64 + 18, cur_dpi);
        float card_x = pad_x;
        float card_w = w - pad_x * 2.0f;

        if (is_connected) {
            float col_w = card_w / 3.0f;
            auto draw_stat_col = [&](int idx, const std::wstring& tag, const std::wstring& val) {
                float cx = card_x + col_w * (idx + 0.5f);
                draw_text_center(tag, fmt_metric_tag_.Get(), cx, middle_y + scale_f(2, cur_dpi), ds.colors.text_submuted);
                draw_text_center(val, fmt_mono_.Get(), cx, middle_y + scale_f(18, cur_dpi), ds.colors.text_primary);
            };
            std::wstring ping_str = std::format(L"{} ms", live_ping_ms_);
            draw_stat_col(0, L"PING", ping_str);
            std::wstring down_str = std::format(L"{:.1f} MB/s", live_down_speed_mb_);
            draw_stat_col(1, L"DOWN", down_str);
            std::wstring up_str = std::format(L"{:.1f} MB/s", live_up_speed_mb_);
            draw_stat_col(2, L"UP", up_str);
        } else if (is_error) {
            float pill_h = static_cast<float>(scale(44, cur_dpi));
            float pill_r = static_cast<float>(scale(ds.metrics.radius_chip, cur_dpi));
            float pill_w = static_cast<float>(scale(110, cur_dpi));
            float gap = static_cast<float>(scale(10, cur_dpi));

            float btn1_x = cur_hero_cx - pill_w - gap / 2.0f;
            float btn2_x = cur_hero_cx + gap / 2.0f;
            float pill_y = middle_y + (scale_f(48, cur_dpi) - pill_h) / 2.0f;

            // "Try again" button
            Color try_bg = try_again_hovered_ ? ds.colors.hover_bg : ds.colors.chip_bg;
            Color try_bd = try_again_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
            fill_rounded_rect(btn1_x, pill_y, pill_w, pill_h, pill_r, try_bg);
            draw_rounded_rect(btn1_x, pill_y, pill_w, pill_h, pill_r, try_bd, 1.0f);
            draw_text_rect(L"Try again", fmt_body_bold_.Get(), btn1_x, pill_y, pill_w, pill_h, ds.colors.text_primary, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

            // "View logs" button
            Color vlg_bg = view_logs_chip_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
            Color vlg_bd = view_logs_chip_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border;
            fill_rounded_rect(btn2_x, pill_y, pill_w, pill_h, pill_r, vlg_bg);
            draw_rounded_rect(btn2_x, pill_y, pill_w, pill_h, pill_r, vlg_bd, 1.0f);
            Color vlg_txt = view_logs_chip_hovered_ ? ds.colors.text_primary : ds.colors.text_muted;
            draw_text_rect(L"View logs", fmt_body_bold_.Get(), btn2_x, pill_y, pill_w, pill_h, vlg_txt, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }

        // ── 5. Details Card ──
        float card_y = static_cast<float>(scale(470, cur_dpi));
        float row_h = static_cast<float>(scale(54, cur_dpi));
        float card_h = row_h * 3.0f;
        float card_r = static_cast<float>(scale(ds.metrics.radius_card, cur_dpi));

        fill_rounded_rect(card_x, card_y, card_w, card_h, card_r, ds.colors.card_bg);

        // Row hover highlights
        if (home_proto_hovered_) {
            fill_card_row_hover(card_x, card_y, card_w, row_h, card_r, 0, 3, ds.colors.dropdown_hover);
        }
        if (home_route_hovered_) {
            fill_card_row_hover(card_x, card_y + row_h, card_w, row_h, card_r, 1, 3, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, card_y, card_w, card_h, card_r, ds.colors.card_border, 1.0f);

        // Row Dividers
        draw_line(card_x, card_y + row_h, card_x + card_w, card_y + row_h, ds.colors.card_border, 1.0f);
        draw_line(card_x, card_y + row_h * 2.0f, card_x + card_w, card_y + row_h * 2.0f, ds.colors.card_border, 1.0f);

        float label_pad_x = static_cast<float>(scale(ds.metrics.row_padding_x, cur_dpi));
        float label_pad_y = (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;

        // Row 1: Protocol
        std::wstring proto_name = L"WARP-in-WARP / gool";
        switch (profile.protocol) {
            case Protocol::Auto: proto_name = L"Auto (Fastest)"; break;
            case Protocol::Gool: proto_name = L"WARP over MASQUE (gool)"; break;
            case Protocol::WarpInWarp: proto_name = L"WARP-in-WARP / gool"; break;
            case Protocol::Masque: proto_name = profile.masque_http2 ? L"MASQUE (HTTP/2)" : L"MASQUE (HTTP/3)"; break;
            case Protocol::Wireguard: proto_name = L"WireGuard"; break;
            case Protocol::Mim: proto_name = L"MiM"; break;
            default: break;
        }
        draw_text(L"Protocol", fmt_body_.Get(), card_x + label_pad_x, card_y + label_pad_y, ds.colors.text_muted);
        draw_text_right(proto_name, fmt_mono_.Get(), card_x + card_w - label_pad_x, card_y + label_pad_y, ds.colors.text_primary);

        // Row 2: Transport
        std::wstring transport_val = L"HTTP/2 · TLS mask";
        if (profile.protocol == Protocol::Wireguard) transport_val = L"UDP · Noise";
        else if (profile.protocol == Protocol::Mim) transport_val = L"TCP · TLS mask";
        else if (profile.protocol == Protocol::Masque && !profile.masque_http2) transport_val = L"QUIC / HTTP/3";
        else if (!profile.exit_loc.empty()) transport_val = std::wstring(profile.exit_loc.begin(), profile.exit_loc.end()) + L" · Balanced";
        draw_text(L"Transport", fmt_body_.Get(), card_x + label_pad_x, card_y + row_h + label_pad_y, ds.colors.text_muted);
        draw_text_right(transport_val, fmt_mono_.Get(), card_x + card_w - label_pad_x, card_y + row_h + label_pad_y, ds.colors.text_primary);

        // Row 3: SOCKS5 Address + Copy Button
        std::wstring socks_str = std::wstring(profile.bind_address.begin(), profile.bind_address.end());
        draw_text(L"SOCKS5", fmt_body_.Get(), card_x + label_pad_x, card_y + row_h * 2.0f + label_pad_y, ds.colors.text_muted);

        float copy_btn_sz = static_cast<float>(scale(44, cur_dpi));
        float copy_btn_x = card_x + card_w - label_pad_x - copy_btn_sz + scale_f(8, cur_dpi);
        float copy_btn_y = card_y + row_h * 2.0f + (row_h - copy_btn_sz) / 2.0f;

        draw_text_right(socks_str, fmt_mono_.Get(), copy_btn_x - scale_f(6, cur_dpi), card_y + row_h * 2.0f + label_pad_y, ds.colors.text_primary);

        if (copy_btn_hovered_) {
            fill_rounded_rect(copy_btn_x, copy_btn_y, copy_btn_sz, copy_btn_sz, static_cast<float>(scale(12, cur_dpi)), ds.colors.hover_bg);
        }

        float cp_cx = copy_btn_x + copy_btn_sz / 2.0f;
        float cp_cy = copy_btn_y + copy_btn_sz / 2.0f;

        if (copy_timer_ > 0.0f) {
            D2D1_POINT_2F chk_pts[3] = {
                D2D1::Point2F(cp_cx - scale_f(5, cur_dpi), cp_cy + scale_f(0.5f, cur_dpi)),
                D2D1::Point2F(cp_cx - scale_f(1, cur_dpi), cp_cy + scale_f(4.5f, cur_dpi)),
                D2D1::Point2F(cp_cx + scale_f(6, cur_dpi), cp_cy - scale_f(3.5f, cur_dpi))
            };
            draw_lines(chk_pts, 3, ds.colors.accent, 1.8f, true);
        } else {
            Color cp_col = copy_btn_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
            float sq = scale_f(10.0f, cur_dpi);
            float r_sub = scale_f(2.5f, cur_dpi);
            draw_rounded_rect(cp_cx - scale_f(3.0f, cur_dpi), cp_cy - scale_f(3.0f, cur_dpi), sq, sq, r_sub, cp_col, 1.4f);
            D2D1_POINT_2F bkg_pts[3] = {
                D2D1::Point2F(cp_cx + scale_f(2.5f, cur_dpi), cp_cy - scale_f(6.5f, cur_dpi)),
                D2D1::Point2F(cp_cx - scale_f(6.5f, cur_dpi), cp_cy - scale_f(6.5f, cur_dpi)),
                D2D1::Point2F(cp_cx - scale_f(6.5f, cur_dpi), cp_cy + scale_f(2.5f, cur_dpi))
            };
            draw_lines(bkg_pts, 3, cp_col, 1.4f, true);
        }

        // ── 6. Footer ──
        draw_text_center(L"Free and open source", fmt_footnote_.Get(), hero_cx, card_y + card_h + scale_f(20, cur_dpi), ds.colors.text_dim);
    }

    // ── Settings View (Direct2D Hardware-Accelerated) ──
    void render_settings_view(float w, float h, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "Settings" Title
        float back_btn_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
        float back_btn_y = static_cast<float>(scale(ds.metrics.padding_top, cur_dpi));
        float back_btn_size = static_cast<float>(scale(ds.metrics.header_btn_size, cur_dpi));

        draw_back_button(back_btn_x, back_btn_y, back_btn_size, cur_dpi);
        draw_text(L"Settings", fmt_view_title_.Get(), back_btn_x + back_btn_size + scale_f(8, cur_dpi), back_btn_y + scale_f(9, cur_dpi), ds.colors.text_primary);

        // 2. Scrollable Body with GPU Scissor & Translation Transform
        float clip_top = back_btn_y + back_btn_size + scale_f(12, cur_dpi);

        render_target_->PushAxisAlignedClip(D2D1::RectF(0.0f, clip_top, w, h), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);

        D2D1_MATRIX_3X2_F cur_mat;
        render_target_->GetTransform(&cur_mat);
        float sy = std::round(scale_f(scroll_anim_y_, cur_dpi));
        render_target_->SetTransform(D2D1::Matrix3x2F::Translation(0.0f, -sy) * cur_mat);

        float card_x = static_cast<float>(scale(ds.metrics.padding_x, cur_dpi));
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float row_h = static_cast<float>(scale(ds.metrics.row_height, cur_dpi));
        float pad_x = static_cast<float>(scale(ds.metrics.row_padding_x, cur_dpi));
        float radius_card = static_cast<float>(scale(ds.metrics.radius_card, cur_dpi));

        auto draw_animated_toggle = [&](float sw_x, float sw_y, int toggle_idx) {
            float anim = switch_anim_[toggle_idx];
            float sw_w = static_cast<float>(scale(40, cur_dpi));
            float sw_h = static_cast<float>(scale(24, cur_dpi));
            float sw_r = sw_h / 2.0f;

            Color track_col = blend_colors(ds.colors.btn_border_dim, ds.colors.accent, anim);
            fill_rounded_rect(sw_x, sw_y, sw_w, sw_h, sw_r, track_col);

            float margin = scale_f(3.0f, cur_dpi);
            float knob_d = scale_f(18.0f, cur_dpi);
            float knob_left = sw_x + margin + anim * (sw_w - margin * 2.0f - knob_d);
            float knob_top = sw_y + margin;

            Color knob_col = blend_colors(ds.colors.icon_color, ds.colors.bg, anim);
            fill_ellipse(knob_left + knob_d / 2.0f, knob_top + knob_d / 2.0f, knob_d / 2.0f, knob_col);
        };

        // ── Card 0: APPEARANCE ──
        float sec0_y = clip_top + scale_f(8, cur_dpi);
        draw_text(L"APPEARANCE", fmt_metric_tag_.Get(), card_x + scale_f(4, cur_dpi), sec0_y, ds.colors.text_submuted);

        float card0_y = sec0_y + scale_f(22, cur_dpi);
        float seg_box_h = static_cast<float>(scale(52, cur_dpi));
        fill_rounded_rect(card_x, card0_y, card_w, seg_box_h, radius_card, ds.colors.card_bg);
        draw_rounded_rect(card_x, card0_y, card_w, seg_box_h, radius_card, ds.colors.card_border, 1.0f);

        float seg_gap = scale_f(4, cur_dpi);
        float seg_w = (card_w - scale_f(8, cur_dpi) - seg_gap * 2.0f) / 3.0f;
        float seg_h = seg_box_h - scale_f(8, cur_dpi);
        float seg_y = card0_y + scale_f(4, cur_dpi);

        float sliding_pill_x = card_x + scale_f(4, cur_dpi) + seg_anim_x_ * (seg_w + seg_gap);
        fill_rounded_rect(sliding_pill_x, seg_y, seg_w, seg_h, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), ds.colors.chip_bg);
        draw_rounded_rect(sliding_pill_x, seg_y, seg_w, seg_h, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), ds.colors.border_hover_bright, 1.0f);

        const wchar_t* seg_labels[] = { L"System", L"Light", L"Dark" };
        const std::string seg_keys[] = { "system", "light", "dark" };

        for (int i = 0; i < 3; ++i) {
            float sx = card_x + scale_f(4, cur_dpi) + static_cast<float>(i) * (seg_w + seg_gap);
            bool is_active = (edit_settings_.theme == seg_keys[i]);
            draw_text_rect(seg_labels[i], fmt_body_.Get(), sx, seg_y, seg_w, seg_h, is_active ? ds.colors.text_primary : ds.colors.text_muted, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }

        // ── Card 1: GENERAL (5 Toggles) ──
        float sec1_y = card0_y + seg_box_h + scale_f(24, cur_dpi);
        draw_text(L"GENERAL", fmt_metric_tag_.Get(), card_x + scale_f(4, cur_dpi), sec1_y, ds.colors.text_submuted);

        float card1_y = sec1_y + scale_f(22, cur_dpi);
        float gen_row_h = static_cast<float>(scale(64, cur_dpi));
        float card1_h = gen_row_h * 5.0f;
        fill_rounded_rect(card_x, card1_y, card_w, card1_h, radius_card, ds.colors.card_bg);

        int card1_hover_idx = -1;
        if (hovered_settings_row_ >= 10 && hovered_settings_row_ <= 13) {
            card1_hover_idx = hovered_settings_row_ - 10;
        } else if (hovered_settings_row_ == 17) {
            card1_hover_idx = 4;
        }
        if (card1_hover_idx >= 0) {
            float hy = card1_y + static_cast<float>(card1_hover_idx) * gen_row_h;
            fill_card_row_hover(card_x, hy, card_w, gen_row_h, radius_card, card1_hover_idx, 5, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, card1_y, card_w, card1_h, radius_card, ds.colors.card_border, 1.0f);

        for (int i = 1; i < 5; ++i) {
            draw_line(card_x, card1_y + gen_row_h * static_cast<float>(i), card_x + card_w, card1_y + gen_row_h * static_cast<float>(i), ds.colors.card_border, 1.0f);
        }

        float sw_x = card_x + card_w - pad_x - scale_f(40, cur_dpi);

        // Row 0: Launch at login
        float gy0 = card1_y + scale_f(12, cur_dpi);
        draw_text(L"Launch at login", fmt_body_.Get(), card_x + pad_x, gy0, ds.colors.text_primary);
        draw_text(L"Start minimized on system boot", fmt_sub_label_.Get(), card_x + pad_x, gy0 + scale_f(20, cur_dpi), ds.colors.text_muted);
        draw_animated_toggle(sw_x, card1_y + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 0);

        // Row 1: Keep in system tray
        float gy1 = card1_y + gen_row_h + scale_f(12, cur_dpi);
        draw_text(L"Keep in system tray", fmt_body_.Get(), card_x + pad_x, gy1, ds.colors.text_primary);
        draw_text(L"Close button hides to notification area", fmt_sub_label_.Get(), card_x + pad_x, gy1 + scale_f(20, cur_dpi), ds.colors.text_muted);
        draw_animated_toggle(sw_x, card1_y + gen_row_h + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 1);

        // Row 2: Kill switch
        float gy2 = card1_y + gen_row_h * 2.0f + scale_f(12, cur_dpi);
        draw_text(L"Kill switch", fmt_body_.Get(), card_x + pad_x, gy2, ds.colors.text_primary);
        draw_text(L"Block all traffic if connection drops", fmt_sub_label_.Get(), card_x + pad_x, gy2 + scale_f(20, cur_dpi), ds.colors.text_muted);
        draw_animated_toggle(sw_x, card1_y + gen_row_h * 2.0f + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 2);

        // Row 3: Windows system proxy
        float gy3 = card1_y + gen_row_h * 3.0f + scale_f(12, cur_dpi);
        draw_text(L"System proxy", fmt_body_.Get(), card_x + pad_x, gy3, ds.colors.text_primary);
        draw_text(L"Route system Internet traffic through Hemera", fmt_sub_label_.Get(), card_x + pad_x, gy3 + scale_f(20, cur_dpi), ds.colors.text_muted);
        draw_animated_toggle(sw_x, card1_y + gen_row_h * 3.0f + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 3);

        // Row 4: Native TUN mode
        float gy4 = card1_y + gen_row_h * 4.0f + scale_f(12, cur_dpi);
        draw_text(L"TUN mode (Full System)", fmt_body_.Get(), card_x + pad_x, gy4, ds.colors.text_primary);
        draw_text(L"Route all system traffic via Wintun", fmt_sub_label_.Get(), card_x + pad_x, gy4 + scale_f(20, cur_dpi), ds.colors.text_muted);
        draw_animated_toggle(sw_x, card1_y + gen_row_h * 4.0f + (gen_row_h - scale_f(24, cur_dpi)) / 2.0f, 7);

        // ── Card 2: CONNECTION & ROUTING ──
        float sec2_y = card1_y + card1_h + scale_f(24, cur_dpi);
        draw_text(L"CONNECTION & ROUTING", fmt_metric_tag_.Get(), card_x + scale_f(4, cur_dpi), sec2_y, ds.colors.text_submuted);

        float card2_y = sec2_y + scale_f(22, cur_dpi);
        float card2_h = row_h * 5.0f;
        fill_rounded_rect(card_x, card2_y, card_w, card2_h, radius_card, ds.colors.card_bg);

        int card2_hover_idx = -1;
        if (hovered_settings_row_ >= 0 && hovered_settings_row_ < 4) {
            card2_hover_idx = hovered_settings_row_;
        } else if (hovered_settings_row_ == 16) {
            card2_hover_idx = 4;
        }
        if (card2_hover_idx >= 0) {
            float hy = card2_y + static_cast<float>(card2_hover_idx) * row_h;
            fill_card_row_hover(card_x, hy, card_w, row_h, radius_card, card2_hover_idx, 5, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, card2_y, card_w, card2_h, radius_card, ds.colors.card_border, 1.0f);

        for (int i = 1; i < 5; ++i) {
            draw_line(card_x, card2_y + row_h * static_cast<float>(i), card_x + card_w, card2_y + row_h * static_cast<float>(i), ds.colors.card_border, 1.0f);
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
        float row_y0 = card2_y + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Protocol", fmt_body_.Get(), card_x + pad_x, row_y0, ds.colors.text_muted);
        draw_text_right(proto_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, row_y0, ds.colors.text_primary);

        // Row 1: Scan mode
        std::wstring scan_lbl = L"Balanced (Recommended) ▾";
        switch (edit_profile_.scan_mode) {
            case ScanMode::Turbo: scan_lbl = L"Turbo (Fastest) ▾"; break;
            case ScanMode::Thorough: scan_lbl = L"Thorough ▾"; break;
            case ScanMode::Verified: scan_lbl = L"Verified (Stealth) ▾"; break;
            case ScanMode::Ironclad: scan_lbl = L"Ironclad ▾"; break;
            default: break;
        }
        float row_y1 = card2_y + row_h + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Scan mode", fmt_body_.Get(), card_x + pad_x, row_y1, ds.colors.text_muted);
        draw_text_right(scan_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, row_y1, ds.colors.text_primary);

        // Row 2: Exit location
        std::wstring exit_lbl = edit_profile_.exit_loc.empty() ? L"Auto (Fastest) ▾" : (std::wstring(edit_profile_.exit_loc.begin(), edit_profile_.exit_loc.end()) + L" ▾");
        float row_y2 = card2_y + row_h * 2.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Exit location", fmt_body_.Get(), card_x + pad_x, row_y2, ds.colors.text_muted);
        draw_text_right(exit_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, row_y2, ds.colors.text_primary);

        // Row 3: IP version
        std::wstring ip_lbl = (edit_profile_.ip_version == IpVersion::V6) ? L"IPv6 ▾" : (edit_profile_.ip_version == IpVersion::Both ? L"Dual ▾" : L"IPv4 ▾");
        float row_y3 = card2_y + row_h * 3.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"IP version", fmt_body_.Get(), card_x + pad_x, row_y3, ds.colors.text_muted);
        draw_text_right(ip_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, row_y3, ds.colors.text_primary);

        // Row 4: Bypass local traffic
        float row_y4 = card2_y + row_h * 4.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Bypass local traffic", fmt_body_.Get(), card_x + pad_x, row_y4, ds.colors.text_primary);
        draw_animated_toggle(sw_x, card2_y + row_h * 4.0f + (row_h - scale_f(24, cur_dpi)) / 2.0f, 6);

        // ── Card 3: ANTI-CENSORSHIP & NETWORK ──
        float sec3_y = card2_y + card2_h + scale_f(24, cur_dpi);
        draw_text(L"ANTI-CENSORSHIP & NETWORK", fmt_metric_tag_.Get(), card_x + scale_f(4, cur_dpi), sec3_y, ds.colors.text_submuted);

        float card3_y = sec3_y + scale_f(22, cur_dpi);
        float card3_h = row_h * 5.0f;
        fill_rounded_rect(card_x, card3_y, card_w, card3_h, radius_card, ds.colors.card_bg);

        int card3_hover_idx = -1;
        if (hovered_settings_row_ == 14) card3_hover_idx = 0;
        else if (hovered_settings_row_ == 15) card3_hover_idx = 1;
        else if (hovered_settings_row_ >= 4 && hovered_settings_row_ <= 6) card3_hover_idx = hovered_settings_row_ - 2;

        if (card3_hover_idx >= 0) {
            float hy = card3_y + static_cast<float>(card3_hover_idx) * row_h;
            fill_card_row_hover(card_x, hy, card_w, row_h, radius_card, card3_hover_idx, 5, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, card3_y, card_w, card3_h, radius_card, ds.colors.card_border, 1.0f);

        for (int i = 1; i < 5; ++i) {
            draw_line(card_x, card3_y + row_h * static_cast<float>(i), card_x + card_w, card3_y + row_h * static_cast<float>(i), ds.colors.card_border, 1.0f);
        }

        // Row 0: TLS fragmentation
        float r3_y0 = card3_y + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"TLS fragmentation", fmt_body_.Get(), card_x + pad_x, r3_y0, ds.colors.text_primary);
        draw_animated_toggle(sw_x, card3_y + (row_h - scale_f(24, cur_dpi)) / 2.0f, 4);

        // Row 1: ECH
        float r3_y1 = card3_y + row_h + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Encrypted Client Hello (ECH)", fmt_body_.Get(), card_x + pad_x, r3_y1, ds.colors.text_primary);
        draw_animated_toggle(sw_x, card3_y + row_h + (row_h - scale_f(24, cur_dpi)) / 2.0f, 5);

        // Row 2: Obfuscation
        std::wstring noize_lbl = L"Balanced ▾";
        switch (edit_profile_.masque_noize) {
            case MasqueNoize::Gfw: noize_lbl = L"Aggressive ▾"; break;
            case MasqueNoize::Off: noize_lbl = L"Off ▾"; break;
            default: break;
        }
        float r3_y2 = card3_y + row_h * 2.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"Obfuscation", fmt_body_.Get(), card_x + pad_x, r3_y2, ds.colors.text_muted);
        draw_text_right(noize_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, r3_y2, ds.colors.text_primary);

        // Row 3: DNS server
        std::wstring dns_lbl = L"Auto (1.1.1.1) ▾";
        if (edit_profile_.dns == "1.1.1.2") dns_lbl = L"Security (1.1.1.2) ▾";
        else if (edit_profile_.dns == "8.8.8.8") dns_lbl = L"Google (8.8.8.8) ▾";
        else if (edit_profile_.dns == "9.9.9.9") dns_lbl = L"Quad9 (9.9.9.9) ▾";
        else if (!edit_profile_.dns.empty()) dns_lbl = std::wstring(edit_profile_.dns.begin(), edit_profile_.dns.end()) + L" ▾";
        float r3_y3 = card3_y + row_h * 3.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"DNS server", fmt_body_.Get(), card_x + pad_x, r3_y3, ds.colors.text_muted);
        draw_text_right(dns_lbl, fmt_mono_.Get(), card_x + card_w - pad_x, r3_y3, ds.colors.text_primary);

        // Row 4: SOCKS5 proxy
        float r3_y4 = card3_y + row_h * 4.0f + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"SOCKS5 proxy", fmt_body_.Get(), card_x + pad_x, r3_y4, ds.colors.text_muted);
        std::wstring socks_display = socks_edit_buffer_.empty() ? L"127.0.0.1:1819" : socks_edit_buffer_;
        if (is_editing_socks_) {
            bool show_caret = (std::fmod(caret_blink_timer_, 1.0f) < 0.5f);
            socks_display += show_caret ? L"|" : L" ";
            draw_text_right(socks_display, fmt_mono_.Get(), card_x + card_w - pad_x, r3_y4, ds.colors.accent);
        } else {
            draw_text_right(socks_display, fmt_mono_.Get(), card_x + card_w - pad_x, r3_y4, ds.colors.text_primary);
        }

        // ── Card 4: ABOUT Row ──
        float sec4_y = card3_y + card3_h + scale_f(24, cur_dpi);
        fill_rounded_rect(card_x, sec4_y, card_w, row_h, radius_card, ds.colors.card_bg);

        if (hovered_settings_row_ == 20) {
            fill_card_row_hover(card_x, sec4_y, card_w, row_h, radius_card, 0, 1, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, sec4_y, card_w, row_h, radius_card, ds.colors.card_border, 1.0f);

        float about_y = sec4_y + (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;
        draw_text(L"About Hemera", fmt_body_.Get(), card_x + pad_x, about_y, ds.colors.text_primary);
        std::wstring about_sub = L"v1.0.3   ›";
        draw_text_right(about_sub, fmt_mono_.Get(), card_x + card_w - pad_x, about_y, ds.colors.text_muted);

        // Footer
        draw_text_center(L"Hemera · Free and open source proxy", fmt_footnote_.Get(), w / 2.0f, sec4_y + row_h + scale_f(24, cur_dpi), ds.colors.text_dim);

        // Dynamic scroll bounds (stops right after footer with a neat 20px bottom padding, zero dead space)
        float dpi_scale = static_cast<float>(cur_dpi) / 96.0f;
        float content_bottom = sec4_y + row_h + scale_f(24.0f + 14.0f + 20.0f, cur_dpi);
        if (content_bottom > h) {
            max_scroll_ = static_cast<int>(std::ceil((content_bottom - h) / dpi_scale));
        } else {
            max_scroll_ = 0;
        }

        if (target_scroll_y_ > static_cast<float>(max_scroll_)) {
            target_scroll_y_ = static_cast<float>(max_scroll_);
        }
        if (scroll_anim_y_ > static_cast<float>(max_scroll_)) {
            scroll_anim_y_ = static_cast<float>(max_scroll_);
        }

        // Pop clip and restore transform
        render_target_->SetTransform(cur_mat);
        render_target_->PopAxisAlignedClip();

        // 3. Sleek Interactive Scrollbar
        if (max_scroll_ > 0) {
            float sb_track_top = clip_top + scale_f(2.0f, cur_dpi);
            float sb_track_bottom = h - scale_f(12.0f, cur_dpi);
            float sb_track_h = sb_track_bottom - sb_track_top;

            if (sb_track_h > scale_f(40.0f, cur_dpi)) {
                float total_content_h = content_bottom - clip_top;
                float visible_h = h - clip_top;
                float thumb_ratio = std::clamp(visible_h / total_content_h, 0.12f, 0.85f);
                float thumb_h = std::max(scale_f(36.0f, cur_dpi), sb_track_h * thumb_ratio);

                float scroll_ratio = std::clamp(scroll_anim_y_ / static_cast<float>(max_scroll_), 0.0f, 1.0f);
                float thumb_y = sb_track_top + scroll_ratio * (sb_track_h - thumb_h);

                float sb_w = (scrollbar_hovered_ || scrollbar_dragging_) ? scale_f(6.0f, cur_dpi) : scale_f(3.5f, cur_dpi);
                float sb_x = w - scale_f(8.0f, cur_dpi) - (sb_w - scale_f(3.5f, cur_dpi)) / 2.0f;
                float sb_radius = sb_w / 2.0f;

                if (scrollbar_hovered_ || scrollbar_dragging_) {
                    fill_rounded_rect(sb_x - scale_f(2.0f, cur_dpi), sb_track_top, sb_w + scale_f(4.0f, cur_dpi), sb_track_h, sb_radius + 1.0f, ds::to_d2d_alpha(ds.colors.card_border, 0.1f));
                }

                Color thumb_col = scrollbar_dragging_ ? ds.colors.accent : (scrollbar_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border_dim);
                fill_rounded_rect(sb_x, thumb_y, sb_w, thumb_h, sb_radius, thumb_col);

                settings_sb_thumb_rect_ = RECT{
                    static_cast<LONG>(w - scale_f(18.0f, cur_dpi)),
                    static_cast<LONG>(thumb_y),
                    static_cast<LONG>(w),
                    static_cast<LONG>(thumb_y + thumb_h)
                };
                settings_sb_track_rect_ = RECT{
                    static_cast<LONG>(w - scale_f(18.0f, cur_dpi)),
                    static_cast<LONG>(sb_track_top),
                    static_cast<LONG>(w),
                    static_cast<LONG>(sb_track_bottom)
                };
            }
        } else {
            settings_sb_thumb_rect_ = RECT{};
            settings_sb_track_rect_ = RECT{};
        }

        // 4. Dropdown Overlay
        if (active_dropdown_ >= 0 && !dropdown_options_.empty()) {
            render_dropdown_overlay(w, h, cur_dpi);
        }
    }

    // ── Floating Custom In-Window Dropdown Card (Direct2D) ──
    void render_dropdown_overlay(float w, float /*h*/, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();
        float card_x = static_cast<float>(scale(ds.metrics.padding_x, cur_dpi));
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float row_h = static_cast<float>(scale(ds.metrics.row_height, cur_dpi));

        float clip_top = static_cast<float>(scale(ds.metrics.padding_top, cur_dpi)) + static_cast<float>(scale(ds.metrics.header_btn_size, cur_dpi)) + scale_f(12, cur_dpi);
        float sec0_y = clip_top + scale_f(8, cur_dpi);
        float card0_y = sec0_y + scale_f(22, cur_dpi);
        float seg_box_h = static_cast<float>(scale(52, cur_dpi));

        float sec1_y = card0_y + seg_box_h + scale_f(24, cur_dpi);
        float card1_y = sec1_y + scale_f(22, cur_dpi);
        float gen_row_h = static_cast<float>(scale(64, cur_dpi));
        float card1_h = gen_row_h * 5.0f;

        float sec2_y = card1_y + card1_h + scale_f(24, cur_dpi);
        float card2_y = sec2_y + scale_f(22, cur_dpi);
        float card2_h = row_h * 5.0f;

        float sec3_y = card2_y + card2_h + scale_f(24, cur_dpi);
        float card3_y = sec3_y + scale_f(22, cur_dpi);

        float sy = std::round(scale_f(scroll_anim_y_, cur_dpi));
        float anchor_y = card2_y - sy;
        if (active_dropdown_ >= 0 && active_dropdown_ < 4) {
            anchor_y = card2_y + static_cast<float>(active_dropdown_) * row_h - sy;
        } else if (active_dropdown_ == 4) {
            anchor_y = card3_y + 2.0f * row_h - sy;
        } else if (active_dropdown_ == 5) {
            anchor_y = card3_y + 3.0f * row_h - sy;
        }

        float item_h = static_cast<float>(scale(ds.metrics.dropdown_item_h, cur_dpi));
        float pop_w = static_cast<float>(scale(260, cur_dpi));
        float pop_h = item_h * static_cast<float>(dropdown_options_.size());
        float pop_x = card_x + card_w - pop_w;
        float pop_y = anchor_y + row_h + scale_f(4, cur_dpi);

        if (pop_y + pop_h > static_cast<float>(scale(660, cur_dpi))) {
            pop_y = anchor_y - pop_h - scale_f(4, cur_dpi);
        }

        dropdown_popup_rect_ = {
            static_cast<LONG>(pop_x),
            static_cast<LONG>(pop_y),
            static_cast<LONG>(pop_x + pop_w),
            static_cast<LONG>(pop_y + pop_h)
        };

        float drop_r = static_cast<float>(scale(ds.metrics.dropdown_radius, cur_dpi));
        fill_rounded_rect(pop_x, pop_y, pop_w, pop_h, drop_r, ds.colors.dropdown_bg);
        draw_rounded_rect(pop_x, pop_y, pop_w, pop_h, drop_r, ds.colors.dropdown_border, 1.0f);

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
                fill_rounded_rect(pop_x + 2.0f, iy + 2.0f, pop_w - 4.0f, item_h - 4.0f, static_cast<float>(scale(8, cur_dpi)), ds.colors.dropdown_hover);
            }

            bool selected = is_option_selected(dropdown_options_[i].id);
            float text_y = iy + (item_h - scale_f(static_cast<float>(ds.typo.body_label), cur_dpi)) / 2.0f;
            if (selected) {
                draw_text(L"✓", fmt_body_.Get(), pop_x + scale_f(12, cur_dpi), text_y, ds.colors.accent);
            }

            draw_text(dropdown_options_[i].label, fmt_body_.Get(),
                      pop_x + scale_f(32, cur_dpi), text_y,
                      selected ? ds.colors.accent : ds.colors.text_primary);
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

    // ── Logs View (Direct2D Hardware-Accelerated) ──
    void render_logs_view(float w, float h, UINT cur_dpi) {
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "Logs" Title + Copy Button + Clear Button
        float back_btn_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
        float back_btn_y = static_cast<float>(scale(ds.metrics.padding_top, cur_dpi));
        float back_btn_size = static_cast<float>(scale(ds.metrics.header_btn_size, cur_dpi));

        draw_back_button(back_btn_x, back_btn_y, back_btn_size, cur_dpi);
        draw_text(L"Logs", fmt_view_title_.Get(), back_btn_x + back_btn_size + scale_f(8, cur_dpi), back_btn_y + scale_f(9, cur_dpi), ds.colors.text_primary);

        // Header Right Action Buttons: Copy & Trash/Clear
        float btn_sz = back_btn_size;
        float card_x = static_cast<float>(scale(ds.metrics.padding_x, cur_dpi));
        float clr_x = w - card_x - btn_sz;
        float cp_x = clr_x - btn_sz - scale_f(8, cur_dpi);

        // 1a. Copy Logs Button
        Color cp_bg = copy_logs_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Color cp_bd = copy_logs_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        fill_rounded_rect(cp_x, back_btn_y, btn_sz, btn_sz, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), cp_bg);
        draw_rounded_rect(cp_x, back_btn_y, btn_sz, btn_sz, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), cp_bd, 1.0f);

        float cpcx = cp_x + btn_sz / 2.0f;
        float cpcy = back_btn_y + btn_sz / 2.0f;

        if (logs_copied_) {
            D2D1_POINT_2F chk_pts[3] = {
                D2D1::Point2F(cpcx - scale_f(5, cur_dpi), cpcy + scale_f(0.5f, cur_dpi)),
                D2D1::Point2F(cpcx - scale_f(1, cur_dpi), cpcy + scale_f(4.5f, cur_dpi)),
                D2D1::Point2F(cpcx + scale_f(6, cur_dpi), cpcy - scale_f(3.5f, cur_dpi))
            };
            draw_lines(chk_pts, 3, ds.colors.accent, 1.8f, true);
        } else {
            Color cp_ic = copy_logs_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
            draw_rounded_rect(cpcx - scale_f(4, cur_dpi), cpcy - scale_f(4, cur_dpi), scale_f(9, cur_dpi), scale_f(9, cur_dpi), scale_f(2, cur_dpi), cp_ic, 1.6f);
            D2D1_POINT_2F bk_pts[3] = {
                D2D1::Point2F(cpcx + scale_f(3, cur_dpi), cpcy - scale_f(6, cur_dpi)),
                D2D1::Point2F(cpcx - scale_f(6, cur_dpi), cpcy - scale_f(6, cur_dpi)),
                D2D1::Point2F(cpcx - scale_f(6, cur_dpi), cpcy + scale_f(3, cur_dpi))
            };
            draw_lines(bk_pts, 3, cp_ic, 1.6f, true);
        }

        // 1b. Trash / Clear Logs Button
        Color clr_bg = clear_logs_hovered_ ? ds.colors.hover_bg : ds.colors.bg;
        Color clr_bd = clear_logs_hovered_ ? ds.colors.border_hover : ds.colors.btn_border;
        fill_rounded_rect(clr_x, back_btn_y, btn_sz, btn_sz, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), clr_bg);
        draw_rounded_rect(clr_x, back_btn_y, btn_sz, btn_sz, static_cast<float>(scale(ds.metrics.radius_control, cur_dpi)), clr_bd, 1.0f);

        float clrcx = clr_x + btn_sz / 2.0f;
        float clrcy = back_btn_y + btn_sz / 2.0f;
        Color tr_col = clear_logs_hovered_ ? ds.colors.text_primary : ds.colors.icon_color;
        draw_line(clrcx - scale_f(6, cur_dpi), clrcy - scale_f(3, cur_dpi), clrcx + scale_f(6, cur_dpi), clrcy - scale_f(3, cur_dpi), tr_col, 1.6f, true);
        draw_line(clrcx - scale_f(2, cur_dpi), clrcy - scale_f(5.5f, cur_dpi), clrcx + scale_f(2, cur_dpi), clrcy - scale_f(5.5f, cur_dpi), tr_col, 1.6f, true);
        D2D1_POINT_2F can_pts[4] = {
            D2D1::Point2F(clrcx - scale_f(4.5f, cur_dpi), clrcy - scale_f(3, cur_dpi)),
            D2D1::Point2F(clrcx - scale_f(4.0f, cur_dpi), clrcy + scale_f(5.5f, cur_dpi)),
            D2D1::Point2F(clrcx + scale_f(4.0f, cur_dpi), clrcy + scale_f(5.5f, cur_dpi)),
            D2D1::Point2F(clrcx + scale_f(4.5f, cur_dpi), clrcy - scale_f(3, cur_dpi))
        };
        draw_lines(can_pts, 4, tr_col, 1.6f, true);

        // 2. Filter Chips Row
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float chips_y = back_btn_y + btn_sz + scale_f(12, cur_dpi);
        float chip_h = scale_f(36, cur_dpi);
        float chip_r = chip_h / 2.0f;
        float chip_gap = scale_f(8, cur_dpi);
        float chip_w = (card_w - chip_gap * 3.0f) / 4.0f;

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

        for (int i = 0; i < 4; ++i) {
            float ch_x = card_x + static_cast<float>(i) * (chip_w + chip_gap);
            bool is_active = (log_filter_ == i);
            bool is_hov = (hovered_log_chip_ == i);

            if (is_active) {
                fill_rounded_rect(ch_x, chips_y, chip_w, chip_h, chip_r, ds.colors.chip_bg);
                draw_rounded_rect(ch_x, chips_y, chip_w, chip_h, chip_r, ds.colors.border_hover_bright, 1.0f);
            } else if (is_hov) {
                fill_rounded_rect(ch_x, chips_y, chip_w, chip_h, chip_r, ds.colors.hover_bg);
                draw_rounded_rect(ch_x, chips_y, chip_w, chip_h, chip_r, ds.colors.border_hover, 1.0f);
            } else {
                draw_rounded_rect(ch_x, chips_y, chip_w, chip_h, chip_r, ds.colors.btn_border, 1.0f);
            }

            std::wstring chip_txt = std::wstring(chip_names[i]) + L" " + std::to_wstring(chip_counts[i]);
            Color c_tx = (is_active || is_hov) ? ds.colors.text_primary : ds.colors.text_muted;
            draw_text_rect(chip_txt, fmt_body_.Get(), ch_x, chips_y, chip_w, chip_h, c_tx, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }

        // 3. Terminal Log Card
        float term_y = chips_y + chip_h + scale_f(12, cur_dpi);
        float res_card_h = static_cast<float>(scale(72, cur_dpi));
        float term_h = h - term_y - res_card_h - scale_f(24, cur_dpi);
        float term_r = static_cast<float>(scale(ds.metrics.radius_card, cur_dpi));

        fill_rounded_rect(card_x, term_y, card_w, term_h, term_r, ds.colors.card_bg);
        draw_rounded_rect(card_x, term_y, card_w, term_h, term_r, ds.colors.card_border, 1.0f);

        std::vector<const LogEntry*> visible_logs;
        visible_logs.reserve(logs_copy.size());
        for (const auto& item : logs_copy) {
            if (log_filter_ == 0 || static_cast<int>(item.level) == log_filter_) {
                visible_logs.push_back(&item);
            }
        }

        render_target_->PushAxisAlignedClip(D2D1::RectF(card_x + 8.0f, term_y + 8.0f, card_x + card_w - 8.0f, term_y + term_h - 8.0f), D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);

        if (visible_logs.empty()) {
            draw_text_rect(L"No log entries", fmt_body_.Get(), card_x, term_y, card_w, term_h, ds.colors.text_dim, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        } else {
            float cur_y = term_y + scale_f(10, cur_dpi) - std::round(scale_f(logs_scroll_anim_y_, cur_dpi));
            float row_x = card_x + scale_f(14, cur_dpi);
            float time_w = scale_f(66, cur_dpi);
            float tag_w = scale_f(44, cur_dpi);
            float msg_x = row_x + time_w + tag_w;
            float right_margin = scale_f(14, cur_dpi);
            float msg_w = std::max(scale_f(80, cur_dpi), (card_x + card_w - right_margin) - msg_x);
            float min_row_h = scale_f(22, cur_dpi);
            float total_content_h = scale_f(10, cur_dpi);

            for (const auto* item : visible_logs) {
                float text_measured_h = measure_text_height(item->message, fmt_mono_wrap_.Get(), msg_w);
                float item_h = std::max(min_row_h, text_measured_h + scale_f(4, cur_dpi));

                if (cur_y + item_h >= term_y && cur_y <= term_y + term_h) {
                    // 1. Time
                    draw_text(item->time_str, fmt_mono_.Get(), row_x, cur_y, ds.colors.text_dim);

                    // 2. Tag
                    Color tag_col = ds.colors.info;
                    if (item->level == LogFilter::Warn) tag_col = ds.colors.warning;
                    else if (item->level == LogFilter::Error) tag_col = ds.colors.error;
                    draw_text(item->tag, fmt_mono_bold_.Get(), row_x + time_w, cur_y, tag_col);

                    // 3. Multiline wrapped message
                    Color msg_col = ds.colors.text_secondary;
                    if (item->level == LogFilter::Error) msg_col = ds.colors.error;
                    else if (item->level == LogFilter::Warn) msg_col = ds.colors.warning;
                    draw_text_rect(item->message, fmt_mono_wrap_.Get(), msg_x, cur_y, msg_w, item_h, msg_col);
                }

                cur_y += item_h;
                total_content_h += item_h;
            }

            total_content_h += scale_f(10, cur_dpi);
            float visible_h = term_h;
            max_logs_scroll_ = std::max(0.0f, (total_content_h - visible_h) / (cur_dpi / 96.0f));
        }

        render_target_->PopAxisAlignedClip();

        // 4. Bottom Resource Card (CPU% & RAM MB with Sparklines)
        float res_y = term_y + term_h + scale_f(12, cur_dpi);
        fill_rounded_rect(card_x, res_y, card_w, res_card_h, term_r, ds.colors.card_bg);
        draw_rounded_rect(card_x, res_y, card_w, res_card_h, term_r, ds.colors.card_border, 1.0f);

        float mid_x = card_x + card_w / 2.0f;
        draw_line(mid_x, res_y, mid_x, res_y + res_card_h, ds.colors.card_border, 1.0f);

        float col_w = card_w / 2.0f;
        float pad = scale_f(14, cur_dpi);

        // CPU
        float c1_x = card_x + pad;
        float c1_top_y = res_y + scale_f(10, cur_dpi);
        draw_text(L"CPU", fmt_metric_tag_.Get(), c1_x, c1_top_y, ds.colors.text_muted);
        std::wstring cpu_str = std::format(L"{:.1f} %", sys_metrics_.cpu_percent);
        draw_text_right(cpu_str, fmt_mono_bold_.Get(), mid_x - pad, c1_top_y - scale_f(2, cur_dpi), ds.colors.text_primary);

        float spark_w = col_w - pad * 2.0f;
        float spark_h = scale_f(26, cur_dpi);
        float spark_y = res_y + res_card_h - spark_h - scale_f(8, cur_dpi);

        if (cpu_history_.size() >= 2) {
            std::vector<D2D1_POINT_2F> pts;
            pts.reserve(cpu_history_.size());
            float max_cpu = 10.0f;
            for (float v : cpu_history_) if (v > max_cpu) max_cpu = v;

            for (size_t i = 0; i < cpu_history_.size(); ++i) {
                float px = c1_x + static_cast<float>(i) * (spark_w / static_cast<float>(cpu_history_.size() - 1));
                float norm = std::clamp(cpu_history_[i] / max_cpu, 0.0f, 1.0f);
                float py = spark_y + spark_h - norm * spark_h;
                pts.push_back(D2D1::Point2F(px, py));
            }
            draw_lines(pts.data(), static_cast<UINT32>(pts.size()), ds.colors.accent, 1.5f, true);
        }

        // RAM
        float c2_x = mid_x + pad;
        draw_text(L"RAM", fmt_metric_tag_.Get(), c2_x, c1_top_y, ds.colors.text_muted);
        std::wstring ram_str = std::format(L"{:.1f} MB", sys_metrics_.ram_mb);
        draw_text_right(ram_str, fmt_mono_bold_.Get(), card_x + card_w - pad, c1_top_y - scale_f(2, cur_dpi), ds.colors.text_primary);

        if (ram_history_.size() >= 2) {
            std::vector<D2D1_POINT_2F> pts;
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
                pts.push_back(D2D1::Point2F(px, py));
            }
            draw_lines(pts.data(), static_cast<UINT32>(pts.size()), ds.colors.accent_ram, 1.5f, true);
        }
    }

    // ── About View (Direct2D Hardware-Accelerated) ──
    void render_about_view(float w, float h, UINT cur_dpi) {
        (void)h;
        const auto& ds = ds::DesignSystem::get();

        // 1. Pinned Header: Back Button + "About" Title
        float back_btn_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
        float back_btn_y = static_cast<float>(scale(ds.metrics.padding_top, cur_dpi));
        float back_btn_size = static_cast<float>(scale(ds.metrics.header_btn_size, cur_dpi));

        draw_back_button(back_btn_x, back_btn_y, back_btn_size, cur_dpi);
        draw_text(L"About", fmt_view_title_.Get(), back_btn_x + back_btn_size + scale_f(8, cur_dpi), back_btn_y + scale_f(9, cur_dpi), ds.colors.text_primary);

        // 2. Logo Icon
        float cx = w / 2.0f;
        float logo_y = back_btn_y + back_btn_size + scale_f(28, cur_dpi);
        float draw_h = scale_f(72, cur_dpi);
        float draw_w = draw_h;

        if (logo_d2d_bitmap_) {
            D2D1_SIZE_F sz = logo_d2d_bitmap_->GetSize();
            if (sz.height > 0.0f) {
                draw_w = draw_h * (sz.width / sz.height);
            }
            render_target_->DrawBitmap(logo_d2d_bitmap_.Get(), D2D1::RectF(cx - draw_w / 2.0f, logo_y, cx + draw_w / 2.0f, logo_y + draw_h));
        } else {
            float dot_sz = scale_f(24, cur_dpi);
            fill_ellipse(cx, logo_y + draw_h / 2.0f, dot_sz / 2.0f, ds.colors.accent);
        }

        // App Name & Version
        float name_y = logo_y + draw_h + scale_f(14, cur_dpi);
        draw_text_center(L"Hemera", fmt_hero_status_.Get(), cx, name_y, ds.colors.text_primary);

        float ver_y = name_y + scale_f(34, cur_dpi);
        draw_text_center(L"Version 1.0.3", fmt_mono_.Get(), cx, ver_y, ds.colors.text_muted);

        // Subtitle text
        float desc_y = ver_y + scale_f(22, cur_dpi);
        draw_text_center(L"Native high-performance circumvention for Windows.", fmt_body_.Get(), cx, desc_y, ds.colors.text_muted);
        draw_text_center(L"Free, open source, no account needed.", fmt_footnote_.Get(), cx, desc_y + scale_f(18, cur_dpi), ds.colors.text_dim);

        // 3. Links Card (Source Code, Issues, Releases, License)
        float card_x = static_cast<float>(scale(ds.metrics.padding_x, cur_dpi));
        float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
        float card_y = desc_y + scale_f(48, cur_dpi);
        about_card_y_ = card_y;
        float row_h = static_cast<float>(scale(ds.metrics.row_height, cur_dpi));
        float card_r = static_cast<float>(scale(ds.metrics.radius_card, cur_dpi));

        fill_rounded_rect(card_x, card_y, card_w, row_h * 4.0f, card_r, ds.colors.card_bg);

        if (about_src_hovered_) {
            fill_card_row_hover(card_x, card_y, card_w, row_h, card_r, 0, 4, ds.colors.dropdown_hover);
        }
        if (about_issue_hovered_) {
            fill_card_row_hover(card_x, card_y + row_h, card_w, row_h, card_r, 1, 4, ds.colors.dropdown_hover);
        }
        if (about_releases_hovered_) {
            fill_card_row_hover(card_x, card_y + row_h * 2.0f, card_w, row_h, card_r, 2, 4, ds.colors.dropdown_hover);
        }
        if (about_license_hovered_) {
            fill_card_row_hover(card_x, card_y + row_h * 3.0f, card_w, row_h, card_r, 3, 4, ds.colors.dropdown_hover);
        }

        draw_rounded_rect(card_x, card_y, card_w, row_h * 4.0f, card_r, ds.colors.card_border, 1.0f);

        for (int i = 1; i < 4; ++i) {
            draw_line(card_x, card_y + row_h * static_cast<float>(i), card_x + card_w, card_y + row_h * static_cast<float>(i), ds.colors.card_border, 1.0f);
        }

        float pad_x = static_cast<float>(scale(ds.metrics.row_padding_x, cur_dpi));
        float text_mid_offset = (row_h - static_cast<float>(scale(ds.typo.body_label, cur_dpi))) / 2.0f;

        // Row 0: GitHub Repository
        float ry0 = card_y + text_mid_offset;
        draw_text(L"GitHub Repository", fmt_body_.Get(), card_x + pad_x, ry0, ds.colors.text_primary);
        draw_text_right(L"ramin-mahmoodi/Hemera ↗", fmt_mono_.Get(), card_x + card_w - pad_x, ry0, ds.colors.accent);

        // Row 1: Report an Issue
        float ry1 = card_y + row_h + text_mid_offset;
        draw_text(L"Report an Issue", fmt_body_.Get(), card_x + pad_x, ry1, ds.colors.text_primary);
        draw_text_right(L"Bug reports & feedback ↗", fmt_body_.Get(), card_x + card_w - pad_x, ry1, ds.colors.text_muted);

        // Row 2: Releases & Updates
        float ry2 = card_y + row_h * 2.0f + text_mid_offset;
        draw_text(L"Releases & Changelog", fmt_body_.Get(), card_x + pad_x, ry2, ds.colors.text_primary);
        draw_text_right(L"v1.0.3 (Latest) ↗", fmt_mono_.Get(), card_x + card_w - pad_x, ry2, ds.colors.text_muted);

        // Row 3: License
        float ry3 = card_y + row_h * 3.0f + text_mid_offset;
        draw_text(L"License", fmt_body_.Get(), card_x + pad_x, ry3, ds.colors.text_primary);
        draw_text_right(L"GNU AGPLv3 ↗", fmt_mono_.Get(), card_x + card_w - pad_x, ry3, ds.colors.text_muted);

        // 4. "Check for updates" Button
        float upd_y = card_y + row_h * 4.0f + scale_f(24, cur_dpi);
        float upd_w = static_cast<float>(scale(180, cur_dpi));
        float upd_h = static_cast<float>(scale(44, cur_dpi));
        float upd_x = cx - upd_w / 2.0f;
        float upd_r = static_cast<float>(scale(ds.metrics.radius_chip, cur_dpi));

        Color upd_bg = update_btn_hovered_ ? ds.colors.hover_bg : ds.colors.chip_bg;
        Color upd_bd = update_btn_hovered_ ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
        fill_rounded_rect(upd_x, upd_y, upd_w, upd_h, upd_r, upd_bg);
        draw_rounded_rect(upd_x, upd_y, upd_w, upd_h, upd_r, upd_bd, 1.0f);

        if (is_checking_update_) {
            float spin_cx = upd_x + scale_f(24, cur_dpi);
            float spin_cy = upd_y + upd_h / 2.0f;
            float s_rad = scale_f(7, cur_dpi);
            draw_arc(spin_cx, spin_cy, s_rad, spin_angle_, 180.0f, ds.colors.accent, 1.8f);

            draw_text_rect(L"Checking...", fmt_body_bold_.Get(), upd_x + scale_f(16, cur_dpi), upd_y, upd_w - scale_f(16, cur_dpi), upd_h, ds.colors.text_primary, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        } else {
            draw_text_rect(L"Check for updates", fmt_body_bold_.Get(), upd_x, upd_y, upd_w, upd_h, ds.colors.text_primary, DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }

        if (is_update_done_) {
            float done_y = upd_y + upd_h + scale_f(14, cur_dpi);
            draw_text_center(L"✓ You're on the latest version", fmt_body_.Get(), cx, done_y, ds.colors.accent);
        }
    }

    void render() {
        if (FAILED(ensure_device_resources())) return;
        RECT rc;
        GetClientRect(hwnd_, &rc);
        float win_w = static_cast<float>(std::max(1L, rc.right - rc.left));
        float win_h = static_cast<float>(std::max(1L, rc.bottom - rc.top));

        cached_bmp_w_ = static_cast<int>(win_w);
        cached_bmp_h_ = static_cast<int>(win_h);

        cached_engine_state_ = engine_->current_state();
        cached_engine_profile_ = engine_->active_profile();
        cached_engine_stats_ = engine_->current_stats();

        UINT cur_dpi = dpi();
        ensure_fonts(cur_dpi);

        render_target_->BeginDraw();

        const auto& ds = ds::DesignSystem::get();
        render_target_->Clear(ds.colors.bg);

        float progress = compute_rise_progress(view_transition_t_);
        float slide_y = scale_f(14.0f, cur_dpi) * (1.0f - progress);

        if (slide_y > 0.05f) {
            render_target_->SetTransform(D2D1::Matrix3x2F::Translation(0.0f, slide_y));
        } else {
            render_target_->SetTransform(D2D1::Matrix3x2F::Identity());
        }

        if (view_ == ActiveView::Home) {
            render_home_view(win_w, win_h, cur_dpi);
        } else if (view_ == ActiveView::Settings) {
            render_settings_view(win_w, win_h, cur_dpi);
        } else if (view_ == ActiveView::Logs) {
            render_logs_view(win_w, win_h, cur_dpi);
        } else if (view_ == ActiveView::About) {
            render_about_view(win_w, win_h, cur_dpi);
        }

        render_target_->SetTransform(D2D1::Matrix3x2F::Identity());

        // Chrome-style Titlebar Controls (Minimize & Close)
        draw_caption_buttons(win_w, cur_dpi);

        HRESULT hr = render_target_->EndDraw();
        if (hr == D2DERR_RECREATE_TARGET) {
            discard_device_resources();
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
        if (tray_hwnd_) {
            DestroyWindow(tray_hwnd_);
            tray_hwnd_ = nullptr;
        }
        tray_rt_.Reset();
        tray_brush_.Reset();
    }

    // ── Custom Direct2D Tray Menu Matching aether-ui-complete (Compact & Refined) ──
    void draw_tray_shield_icon(float cx, float cy, UINT cur_dpi) {
        float s = scale_f(5.5f, cur_dpi);
        D2D1_POINT_2F pts[6] = {
            D2D1::Point2F(cx, cy - s),
            D2D1::Point2F(cx + s * 0.9f, cy - s * 0.5f),
            D2D1::Point2F(cx + s * 0.85f, cy + s * 0.2f),
            D2D1::Point2F(cx, cy + s),
            D2D1::Point2F(cx - s * 0.85f, cy + s * 0.2f),
            D2D1::Point2F(cx - s * 0.9f, cy - s * 0.5f)
        };
        tray_brush_->SetColor(ds::DesignSystem::get().colors.icon_color);
        for (int i = 0; i < 5; ++i) {
            tray_rt_->DrawLine(pts[i], pts[i + 1], tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
        }
        tray_rt_->DrawLine(pts[5], pts[0], tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
    }

    void draw_tray_window_icon(float cx, float cy, UINT cur_dpi) {
        float rw = scale_f(5.5f, cur_dpi);
        float rh = scale_f(4.5f, cur_dpi);
        tray_brush_->SetColor(ds::DesignSystem::get().colors.icon_color);
        tray_rt_->DrawRectangle(D2D1::RectF(cx - rw, cy - rh, cx + rw, cy + rh), tray_brush_.Get(), scale_f(1.2f, cur_dpi));
        tray_rt_->DrawLine(D2D1::Point2F(cx - rw, cy - rh + scale_f(2.6f, cur_dpi)),
                           D2D1::Point2F(cx + rw, cy - rh + scale_f(2.6f, cur_dpi)),
                           tray_brush_.Get(), scale_f(1.0f, cur_dpi));
    }

    void draw_tray_terminal_icon(float cx, float cy, UINT cur_dpi) {
        tray_brush_->SetColor(ds::DesignSystem::get().colors.icon_color);
        D2D1_POINT_2F pts[3] = {
            D2D1::Point2F(cx - scale_f(4.0f, cur_dpi), cy - scale_f(3.5f, cur_dpi)),
            D2D1::Point2F(cx - scale_f(0.5f, cur_dpi), cy),
            D2D1::Point2F(cx - scale_f(4.0f, cur_dpi), cy + scale_f(3.5f, cur_dpi))
        };
        for (int i = 0; i < 2; ++i) {
            tray_rt_->DrawLine(pts[i], pts[i + 1], tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
        }
        tray_rt_->DrawLine(D2D1::Point2F(cx + scale_f(1.0f, cur_dpi), cy + scale_f(3.5f, cur_dpi)),
                           D2D1::Point2F(cx + scale_f(5.0f, cur_dpi), cy + scale_f(3.5f, cur_dpi)),
                           tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
    }

    void draw_tray_sliders_icon(float cx, float cy, UINT cur_dpi) {
        tray_brush_->SetColor(ds::DesignSystem::get().colors.icon_color);
        float s = scale_f(5.0f, cur_dpi);
        float y1 = cy - scale_f(2.4f, cur_dpi);
        float y2 = cy + scale_f(2.4f, cur_dpi);
        tray_rt_->DrawLine(D2D1::Point2F(cx - s, y1), D2D1::Point2F(cx + s, y1), tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
        tray_rt_->DrawLine(D2D1::Point2F(cx - s, y2), D2D1::Point2F(cx + s, y2), tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
        float dot_r = scale_f(1.6f, cur_dpi);
        tray_rt_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx - scale_f(1.8f, cur_dpi), y1), dot_r, dot_r), tray_brush_.Get());
        tray_rt_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx + scale_f(1.8f, cur_dpi), y2), dot_r, dot_r), tray_brush_.Get());
    }

    void draw_tray_power_icon(float cx, float cy, UINT cur_dpi) {
        Color col = (tray_hovered_item_ == 6) ? ds::DesignSystem::get().colors.text_primary : ds::DesignSystem::get().colors.text_muted;
        tray_brush_->SetColor(col);
        float r = scale_f(4.8f, cur_dpi);
        const int num_pts = 16;
        D2D1_POINT_2F arc_pts[num_pts];
        float start_ang = 0.8f;
        float end_ang = 5.48f;
        for (int i = 0; i < num_pts; ++i) {
            float a = start_ang + (end_ang - start_ang) * (static_cast<float>(i) / (num_pts - 1)) + 1.57f;
            arc_pts[i] = D2D1::Point2F(cx + r * std::cos(a), cy + r * std::sin(a));
        }
        for (int i = 0; i < num_pts - 1; ++i) {
            tray_rt_->DrawLine(arc_pts[i], arc_pts[i + 1], tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
        }
        tray_rt_->DrawLine(D2D1::Point2F(cx, cy - r), D2D1::Point2F(cx, cy - scale_f(0.8f, cur_dpi)), tray_brush_.Get(), scale_f(1.3f, cur_dpi), stroke_round_.Get());
    }

    int get_tray_item_at(int x, int y, UINT cur_dpi, float w) const {
        float btn_pad_x = scale_f(12.0f, cur_dpi);
        float btn_y = scale_f(44.0f, cur_dpi);
        float btn_w = w - btn_pad_x * 2.0f;
        float btn_h = scale_f(34.0f, cur_dpi);
        if (y >= btn_y && y <= btn_y + btn_h && x >= btn_pad_x && x <= btn_pad_x + btn_w) {
            return 1;
        }

        float div1_y = btn_y + btn_h + scale_f(8.0f, cur_dpi);
        float kill_y = div1_y + 1.0f;
        float kill_h = scale_f(36.0f, cur_dpi);
        if (y >= kill_y && y < kill_y + kill_h) return 2;

        float div2_y = kill_y + kill_h;
        float nav_start_y = div2_y + 1.0f;
        float nav_h = scale_f(32.0f, cur_dpi);
        if (y >= nav_start_y && y < nav_start_y + nav_h) return 3;
        if (y >= nav_start_y + nav_h && y < nav_start_y + nav_h * 2.0f) return 4;
        if (y >= nav_start_y + nav_h * 2.0f && y < nav_start_y + nav_h * 3.0f) return 5;

        float div3_y = nav_start_y + nav_h * 3.0f;
        float quit_y = div3_y + 1.0f;
        float quit_h = scale_f(32.0f, cur_dpi);
        if (y >= quit_y && y < quit_y + quit_h) return 6;

        return -1;
    }

    void render_tray_menu(HWND hwnd) {
        RECT rc;
        GetClientRect(hwnd, &rc);
        D2D1_SIZE_U size = D2D1::SizeU(std::max(1L, rc.right - rc.left), std::max(1L, rc.bottom - rc.top));

        if (!tray_rt_) {
            D2D1_RENDER_TARGET_PROPERTIES rt_props = D2D1::RenderTargetProperties(
                D2D1_RENDER_TARGET_TYPE_SOFTWARE,
                D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED),
                96.0f, 96.0f
            );
            D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_props = D2D1::HwndRenderTargetProperties(
                hwnd, size, D2D1_PRESENT_OPTIONS_IMMEDIATELY
            );
            d2d_factory_->CreateHwndRenderTarget(rt_props, hwnd_props, &tray_rt_);
            if (tray_rt_) {
                tray_rt_->SetDpi(96.0f, 96.0f);
                tray_rt_->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
                tray_rt_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);
                tray_rt_->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &tray_brush_);
            }
        } else {
            D2D1_SIZE_U cur_sz = tray_rt_->GetPixelSize();
            if (cur_sz.width != size.width || cur_sz.height != size.height) {
                tray_rt_->Resize(size);
            }
            tray_rt_->SetDpi(96.0f, 96.0f);
        }
        if (!tray_rt_ || !tray_brush_) return;

        const auto& ds = ds::DesignSystem::get();
        UINT cur_dpi = GetDpiForWindow(hwnd);
        if (cur_dpi == 0) cur_dpi = dpi();

        ensure_fonts(cur_dpi);

        float w = static_cast<float>(rc.right - rc.left);
        float h = static_cast<float>(rc.bottom - rc.top);

        tray_rt_->BeginDraw();
        // Clear to transparent so DWM smoothly composites the rounded anti-aliased edges
        tray_rt_->Clear(D2D1::ColorF(0.0f, 0.0f, 0.0f, 0.0f));

        float r14 = scale_f(14.0f, cur_dpi);
        // Fill rounded card body with Direct2D subpixel anti-aliasing
        tray_brush_->SetColor(ds.colors.card_bg);
        tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(0.0f, 0.0f, w, h), r14, r14), tray_brush_.Get());

        // Draw antialiased card border
        tray_brush_->SetColor(ds.colors.card_border);
        tray_rt_->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(0.5f, 0.5f, w - 0.5f, h - 0.5f), r14, r14), tray_brush_.Get(), 1.0f);

        auto st = engine_->current_state();
        bool is_connected = (st.kind == StateKind::Connected);
        bool is_connecting = (st.kind == StateKind::Connecting);
        bool is_error = (st.kind == StateKind::Error);
        auto stats = engine_->current_stats();

        // 1. Header (Top)
        float pad_x = scale_f(14.0f, cur_dpi);
        float dot_x = pad_x;
        float dot_y = scale_f(14.0f, cur_dpi);
        float dot_r = scale_f(4.5f, cur_dpi);

        Color dot_col = is_connected ? ds.colors.accent :
                        (is_connecting ? ds.colors.warning :
                        (is_error ? ds.colors.error : ds.colors.text_dim));
        tray_brush_->SetColor(dot_col);
        tray_rt_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(dot_x + dot_r, dot_y + dot_r), dot_r, dot_r), tray_brush_.Get());

        float text_x = dot_x + dot_r * 2.0f + scale_f(10.0f, cur_dpi);
        tray_brush_->SetColor(ds.colors.text_primary);
        fmt_tray_title_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        fmt_tray_title_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        tray_rt_->DrawTextW(L"Hemera", 6, fmt_tray_title_.Get(), D2D1::RectF(text_x, scale_f(10.0f, cur_dpi), w, scale_f(26.0f, cur_dpi)), tray_brush_.Get());

        std::wstring status_str;
        if (is_connected) {
            uint64_t up_s = stats.uptime;
            status_str = std::format(L"Connected  {:02d}:{:02d}:{:02d}", up_s / 3600, (up_s % 3600) / 60, up_s % 60);
        } else if (is_connecting) {
            status_str = L"Connecting...";
        } else if (is_error) {
            status_str = L"Connection failed";
        } else {
            status_str = L"Not connected";
        }
        tray_brush_->SetColor(ds.colors.text_muted);
        fmt_tray_sub_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        fmt_tray_sub_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        tray_rt_->DrawTextW(status_str.c_str(), static_cast<UINT32>(status_str.size()), fmt_tray_sub_.Get(), D2D1::RectF(text_x, scale_f(26.0f, cur_dpi), w - scale_f(10.0f, cur_dpi), scale_f(42.0f, cur_dpi)), tray_brush_.Get());

        // 2. Main Connect/Disconnect Button
        float btn_pad_x = scale_f(12.0f, cur_dpi);
        float btn_y = scale_f(44.0f, cur_dpi);
        float btn_w = w - btn_pad_x * 2.0f;
        float btn_h = scale_f(34.0f, cur_dpi);
        float btn_r = scale_f(10.0f, cur_dpi);

        bool btn_hov = (tray_hovered_item_ == 1);
        Color btn_bg;
        Color btn_bd;
        std::wstring btn_label;
        if (is_connected) {
            btn_label = L"Disconnect";
            btn_bg = btn_hov ? ds.colors.hover_bg : Color{ 0, 0, 0, 0 };
            btn_bd = btn_hov ? ds.colors.border_hover_bright : ds.colors.card_border;
        } else if (is_connecting) {
            btn_label = L"Cancel";
            btn_bg = btn_hov ? ds.colors.hover_bg : Color{ 0, 0, 0, 0 };
            btn_bd = btn_hov ? ds.colors.border_hover_bright : ds.colors.card_border;
        } else if (is_error) {
            btn_label = L"Try again";
            btn_bg = btn_hov ? ds.colors.hover_bg : ds.colors.chip_bg;
            btn_bd = btn_hov ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
        } else {
            btn_label = L"Connect";
            btn_bg = btn_hov ? ds.colors.hover_bg : ds.colors.chip_bg;
            btn_bd = btn_hov ? ds.colors.border_hover_bright : ds.colors.btn_border_dim;
        }

        if (btn_bg.a > 0.0f) {
            tray_brush_->SetColor(btn_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(btn_pad_x, btn_y, btn_pad_x + btn_w, btn_y + btn_h), btn_r, btn_r), tray_brush_.Get());
        }
        tray_brush_->SetColor(btn_bd);
        tray_rt_->DrawRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(btn_pad_x, btn_y, btn_pad_x + btn_w, btn_y + btn_h), btn_r, btn_r), tray_brush_.Get(), 1.0f);

        tray_brush_->SetColor(ds.colors.text_primary);
        D2D1_RECT_F btn_text_rc = D2D1::RectF(btn_pad_x, btn_y, btn_pad_x + btn_w, btn_y + btn_h);
        fmt_tray_btn_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        fmt_tray_btn_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        tray_rt_->DrawTextW(btn_label.c_str(), static_cast<UINT32>(btn_label.size()), fmt_tray_btn_.Get(), btn_text_rc, tray_brush_.Get());
        fmt_tray_btn_->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        fmt_tray_btn_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

        // Divider 1
        float cur_y = btn_y + btn_h + scale_f(8.0f, cur_dpi);
        tray_brush_->SetColor(ds.colors.card_border);
        tray_rt_->DrawLine(D2D1::Point2F(0, cur_y), D2D1::Point2F(w, cur_y), tray_brush_.Get(), 1.0f);
        cur_y += 1.0f;

        // 3. Kill switch row (Animated Toggle)
        float kill_h = scale_f(36.0f, cur_dpi);
        float hov_pad_x = scale_f(4.0f, cur_dpi);
        float hov_r = scale_f(8.0f, cur_dpi);
        if (tray_hovered_item_ == 2) {
            tray_brush_->SetColor(ds.colors.hover_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(hov_pad_x, cur_y, w - hov_pad_x, cur_y + kill_h), hov_r, hov_r), tray_brush_.Get());
        }
        float icon_x = scale_f(14.0f, cur_dpi);
        float icon_cy = cur_y + kill_h / 2.0f;
        draw_tray_shield_icon(icon_x + scale_f(7.0f, cur_dpi), icon_cy, cur_dpi);

        tray_brush_->SetColor(ds.colors.text_primary);
        fmt_tray_item_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        tray_rt_->DrawTextW(L"Kill switch", 11, fmt_tray_item_.Get(), D2D1::RectF(scale_f(38.0f, cur_dpi), cur_y, w - scale_f(54.0f, cur_dpi), cur_y + kill_h), tray_brush_.Get());
        fmt_tray_item_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

        float sw_w = scale_f(32.0f, cur_dpi);
        float sw_h = scale_f(18.0f, cur_dpi);
        float sw_x = w - scale_f(12.0f, cur_dpi) - sw_w;
        float sw_y = cur_y + (kill_h - sw_h) / 2.0f;
        float sw_r = sw_h / 2.0f;

        // Smoothly animated toggle switch (interpolates 0.0 to 1.0)
        float anim = switch_anim_[2];
        Color track_col = blend_colors(ds.colors.btn_border_dim, ds.colors.accent, anim);
        tray_brush_->SetColor(track_col);
        tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(sw_x, sw_y, sw_x + sw_w, sw_y + sw_h), sw_r, sw_r), tray_brush_.Get());

        float margin = scale_f(2.0f, cur_dpi);
        float thumb_d = sw_h - margin * 2.0f;
        float thumb_x = sw_x + margin + anim * (sw_w - margin * 2.0f - thumb_d);
        float thumb_y = sw_y + margin;
        Color thumb_col = blend_colors(ds.colors.icon_color, ds.colors.card_bg, anim);
        tray_brush_->SetColor(thumb_col);
        tray_rt_->FillEllipse(D2D1::Ellipse(D2D1::Point2F(thumb_x + thumb_d / 2.0f, thumb_y + thumb_d / 2.0f), thumb_d / 2.0f, thumb_d / 2.0f), tray_brush_.Get());

        cur_y += kill_h;

        // Divider 2
        tray_brush_->SetColor(ds.colors.card_border);
        tray_rt_->DrawLine(D2D1::Point2F(0, cur_y), D2D1::Point2F(w, cur_y), tray_brush_.Get(), 1.0f);
        cur_y += 1.0f;

        // 4. Navigation Items
        float nav_h = scale_f(32.0f, cur_dpi);
        fmt_tray_item_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

        // Item 3: Open Hemera
        if (tray_hovered_item_ == 3) {
            tray_brush_->SetColor(ds.colors.hover_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(hov_pad_x, cur_y, w - hov_pad_x, cur_y + nav_h), hov_r, hov_r), tray_brush_.Get());
        }
        draw_tray_window_icon(icon_x + scale_f(7.0f, cur_dpi), cur_y + nav_h / 2.0f, cur_dpi);
        tray_brush_->SetColor(ds.colors.text_primary);
        tray_rt_->DrawTextW(L"Open Hemera", 11, fmt_tray_item_.Get(), D2D1::RectF(scale_f(38.0f, cur_dpi), cur_y, w, cur_y + nav_h), tray_brush_.Get());
        cur_y += nav_h;

        // Item 4: Logs
        if (tray_hovered_item_ == 4) {
            tray_brush_->SetColor(ds.colors.hover_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(hov_pad_x, cur_y, w - hov_pad_x, cur_y + nav_h), hov_r, hov_r), tray_brush_.Get());
        }
        draw_tray_terminal_icon(icon_x + scale_f(7.0f, cur_dpi), cur_y + nav_h / 2.0f, cur_dpi);
        tray_brush_->SetColor(ds.colors.text_primary);
        tray_rt_->DrawTextW(L"Logs", 4, fmt_tray_item_.Get(), D2D1::RectF(scale_f(38.0f, cur_dpi), cur_y, w, cur_y + nav_h), tray_brush_.Get());
        cur_y += nav_h;

        // Item 5: Settings
        if (tray_hovered_item_ == 5) {
            tray_brush_->SetColor(ds.colors.hover_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(hov_pad_x, cur_y, w - hov_pad_x, cur_y + nav_h), hov_r, hov_r), tray_brush_.Get());
        }
        draw_tray_sliders_icon(icon_x + scale_f(7.0f, cur_dpi), cur_y + nav_h / 2.0f, cur_dpi);
        tray_brush_->SetColor(ds.colors.text_primary);
        tray_rt_->DrawTextW(L"Settings", 8, fmt_tray_item_.Get(), D2D1::RectF(scale_f(38.0f, cur_dpi), cur_y, w, cur_y + nav_h), tray_brush_.Get());
        cur_y += nav_h;

        // Divider 3
        tray_brush_->SetColor(ds.colors.card_border);
        tray_rt_->DrawLine(D2D1::Point2F(0, cur_y), D2D1::Point2F(w, cur_y), tray_brush_.Get(), 1.0f);
        cur_y += 1.0f;

        // 5. Quit Item
        float quit_h = scale_f(32.0f, cur_dpi);
        if (tray_hovered_item_ == 6) {
            tray_brush_->SetColor(ds.colors.hover_bg);
            tray_rt_->FillRoundedRectangle(D2D1::RoundedRect(D2D1::RectF(hov_pad_x, cur_y, w - hov_pad_x, cur_y + quit_h - scale_f(2.0f, cur_dpi)), hov_r, hov_r), tray_brush_.Get());
        }
        draw_tray_power_icon(icon_x + scale_f(7.0f, cur_dpi), cur_y + quit_h / 2.0f, cur_dpi);
        Color quit_col = (tray_hovered_item_ == 6) ? ds.colors.text_primary : ds.colors.text_muted;
        tray_brush_->SetColor(quit_col);
        tray_rt_->DrawTextW(L"Quit Hemera", 11, fmt_tray_item_.Get(), D2D1::RectF(scale_f(38.0f, cur_dpi), cur_y, w, cur_y + quit_h), tray_brush_.Get());
        fmt_tray_item_->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);

        tray_rt_->EndDraw();
    }

    LRESULT handle_tray_message(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_CREATE: {
                SetTimer(hwnd, 1, 16, nullptr); // 60 FPS animation timer
                return 0;
            }
            case WM_TIMER: {
                if (IsWindowVisible(hwnd)) {
                    if (has_active_animations()) {
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                }
                return 0;
            }
            case WM_ACTIVATE: {
                if (LOWORD(wParam) == WA_INACTIVE) {
                    ShowWindow(hwnd, SW_HIDE);
                    tray_hovered_item_ = -1;
                    tray_pressed_item_ = -1;
                    return 0;
                }
                return 0;
            }
            case WM_KILLFOCUS: {
                ShowWindow(hwnd, SW_HIDE);
                tray_hovered_item_ = -1;
                tray_pressed_item_ = -1;
                return 0;
            }
            case WM_ERASEBKGND:
                return 1;
            case WM_PAINT: {
                PAINTSTRUCT ps;
                BeginPaint(hwnd, &ps);
                render_tray_menu(hwnd);
                EndPaint(hwnd, &ps);
                return 0;
            }
            case WM_MOUSEMOVE: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);
                UINT cur_dpi = GetDpiForWindow(hwnd);
                if (cur_dpi == 0) cur_dpi = dpi();
                RECT rc;
                GetClientRect(hwnd, &rc);
                float w = static_cast<float>(rc.right - rc.left);

                int item = get_tray_item_at(x, y, cur_dpi, w);
                if (item != tray_hovered_item_) {
                    tray_hovered_item_ = item;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }

                TRACKMOUSEEVENT tme{};
                tme.cbSize = sizeof(tme);
                tme.dwFlags = TME_LEAVE;
                tme.hwndTrack = hwnd;
                TrackMouseEvent(&tme);
                return 0;
            }
            case WM_MOUSELEAVE: {
                if (tray_hovered_item_ != -1) {
                    tray_hovered_item_ = -1;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return 0;
            }
            case WM_SETCURSOR: {
                POINT pt;
                GetCursorPos(&pt);
                ScreenToClient(hwnd, &pt);
                UINT cur_dpi = GetDpiForWindow(hwnd);
                if (cur_dpi == 0) cur_dpi = dpi();
                RECT rc;
                GetClientRect(hwnd, &rc);
                int item = get_tray_item_at(pt.x, pt.y, cur_dpi, static_cast<float>(rc.right - rc.left));
                if (item >= 1 && item <= 6) {
                    SetCursor(LoadCursorW(nullptr, IDC_HAND));
                } else {
                    SetCursor(LoadCursorW(nullptr, IDC_ARROW));
                }
                return TRUE;
            }
            case WM_LBUTTONDOWN: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);
                UINT cur_dpi = GetDpiForWindow(hwnd);
                if (cur_dpi == 0) cur_dpi = dpi();
                RECT rc;
                GetClientRect(hwnd, &rc);
                tray_pressed_item_ = get_tray_item_at(x, y, cur_dpi, static_cast<float>(rc.right - rc.left));
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            case WM_LBUTTONUP: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);
                UINT cur_dpi = GetDpiForWindow(hwnd);
                if (cur_dpi == 0) cur_dpi = dpi();
                RECT rc;
                GetClientRect(hwnd, &rc);
                int clicked = get_tray_item_at(x, y, cur_dpi, static_cast<float>(rc.right - rc.left));

                if (clicked == tray_pressed_item_ && clicked >= 1) {
                    if (clicked == 1) {
                        auto st = engine_->current_state();
                        if (st.kind == StateKind::Connected || st.kind == StateKind::Connecting) {
                            (void)engine_->disconnect();
                        } else {
                            (void)engine_->connect();
                        }
                        cached_engine_state_ = engine_->current_state();
                        InvalidateRect(hwnd, nullptr, FALSE);
                        if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
                    } else if (clicked == 2) {
                        edit_settings_.kill_switch = !edit_settings_.kill_switch;
                        engine_->save_settings(edit_settings_);
                        // Animated smoothly by step_animations
                        InvalidateRect(hwnd, nullptr, FALSE);
                        if (hwnd_) InvalidateRect(hwnd_, nullptr, FALSE);
                    } else if (clicked == 3) {
                        ShowWindow(hwnd, SW_HIDE);
                        ShowWindow(hwnd_, SW_SHOW);
                        ShowWindow(hwnd_, SW_RESTORE);
                        SetForegroundWindow(hwnd_);
                        switch_view(ActiveView::Home);
                    } else if (clicked == 4) {
                        ShowWindow(hwnd, SW_HIDE);
                        switch_view(ActiveView::Logs);
                        ShowWindow(hwnd_, SW_SHOW);
                        ShowWindow(hwnd_, SW_RESTORE);
                        SetForegroundWindow(hwnd_);
                    } else if (clicked == 5) {
                        ShowWindow(hwnd, SW_HIDE);
                        switch_view(ActiveView::Settings);
                        ShowWindow(hwnd_, SW_SHOW);
                        ShowWindow(hwnd_, SW_RESTORE);
                        SetForegroundWindow(hwnd_);
                    } else if (clicked == 6) {
                        ShowWindow(hwnd, SW_HIDE);
                        (void)engine_->disconnect();
                        DestroyWindow(hwnd_);
                    }
                }
                tray_pressed_item_ = -1;
                InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            case WM_DESTROY: {
                KillTimer(hwnd, 1);
                tray_rt_.Reset();
                tray_brush_.Reset();
                tray_hwnd_ = nullptr;
                return 0;
            }
            default:
                return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    static LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        MainWindow::Impl* impl = reinterpret_cast<MainWindow::Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (!impl && msg == WM_CREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            impl = reinterpret_cast<MainWindow::Impl*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(impl));
        }
        if (impl) {
            return impl->handle_tray_message(hwnd, msg, wParam, lParam);
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    void ensure_tray_resources() {
        if (tray_hwnd_ && tray_rt_) return;

        UINT cur_dpi = dpi();
        int menu_w = MulDiv(228, cur_dpi, 96);
        int menu_h = MulDiv(254, cur_dpi, 96);

        if (!tray_hwnd_) {
            WNDCLASSEXW twc{};
            twc.cbSize = sizeof(WNDCLASSEXW);
            twc.style = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
            twc.lpfnWndProc = MainWindow::Impl::TrayWndProc;
            twc.hInstance = hInstance_;
            twc.lpszClassName = L"HemeraTrayMenuClass";
            twc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            RegisterClassExW(&twc);

            tray_hwnd_ = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                L"HemeraTrayMenuClass", L"HemeraTrayMenu",
                WS_POPUP,
                -30000, -30000, menu_w, menu_h,
                hwnd_, nullptr, hInstance_, this
            );
        }

        if (tray_hwnd_ && !tray_rt_) {
            D2D1_SIZE_U size = D2D1::SizeU(std::max(1, menu_w), std::max(1, menu_h));
            D2D1_RENDER_TARGET_PROPERTIES rt_props = D2D1::RenderTargetProperties(
                D2D1_RENDER_TARGET_TYPE_SOFTWARE,
                D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED),
                96.0f, 96.0f
            );
            D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_props = D2D1::HwndRenderTargetProperties(
                tray_hwnd_, size, D2D1_PRESENT_OPTIONS_IMMEDIATELY
            );
            d2d_factory_->CreateHwndRenderTarget(rt_props, hwnd_props, &tray_rt_);
            if (tray_rt_) {
                tray_rt_->SetDpi(96.0f, 96.0f);
                tray_rt_->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
                tray_rt_->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_CLEARTYPE);
                tray_rt_->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &tray_brush_);
            }
        }

        if (tray_hwnd_) {
            MARGINS margins = { -1, -1, -1, -1 };
            DwmExtendFrameIntoClientArea(tray_hwnd_, &margins);
            DWORD corner_pref = 3; // DWMWCP_ROUNDSMALL
            DwmSetWindowAttribute(tray_hwnd_, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, &corner_pref, sizeof(corner_pref));
        }

        ensure_fonts(cur_dpi);

        if (tray_hwnd_ && tray_rt_) {
            render_tray_menu(tray_hwnd_);
        }
    }

    void show_tray_menu(int x, int y) {
        POINT pt = { x, y };
        HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{ sizeof(MONITORINFO) };
        GetMonitorInfoW(hMon, &mi);

        UINT cur_dpi = 96;
        HMODULE hShcore = GetModuleHandleW(L"shcore.dll");
        if (!hShcore) hShcore = LoadLibraryW(L"shcore.dll");
        if (hShcore) {
            typedef HRESULT(WINAPI* GetDpiForMonitorFn)(HMONITOR, int, UINT*, UINT*);
            auto pfn = reinterpret_cast<GetDpiForMonitorFn>(GetProcAddress(hShcore, "GetDpiForMonitor"));
            if (pfn) {
                UINT dx = 96, dy = 96;
                if (SUCCEEDED(pfn(hMon, 0 /* MDT_EFFECTIVE_DPI */, &dx, &dy)) && dx > 0) {
                    cur_dpi = dx;
                }
            }
        }
        if (cur_dpi == 96) {
            cur_dpi = dpi();
        }

        ensure_tray_resources();
        if (!tray_hwnd_) return;

        if (IsWindowVisible(tray_hwnd_)) {
            ShowWindow(tray_hwnd_, SW_HIDE);
            return;
        }

        ensure_fonts(cur_dpi);

        const auto& ds = ds::DesignSystem::get();
        BOOL dark_mode = ds::is_effective_dark(ds.active_theme) ? TRUE : FALSE;
        DwmSetWindowAttribute(tray_hwnd_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark_mode, sizeof(dark_mode));

        MARGINS margins = { -1, -1, -1, -1 };
        DwmExtendFrameIntoClientArea(tray_hwnd_, &margins);
        DWORD corner_pref = 3; // DWMWCP_ROUNDSMALL
        DwmSetWindowAttribute(tray_hwnd_, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, &corner_pref, sizeof(corner_pref));

        int menu_w = MulDiv(228, cur_dpi, 96);
        int menu_h = MulDiv(254, cur_dpi, 96);

        int pos_x = x - menu_w;
        int pos_y = y - menu_h;
        pos_x = std::clamp(pos_x, static_cast<int>(mi.rcWork.left) + 8, static_cast<int>(mi.rcWork.right) - menu_w - 8);
        pos_y = std::clamp(pos_y, static_cast<int>(mi.rcWork.top) + 8, static_cast<int>(mi.rcWork.bottom) - menu_h - 8);

        // DO NOT use SetWindowRgn with CreateRoundRectRgn:
        // Removing 1-bit GDI binary mask eliminates jagged/pixelated edges and gives smooth D2D anti-aliasing!
        SetWindowRgn(tray_hwnd_, nullptr, TRUE);

        SetWindowPos(tray_hwnd_, HWND_TOPMOST, pos_x, pos_y, menu_w, menu_h, SWP_SHOWWINDOW);
        SetForegroundWindow(tray_hwnd_);
        InvalidateRect(tray_hwnd_, nullptr, TRUE);
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

            case WM_NCCALCSIZE: {
                if (wParam == TRUE) {
                    return 0; // Cover entire window without OS non-client frame
                }
                return DefWindowProcW(hwnd, msg, wParam, lParam);
            }

            case WM_NCHITTEST: {
                POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                ScreenToClient(hwnd, &pt);

                if (impl) {
                    const UINT cur_dpi = impl->dpi();
                    float cap_btn_w = scale_f(46.0f, cur_dpi);
                    float cap_btn_h = scale_f(30.0f, cur_dpi);
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    float win_w = static_cast<float>(rc.right - rc.left);

                    // Minimize & Close buttons: receive normal client mouse events
                    if (pt.y >= 0 && pt.y <= cap_btn_h && pt.x >= win_w - cap_btn_w * 2.0f && pt.x <= win_w) {
                        return HTCLIENT;
                    }

                    // Clickable controls
                    if (impl->is_mouse_over_clickable(pt.x, pt.y)) {
                        return HTCLIENT;
                    }

                    // Top titlebar drag zone
                    if (pt.y >= 0 && pt.y <= scale_f(36.0f, cur_dpi)) {
                        return HTCAPTION;
                    }
                }

                return HTCLIENT;
            }

            case WM_NCPAINT:
                return 0;

            case WM_NCACTIVATE: {
                if (wParam == FALSE) {
                    impl->min_btn_hovered_ = false;
                    impl->min_btn_pressed_ = false;
                    impl->close_btn_hovered_ = false;
                    impl->close_btn_pressed_ = false;
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                return TRUE;
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
                        // Advance animation clocks smoothly so animation phase doesn't pause,
                        // but DO NOT force synchronous UpdateWindow() so DWM window dragging
                        // runs at native 144Hz/240Hz screen refresh rate with zero stutter!
                        auto now = std::chrono::steady_clock::now();
                        float dt = std::chrono::duration<float>(now - impl->last_frame_time_).count();
                        if (dt > 0.040f) dt = 0.040f;
                        impl->last_frame_time_ = now;
                        impl->step_animations(dt);
                        return 0;
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
                BeginPaint(hwnd, &ps);
                if (impl) impl->render();
                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_SIZE: {
                if (wParam == SIZE_MINIMIZED) {
                    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
                    return 0;
                }
                if (impl) {
                    UINT w = LOWORD(lParam);
                    UINT h = HIWORD(lParam);
                    impl->cached_bmp_w_ = static_cast<int>(w);
                    impl->cached_bmp_h_ = static_cast<int>(h);
                    if (impl->render_target_) {
                        impl->render_target_->Resize(D2D1::SizeU(std::max(1u, w), std::max(1u, h)));
                    }
                    if (w > 0 && h > 0) {
                        HRGN rgn = CreateRectRgn(0, 0, static_cast<int>(w), static_cast<int>(h));
                        SetWindowRgn(hwnd, rgn, TRUE);
                    }
                }
                return 0;
            }

            case WM_MOUSEWHEEL: {
                short delta = GET_WHEEL_DELTA_WPARAM(wParam);
                UINT scroll_lines = 3;
                SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &scroll_lines, 0);
                if (scroll_lines == 0) scroll_lines = 3;
                float notch_step = static_cast<float>(scroll_lines) * 26.0f; // 78.0 DIPs per notch (swift & responsive)
                float notches = static_cast<float>(delta) / 120.0f;
                float scroll_amount = notches * notch_step;

                if (impl->view_ == ActiveView::Settings) {
                    impl->target_scroll_y_ = std::clamp(impl->target_scroll_y_ - scroll_amount, 0.0f, static_cast<float>(impl->max_scroll_));
                } else if (impl->view_ == ActiveView::Logs) {
                    impl->target_logs_scroll_y_ = std::clamp(impl->target_logs_scroll_y_ - scroll_amount, 0.0f, impl->max_logs_scroll_);
                }
                impl->last_frame_time_ = std::chrono::steady_clock::now();
                return 0;
            }

            case WM_MOUSEMOVE: {
                int x = GET_X_LPARAM(lParam);
                int y = GET_Y_LPARAM(lParam);

                if (impl->scrollbar_dragging_ && impl->view_ == ActiveView::Settings) {
                    float dy = static_cast<float>(y) - impl->scrollbar_drag_start_y_;
                    float track_h = static_cast<float>(impl->settings_sb_track_rect_.bottom - impl->settings_sb_track_rect_.top);
                    float thumb_h = static_cast<float>(impl->settings_sb_thumb_rect_.bottom - impl->settings_sb_thumb_rect_.top);
                    float travel = track_h - thumb_h;
                    if (travel > 1.0f && impl->max_scroll_ > 0) {
                        float d_scroll = (dy / travel) * static_cast<float>(impl->max_scroll_);
                        impl->target_scroll_y_ = std::clamp(impl->scrollbar_drag_start_scroll_ + d_scroll, 0.0f, static_cast<float>(impl->max_scroll_));
                        impl->scroll_anim_y_ = impl->target_scroll_y_;
                        impl->scroll_vel_y_ = 0.0f;
                        InvalidateRect(hwnd, nullptr, FALSE);
                    }
                    return 0;
                }

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

                float cap_btn_w = scale_f(46.0f, cur_dpi);
                float cap_btn_h = scale_f(30.0f, cur_dpi);
                float close_x = w - cap_btn_w;
                float min_x = close_x - cap_btn_w;
                bool prev_min = impl->min_btn_hovered_;
                bool prev_close = impl->close_btn_hovered_;

                impl->min_btn_hovered_ = (x >= min_x && x < close_x && y >= 0 && y <= cap_btn_h);
                impl->close_btn_hovered_ = (x >= close_x && x <= w && y >= 0 && y <= cap_btn_h);

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
                bool prev_about_rel = impl->about_releases_hovered_;
                bool prev_about_lic = impl->about_license_hovered_;
                bool prev_upd = impl->update_btn_hovered_;
                bool prev_sb_hov = impl->scrollbar_hovered_;

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

                if (impl->view_ == ActiveView::Settings && impl->max_scroll_ > 0) {
                    impl->scrollbar_hovered_ = (x >= impl->settings_sb_track_rect_.left && x <= impl->settings_sb_track_rect_.right &&
                                                y >= impl->settings_sb_track_rect_.top && y <= impl->settings_sb_track_rect_.bottom);
                } else {
                    impl->scrollbar_hovered_ = false;
                }

                if (impl->view_ == ActiveView::Home) {
                    float hero_cx = w / 2.0f;
                    float hero_cy = (float)scale(210, cur_dpi);
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
                    float row_h = (float)scale(54, cur_dpi);
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
                    float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
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
                    float card1_h = gen_row_h * 5.0f;

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
                            int r = static_cast<int>((y - card1_y) / gen_row_h);
                            if (r == 4) impl->hovered_settings_row_ = 17; // Row 4: Native TUN mode
                            else impl->hovered_settings_row_ = 10 + r;
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
                    float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float clr_x = w - card_x - back_sz;
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
                        float ch_x = card_x + static_cast<float>(i) * (chip_w + chip_gap);
                        if (x >= ch_x && x <= ch_x + chip_w && y >= chips_y && y <= chips_y + chip_h) {
                            impl->hovered_log_chip_ = i;
                            break;
                        }
                    }

                } else if (impl->view_ == ActiveView::About) {
                    float back_x = scale_f(static_cast<float>(ds.metrics.padding_x) - 10.0f, cur_dpi);
                    float back_y = (float)scale(ds.metrics.padding_top, cur_dpi);
                    float back_sz = (float)scale(ds.metrics.header_btn_size, cur_dpi);
                    impl->back_btn_hovered_ = (x >= back_x && x <= back_x + back_sz && y >= back_y && y <= back_y + back_sz);

                    float card_x = (float)scale(ds.metrics.padding_x, cur_dpi);
                    float card_w = w - scale_f(static_cast<float>(ds.metrics.padding_x * 2), cur_dpi);
                    float row_h = scale_f(static_cast<float>(ds.metrics.row_height), cur_dpi);
                    float card_y = (impl->about_card_y_ > 0.0f) ? impl->about_card_y_ : scale_f(290.0f, cur_dpi);

                    impl->about_src_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y && y < card_y + row_h);
                    impl->about_issue_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y + row_h && y < card_y + row_h * 2.0f);
                    impl->about_releases_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y + row_h * 2.0f && y < card_y + row_h * 3.0f);
                    impl->about_license_hovered_ = (x >= card_x && x <= card_x + card_w && y >= card_y + row_h * 3.0f && y <= card_y + row_h * 4.0f);

                    float upd_w = scale_f(180, cur_dpi);
                    float upd_h = scale_f(44, cur_dpi);
                    float upd_x = w / 2.0f - upd_w / 2.0f;
                    float upd_y = card_y + row_h * 4.0f + scale_f(24, cur_dpi);
                    impl->update_btn_hovered_ = (x >= upd_x && x <= upd_x + upd_w && y >= upd_y && y <= upd_y + upd_h);
                }

                if (prev_min != impl->min_btn_hovered_ || prev_close != impl->close_btn_hovered_ ||
                    prev_hero != impl->hero_hovered_ || prev_logs != impl->logs_btn_hovered_ ||
                    prev_set != impl->settings_btn_hovered_ || prev_back != impl->back_btn_hovered_ ||
                    prev_save != impl->save_btn_hovered_ || prev_cp != impl->copy_btn_hovered_ ||
                    prev_proto != impl->home_proto_hovered_ || prev_route != impl->home_route_hovered_ ||
                    prev_cp_logs != impl->copy_logs_hovered_ || prev_clr_logs != impl->clear_logs_hovered_ ||
                    prev_log_chip != impl->hovered_log_chip_ ||
                    prev_row != impl->hovered_settings_row_ || prev_about_src != impl->about_src_hovered_ ||
                    prev_about_iss != impl->about_issue_hovered_ ||
                    prev_about_rel != impl->about_releases_hovered_ ||
                    prev_about_lic != impl->about_license_hovered_ ||
                    prev_upd != impl->update_btn_hovered_ ||
                    prev_sb_hov != impl->scrollbar_hovered_) {
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

                // Custom Chrome Caption Buttons (Minimize & Close)
                {
                    const UINT cur_dpi = impl->dpi();
                    float cap_btn_w = scale_f(46.0f, cur_dpi);
                    float cap_btn_h = scale_f(30.0f, cur_dpi);
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    float win_w = static_cast<float>(rc.right - rc.left);
                    float close_x = win_w - cap_btn_w;
                    float min_x = close_x - cap_btn_w;

                    if (y >= 0 && y <= cap_btn_h) {
                        if (x >= min_x && x < close_x) {
                            impl->min_btn_pressed_ = true;
                            SetCapture(hwnd);
                            InvalidateRect(hwnd, nullptr, FALSE);
                            return 0;
                        } else if (x >= close_x && x <= win_w) {
                            impl->close_btn_pressed_ = true;
                            SetCapture(hwnd);
                            InvalidateRect(hwnd, nullptr, FALSE);
                            return 0;
                        }
                    }
                }

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

                if (impl->view_ == ActiveView::Settings && impl->max_scroll_ > 0) {
                    if (x >= impl->settings_sb_track_rect_.left && x <= impl->settings_sb_track_rect_.right &&
                        y >= impl->settings_sb_track_rect_.top && y <= impl->settings_sb_track_rect_.bottom) {

                        float thumb_top = static_cast<float>(impl->settings_sb_thumb_rect_.top);
                        float thumb_bot = static_cast<float>(impl->settings_sb_thumb_rect_.bottom);

                        if (y >= thumb_top && y <= thumb_bot) {
                            impl->scrollbar_dragging_ = true;
                            impl->scrollbar_drag_start_y_ = static_cast<float>(y);
                            impl->scrollbar_drag_start_scroll_ = impl->scroll_anim_y_;
                            SetCapture(hwnd);
                            InvalidateRect(hwnd, nullptr, FALSE);
                            return 0;
                        } else {
                            float track_h = static_cast<float>(impl->settings_sb_track_rect_.bottom - impl->settings_sb_track_rect_.top);
                            float thumb_h = thumb_bot - thumb_top;
                            float travel = track_h - thumb_h;
                            if (travel > 1.0f) {
                                float rel_y = static_cast<float>(y - impl->settings_sb_track_rect_.top) - thumb_h / 2.0f;
                                float pct = std::clamp(rel_y / travel, 0.0f, 1.0f);
                                impl->target_scroll_y_ = pct * static_cast<float>(impl->max_scroll_);
                                impl->scroll_anim_y_ = impl->target_scroll_y_;
                                impl->scroll_vel_y_ = 0.0f;
                                impl->scrollbar_dragging_ = true;
                                impl->scrollbar_drag_start_y_ = static_cast<float>(y);
                                impl->scrollbar_drag_start_scroll_ = impl->scroll_anim_y_;
                                SetCapture(hwnd);
                                InvalidateRect(hwnd, nullptr, FALSE);
                                return 0;
                            }
                        }
                    }
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
                        if (impl->edit_profile_.system_proxy) {
                            impl->edit_profile_.tun_mode = false;
                        }
                        impl->commit_settings_save();
                        InvalidateRect(hwnd, nullptr, FALSE);
                    } else if (impl->hovered_settings_row_ == 17) {
                        impl->edit_profile_.tun_mode = !impl->edit_profile_.tun_mode;
                        if (impl->edit_profile_.tun_mode) {
                            impl->edit_profile_.system_proxy = false;
                        }
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
                        ShellExecuteW(nullptr, L"open", L"https://github.com/ramin-mahmoodi/Hemera", nullptr, nullptr, SW_SHOWNORMAL);
                    } else if (impl->about_issue_hovered_) {
                        ShellExecuteW(nullptr, L"open", L"https://github.com/ramin-mahmoodi/Hemera/issues", nullptr, nullptr, SW_SHOWNORMAL);
                    } else if (impl->about_releases_hovered_) {
                        ShellExecuteW(nullptr, L"open", L"https://github.com/ramin-mahmoodi/Hemera/releases", nullptr, nullptr, SW_SHOWNORMAL);
                    } else if (impl->about_license_hovered_) {
                        ShellExecuteW(nullptr, L"open", L"https://github.com/ramin-mahmoodi/Hemera/blob/main/LICENSE", nullptr, nullptr, SW_SHOWNORMAL);
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
                if (impl->scrollbar_dragging_) {
                    impl->scrollbar_dragging_ = false;
                    ReleaseCapture();
                    InvalidateRect(hwnd, nullptr, FALSE);
                }

                if (impl->min_btn_pressed_ || impl->close_btn_pressed_) {
                    ReleaseCapture();
                    const UINT cur_dpi = impl->dpi();
                    float cap_btn_w = scale_f(46.0f, cur_dpi);
                    float cap_btn_h = scale_f(30.0f, cur_dpi);
                    RECT rc;
                    GetClientRect(hwnd, &rc);
                    float win_w = static_cast<float>(rc.right - rc.left);
                    float close_x = win_w - cap_btn_w;
                    float min_x = close_x - cap_btn_w;
                    bool was_min = impl->min_btn_pressed_;
                    bool was_close = impl->close_btn_pressed_;
                    impl->min_btn_pressed_ = false;
                    impl->close_btn_pressed_ = false;
                    InvalidateRect(hwnd, nullptr, FALSE);

                    int x = GET_X_LPARAM(lParam);
                    int y = GET_Y_LPARAM(lParam);

                    if (was_min && (x >= min_x && x < close_x && y >= 0 && y <= cap_btn_h)) {
                        PostMessageW(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
                        return 0;
                    }
                    if (was_close && (x >= close_x && x <= win_w && y >= 0 && y <= cap_btn_h)) {
                        PostMessageW(hwnd, WM_CLOSE, 0, 0);
                        return 0;
                    }
                    return 0;
                }

                if (impl->hero_pressed_) {
                    impl->hero_pressed_ = false;
                    impl->hero_target_scale_ = impl->hero_hovered_ ? 1.03f : 1.0f;

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
                    impl->cached_engine_state_ = impl->engine_->current_state();
                    InvalidateRect(hwnd, nullptr, FALSE);
                    UpdateWindow(hwnd);
                }
                return 0;
            }

            case WM_HEMERA_STATE_CHANGE: {
                auto state = impl->engine_->current_state();
                impl->cached_engine_state_ = state;
                if (state.kind == StateKind::Error) {
                    impl->shake_timer_ = 0.45f;
                } else if (state.kind == StateKind::Idle) {
                    _heapmin();
                    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
                }
                InvalidateRect(hwnd, nullptr, FALSE);
                UpdateWindow(hwnd);
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
                if (lParam == WM_LBUTTONUP) {
                    // Left-click: Open and restore Hemera main window
                    if (impl->tray_hwnd_ && IsWindowVisible(impl->tray_hwnd_)) {
                        ShowWindow(impl->tray_hwnd_, SW_HIDE);
                    }
                    ShowWindow(hwnd, SW_SHOW);
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                } else if (lParam == WM_RBUTTONUP) {
                    // Right-click: Open custom Direct2D tray flyout menu
                    POINT pt;
                    GetCursorPos(&pt);
                    impl->show_tray_menu(pt.x, pt.y);
                }
                return 0;
            }

            case WM_CLOSE: {
                auto s = impl->engine_->load_settings();
                if (s.close_to_tray) {
                    ShowWindow(hwnd, SW_HIDE);
                    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
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
    // Dark background brush: prevents OS white-window flash during creation!
    wc.hbrBackground = CreateSolidBrush(RGB(15, 17, 23));
    RegisterClassExW(&wc);

    const auto& ds = ds::DesignSystem::get();
    UINT sys_dpi = GetDpiForSystem();
    if (sys_dpi == 0) sys_dpi = 96;

    const int client_w = MulDiv(ds.metrics.window_width, sys_dpi, 96);
    const int client_h = MulDiv(ds.metrics.window_height, sys_dpi, 96);

    int pos_x = (GetSystemMetrics(SM_CXSCREEN) - client_w) / 2;
    int pos_y = (GetSystemMetrics(SM_CYSCREEN) - client_h) / 2;

    impl_->hwnd_ = CreateWindowExW(
        WS_EX_APPWINDOW, L"HemeraMainWindowClass", L"Hemera",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME,
        pos_x, pos_y, client_w, client_h,
        nullptr, nullptr, impl_->hInstance_, impl_.get()
    );

    if (!impl_->hwnd_) return false;

    // Enforce 100% square 90-degree corners:
    // 1. Rectangular window region (guarantees sharp corners across all Windows versions)
    HRGN rgn = CreateRectRgn(0, 0, client_w, client_h);
    SetWindowRgn(impl_->hwnd_, rgn, TRUE);

    // 2. DWM preference for Windows 11
    DWORD corner_pref = 1; // DWMWCP_DONOTROUND
    DwmSetWindowAttribute(impl_->hwnd_, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, &corner_pref, sizeof(corner_pref));

    // Apply immersive title bar mode based on active theme
    BOOL dark_mode = ds::is_effective_dark(ds.active_theme) ? TRUE : FALSE;
    DwmSetWindowAttribute(impl_->hwnd_, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark_mode, sizeof(dark_mode));

    SetWindowPos(impl_->hwnd_, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    // Register thread-safe engine callbacks
    HWND target_hwnd = impl_->hwnd_;
    impl_->engine_->set_on_state_changed([target_hwnd](const ConnectionState&) {
        PostMessageW(target_hwnd, WM_HEMERA_STATE_CHANGE, 0, 0);
    });

    impl_->engine_->set_on_log([target_hwnd](const LogLine& log) {
        auto* copy = new LogLine(log);
        PostMessageW(target_hwnd, WM_HEMERA_LOG, 0, reinterpret_cast<LPARAM>(copy));
    });

    // Pre-render the first Direct2D frame BEFORE presenting the window to the user
    // This completely eliminates any blank/white startup delay!
    impl_->ensure_device_resources();
    impl_->render();
    if (!impl_->start_minimized_) {
        ShowWindow(impl_->hwnd_, SW_SHOWNORMAL);
        UpdateWindow(impl_->hwnd_);
    }

    impl_->ensure_tray_resources();

    // Reclaim cold startup pages (DLLs, font tables, one-time CRT init)
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);

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
        bool tray_visible = impl_->tray_hwnd_ && IsWindow(impl_->tray_hwnd_) && IsWindowVisible(impl_->tray_hwnd_);
        bool active_anim = (is_visible || tray_visible) && impl_->has_active_animations();

        if (active_anim) {
            if (is_visible) {
                impl_->step_animations(dt);
                InvalidateRect(impl_->hwnd_, nullptr, FALSE);
                UpdateWindow(impl_->hwnd_);
            } else {
                impl_->step_animations(dt);
            }
            if (tray_visible) {
                InvalidateRect(impl_->tray_hwnd_, nullptr, FALSE);
            }
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
