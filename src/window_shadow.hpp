#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>
#include <memory>
#include <cstring>

namespace hemera::gui {

// Telegram Desktop exact window drop shadow implementation
// Based on Telegram Desktop (tdesktop/lib_ui/ui/platform/win/ui_window_shadow_win.cpp)
// Creates 4 thin WS_EX_LAYERED popup strips surrounding the main window with exact
// Telegram alpha curves, zero clipping, zero resize lag, and sub-pixel antialiasing.
class WindowShadow final {
public:
    explicit WindowShadow(HWND parent) : parent_(parent) {
        init();
    }

    ~WindowShadow() {
        destroy();
    }

    WindowShadow(const WindowShadow&) = delete;
    WindowShadow& operator=(const WindowShadow&) = delete;

    void update(const WINDOWPOS* pos = nullptr) {
        if (!parent_ || !IsWindow(parent_)) return;

        if (IsIconic(parent_) || !IsWindowVisible(parent_)) {
            hide();
            return;
        }

        RECT rc{};
        GetWindowRect(parent_, &rc);
        int win_x = rc.left;
        int win_y = rc.top;
        int win_w = rc.right - rc.left;
        int win_h = rc.bottom - rc.top;

        if (pos) {
            if (!(pos->flags & SWP_NOMOVE)) {
                win_x = pos->x;
                win_y = pos->y;
            }
            if (!(pos->flags & SWP_NOSIZE)) {
                win_w = pos->cx;
                win_h = pos->cy;
            }
        }

        if (win_w <= 0 || win_h <= 0) return;

        UINT cur_dpi = GetDpiForWindow(parent_);
        if (cur_dpi == 0) cur_dpi = 96;
        const int size = MulDiv(16, cur_dpi, 96);

        const bool size_changed = (win_w != last_win_w_ || win_h != last_win_h_ || size != last_size_);
        const bool pos_changed = (win_x != last_win_x_ || win_y != last_win_y_);

        last_win_x_ = win_x;
        last_win_y_ = win_y;
        last_win_w_ = win_w;
        last_win_h_ = win_h;
        last_size_ = size;

        if (size_changed) {
            render_and_update_all(win_x, win_y, win_w, win_h, size);
        } else if (pos_changed) {
            reposition_only(win_x, win_y, win_w, win_h, size);
        }

        if (hidden_) {
            show();
        }
    }

    void show() {
        if (!hidden_) return;
        hidden_ = false;
        for (HWND h : handles_) {
            if (h && IsWindow(h)) {
                SetWindowPos(h, parent_, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
            }
        }
    }

    void hide() {
        if (hidden_) return;
        hidden_ = true;
        for (HWND h : handles_) {
            if (h && IsWindow(h)) {
                ShowWindow(h, SW_HIDE);
            }
        }
    }

    void sync_z_order() {
        if (hidden_) return;
        for (HWND h : handles_) {
            if (h && IsWindow(h)) {
                SetWindowPos(h, parent_, 0, 0, 0, 0,
                             SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            }
        }
    }

private:
    // Exact Telegram Desktop shadow alpha table from tdesktop's WindowShadow
    // Logged at startup as: "Window Shadow: 1, 1, 3, 4, 6, 9, 13, 18, 24, 31, 38, 46"
    static constexpr uint8_t TELEGRAM_SHADOW_ALPHAS[12] = {
        1, 1, 3, 4, 6, 9, 13, 18, 24, 31, 38, 46
    };

    static uint8_t sample_alpha(float normalized_dist) {
        if (normalized_dist <= 0.0f) return 0;
        if (normalized_dist >= 1.0f) return 46;
        float f = normalized_dist * 11.0f;
        int idx = static_cast<int>(f);
        if (idx >= 11) return 46;
        float frac = f - static_cast<float>(idx);
        float a0 = static_cast<float>(TELEGRAM_SHADOW_ALPHAS[idx]);
        float a1 = static_cast<float>(TELEGRAM_SHADOW_ALPHAS[idx + 1]);
        return static_cast<uint8_t>(std::clamp(std::round(a0 + frac * (a1 - a0)), 0.0f, 46.0f));
    }

    static LRESULT CALLBACK ShadowWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        auto* self = reinterpret_cast<WindowShadow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
            case WM_NCHITTEST:
                return HTNOWHERE;

            case WM_NCLBUTTONDOWN:
            case WM_LBUTTONDOWN:
                if (self && self->parent_ && IsWindow(self->parent_)) {
                    SetForegroundWindow(self->parent_);
                    SetActiveWindow(self->parent_);
                }
                return 0;

            case WM_MOUSEACTIVATE:
                return MA_NOACTIVATE;

            case WM_DESTROY:
                return 0;

            default:
                return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    void init() {
        static const auto instance = GetModuleHandleW(nullptr);
        static const wchar_t* const class_name = L"HemeraTelegramWindowShadow";
        static const bool registered = [] {
            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.style = CS_HREDRAW | CS_VREDRAW;
            wc.lpfnWndProc = ShadowWndProc;
            wc.hInstance = instance;
            wc.lpszClassName = class_name;
            wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
            return RegisterClassExW(&wc) != 0;
        }();
        (void)registered;

        screen_dc_ = GetDC(nullptr);

        for (int i = 0; i < 4; ++i) {
            handles_[i] = CreateWindowExW(
                WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                class_name,
                L"",
                WS_POPUP,
                0, 0, 0, 0,
                nullptr, nullptr, instance, nullptr
            );
            if (handles_[i]) {
                SetWindowLongPtrW(handles_[i], GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
                SetWindowLongPtrW(handles_[i], GWLP_HWNDPARENT, reinterpret_cast<LONG_PTR>(parent_));
            }
        }
    }

    void destroy() {
        for (int i = 0; i < 4; ++i) {
            if (handles_[i] && IsWindow(handles_[i])) {
                DestroyWindow(handles_[i]);
                handles_[i] = nullptr;
            }
        }
        if (screen_dc_) {
            ReleaseDC(nullptr, screen_dc_);
            screen_dc_ = nullptr;
        }
    }

    void reposition_only(int win_x, int win_y, int win_w, int win_h, int size) {
        // Window 0: Top
        if (handles_[0]) {
            SetWindowPos(handles_[0], parent_, win_x, win_y - size, win_w, size,
                         SWP_NOACTIVATE | SWP_NOSIZE);
        }
        // Window 1: Right
        if (handles_[1]) {
            SetWindowPos(handles_[1], parent_, win_x + win_w, win_y - size, size, win_h + 2 * size,
                         SWP_NOACTIVATE | SWP_NOSIZE);
        }
        // Window 2: Bottom
        if (handles_[2]) {
            SetWindowPos(handles_[2], parent_, win_x, win_y + win_h, win_w, size,
                         SWP_NOACTIVATE | SWP_NOSIZE);
        }
        // Window 3: Left
        if (handles_[3]) {
            SetWindowPos(handles_[3], parent_, win_x - size, win_y - size, size, win_h + 2 * size,
                         SWP_NOACTIVATE | SWP_NOSIZE);
        }
    }

    void render_and_update_all(int win_x, int win_y, int win_w, int win_h, int size) {
        if (!screen_dc_) return;

        // 1. Top Shadow: width = win_w, height = size
        render_top_strip(handles_[0], win_x, win_y - size, win_w, size);

        // 2. Right Shadow: width = size, height = win_h + 2 * size
        render_right_strip(handles_[1], win_x + win_w, win_y - size, size, win_h + 2 * size);

        // 3. Bottom Shadow: width = win_w, height = size
        render_bottom_strip(handles_[2], win_x, win_y + win_h, win_w, size);

        // 4. Left Shadow: width = size, height = win_h + 2 * size
        render_left_strip(handles_[3], win_x - size, win_y - size, size, win_h + 2 * size);
    }

    void render_top_strip(HWND hwnd, int x, int y, int w, int h) {
        if (!hwnd || w <= 0 || h <= 0) return;
        std::vector<uint32_t> pixels(w * h, 0);

        for (int row = 0; row < h; ++row) {
            float norm = static_cast<float>(row + 1) / static_cast<float>(h);
            uint32_t px = static_cast<uint32_t>(sample_alpha(norm)) << 24;
            uint32_t* row_ptr = &pixels[row * w];
            std::fill_n(row_ptr, w, px);
        }

        update_layered(hwnd, x, y, w, h, pixels.data());
    }

    void render_bottom_strip(HWND hwnd, int x, int y, int w, int h) {
        if (!hwnd || w <= 0 || h <= 0) return;
        std::vector<uint32_t> pixels(w * h, 0);

        for (int row = 0; row < h; ++row) {
            float norm = static_cast<float>(h - row) / static_cast<float>(h);
            uint32_t px = static_cast<uint32_t>(sample_alpha(norm)) << 24;
            uint32_t* row_ptr = &pixels[row * w];
            std::fill_n(row_ptr, w, px);
        }

        update_layered(hwnd, x, y, w, h, pixels.data());
    }

    void render_left_strip(HWND hwnd, int x, int y, int w, int h) {
        if (!hwnd || w <= 0 || h <= 0) return;
        std::vector<uint32_t> pixels(w * h, 0);
        const int s = w; // thickness

        for (int row = 0; row < h; ++row) {
            uint32_t* row_ptr = &pixels[row * w];

            if (row < s) {
                // Top-left corner arc
                float dy = static_cast<float>(s - row);
                for (int col = 0; col < s; ++col) {
                    float dx = static_cast<float>(s - col);
                    float dist = std::sqrt(dx * dx + dy * dy);
                    if (dist <= static_cast<float>(s)) {
                        float norm = std::clamp((static_cast<float>(s) - dist + 1.0f) / static_cast<float>(s), 0.0f, 1.0f);
                        row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                    }
                }
            } else if (row >= h - s) {
                // Bottom-left corner arc
                float dy = static_cast<float>(row - (h - s) + 1);
                for (int col = 0; col < s; ++col) {
                    float dx = static_cast<float>(s - col);
                    float dist = std::sqrt(dx * dx + dy * dy);
                    if (dist <= static_cast<float>(s)) {
                        float norm = std::clamp((static_cast<float>(s) - dist + 1.0f) / static_cast<float>(s), 0.0f, 1.0f);
                        row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                    }
                }
            } else {
                // Straight left edge
                for (int col = 0; col < s; ++col) {
                    float norm = static_cast<float>(col + 1) / static_cast<float>(s);
                    row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                }
            }
        }

        update_layered(hwnd, x, y, w, h, pixels.data());
    }

    void render_right_strip(HWND hwnd, int x, int y, int w, int h) {
        if (!hwnd || w <= 0 || h <= 0) return;
        std::vector<uint32_t> pixels(w * h, 0);
        const int s = w; // thickness

        for (int row = 0; row < h; ++row) {
            uint32_t* row_ptr = &pixels[row * w];

            if (row < s) {
                // Top-right corner arc
                float dy = static_cast<float>(s - row);
                for (int col = 0; col < s; ++col) {
                    float dx = static_cast<float>(col + 1);
                    float dist = std::sqrt(dx * dx + dy * dy);
                    if (dist <= static_cast<float>(s)) {
                        float norm = std::clamp((static_cast<float>(s) - dist + 1.0f) / static_cast<float>(s), 0.0f, 1.0f);
                        row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                    }
                }
            } else if (row >= h - s) {
                // Bottom-right corner arc
                float dy = static_cast<float>(row - (h - s) + 1);
                for (int col = 0; col < s; ++col) {
                    float dx = static_cast<float>(col + 1);
                    float dist = std::sqrt(dx * dx + dy * dy);
                    if (dist <= static_cast<float>(s)) {
                        float norm = std::clamp((static_cast<float>(s) - dist + 1.0f) / static_cast<float>(s), 0.0f, 1.0f);
                        row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                    }
                }
            } else {
                // Straight right edge
                for (int col = 0; col < s; ++col) {
                    float norm = static_cast<float>(s - col) / static_cast<float>(s);
                    row_ptr[col] = static_cast<uint32_t>(sample_alpha(norm)) << 24;
                }
            }
        }

        update_layered(hwnd, x, y, w, h, pixels.data());
    }

    void update_layered(HWND hwnd, int x, int y, int w, int h, const uint32_t* bits) {
        BITMAPINFO bmi{};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // Top-down DIB
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        void* dib_bits = nullptr;
        HDC mem_dc = CreateCompatibleDC(screen_dc_);
        HBITMAP dib = CreateDIBSection(screen_dc_, &bmi, DIB_RGB_COLORS, &dib_bits, nullptr, 0);

        if (dib && dib_bits) {
            std::memcpy(dib_bits, bits, static_cast<size_t>(w) * h * sizeof(uint32_t));
            HGDIOBJ old_bmp = SelectObject(mem_dc, dib);

            POINT pt_dst = { x, y };
            SIZE sz = { w, h };
            POINT pt_src = { 0, 0 };

            BLENDFUNCTION blend{};
            blend.BlendOp = AC_SRC_OVER;
            blend.BlendFlags = 0;
            blend.SourceConstantAlpha = 255;
            blend.AlphaFormat = AC_SRC_ALPHA;

            UpdateLayeredWindow(hwnd, screen_dc_, &pt_dst, &sz, mem_dc, &pt_src, 0, &blend, ULW_ALPHA);

            SelectObject(mem_dc, old_bmp);
            DeleteObject(dib);
        }

        DeleteDC(mem_dc);
    }

    HWND parent_ = nullptr;
    HWND handles_[4] = { nullptr };
    HDC screen_dc_ = nullptr;
    bool hidden_ = true;

    int last_win_x_ = 0;
    int last_win_y_ = 0;
    int last_win_w_ = 0;
    int last_win_h_ = 0;
    int last_size_ = 0;
};

} // namespace hemera::gui
