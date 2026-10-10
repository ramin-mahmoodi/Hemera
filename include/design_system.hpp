#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objidl.h>
#include <d2d1.h>
#include <dwrite.h>
#include <string>
#include <algorithm>

namespace hemera::gui::ds {

struct Color : D2D1_COLOR_F {
    constexpr Color() noexcept : D2D1_COLOR_F{0.0f, 0.0f, 0.0f, 1.0f} {}
    constexpr Color(float r_, float g_, float b_, float a_ = 1.0f) noexcept : D2D1_COLOR_F{r_, g_, b_, a_} {}
    constexpr Color(int a_, int r_, int g_, int b_) noexcept
        : D2D1_COLOR_F{
            static_cast<float>(r_) / 255.0f,
            static_cast<float>(g_) / 255.0f,
            static_cast<float>(b_) / 255.0f,
            static_cast<float>(a_) / 255.0f
        } {}

    BYTE GetA() const noexcept { return static_cast<BYTE>(std::clamp(a * 255.0f + 0.5f, 0.0f, 255.0f)); }
    BYTE GetR() const noexcept { return static_cast<BYTE>(std::clamp(r * 255.0f + 0.5f, 0.0f, 255.0f)); }
    BYTE GetG() const noexcept { return static_cast<BYTE>(std::clamp(g * 255.0f + 0.5f, 0.0f, 255.0f)); }
    BYTE GetB() const noexcept { return static_cast<BYTE>(std::clamp(b * 255.0f + 0.5f, 0.0f, 255.0f)); }
};

inline D2D1_COLOR_F to_d2d(const Color& c) noexcept {
    return c;
}

inline D2D1_COLOR_F to_d2d_alpha(const Color& c, float alpha_mult) noexcept {
    return D2D1::ColorF(c.r, c.g, c.b, c.a * std::clamp(alpha_mult, 0.0f, 1.0f));
}

enum class ThemeMode {
    System,
    Light,
    Dark
};

// Check Windows registry for OS Light / Dark mode
inline bool is_windows_dark_mode() {
    DWORD data = 0;
    DWORD dataSize = sizeof(data);
    LONG res = RegGetValueW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme",
        RRF_RT_REG_DWORD,
        nullptr,
        &data,
        &dataSize
    );
    if (res == ERROR_SUCCESS) {
        return (data == 0); // 0 = dark mode, 1 = light mode
    }
    return true; // Default to dark mode
}

// ---- Color Palette Tokens (Matching tokens.css exactly) -----------------------------
struct ColorTokens {
    // Canvas & Surfaces
    Color bg;                  // Window background (--bg)
    Color card_bg;             // Surface / card background (--surface)
    Color btn_bg;              // Button background idle (--btn)
    Color btn_on_bg;           // Button background connected (--btn-on)
    Color chip_bg;             // Active chip / segmented control (--chip)
    Color hover_bg;            // General hover background (--hov)

    // Borders
    Color card_border;         // Primary border (--bd)
    Color btn_border;          // Secondary border (--bd2)
    Color btn_border_dim;      // Tertiary border (--bd3)
    Color border_hover;        // Border hover (--bdh)
    Color border_hover_bright; // Border hover bright (--bdh2)
    Color divider;             // Inner row divider (--bd)

    // Typography & Icons
    Color text_primary;        // High-contrast text (--tx)
    Color text_secondary;      // Secondary text (--tx2)
    Color icon_color;          // Neutral icon stroke (--ic)
    Color text_muted;          // Subtitles & labels (--mu)
    Color text_submuted;       // Metric header tags (--mu2)
    Color text_dim;            // Footnotes & captions (--fa)

    // Accent (Teal + Indigo)
    Color accent;              // Primary accent (--ac: Teal)
    Color accent_ram;          // Secondary accent (--ac2: RAM line, Indigo)
    Color accent_bg;           // Accent button background (--btn-on)
    Color accent_hover;        // Accent button hover
    Color info;                // Info tag / cyan (--info)
    Color warning;             // Warning (--warn)
    Color error;               // Error (--err)

    // Hero Power Button
    Color hero_idle_bg;
    Color hero_idle_border;
    Color hero_idle_icon;

    // Glow effects
    Color hero_glow_on_inner;
    Color hero_glow_on_outer;
    Color hero_glow_err_inner;
    Color hero_glow_err_outer;
    Color hero_glow_off;

    // Ambient background radial glows
    Color gl_idle;
    Color gl_conn;
    Color gl_on;
    Color gl_err;
    Color gl_warn;

    // Dropdown & Popups
    Color dropdown_bg;
    Color dropdown_hover;
    Color dropdown_border;

    // Win32 GDI COLORREF
    COLORREF win_bg   = RGB(11, 11, 13);
    COLORREF win_card = RGB(14, 14, 17);
    COLORREF win_text = RGB(237, 237, 237);
};

inline ColorTokens get_dark_tokens() {
    ColorTokens t;
    t.bg                  = { 255,  11,  11,  13 }; // #0B0B0D
    t.card_bg             = { 255,  14,  14,  17 }; // #0E0E11
    t.btn_bg              = { 255,  16,  16,  19 }; // #101013
    t.btn_on_bg           = { 255,  15,  26,  25 }; // #0F1A19
    t.chip_bg             = { 255,  23,  23,  27 }; // #17171B
    t.hover_bg            = { 255,  19,  19,  22 }; // #131316

    t.card_border         = { 255,  27,  27,  32 }; // #1B1B20
    t.btn_border          = { 255,  31,  31,  36 }; // #1F1F24
    t.btn_border_dim      = { 255,  38,  38,  44 }; // #26262C
    t.border_hover        = { 255,  42,  42,  48 }; // #2A2A30
    t.border_hover_bright = { 255,  52,  52,  59 }; // #34343B
    t.divider             = { 255,  27,  27,  32 };

    t.text_primary        = { 255, 237, 237, 237 }; // #EDEDED
    t.text_secondary      = { 255, 201, 201, 207 }; // #C9C9CF
    t.icon_color          = { 255, 161, 161, 170 }; // #A1A1AA
    t.text_muted          = { 255, 138, 138, 147 }; // #8A8A93
    t.text_submuted       = { 255, 122, 122, 130 }; // #7A7A82
    t.text_dim            = { 255, 113, 113, 122 }; // #71717A

    t.accent              = { 255,  94, 234, 212 }; // #5EEAD4 (Teal)
    t.accent_ram          = { 255, 165, 180, 252 }; // #A5B4FC (RAM sparkline Indigo)
    t.accent_bg           = { 255,  15,  26,  25 }; // #0F1A19
    t.accent_hover        = { 255,  24,  44,  40 };
    t.info                = { 255, 125, 211, 252 }; // #7DD3FC
    t.warning             = { 255, 251, 191,  36 }; // #FBBF24
    t.error               = { 255, 248, 113, 113 }; // #F87171

    t.hero_idle_bg        = { 255,  16,  16,  19 };
    t.hero_idle_border    = { 255,  38,  38,  44 };
    t.hero_idle_icon      = { 255, 138, 138, 147 };

    t.hero_glow_on_inner  = {  16,  94, 234, 212 };
    t.hero_glow_on_outer  = {  46,  94, 234, 212 };
    t.hero_glow_err_inner = {  18, 248, 113, 113 };
    t.hero_glow_err_outer = {  31, 248, 113, 113 };
    t.hero_glow_off       = {   4, 255, 255, 255 };

    t.gl_idle             = {  10, 255, 255, 255 }; // rgba(255,255,255,.04)
    t.gl_conn             = {  20,  94, 234, 212 }; // rgba(94,234,212,.08)
    t.gl_on               = {  41,  94, 234, 212 }; // rgba(94,234,212,.16)
    t.gl_err              = {  36, 248, 113, 113 }; // rgba(248,113,113,.14)
    t.gl_warn             = {  26, 251, 191,  36 }; // rgba(251,191,36,.10)

    t.dropdown_bg         = { 255,  14,  14,  17 };
    t.dropdown_hover      = { 255,  22,  22,  27 };
    t.dropdown_border     = { 255,  27,  27,  32 };

    t.win_bg   = RGB(11, 11, 13);
    t.win_card = RGB(14, 14, 17);
    t.win_text = RGB(237, 237, 237);
    return t;
}

inline ColorTokens get_light_tokens() {
    ColorTokens t;
    t.bg                  = { 255, 246, 246, 247 }; // #F6F6F7
    t.card_bg             = { 255, 255, 255, 255 }; // #FFFFFF
    t.btn_bg              = { 255, 255, 255, 255 }; // #FFFFFF
    t.btn_on_bg           = { 255, 230, 246, 243 }; // #E6F6F3
    t.chip_bg             = { 255, 234, 234, 238 }; // #EAEAEE
    t.hover_bg            = { 255, 239, 239, 241 }; // #EFEFF1

    t.card_border         = { 255, 228, 228, 231 }; // #E4E4E7
    t.btn_border          = { 255, 228, 228, 231 }; // #E4E4E7
    t.btn_border_dim      = { 255, 212, 212, 216 }; // #D4D4D8
    t.border_hover        = { 255, 207, 207, 214 }; // #CFCFD6
    t.border_hover_bright = { 255, 189, 189, 198 }; // #BDBDC6
    t.divider             = { 255, 228, 228, 231 };

    t.text_primary        = { 255,  24,  24,  27 }; // #18181B
    t.text_secondary      = { 255,  63,  63,  70 }; // #3F3F46
    t.icon_color          = { 255,  82,  82,  91 }; // #52525B
    t.text_muted          = { 255,  95,  95, 104 }; // #5F5F68
    t.text_submuted       = { 255, 107, 107, 116 }; // #6B6B74
    t.text_dim            = { 255, 113, 113, 122 }; // #71717A

    t.accent              = { 255,  11, 127, 114 }; // #0B7F72 (Teal)
    t.accent_ram          = { 255,  79,  70, 229 }; // #4F46E5 (RAM sparkline Indigo)
    t.accent_bg           = { 255, 230, 246, 243 }; // #E6F6F3
    t.accent_hover        = { 255, 209, 237, 232 };
    t.info                = { 255,   3, 105, 161 }; // #0369A1
    t.warning             = { 255, 180,  83,   9 }; // #B45309
    t.error               = { 255, 185,  28,  28 }; // #B91C1C

    t.hero_idle_bg        = { 255, 255, 255, 255 };
    t.hero_idle_border    = { 255, 212, 212, 216 };
    t.hero_idle_icon      = { 255,  95,  95, 104 };

    t.hero_glow_on_inner  = {  20,  11, 127, 114 };
    t.hero_glow_on_outer  = {  51,  11, 127, 114 };
    t.hero_glow_err_inner = {  18, 185,  28,  28 };
    t.hero_glow_err_outer = {  26, 185,  28,  28 };
    t.hero_glow_off       = {   8,   0,   0,   0 };

    t.gl_idle             = {  15,  11, 127, 114 }; // rgba(11,127,114,.06)
    t.gl_conn             = {  23,  11, 127, 114 }; // rgba(11,127,114,.09)
    t.gl_on               = {  41,  11, 127, 114 }; // rgba(11,127,114,.16)
    t.gl_err              = {  26, 185,  28,  28 }; // rgba(185,28,28,.10)
    t.gl_warn             = {  26, 180,  83,   9 }; // rgba(180,83,9,.10)

    t.dropdown_bg         = { 255, 255, 255, 255 };
    t.dropdown_hover      = { 255, 241, 241, 243 };
    t.dropdown_border     = { 255, 228, 228, 231 };

    t.win_bg   = RGB(246, 246, 247);
    t.win_card = RGB(255, 255, 255);
    t.win_text = RGB(24, 24, 27);
    return t;
}

inline ColorTokens get_tokens(ThemeMode mode) {
    if (mode == ThemeMode::Dark) return get_dark_tokens();
    if (mode == ThemeMode::Light) return get_light_tokens();
    return is_windows_dark_mode() ? get_dark_tokens() : get_light_tokens();
}

inline bool is_effective_dark(ThemeMode mode) {
    if (mode == ThemeMode::Dark) return true;
    if (mode == ThemeMode::Light) return false;
    return is_windows_dark_mode();
}

// ---- Geometry & Spacing Tokens (DIP values) -----------------------------------------------------
struct MetricTokens {
    int window_width          = 420; // 420 DIPs strictly matching artboard
    int window_height         = 720; // 720 DIPs strictly matching artboard
    int padding_x             = 28;  // 28 DIPs side padding
    int padding_top           = 36;  // 36 DIPs top padding (providing breathing room below Chrome caption buttons)
    int padding_bottom        = 24;  // 24 DIPs bottom padding

    int radius_card           = 16;  // 16 DIPs border-radius for cards
    int radius_control        = 12;  // 12 DIPs border-radius for buttons
    int radius_chip           = 22;  // 22 DIPs border-radius for pill chips

    int hero_diameter         = 176; // 176 DIPs circle
    int hero_icon_size        = 52;  // 52 DIPs power icon SVG
    int header_btn_size       = 44;  // 44x44 DIPs header icon buttons
    int status_box_height     = 64;  // 64 DIPs status text block
    int stats_box_height      = 56;  // 56 DIPs middle metrics section

    int row_height            = 52;  // 52 DIPs card row height
    int row_padding_x         = 18;  // 18 DIPs horizontal padding inside rows
    int dropdown_item_h       = 38;  // 38 DIPs dropdown item height
    int dropdown_radius       = 12;  // 12 DIPs dropdown card radius
};

// ---- Typography Tokens (Font Size in DIPs) ------------------------------------------------------
struct TypoTokens {
    int hero_status_title     = 26; // "Connected" / "Not connected"
    int view_title            = 20; // "Settings" / "Logs" / "About"
    int app_title             = 15; // "Hemera"
    int body_label            = 14; // Labels & values
    int mono_value            = 13; // Monospace values
    int footnote              = 12; // "Free and open source"
    int metric_tag            = 11; // "PING", "SPEED", "CPU", "RAM"
};

// ---- Design System Root ------------------------------------------------------------------------
struct DesignSystem {
    ColorTokens colors = get_dark_tokens();
    MetricTokens metrics;
    TypoTokens typo;
    ThemeMode active_theme = ThemeMode::Dark;

    void set_theme(ThemeMode mode) {
        active_theme = mode;
        colors = get_tokens(mode);
    }

    [[nodiscard]] static DesignSystem& get() {
        static DesignSystem instance;
        return instance;
    }
};

// DPI scaling helper
inline int scale(int dip, UINT dpi) {
    return MulDiv(dip, dpi, 96);
}

inline float scale_f(float dip, UINT dpi) {
    return (dip * static_cast<float>(dpi)) / 96.0f;
}

} // namespace hemera::gui::ds
