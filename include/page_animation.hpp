#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d2d1.h>
#include <algorithm>
#include <cmath>

namespace hemera::gui {

/// Principled Cascading Page Rise Animation Controller
/// Replicates the CSS .rise specification:
///   from { opacity: 0; transform: translateY(14px); }
///   to   { opacity: 1; transform: none; }
///   duration: 0.60s, easing: cubic-bezier(0.2, 0.7, 0.2, 1.0)
class PageAnimationController {
public:
    struct ItemAnim {
        float dy = 0.0f;       ///< Vertical translation offset in scaled pixels
        float opacity = 0.0f;  ///< Alpha multiplier [0.0f, 1.0f]
        bool visible = false;  ///< False if still before start delay
    };

    PageAnimationController() noexcept = default;

    /// Reset animation clock (called whenever switching views)
    void reset() noexcept {
        elapsed_ = 0.0f;
    }

    /// Advance elapsed time by delta seconds
    void step(float dt) noexcept {
        elapsed_ += dt;
    }

    /// True if animations are actively progressing
    bool is_active(float max_duration = 1.05f) const noexcept {
        return elapsed_ < max_duration;
    }

    float elapsed() const noexcept {
        return elapsed_;
    }

    /// Compute animation state for a component given its cascade delay
    ItemAnim compute(float delay_sec, UINT cur_dpi, float distance_px = 14.0f, float duration_sec = 0.55f) const noexcept {
        if (elapsed_ >= delay_sec + duration_sec) {
            return { 0.0f, 1.0f, true };
        }
        if (elapsed_ < delay_sec) {
            float dpi_scale = static_cast<float>(cur_dpi) / 96.0f;
            return { distance_px * dpi_scale, 0.0f, false };
        }

        float t = std::clamp((elapsed_ - delay_sec) / duration_sec, 0.0f, 1.0f);
        // Silky cubic-bezier(0.2, 0.7, 0.2, 1.0) ease-out curve matching CSS .rise
        float inv = 1.0f - t;
        float progress = 1.0f - inv * inv * inv * (1.0f + 0.35f * t);
        float dpi_scale = static_cast<float>(cur_dpi) / 96.0f;
        float dy = distance_px * dpi_scale * (1.0f - progress);
        float opacity = std::clamp(progress, 0.0f, 1.0f);

        return { dy, opacity, opacity > 0.005f };
    }

private:
    float elapsed_ = 0.0f;
};

/// Semantic cascading delay constants for consistent UI timing (distinct 60ms waterfall wave)
namespace anim_delay {
    constexpr float Header    = 0.00f; ///< Pinned or top header controls
    constexpr float Primary   = 0.06f; ///< Primary hero block / top cards
    constexpr float Secondary = 0.12f; ///< Main interactive card / terminal
    constexpr float Tertiary  = 0.18f; ///< Secondary card / resources / details
    constexpr float Quaternary= 0.24f; ///< Network / links / extra controls
    constexpr float Quinary   = 0.30f; ///< Zero Trust / secondary cards
    constexpr float Senary    = 0.36f; ///< About row
    constexpr float Footer    = 0.42f; ///< Footers & captions
}

} // namespace hemera::gui
