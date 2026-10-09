#pragma once

namespace aether::autostart {

// Returns true if autostart at Windows user login is enabled
bool is_enabled();

// Enables or disables autostart with the --minimized flag
bool set_enabled(bool enable);

} // namespace aether::autostart
