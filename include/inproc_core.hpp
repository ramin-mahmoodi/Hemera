#pragma once

#include "localapi.hpp"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <string_view>
#include <cstdint>

namespace aether::core {

using localapi::Cancel;

struct InprocCallbacks {
    std::function<void(std::string_view)> on_log;
    std::function<void(const std::string& state)> on_state_changed;
    std::function<void(uint64_t up_bytes, uint64_t down_bytes, uint64_t uptime_secs)> on_stats;
};

// Runs the Aether proxy core engine synchronously on the calling thread until cancelled or terminated.
int run_inproc(const std::vector<std::string>& args,
               const std::map<std::string, std::string>& settings_env,
               Cancel& cancel,
               InprocCallbacks callbacks = InprocCallbacks{});

} // namespace aether::core
