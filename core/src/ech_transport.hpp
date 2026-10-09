#pragma once

// The live side of dns.hpp's EchTransport: the HTTPS-record query goes out over a real socket
// -- UDP or TCP straight at the resolver, or DNS-over-HTTPS through https_runtime::send -- and
// the ech parameter comes back out of the answer. One attempt per call inside five seconds for
// UDP/TCP (a resolver that needs longer is down for the purposes of a session start) and ten
// for DoH; an unanswered lookup is the empty error fetch_ech_config reads as "did not answer".

#include "dns.hpp"
#include "settings.hpp"

namespace hemera::core {

[[nodiscard]] EchTransport default_ech_transport(const Settings& settings);

} // namespace hemera::core
