#pragma once

// Port of hemera/src/ffi.rs (commit 6175b67): the C ABI core/include/hemera_core.h declares --
// the embedding contract the GUI, the harness and any other supervisor drive the core through.
// Every entry point is here, with the Rust's job lifecycle, its polling and cancel semantics,
// its string ownership (the core allocates, hemera_string_free releases) and its error texts.
//
// What the Rust gets from its own crate, the port gets from the supervisor, because the sockets
// and the orchestrator are not in this module: Rust's ffi.rs spawns onto the crate's tokio
// runtime, reaches the network through api.rs and runs the whole core through lib.rs::run_with.
// The ported core is synchronous (localapi.hpp: "C++ work is synchronous"), so a job runs on a
// worker thread of its own, the engine work goes through localapi::Engine, run_with is a
// callback, and the ECH resolver socket is dns.hpp's EchTransport callback. The three are
// installed as one Host before the ABI is used; a call that would do engine work with no host
// installed fails with the Rust's own "could not start the async runtime", because the host is
// the port's counterpart of the runtime. Everything else -- the payload reading with serde's
// error wording, the reply envelope, the id counter, the three registries, the panic guard --
// is ported line for line.
//
// SECURITY. No reply, note or log line from this module carries a token, a key or a credential:
// team payloads travel through fields, tokens appear in replies only as the values the engine
// handed back, and the identity surface is IdentitySummary, which is the identity minus its
// secrets. hemera-masque.toml is never opened here; the only file this module names is the path
// a caller gives hemera_identity_open.

#include "../include/hemera_core.h"

#include "json.hpp"
#include "localapi.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace hemera::core::ffi {

// env!("CARGO_PKG_VERSION") of the pinned crate: what hemera_version reports.
inline constexpr std::string_view CORE_VERSION = "2.3.0";

// ffi.rs's `type Reply = Result<Value, String>`.
using Reply = std::expected<json::Value, std::string>;

// The work of one spawned job: Rust's `F: FnOnce(api::Cancel) -> Fut`. Cancellation is the
// cooperative one localapi.hpp documents: the work sees the flag and answers for it.
using JobWork = std::function<Reply(const localapi::Cancel& cancel)>;

// lib.rs::run_with, the whole-core run hemera_core_start drives. lib.rs is not ported yet, so
// the supervisor owns it; `cancel` must be honoured the way every engine method honours it.
using CoreRun = std::function<std::expected<void, localapi::ApiError>(
    const std::vector<std::string>& arguments, const localapi::Cancel& cancel)>;

// The supervisor's side of the ABI: everything ffi.rs reaches through tokio and the crate's own
// sockets, as three callbacks. `engine` must outlive every call and every job; a job started
// while no host is installed fails with "could not start the async runtime". A job that asks
// for ECH with no `ech_transport` fails with the NO_ECH_KEY error rather than going on: going
// on without a key would send the server name in the clear, and the Rust's lookup never skips
// silently either.
struct Host {
    localapi::Engine* engine = nullptr;
    CoreRun run_core;
    EchTransport ech_transport;
};

// Installs the host, replacing any earlier one. Jobs already running keep the host they read
// when they started. Safe to call from any thread.
void install_host(Host host);

// Drops the host: later calls that would do engine work report the runtime error above.
void clear_host();

// Whether a host with an engine is installed.
[[nodiscard]] bool host_installed();

// ---- The internals ffi.rs's own tests drive, exposed for tests/ffi_tests.cpp ----

// ffi.rs::spawn_job: registers a job under a fresh id, hands the work to a worker thread and
// answers {"job":id} right away. "could not start the async runtime" when no host is installed
// or no worker thread could start; in neither case does a job id leak into the registry.
[[nodiscard]] Reply spawn_job(JobWork work);

// ffi.rs::keep_identity: registers `identity` under a fresh handle and answers
// {"identity":handle,"summary":{...}} -- the summary, never the identity itself.
[[nodiscard]] json::Value keep_identity(Identity identity);

} // namespace hemera::core::ffi
