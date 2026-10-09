#pragma once

// Port of the sending half of aether/src/https.rs: `send`, its `exchange`, and the two carriers the
// handshake hands the request to. The shapes it sends with -- the request, the answer's grammar, the
// header block -- are https.hpp's; the ClientHello it shapes is tls.hpp's `Fingerprint`, which is
// what puts GREASE, the extension permutation, the groups and the cipher rule on the context. There
// is no second TLS builder here: `configuration()` is a client context and one call to
// `Fingerprint::apply`, exactly as https.rs:139-149 writes it.
//
// It is blocking and thread-based, as the rest of this port is: a raw Winsock TCP socket, BoringSSL
// driven over a memory BIO pair, and one deadline that covers the resolve, the connect, the
// handshake and the whole exchange -- which is what `tokio::time::timeout` around `exchange` is in
// the Rust. Nothing here waits on an event loop, and nothing here outlives the call.

#include "https.hpp"
#include "settings.hpp"
#include "tls.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace aether::core::https {

// What the exchange reads without owning: the settings the Rust core takes off the process
// environment at dial time -- AETHER_UPSTREAM among them -- and a sink for the lines it logs.
struct Call {
    // Null means the environment, which is how https.rs's `dial` reaches `upstream::configured()`.
    const Settings* settings = nullptr;
    // The Rust's `log::` lines in the order it writes them: the proxy the dialling went through and
    // the ECH retry. Left out, they are dropped, which is what a caller that logs nothing wants.
    std::vector<std::string>* notes = nullptr;
};

// Sends `request` with the TLS fingerprint `fingerprint`, and gives up after `timeout`. With `ech`,
// an ECHConfigList, the handshake offers it and goes no further without it: a server that turns it
// down hands back the key it holds now, which takes its place in `ech`, and the handshake is made
// once more with that one. A null `ech` -- or one pointing at an empty optional, which is the same
// Rust `None` a caller gets out of `Option<Vec<u8>>::as_mut` -- asks for no ECH at all.
//
// The error is the text an `AetherError` would print, kind prefix and all: "tls: handshake with
// api.cloudflareclient.com: ...", "ech: the handshake went without ECH", "api: ... did not answer
// within 20s".
[[nodiscard]] std::expected<Response, std::string>
send(const Request& request, const Fingerprint& fingerprint,
     std::optional<std::vector<std::uint8_t>>* ech, std::chrono::milliseconds timeout,
     const Call& call = {});

} // namespace aether::core::https
