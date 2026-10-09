#pragma once

#include <stdint.h>

/* Hemera core, embedding contract.
 *
 * This mirrors the C ABI of the Rust core (hemera/src/ffi.rs) one call for one call, so the
 * GUI, the command line harness and the Rust engine all speak the same shapes.
 *
 * Every function that returns char* returns a heap-allocated, NUL-terminated UTF-8 JSON
 * string. The caller must release it with hemera_string_free and must not free it any other
 * way: it is allocated by the core, which may use a different heap than the caller.
 *
 * A reply is either
 *   {"ok":true, ...result fields}
 * or
 *   {"ok":false,"error":"one human-readable sentence"}
 *
 * An error reply never leaves a half-built state behind: the call either started the work or
 * did nothing at all. Long-running work returns a job handle right away and is polled:
 *   {"ok":true,"state":"running"}
 *   {"ok":true,"state":"done","result":{...}}
 * A job keeps running until it is cancelled or freed; polling after a free is an error.
 *
 * Handles (identity, job, session) are process-wide, unique, and never reused. They stay valid
 * until the matching *_free call, and are not valid across process restarts.
 *
 * Every function is safe to call from any thread. None of them block on the network: work that
 * would has to go through a job handle.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* {"version":"<core version>"} */
char* hemera_version(void);

/* Releases a string returned by any other call in this header. NULL is ignored. */
void hemera_string_free(char* raw);

/* --- jobs --- */

/* Polls a job. Error when the id is unknown. */
char* hemera_job_poll(uint64_t id);

/* Asks a running job to stop. It keeps its result until hemera_job_free. */
char* hemera_job_cancel(uint64_t id);

/* Stops a job if it is still running and drops the handle. Freeing an unknown id is not an error. */
char* hemera_job_free(uint64_t id);

/* --- identity --- */

/* Loads an identity from `path`, registering it first when the file is absent.
 * payload: {"path":string, "transport":"masque"|"wg", "model":string, "locale":string,
 *           "team":{"team":string,"client_id":string,"client_secret":string,
 *                   "token":string,"email":string}}
 * result:  {"identity":handle,"summary":{...},"path":string,"lastconn_path":string}
 * Only "path" is required; the rest fall back to the core defaults. */
char* hemera_identity_open(const char* payload);

/* The non-secret view of an identity: device and tunnel addresses, organisation, gateway,
 * assigned endpoint, whether a MASQUE client certificate is present, when it was issued,
 * and whether it is still inside its lifetime. */
char* hemera_identity_summary(uint64_t id);

/* Drops the handle. The identity file on disk is left alone. */
char* hemera_identity_free(uint64_t id);

/* --- route discovery --- */

/* Scans for a working gateway.
 * payload: {"transport":"masque"|"wg", "mode":"turbo"|"balanced"|"thorough"|"verified"|"ironclad",
 *           "ip":"v4"|"v6"|"both", "profile":string, "ports":[uint16], "excluded":[ip:port],
 *           "ech":bool}
 * result:  {"endpoint":"ip:port"} */
char* hemera_scan_start(uint64_t identity, const char* payload);

/* Opens a tunnel to one endpoint and proves traffic actually goes through it.
 * payload: {"peer":"ip:port", "transport":"masque"|"wg", "socks":"ip:port", "http":"ip:port",
 *           "profile":string, "keepalive":uint16, "ech":bool}
 * result:  {"reachable":bool} */
char* hemera_verify_start(uint64_t identity, const char* payload);

/* Carries traffic until it is cancelled or the tunnel dies. "peer" is required.
 * result:  {"state":"closed"} on a clean shutdown, {"state":"stopped"} when cancelled */
char* hemera_tunnel_start(uint64_t identity, const char* payload);

/* Runs the whole core from command-line arguments, exactly as the hemera binary would.
 * arguments: a JSON array of strings, or NULL for an empty list.
 * result:    {"state":"closed"} or {"state":"stopped"} */
char* hemera_core_start(const char* arguments);

/* --- Zero Trust enrolment --- */

/* payload: {"team":string,"client_id":string,"client_secret":string,"token":string,"email":string}
 * result:  {"token":"<enrolment jwt>"} */
char* hemera_team_sign_in(const char* payload);

/* Starts an emailed one-time-code sign-in. "email" is required.
 * result:  {"session":handle,"email":string} */
char* hemera_team_code_request(const char* payload);

char* hemera_team_code_resend(uint64_t session);

/* result: {"token":"<enrolment jwt>"} */
char* hemera_team_code_submit(uint64_t session, const char* code);

char* hemera_team_session_free(uint64_t id);

char* hemera_team_token_set(const char* token);

char* hemera_team_token_clear(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
