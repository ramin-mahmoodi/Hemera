#pragma once

#include "identity.hpp"
#include "settings.hpp"

#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace hemera::core::zerotrust {

// Port of hemera/src/zerotrust.rs, commit 6175b67: how a device signs in to a Cloudflare Zero
// Trust team and comes back holding an enrolment token. What the token is then spent on -- the
// registration body, the device keys, the account file -- is the account layer's, and identity.hpp
// already carries the account itself.
//
// Everything that only thinks is ported here: the team name, the URLs, the requests with their
// field names, the HTML and cookie and JWT reading, the code prompt wording, the attempt and
// expiry arithmetic, and the session's token cache. What needs a socket or a terminal is two
// callbacks the engine answers, the same way dns.hpp hands the ECH lookup to the egress layer:
// `AccessHttp` for the HTTP exchange and `CodePrompt` for the login code. Neither is faked, and no
// request leaves this module until the engine says what came back.
//
// SECURITY. An access token, a client secret, a login code or a nonce never enters an error string,
// a log line or a note -- zerotrust.rs never prints them either, and the checks here keep it that
// way. `redacted()` is the only rendering of a value that carries one, and it reports lengths.
// Nothing here reads or writes hemera-masque.toml; the token goes to the account layer, which
// decides where it lands (Identity's access_token field, written by save_identity()).

// -- Names, paths and limits a caller reads --------------------------------------------------

// The domain a team's enrolment page hangs under.
inline constexpr std::string_view TEAM_SUFFIX = "cloudflareaccess.com";
// The path on it the device is opened at.
inline constexpr std::string_view ENROLL_PATH = "/warp";
// The one path a login code is confirmed at, spelled out of the team domain in Rust.
inline constexpr std::string_view CALLBACK_PATH = "/cdn-cgi/access/callback";
// The line a non-interactive run prints when it wants a code, so a wrapper can spot the ask.
inline constexpr std::string_view CODE_PROMPT_MARKER = "[zerotrust] login-code-needed";

// The marker a token follows on an enrolment page.
inline constexpr std::string_view JWT_MARKER = "token=";
// The cookie Access puts the enrolment token in, and the lower-case spelling Rust also accepts.
inline constexpr std::string_view AUTH_COOKIE = "CF_Authorization=";
inline constexpr std::string_view AUTH_COOKIE_LOWER = "cf_authorization=";
// The two service-token headers, by name; their values are the secret halves.
inline constexpr std::string_view CLIENT_ID_HEADER = "CF-Access-Client-Id";
inline constexpr std::string_view CLIENT_SECRET_HEADER = "CF-Access-Client-Secret";
// A token shorter than this is no JWT, whatever else it looks like.
inline constexpr std::size_t JWT_MIN_LEN = 32;
// An HTML entity is at most this many bytes between the `&` and the `;`.
inline constexpr std::size_t ENTITY_MAX_LEN = 8;

// How long one enrolment request may take (Rust's Duration::from_secs(20)).
inline constexpr int AUTH_TIMEOUT_MS = 20000;
// How long a non-interactive run waits for a code to be typed back (300s). An interactive read is
// waited on forever; `0` in `CodePromptAsk::wait_secs` says so.
inline constexpr std::uint64_t CODE_WAIT_SECS = 300;
// A login code is tried this many times before the flow gives up. No sleeping between them: the
// only retry arithmetic in zerotrust.rs is this count and the attempts left in the note.
inline constexpr std::uint32_t CODE_ATTEMPTS = 3;
// The install id the registration names the device by, and the length of the random tail of an
// FCM token. Together they fix the token's length at INSTALL_ID_LEN + 1 + 6 + FCM_SUFFIX_LEN.
inline constexpr std::size_t INSTALL_ID_LEN = 22;
inline constexpr std::size_t FCM_SUFFIX_LEN = 134;
inline constexpr std::string_view FCM_TOKEN_PREFIX = ":APA91b";

// The settings the enrolment reads. `Settings` carries them under exactly these keys, which are
// the environment names the Rust core reads.
inline constexpr std::string_view TEAM_ENV = "HEMERA_TEAM";
inline constexpr std::string_view CLIENT_ID_ENV = "HEMERA_ACCESS_CLIENT_ID";
inline constexpr std::string_view CLIENT_SECRET_ENV = "HEMERA_ACCESS_CLIENT_SECRET";
inline constexpr std::string_view TOKEN_ENV = "HEMERA_ACCESS_TOKEN";
inline constexpr std::string_view EMAIL_ENV = "HEMERA_ACCESS_EMAIL";

// -- The team, and what the caller handed with it --------------------------------------------

// One team and however the caller said to sign in to it. `team` is always normalized; the four
// options are what arrived, trimmed and non-empty or absent.
struct TeamSettings {
    std::string team;
    std::optional<std::string> client_id;
    std::optional<std::string> client_secret;
    std::optional<std::string> token;
    std::optional<std::string> email;

    // The four settings read off `settings`, as `TeamSettings::from_env` reads them off the
    // environment. Nothing when no team name in there can be normalized -- which is the Rust's
    // "no Zero Trust at all", not an error.
    [[nodiscard]] static std::optional<TeamSettings> from_env(const Settings& settings);

    // Both halves of a service token, which is the only way it works.
    [[nodiscard]] bool has_service_token() const;
    [[nodiscard]] std::string team_domain() const;
    [[nodiscard]] std::string login_url() const;
};

// A team name as it was written -- bare, a domain, an enrolment URL, in either case, with any
// number of trailing dots or slashes -- or nothing when it is no team name at all. Only letters,
// digits, '-' and '_' survive.
[[nodiscard]] std::optional<std::string> normalize_team(std::string_view raw);

// `https://<team>.cloudflareaccess.com`, however `team` got there.
[[nodiscard]] std::string team_domain(std::string_view team);

// How the settings read with their secrets left out: the team and the email as they are, every
// credential as its length or `unset`. The only rendering of a TeamSettings anything should log.
[[nodiscard]] std::string redacted(const TeamSettings& settings);

// -- JWT reading -----------------------------------------------------------------------------

// A trimmed, 32-byte-long, three-part, base64url token whose header decodes. The whole char set is
// checked, so a padded or spaced-out value is refused.
[[nodiscard]] bool looks_like_jwt(std::string_view token);

// `exp` of a token's payload, as the integer it holds. Nothing when the token is no three segments,
// its payload is no base64url JSON, or the claim is missing or is no whole non-negative number --
// which `jwt_expired` then reads as never expiring.
[[nodiscard]] std::optional<std::uint64_t> jwt_expiry(std::string_view token);

// A token is expired once its `exp` is now or behind it; one with no `exp` claim is never expired.
[[nodiscard]] bool jwt_expired(std::string_view token, std::uint64_t now);

// The token in `html`, the value that follows the first `token=` up to the first `"`, `'`, `&`, `<`
// or space. Nothing when no such value looks like a JWT.
[[nodiscard]] std::optional<std::string> extract_jwt_from_html(std::string_view html);

// The token in one `Set-Cookie` header: the value of a `CF_Authorization=` entry. The scan stops at
// the first `;`-separated part that is no such entry, which is what Rust's `?` does inside the loop,
// so a cookie that leads with something else yields nothing however far the token is behind it.
[[nodiscard]] std::optional<std::string> extract_jwt_from_cookie(std::string_view header);

// -- The device's own identifiers --------------------------------------------------------------

// The 22 alphanumeric characters a registration names this install by.
[[nodiscard]] std::string generate_install_id();

// The install id, a `:` and an FCM token's `APA91b` tail of 134 more characters.
[[nodiscard]] std::string generate_fcm_token(std::string_view install_id);

// Random alphanumeric text of `len` characters, from the same 62-symbol alphabet.
[[nodiscard]] std::string random_alphanumeric(std::size_t len);

// -- The enrolment page, read as text ----------------------------------------------------------

// The `action` of the page's `id="totp-form"` form, entities decoded, and only when it is an
// `https://` URL. This is where an email one-time code is asked for.
[[nodiscard]] std::optional<std::string> extract_totp_form_action(std::string_view html);

// The named and numeric HTML entities in `raw` (`&amp;`, `&#x2F;`, `&#39;`, ...), each of at most
// ENTITY_MAX_LEN bytes; anything else keeps its `&`.
[[nodiscard]] std::string decode_entities(std::string_view raw);

// `key` of `key=value` in the query part of `url`, percent decoded. A pair with no `=` stops the
// search, as Rust's `?` does, so a query that carries one after it yields nothing.
[[nodiscard]] std::optional<std::string> query_value(std::string_view url, std::string_view key);

// -- What the engine has to answer -------------------------------------------------------------

// One form field or header: the name the Rust code writes, and its value, which may be a secret.
struct AccessField {
    std::string name;
    std::string value;
};

// A request the enrolment is asking for. The engine owns the client: it sends it with
// `UA_REGISTER` (consts.hpp) as the user agent, `AUTH_TIMEOUT_MS` as the timeout, server-certificate
// verification off -- zerotrust.rs sets `danger_accept_invalid_certs(true)` unconditionally -- and
// through the `HEMERA_UPSTREAM` proxy when one is configured, which is all `through_upstream` does.
// `follow_redirects` and `keep_cookies` say which of the two clients the Rust builds is meant: the
// email flow's keeps a cookie jar and follows redirects, the service-token one keeps neither.
// `form` is the urlencoded body, fields in the order they are listed, percent-encoded by the engine;
// empty means a bodyless GET.
struct AccessRequest {
    std::string method; // "GET" or "POST"
    std::string url;
    std::vector<AccessField> headers;
    std::vector<AccessField> form;
    bool follow_redirects = true;
    bool keep_cookies = false;
};

// What came back. `final_url` is where the redirects ended (the Rust reads `landing.url()`), and
// `set_cookie` holds every `Set-Cookie` header in order, values the engine can give as text only --
// Rust skips a header whose bytes are no text. A body the engine could not read leaves `body` empty
// and says how in `body_error`, because the four call sites treat that differently: two of them
// stop on it, two of them carry on with nothing.
struct AccessResponse {
    std::uint16_t status = 0;
    std::string final_url;
    std::vector<std::string> set_cookie;
    std::string body;
    std::optional<std::string> body_error;
};

// The exchange itself. The error is the transport's own message, which this module puts behind the
// prefix of the call site; it must not repeat a header or form value from the request.
using AccessHttp =
    std::function<std::expected<AccessResponse, std::string>(const AccessRequest& request)>;

// A request builder, one per call site, so the shape of what goes out is checkable without a
// socket. These are the whole of the outbound side; `AccessHttp` only carries them.
[[nodiscard]] AccessRequest landing_request(const std::string& login_url);
[[nodiscard]] AccessRequest service_token_request(const std::string& login_url,
                                                 std::string_view client_id,
                                                 std::string_view client_secret);
[[nodiscard]] AccessRequest code_request(std::string_view verify_url, std::string_view email);
[[nodiscard]] AccessRequest callback_request(const std::string& domain, std::string_view code,
                                             std::string_view nonce);

// A request as the log may show it: method, URL, and for every header and form field its name --
// the values only where they are no secret, which is the email and nothing else.
[[nodiscard]] std::string redacted(const AccessRequest& request);

// What a `Set-Cookie` name is, and its value, is decided by the engine; these two say which form
// field values are secret, so `redacted` and the callers agree.
[[nodiscard]] bool is_secret_field(std::string_view name);

// The status as Rust's `{status}` writes it: the number and, for a code with a canonical reason,
// that reason -- `403 Forbidden`. An unknown code is the number alone.
[[nodiscard]] std::string status_display(std::uint16_t status);

// 200 through 299, which is all `status.is_success()` asks.
[[nodiscard]] bool status_is_success(std::uint16_t status);

// How far a code is waited for: never on a terminal, CODE_WAIT_SECS on a pipe.
enum class CodeRead {
    Line,    // a line came back, in `line`
    Closed,  // nothing is coming: end of input, or the pipe closed
    Failed,  // the read itself failed
    TimedOut // CODE_WAIT_SECS went by with nothing typed
};

// What the engine is being asked to do: show `banner`, then read a line. `wait_secs` is 0 when the
// read has no deadline, which only happens when `interactive`.
struct CodePromptAsk {
    std::string email;
    std::uint32_t attempt = 1;
    bool interactive = false;
    std::string banner;
    std::uint64_t wait_secs = CODE_WAIT_SECS;
};

struct CodePromptReply {
    CodeRead read = CodeRead::Closed;
    std::string line;
};

// The terminal read. The engine prints `banner` and answers what its stdin does; every word the
// flow then says about that answer is decided by `code_prompt_result`, not here.
using CodePrompt = std::function<CodePromptReply(const CodePromptAsk& ask)>;

// The line a non-interactive run prints: marker, attempt number, address. No newline in it.
[[nodiscard]] std::string code_prompt_line(std::string_view email, std::uint32_t attempt);

// What goes to the user, verbatim as the Rust builds it: on a terminal a whole-line ask, the first
// of them worded differently from a retry; off one, `code_prompt_line` and a newline.
[[nodiscard]] std::string code_banner(bool interactive, std::string_view email,
                                      std::uint32_t attempt);

// The whole ask for one attempt: banner, deadline and all.
[[nodiscard]] CodePromptAsk code_prompt_ask(std::string_view email, std::uint32_t attempt,
                                           bool interactive);

// What the answer means: the code, or the error the Rust returns for that outcome. An empty or
// whitespace-only line is no code entered.
[[nodiscard]] std::expected<std::string, std::string> code_prompt_result(const CodePromptAsk& asked,
                                                                        const CodePromptReply& got);

// Everything outside this module the flow needs.
struct Hooks {
    AccessHttp http;
    CodePrompt code_prompt;
    // stdin().is_terminal(): which banner is shown, whether the read has a deadline, and which
    // words a closed read is reported in.
    bool interactive = false;
};

// -- The flow, as states and transitions -------------------------------------------------------

// How `sign_in` reaches a token, in the order zerotrust.rs tries them. `None` is the refusal: a
// team with no way to sign in, which stops the flow before any request is made.
enum class Method { None, SuppliedToken, ServiceToken, EmailCode };

[[nodiscard]] Method sign_in_method(const TeamSettings& settings);

// Where the enrolment stands, read off the settings and the session cache -- the same two things
// resolve_token looks at, so a caller can show this without driving the flow.
enum class Stage {
    NoTeam,    // nothing to enrol: no team name the flow would accept
    Cached,    // this session already holds a token that has not expired
    NoMethod,  // a team, and no way in: sign_in refuses it
    SuppliedToken,
    ServiceToken,
    EmailCode,
};

[[nodiscard]] Stage stage_of(const TeamSettings& settings, bool cache_holds_token);
[[nodiscard]] std::string_view label(Stage stage);

// Attempts left after `attempt` (1-based), which is what the note between tries counts down. Never
// below zero, where Rust's subtraction would have panicked had the loop run on.
[[nodiscard]] std::uint32_t attempts_left(std::uint32_t attempt);

// A code the callback answered with: the token it issued, or the status it refused it at.
struct CodeOutcome {
    enum class Kind { Token, Rejected };

    Kind kind = Kind::Rejected;
    std::string token;      // empty for a refusal
    std::uint16_t status = 0; // the refused status

    [[nodiscard]] static CodeOutcome accepted(std::string token);
    [[nodiscard]] static CodeOutcome refused(std::uint16_t status);
    [[nodiscard]] bool accepted() const { return kind == Kind::Token; }
};

// -- The email one-time-code session ------------------------------------------------------------

// An email code that is out: the page's verify URL, the address, and the nonce the code is tied to.
// The client is the engine's callback, held so a resend and a submit need no arguments.
class EmailSignIn {
public:
    EmailSignIn() = default;
    EmailSignIn(AccessHttp http, std::string team, std::string email, std::string nonce,
                std::string verify_url);

    [[nodiscard]] const std::string& team() const { return team_; }
    [[nodiscard]] const std::string& email() const { return email_; }
    [[nodiscard]] const std::string& verify_url() const { return verify_url_; }
    [[nodiscard]] const std::string& nonce() const { return nonce_; }

    // Ask for another code. A fresh nonce replaces the held one; when the answer carries none the
    // old nonce stays, and the call still counts as a success, exactly as Rust's `if let`.
    std::expected<void, std::string> resend_code(std::vector<std::string>& notes);

    // Post the code with the nonce. An empty code is refused before anything is sent. A code the
    // callback does not take is a `CodeOutcome`, not an error, and its status is in it.
    [[nodiscard]] std::expected<CodeOutcome, std::string> submit_code(
        std::string_view code, std::vector<std::string>& notes) const;

private:
    AccessHttp http_;
    std::string team_;
    std::string email_;
    std::string nonce_;
    std::string verify_url_;
};

// Open the team's enrolment page, find its email-code form on it, and ask it to email a code to
// `email`. The address is trimmed; blank is refused before the page is opened.
[[nodiscard]] std::expected<EmailSignIn, std::string> begin_email_signin(
    const TeamSettings& settings, std::string_view email, const AccessHttp& http,
    std::vector<std::string>& notes);

// Ask `verify_url` for a code for `email`, and read the nonce back off the URL the answer ended at,
// or off `fallback_url` if that one carries none. A refusal status is an error; a success with no
// nonce anywhere is nothing, which the caller decides what to make of.
[[nodiscard]] std::expected<std::optional<std::string>, std::string> request_email_code(
    const AccessHttp& http, std::string_view verify_url, std::string_view email,
    const std::optional<std::string>& fallback_url, std::vector<std::string>& notes);

// The whole email flow: a session, then up to CODE_ATTEMPTS codes asked for through the hook and
// posted, keeping the last status the callback answered with.
[[nodiscard]] std::expected<std::string, std::string> fetch_token_with_email_code(
    const TeamSettings& settings, std::string_view email, const Hooks& hooks,
    std::vector<std::string>& notes);

// The service-token exchange: one request with both headers, then the token out of a `Set-Cookie`
// or out of the body.
[[nodiscard]] std::expected<std::string, std::string> fetch_token_with_service_token(
    const TeamSettings& settings, const AccessHttp& http, std::vector<std::string>& notes);

// One login code asked for through the hook. Exposed because the loop in
// fetch_token_with_email_code is not the only way to want one.
[[nodiscard]] std::expected<std::string, std::string> prompt_login_code(
    const Hooks& hooks, std::string_view email, std::uint32_t attempt,
    std::vector<std::string>& notes);

// Which of the four ways sign_in takes, and why: a supplied token as it stands, else the service
// token, else the email code, else the refusal naming all three.
[[nodiscard]] std::expected<std::string, std::string> sign_in(const TeamSettings& settings,
                                                             const Hooks& hooks,
                                                             std::vector<std::string>& notes);

// -- The session's token cache -------------------------------------------------------------------

// resolve_token's one step: a live cached token is reused, an expired one is dropped first, and a
// fresh token from sign_in goes into the cache for the rest of the session. `notes` gets the two
// debug lines the Rust logs about the cache.
[[nodiscard]] std::expected<std::string, std::string> resolve_token(const TeamSettings& settings,
                                                                   const Hooks& hooks,
                                                                   std::vector<std::string>& notes);

// A token handed over by hand: trimmed, then checked for shape and for expiry before it is cached.
// Both errors name the value's problem, never the value.
[[nodiscard]] std::expected<void, std::string> store_token(std::string_view token);

// The cached token, when there is one and it has not expired.
[[nodiscard]] std::optional<std::string> cached_token();

void clear_token();

} // namespace hemera::core::zerotrust
