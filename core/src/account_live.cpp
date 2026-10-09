// Live exchange half of account.rs: api_call and the round trips over https_runtime::send.
// Blocking and thread-based, like the rest of this port: https::send owns its deadline, the
// retry sleeps are std::this_thread::sleep_for, and the cancel flag is only read between
// attempts -- a run in flight finishes its attempt first.

#include "account_live.hpp"

#include "consts.hpp"
#include "egress.hpp"
#include "encoding.hpp"
#include "https_runtime.hpp"
#include "socks.hpp"
#include "tls.hpp"
#include "upstream.hpp"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <thread>

namespace aether::core::account {

namespace {

 // coreflow.hpp's ECH_ENV, repeated here because that header includes account.hpp and the
 // dependency cannot point back.
constexpr std::string_view kEchEnv = "AETHER_ECH";

[[nodiscard]] std::string live_display(const LiveError& error) {
    switch (error.kind) {
        case LiveKind::IdentityRefused:
            return "identity refused: " + error.message;
        case LiveKind::Ech:
            return "ech: " + error.message;
        case LiveKind::Tls:
            return "tls: " + error.message;
        case LiveKind::Api:
            break;
    }
    return "api: " + error.message;
}

void emit_info(const LiveEnv& env, const std::string& line) {
    if (env.info) env.info(line);
}

void emit_warn(const LiveEnv& env, const std::string& line) {
    if (env.warn) env.warn(line);
}

void emit_debug(const LiveEnv& env, const std::string& line) {
    if (env.debug) env.debug(line);
}

void emit_notes(const LiveEnv& env, const std::vector<std::string>& notes, bool warn) {
    for (const auto& line : notes) {
        if (warn) emit_warn(env, line);
        else if (line.starts_with("[zerotrust]") || line.starts_with("[account]")) {
            emit_debug(env, line);
        } else {
            emit_info(env, line);
        }
    }
}

// enroll_address, no_attempt_error, transport_error, status_error, decode_error and the
// finish_provision failures hand their text back already rendered, "api: " on the front; the
// LiveError carries the bare reason and the kind supplies the prefix on display (the same
// strip coreflow::startup applies at coreflow.cpp:1377).
[[nodiscard]] std::string strip_prefix_kind(std::string text, std::string_view prefix) {
    if (text.rfind(prefix, 0) == 0) text.erase(0, prefix.size());
    return text;
}

[[nodiscard]] LiveError live_api(std::string text) {
    return LiveError{LiveKind::Api, strip_prefix_kind(std::move(text), "api: ")};
}

[[nodiscard]] LiveError live_tls(std::string text) {
    return LiveError{LiveKind::Tls, strip_prefix_kind(std::move(text), "tls: ")};
}

[[nodiscard]] std::string bio_text(BIO* bio) {
    std::string out;
    if (bio == nullptr) return out;
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (len > 0 && data != nullptr) out.assign(data, static_cast<std::size_t>(len));
    return out;
}

} // namespace

std::expected<MasqueKeyPair, std::string> generate_masque_keypair() {
    // EcGroup::from_curve_name(NID_X9_62_PRIME256V1) + EcKey::generate, in that order.
    bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!ec || !EC_KEY_generate_key(ec.get())) return std::unexpected(std::string("tls: EC key failed"));
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey.get(), ec.release())) {
        return std::unexpected(std::string("tls: EC key failed"));
    }

    bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
    if (!key_bio || !PEM_write_bio_PKCS8PrivateKey(key_bio.get(), pkey.get(), nullptr, nullptr,
                                                   0, nullptr, nullptr)) {
        return std::unexpected(std::string("tls: key PEM failed"));
    }
    const std::string key_pem = bio_text(key_bio.get());

    unsigned char* spki = nullptr;
    const int spki_len = i2d_PUBKEY(pkey.get(), &spki);
    if (spki_len <= 0) return std::unexpected(std::string("tls: SPKI DER failed"));
    std::vector<std::uint8_t> spki_der(spki, spki + spki_len);
    OPENSSL_free(spki);

    // X509Builder: version 2, serial 0, empty subject == issuer, now to +365 days, sha256 self-sign.
    bssl::UniquePtr<X509> cert(X509_new());
    if (!cert) return std::unexpected(std::string("tls: X509 failed"));
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    if (!name || !X509_set_version(cert.get(), 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 0) ||
        !X509_set_subject_name(cert.get(), name.get()) ||
        !X509_set_issuer_name(cert.get(), name.get()) ||
        !X509_gmtime_adj(X509_get_notBefore(cert.get()), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(cert.get()),
                         static_cast<long>(MASQUE_CERT_LIFETIME_SECS)) ||
        !X509_set_pubkey(cert.get(), pkey.get()) || !X509_sign(cert.get(), pkey.get(), EVP_sha256())) {
        return std::unexpected(std::string("tls: X509 failed"));
    }
    bssl::UniquePtr<BIO> cert_bio(BIO_new(BIO_s_mem()));
    if (!cert_bio || !PEM_write_bio_X509(cert_bio.get(), cert.get())) {
        return std::unexpected(std::string("tls: cert PEM failed"));
    }
    const std::string cert_pem = bio_text(cert_bio.get());

    MasqueKeyPair pair;
    pair.key_pem.assign(key_pem.begin(), key_pem.end());
    pair.cert_pem.assign(cert_pem.begin(), cert_pem.end());
    pair.spki_der = std::move(spki_der);
    return pair;
}

LiveResult<AccountData> api_call(std::string_view label, std::string_view method,
                                 std::string_view path,
                                 std::optional<std::span<const std::uint8_t>> body,
                                 std::optional<std::string_view> bearer,
                                 std::optional<std::string_view> jwt, const LiveEnv& env) {
    const Settings& settings = *env.settings;

    auto target = enroll_address(settings);
    if (!target.has_value()) {
        return std::unexpected(live_api(target.error()));
    }
    // The system resolver looks a name up outside the socket mark; through the upstream proxy,
    // the proxy looks it up and only the marked connection to the proxy leaves.
    std::vector<std::string> upstream_notes;
    const bool has_upstream = upstream::configured(settings, upstream_notes).has_value();
    for (const auto& line : upstream_notes) emit_info(env, line);
    if (egress::mark() != 0 && !has_upstream &&
        !::aether::core::parse_address(target->first).has_value()) {
        return std::unexpected(LiveError{
            LiveKind::Api, std::string(label) + ": " + target->first +
                               " would be looked up outside the socket mark, so the call would loop "
                               "back into the tunnel; give --enroll-address an IP address"});
    }

    // api_ech: nothing without --ech; the remembered key; else the lookup, once for the run.
    std::optional<std::vector<std::uint8_t>> ech;
    if (const auto setting = settings.get(kEchEnv);
        setting.has_value() && !setting->empty()) {
        if (const auto remembered = api_ech_in_use()) {
            ech = remembered;
        } else {
            auto looked = ech_key(settings, EchPurpose::Api, [&]() {
                    return ::aether::core::fetch_ech_config(settings, env.ech_transport);
                });
            if (!looked.has_value()) {
                return std::unexpected(LiveError{LiveKind::Ech, looked.error()});
            }
            ech = *looked;
            if (ech.has_value()) remember_api_ech(*ech);
        }
    }

    const Fingerprint fingerprint = Fingerprint::configured(settings);
    const HeaderFields headers = front_headers(bearer, jwt);
    const std::string host(api_host());
    const std::vector<std::uint8_t> body_bytes =
        body.has_value() ? std::vector<std::uint8_t>(body->begin(), body->end())
                         : std::vector<std::uint8_t>{};
    const https::Request request{
        .method = method,
        .host = host,
        .port = 443,
        .address = std::pair<std::string_view, std::uint16_t>{target->first, target->second},
        .sni = {},
        .path = path,
        .headers = std::span<const std::pair<std::string, std::string>>(headers),
        .body = body.has_value()
                    ? std::optional<std::span<const std::uint8_t>>(std::span(body_bytes))
                    : std::nullopt,
    };

    LiveError last_error = live_api(no_attempt_error(label));
    for (std::uint32_t attempt = 0; attempt < API_ATTEMPTS; ++attempt) {
        if (attempt > 0) {
            const auto wait = backoff_delay(attempt - 1);
            emit_warn(env, retry_line(label, attempt, wait, live_display(last_error)));
            std::this_thread::sleep_for(wait);
        }

        std::vector<std::string> call_notes;
        auto sent = https::send(request, fingerprint, &ech, API_TIMEOUT,
                                https::Call{&settings, &call_notes});
        for (const auto& line : call_notes) emit_info(env, line);
        if (ech.has_value()) remember_api_ech(*ech);
        if (!sent.has_value()) {
            last_error = live_api(transport_error(label, sent.error()));
            continue;
        }
        const https::Response& response = *sent;

        if (response.status < 100 || response.status > 999) {
            last_error = live_api(status_error(label, response.status));
            continue;
        }
        const std::string text =
            socks::utf8_lossy(std::span<const std::uint8_t>(response.body));

        if (response.status >= 200 && response.status < 300) {
            if (ech.has_value()) emit_info(env, ech_line(label));
            auto parsed = account_data_from_json(text);
            if (!parsed.has_value()) {
                last_error = live_api(decode_error(label, parsed.error(), response.body.size()));
                continue;
            }
            return *parsed;
        }

        // The variant is chosen on the status alone, before anything is known about whether the
        // call will be tried again, so a 401 that is retried is still named for the identity.
        last_error = LiveError{refuses_identity(response.status) ? LiveKind::IdentityRefused
                                                                : LiveKind::Api,
                               std::string(label) + ": " +
                                   describe_rejection(response.status, text)};
        if (!worth_retrying(response.status)) return std::unexpected(last_error);

        if (const auto cooldown = retry_after(response.headers)) {
            emit_warn(env, cooldown_line(label, *cooldown));
            std::this_thread::sleep_for(*cooldown);
        }
    }
    return std::unexpected(last_error);
}

LiveResult<std::pair<AccountData, std::array<std::uint8_t, 32>>> register_device(
    std::string_view model, std::string_view locale, std::optional<std::string_view> jwt,
    const LiveEnv& env) {
    const auto [wg_private, wg_public] = generate_x25519_keypair();
    const Registration body{
        .key = wg_public,
        .install_id = {},
        .fcm_token = {},
        .tos = tos_timestamp(),
        .model = std::string(model),
        .serial_number = random_android_serial(),
        .os_version = {},
        .key_type = "curve25519",
        .tunnel_type = "wireguard",
        .locale = std::string(locale),
    };
    const std::string encoded = body.to_json_text();
    const std::string path = std::string("/") + std::string(::aether::core::API_VERSION) + "/reg";
    auto account = api_call("registration", "POST", path,
                            std::optional<std::span<const std::uint8_t>>(
                                std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t*>(encoded.data()),
                                    encoded.size())),
                            std::nullopt, jwt, env);
    if (!account.has_value()) return std::unexpected(account.error());
    return std::pair{*account, wg_private};
}

LiveResult<void> enable_warp(std::string_view device_id, std::string_view token,
                             const LiveEnv& env) {
    constexpr std::string_view payload = R"({"warp_enabled":true})";
    const std::string path = std::string("/") + std::string(::aether::core::API_VERSION) + "/reg/" +
                             std::string(device_id);
    auto answered = api_call("enabling warp", "PATCH", path,
                             std::optional<std::span<const std::uint8_t>>(
                                 std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t*>(payload.data()),
                                     payload.size())),
                             token, std::nullopt, env);
    if (!answered.has_value()) return std::unexpected(answered.error());
    return {};
}

LiveResult<AccountData> enroll_key(std::string_view device_id, std::string_view token,
                                   std::span<const std::uint8_t> spki_der,
                                   const std::optional<std::string>& name, const LiveEnv& env) {
    const DeviceUpdate body = device_update_body(spki_der, name);
    const std::string encoded = body.to_json_text();
    const std::string path = std::string("/") + std::string(::aether::core::API_VERSION) + "/reg/" +
                             std::string(device_id);
    return api_call("key enrollment", "PATCH", path,
                    std::optional<std::span<const std::uint8_t>>(
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size())),
                    token, std::nullopt, env);
}

LiveResult<std::pair<AccountData, std::array<std::uint8_t, 32>>> register_with_team(
    std::string_view model, std::string_view locale, std::string_view token, const LiveEnv& env) {
    const auto [wg_private, wg_public] = generate_x25519_keypair();
    const TeamRegistration body = team_registration_body(wg_public, model, locale);
    const std::string encoded = body.to_json_text();
    const std::string path = std::string("/") + std::string(::aether::core::API_VERSION) + "/reg";
    auto account = api_call("team registration", "POST", path,
                            std::optional<std::span<const std::uint8_t>>(
                                std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t*>(encoded.data()),
                                    encoded.size())),
                            std::nullopt, token, env);
    if (!account.has_value()) return std::unexpected(account.error());
    return std::pair{*account, wg_private};
}

LiveResult<Identity> provision_team(std::string_view model, std::string_view locale,
                                    const zerotrust::TeamSettings& team, const LiveEnv& env) {
    std::vector<std::string> sign_in_notes;
    auto token = zerotrust::resolve_token(team, env.team_hooks, sign_in_notes);
    emit_notes(env, sign_in_notes, false);
    if (!token.has_value()) return std::unexpected(LiveError{LiveKind::Api, token.error()});
    auto registered = register_with_team(model, locale, *token, env);
    if (!registered.has_value()) return std::unexpected(registered.error());
    std::vector<std::string> notes;
    auto identity = finish_provision(registered->first, registered->second, notes);
    emit_notes(env, notes, false);
    if (!identity.has_value()) {
        return std::unexpected(live_api(identity.error()));
    }
    return *identity;
}

LiveResult<Identity> provision_wg(std::string_view model, std::string_view locale,
                                  std::optional<std::string_view> jwt, const LiveEnv& env) {
    auto registered = register_device(model, locale, jwt, env);
    if (!registered.has_value()) return std::unexpected(registered.error());
    std::vector<std::string> notes;
    auto identity = finish_provision(registered->first, registered->second, notes);
    emit_notes(env, notes, false);
    if (!identity.has_value()) {
        return std::unexpected(live_api(identity.error()));
    }
    return *identity;
}

LiveResult<AccountData> fetch_device(std::string_view device_id, std::string_view token,
                                     const LiveEnv& env) {
    const std::string path = std::string("/") + std::string(::aether::core::API_VERSION) + "/reg/" +
                             std::string(device_id);
    return api_call("device refresh", "GET", path, std::nullopt, token, std::nullopt, env);
}

Identity refresh_profile(Identity identity, const LiveEnv& env) {
    auto fetched = fetch_device(identity.device_id, identity.access_token, env);
    if (!fetched.has_value()) {
        std::vector<std::string> notes;
        if (fetched.error().kind == LiveKind::IdentityRefused) {
            Identity refused = refresh_after_refusal(identity, fetched.error().message, notes);
            emit_notes(env, notes, true);
            return refused;
        }
        Identity kept = refresh_with_saved_profile(identity, live_display(fetched.error()), notes);
        emit_notes(env, notes, true);
        return kept;
    }
    std::vector<std::string> notes;
    Identity refreshed = refresh_from_profile(*fetched, identity, notes);
    emit_notes(env, notes, false);
    return refreshed;
}

LiveResult<MasqueEnrollment> ensure_masque_enrolled(const Identity& identity, const LiveEnv& env) {
    const EnrollmentPlan plan = plan_masque_enrollment(identity);
    if (!plan.needs_enrollment) {
        MasqueEnrollment current;
        current.cert_pem.assign(identity.cert_pem.begin(), identity.cert_pem.end());
        current.key_pem.assign(identity.key_pem.begin(), identity.key_pem.end());
        current.issued_at = identity.cert_issued_at;
        current.renewed = false;
        return current;
    }
    emit_info(env, plan.note);

    auto keypair = generate_masque_keypair();
    if (!keypair.has_value()) return std::unexpected(live_tls(keypair.error()));
    auto enrolled = enroll_key(identity.device_id, identity.access_token, keypair->spki_der,
                               std::nullopt, env);
    if (enrolled.has_value()) {
        emit_info(env, "[+] MASQUE key enrolled");
        return new_masque_enrollment(*keypair, ::aether::core::now_unix());
    }
    std::vector<std::string> notes;
    auto kept = masque_enrollment_after_error(identity, live_display(enrolled.error()), notes);
    emit_notes(env, notes, true);
    if (!kept.has_value()) {
        // cert_still_usable refused the fallback: the enrollment's own error stands.
        const LiveError& original = enrolled.error();
        if (original.kind == LiveKind::IdentityRefused) {
            return std::unexpected(
                LiveError{LiveKind::IdentityRefused, original.message});
        }
        return std::unexpected(original);
    }
    return *kept;
}

} // namespace aether::core::account
