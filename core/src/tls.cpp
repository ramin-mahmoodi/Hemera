#include "tls.hpp"

#include "consts.hpp"
#include "encoding.hpp"
#include "settings.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>

namespace hemera::core {

namespace {

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// BoringSSL pushes onto an error queue whenever a call fails, and an entry left there makes the
// next unrelated failure look like it has an explanation.
void clear_ssl_error() {
    while (ERR_get_error() != 0) {
    }
}

// The sequential CBS-style reader of tls.rs::Fields: every short read is a failure, and a
// failed config fails the whole list, including one that would have been skipped.
struct Reader {
    std::span<const uint8_t> bytes;
    size_t at = 0;

    bool take(size_t len, std::span<const uint8_t>& out) {
        if (bytes.size() - at < len) return false;
        out = bytes.subspan(at, len);
        at += len;
        return true;
    }

    bool u8(uint8_t& out) {
        std::span<const uint8_t> span;
        if (!take(1, span)) return false;
        out = span[0];
        return true;
    }

    bool u16(uint16_t& out) {
        std::span<const uint8_t> span;
        if (!take(2, span)) return false;
        out = static_cast<uint16_t>((span[0] << 8) | span[1]);
        return true;
    }

    bool u8_prefixed(std::span<const uint8_t>& out) {
        uint8_t len = 0;
        return u8(len) && take(len, out);
    }

    bool u16_prefixed(std::span<const uint8_t>& out) {
        uint16_t len = 0;
        return u16(len) && take(len, out);
    }

    bool exhausted() const { return at == bytes.size(); }
};

constexpr uint16_t ECH_CONFIG_VERSION = 0xfe0d;
constexpr uint16_t HPKE_DHKEM_X25519_HKDF_SHA256 = 0x0020;
constexpr uint16_t HPKE_KDF_HKDF_SHA256 = 0x0001;
constexpr size_t X25519_PUBLIC_KEY_LEN = 32;

bool hpke_suite_usable(std::span<const uint8_t> suites) {
    for (size_t i = 0; i + 3 < suites.size(); i += 4) {
        const uint16_t kdf = static_cast<uint16_t>((suites[i] << 8) | suites[i + 1]);
        const uint16_t aead = static_cast<uint16_t>((suites[i + 2] << 8) | suites[i + 3]);
        if (kdf == HPKE_KDF_HKDF_SHA256 && (aead == 0x0001 || aead == 0x0002 || aead == 0x0003)) {
            return true;
        }
    }
    return false;
}

bool all_digits(std::string_view text) {
    return !text.empty() && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

bool all_hex_digits(std::string_view text) {
    return !text.empty() && std::ranges::all_of(text, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

bool valid_label(std::string_view label) {
    if (label.empty() || label.size() > 63) return false;
    if (label.front() == '-' || label.back() == '-') return false;
    return std::ranges::all_of(label, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-';
    });
}

std::mutex session_mutex;
std::optional<std::vector<uint8_t>> session_key;
int session_count = 0;

} // namespace

bool valid_public_name(std::string_view name) {
    if (name.empty()) return false;

    std::vector<std::string_view> labels;
    size_t start = 0;
    while (true) {
        const size_t dot = name.find('.', start);
        labels.push_back(
            name.substr(start, dot == std::string_view::npos ? std::string_view::npos : dot - start));
        if (dot == std::string_view::npos) break;
        start = dot + 1;
    }

    for (size_t i = 0; i < labels.size(); ++i) {
        const std::string_view label = labels[i];
        if (!valid_label(label)) return false;
        if (i + 1 != labels.size()) continue;
        // An all-numeric last label is an address and `0x..` is a packed constant: neither is a
        // name an ECH server would ever put in a public_name.
        if (all_digits(label)) return false;
        if (label.size() > 2 && (label.starts_with("0x") || label.starts_with("0X")) &&
            all_hex_digits(label.substr(2))) {
            return false;
        }
    }
    return true;
}

std::expected<void, std::string> check_ech_config_list(std::span<const uint8_t> list) {
    Reader outer{list};
    std::span<const uint8_t> body;
    if (!outer.u16_prefixed(body) || body.empty() || !outer.exhausted()) {
        return std::unexpected("it is no ECHConfigList");
    }

    Reader configs{body};
    std::span<const uint8_t> first_offerable;
    bool found = false;

    while (!configs.exhausted()) {
        uint16_t version = 0;
        std::span<const uint8_t> contents;
        if (!configs.u16(version) || !configs.u16_prefixed(contents)) {
            return std::unexpected("it is no ECHConfigList");
        }
        if (version != ECH_CONFIG_VERSION) continue;

        Reader ech{contents};
        uint8_t config_id = 0;
        uint16_t kem_id = 0;
        std::span<const uint8_t> public_key;
        std::span<const uint8_t> suites;
        uint8_t max_name_len = 0;
        std::span<const uint8_t> public_name;
        std::span<const uint8_t> extensions;
        if (!ech.u8(config_id) || !ech.u16(kem_id) || !ech.u16_prefixed(public_key) ||
            !ech.u16_prefixed(suites) || !ech.u8(max_name_len) ||
            !ech.u8_prefixed(public_name) || !ech.u16_prefixed(extensions)) {
            return std::unexpected("it is no ECHConfigList");
        }
        if (public_key.empty() || suites.empty() || suites.size() % 4 != 0 ||
            public_name.empty() || !ech.exhausted()) {
            return std::unexpected("it is no ECHConfigList");
        }

        const std::string_view name(reinterpret_cast<const char*>(public_name.data()),
                                    public_name.size());
        if (!valid_public_name(name)) continue;

        bool mandatory_extension = false;
        {
            Reader ext{extensions};
            while (!ext.exhausted()) {
                uint16_t type = 0;
                std::span<const uint8_t> data;
                if (!ext.u16(type) || !ext.u16_prefixed(data)) {
                    return std::unexpected("it is no ECHConfigList");
                }
                if ((type & 0x8000) != 0) mandatory_extension = true;
            }
        }

        if (!found && !mandatory_extension && kem_id == HPKE_DHKEM_X25519_HKDF_SHA256 &&
            hpke_suite_usable(suites)) {
            first_offerable = public_key;
            found = true;
        }
    }

    if (!found) {
        return std::unexpected(
            "it holds no config BoringSSL offers: ECH version 0xfe0d, X25519, and HKDF-SHA256 "
            "with AES-GCM or ChaCha20-Poly1305");
    }
    if (first_offerable.size() != X25519_PUBLIC_KEY_LEN) {
        return std::unexpected("the X25519 key of its config is not 32 bytes long");
    }
    return {};
}

std::expected<void, std::string> ensure_offerable(std::span<const uint8_t> list) {
    if (const auto checked = check_ech_config_list(list); !checked) {
        return std::unexpected("the ECH key cannot be offered: " + checked.error());
    }
    return {};
}

const std::vector<SpkiPin>& masque_pins() {
    // consts.hpp owns the numbers; a second copy here would be one certificate rotation away
    // from a silent mismatch.
    static const std::vector<SpkiPin> pins = [] {
        std::vector<SpkiPin> out;
        out.reserve(std::size(MASQUE_PINS));
        for (const auto& pin : MASQUE_PINS) {
            SpkiPin copy{};
            std::ranges::copy(pin, copy.begin());
            out.push_back(copy);
        }
        return out;
    }();
    return pins;
}

std::optional<SpkiPin> spki_sha256(X509* cert) {
    if (cert == nullptr) return std::nullopt;
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (pubkey == nullptr) return std::nullopt;

    std::optional<SpkiPin> out;
    uint8_t* der = nullptr;
    const int len = i2d_PUBKEY(pubkey, &der);
    if (len > 0 && der != nullptr) {
        // i2d_PUBKEY writes the SubjectPublicKeyInfo, which is what a pin covers.
        SpkiPin digest{};
        SHA256(der, static_cast<size_t>(len), digest.data());
        out = digest;
        OPENSSL_free(der);
    }
    EVP_PKEY_free(pubkey);
    return out;
}

namespace {

int get_pins_ex_index() {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void* /*parent*/, void* ptr, CRYPTO_EX_DATA* /*ad*/, int /*index*/, long /*argl*/, void* /*argp*/) {
            delete static_cast<std::vector<SpkiPin>*>(ptr);
        });
    return index;
}

enum ssl_verify_result_t pin_callback(SSL* ssl, uint8_t* out_alert) {
    X509* leaf = SSL_get_peer_certificate(ssl);
    if (leaf == nullptr) {
        *out_alert = SSL_AD_BAD_CERTIFICATE;
        return ssl_verify_invalid;
    }
    const std::optional<SpkiPin> pin = spki_sha256(leaf);
    X509_free(leaf);
    if (!pin.has_value()) {
        *out_alert = SSL_AD_INTERNAL_ERROR;
        return ssl_verify_invalid;
    }

    SSL_CTX* ctx = SSL_get_SSL_CTX(ssl);
    const auto* pins = ctx ? static_cast<const std::vector<SpkiPin>*>(
                                 SSL_CTX_get_ex_data(ctx, get_pins_ex_index()))
                           : nullptr;
    if (pins != nullptr) {
        for (const SpkiPin& expected : *pins) {
            if (*pin == expected) return ssl_verify_ok;
        }
    }
    *out_alert = SSL_AD_CERTIFICATE_UNKNOWN;
    return ssl_verify_invalid;
}

} // namespace

bool verify_enabled(const Settings& settings) {
    const std::optional value = settings.get("HEMERA_TLS_VERIFY");
    return value.has_value() && is_truthy(*value);
}

std::string install_verification(SSL_CTX* ctx, bool pin_endpoint, std::vector<SpkiPin> pins,
                                 const Settings& settings) {
    static std::atomic_flag announced = ATOMIC_FLAG_INIT;
    const auto once = [](std::string text) {
        return announced.test_and_set() ? std::string() : text;
    };

    if (!verify_enabled(settings)) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        return once("tls verification: disabled (default; --tls-verify enables pinning)");
    }

    if (pin_endpoint && !pins.empty()) {
        const size_t loaded = pins.size();
        const int idx = get_pins_ex_index();
        void* old = SSL_CTX_get_ex_data(ctx, idx);
        delete static_cast<std::vector<SpkiPin>*>(old);

        auto* stored = new std::vector<SpkiPin>(std::move(pins));
        SSL_CTX_set_ex_data(ctx, idx, stored);
        SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, pin_callback);
        return once("tls verification: pin-based (" + std::to_string(loaded) + " pins loaded)");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return once("tls verification: none (--tls-verify set but no pins configured)");
}

Fingerprint Fingerprint::configured(const Settings& settings) {
    Fingerprint out;
    if (const std::optional ciphers = settings.get("HEMERA_TLS_CIPHERS");
        ciphers.has_value() && !trim(*ciphers).empty()) {
        out.ciphers = std::string(trim(*ciphers));
    }
    if (const std::optional groups = settings.get("HEMERA_TLS_GROUPS");
        groups.has_value() && !trim(*groups).empty()) {
        out.groups = std::string(trim(*groups));
    }
    if (const std::optional grease = settings.get("HEMERA_DISABLE_GREASE");
        grease.has_value()) {
        out.grease = !is_truthy(*grease);
    }
    return out;
}

std::expected<void, std::string> Fingerprint::apply(SSL_CTX* ctx,
                                                   std::span<const uint8_t> alpn) const {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_grease_enabled(ctx, grease ? 1 : 0);
    SSL_CTX_set_permute_extensions(ctx, 1);

    if (SSL_CTX_set1_curves_list(ctx, groups.c_str()) != 1) {
        clear_ssl_error();
        return std::unexpected(
            "\"" + groups + "\" is no group list BoringSSL takes (group names separated by ':')");
    }

    if (!alpn.empty() &&
        SSL_CTX_set_alpn_protos(ctx, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0) {
        clear_ssl_error();
        return std::unexpected("the ALPN protocol list was rejected");
    }

    SSL_CTX_enable_signed_cert_timestamps(ctx);
    SSL_CTX_enable_ocsp_stapling(ctx);

    const std::string rule = ciphers.value_or(std::string(CHROME_CIPHERS));
    if (SSL_CTX_set_strict_cipher_list(ctx, rule.c_str()) != 1) {
        clear_ssl_error();
        return std::unexpected(
            "\"" + rule + "\" is no cipher list BoringSSL takes (cipher names separated by ':')");
    }
    return {};
}

std::expected<void, std::string> check_tls_options(const Settings& settings) {
    const Fingerprint shaped = Fingerprint::configured(settings);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) return std::unexpected("cannot create a TLS context to check options");
    const struct Guard {
        SSL_CTX* ctx;
        ~Guard() { SSL_CTX_free(ctx); }
    } guard{ctx};

    // The suites first, as the Rust core checks them: with both lists broken it is --tls-ciphers
    // that gets named. Chrome's own rule is not checked here; Rust checks only a list the user
    // gave, and the default is validated again by apply() on the context a handshake runs on.
    if (shaped.ciphers) {
        if (SSL_CTX_set_strict_cipher_list(ctx, shaped.ciphers->c_str()) != 1) {
            clear_ssl_error();
            return std::unexpected("--tls-ciphers: \"" + *shaped.ciphers +
                                   "\" is no cipher list BoringSSL takes (cipher names separated by ':')");
        }
    }

    if (SSL_CTX_set1_curves_list(ctx, shaped.groups.c_str()) != 1) {
        clear_ssl_error();
        return std::unexpected("--tls-groups: \"" + shaped.groups +
                               "\" is no group list BoringSSL takes (group names separated by ':')");
    }
    return {};
}

std::expected<void, std::string> use_device_certificate(SSL_CTX* ctx, std::string_view cert_pem,
                                                       std::string_view key_pem) {
    if (cert_pem.empty() || key_pem.empty()) {
        return std::unexpected("no device certificate to present");
    }

    BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (bio == nullptr) return std::unexpected("no device certificate to present");
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (cert == nullptr) {
        clear_ssl_error();
        return std::unexpected("the device certificate is no PEM certificate");
    }
    const int cert_set = SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);
    if (cert_set != 1) {
        clear_ssl_error();
        return std::unexpected("the device certificate was refused");
    }

    bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (bio == nullptr) return std::unexpected("no device certificate to present");
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        clear_ssl_error();
        return std::unexpected("the device key is no PEM private key");
    }
    const int key_set = SSL_CTX_use_PrivateKey(ctx, key);
    EVP_PKEY_free(key);
    // BoringSSL refuses a key that does not match the certificate already on the context here,
    // so no separate SSL_CTX_check_private_key pass is needed.
    if (key_set != 1) {
        clear_ssl_error();
        return std::unexpected("the device key does not match its certificate");
    }
    return {};
}

void use_ech(std::optional<std::vector<uint8_t>> config_list) {
    const std::lock_guard lock(session_mutex);
    session_key = std::move(config_list);
}

std::optional<std::vector<uint8_t>> session_ech() {
    const std::lock_guard lock(session_mutex);
    return session_key;
}

void adopt_ech_retry(std::vector<uint8_t> retry) {
    const std::lock_guard lock(session_mutex);
    if (session_key.has_value()) session_key = std::move(retry);
}

EchSession::EchSession(std::optional<std::vector<uint8_t>> config_list) {
    const std::lock_guard lock(session_mutex);
    ++session_count;
    // A session that starts without a key leaves the one already in place; the first session
    // decides what that is, even when it starts with nothing.
    if (config_list.has_value() || session_count == 1) session_key = std::move(config_list);
}

EchSession::~EchSession() {
    const std::lock_guard lock(session_mutex);
    if (--session_count == 0) session_key = std::nullopt;
}

std::expected<std::optional<std::vector<uint8_t>>, std::string> inject_ech(SSL* ssl) {
    const std::optional<std::vector<uint8_t>> key = session_ech();
    if (!key.has_value()) return std::optional<std::vector<uint8_t>>{};

    if (const auto usable = ensure_offerable(*key); !usable) {
        return std::unexpected(usable.error());
    }
    if (SSL_set1_ech_config_list(ssl, key->data(), key->size()) != 1) {
        clear_ssl_error();
        return std::unexpected("SSL_set1_ech_config_list failed");
    }
    return key;
}

bool ech_accepted(SSL* ssl) {
    return SSL_ech_accepted(ssl) == 1;
}

bool ech_rejected(bool application_error, uint32_t crypto_error_code) {
    // Rust reads quiche's local error and requires !is_app: an application close that happens to
    // carry 0x179 is not the ECH alert, and treating it as one would ask BoringSSL for retry
    // configs that are only a placeholder.
    return !application_error && crypto_error_code == 0x100u + 121u;
}

std::optional<std::vector<uint8_t>> extract_ech_retry_configs(SSL* ssl) {
    const uint8_t* data = nullptr;
    size_t len = 0;
    SSL_get0_ech_retry_configs(ssl, &data, &len);
    if (data == nullptr || len == 0) return std::nullopt;

    // When the server sent nothing usable BoringSSL hands back a placeholder that parses as no
    // config at all, so it fails the same check a fetched key goes through.
    const std::span<const uint8_t> retry(data, len);
    if (!check_ech_config_list(retry)) return std::nullopt;
    return std::vector<uint8_t>(retry.begin(), retry.end());
}

namespace {

struct EchOption {
    std::string_view purpose;
    std::string_view refusal;
};

constexpr EchOption SESSION_OPTION{"", "stopping rather than send the server name in the clear"};
constexpr EchOption API_OPTION{" for the WARP API",
                               "not asking it rather than send its name in the clear"};

} // namespace

std::expected<std::optional<std::vector<uint8_t>>, std::string> ech_key(
    const Settings& settings, EchPurpose purpose,
    const std::function<std::expected<std::vector<uint8_t>, std::string>()>& fetch) {
    const EchOption& option = purpose == EchPurpose::Api ? API_OPTION : SESSION_OPTION;

    // An empty value means no key was asked for. Whitespace is a different thing: it asks for a
    // key and cannot deliver one, so it is an error rather than a silent off.
    const std::optional value = settings.get("HEMERA_ECH");
    if (!value.has_value() || value->empty()) return std::optional<std::vector<uint8_t>>{};

    // Rust folds every way of not getting a key — a lookup that missed, a value that is not
    // base64, a list BoringSSL will not offer — through the one NO_ECH_KEY sentence, so the phrase
    // an app matches on to explain why it stopped is always there. The value itself is never
    // echoed back.
    std::expected<std::vector<uint8_t>, std::string> key = [&]() -> std::expected<
        std::vector<uint8_t>, std::string> {
        if (lowered(trim(*value)) == "auto") return fetch();
        const std::optional decoded = base64_decode(trim(*value));
        if (!decoded) return std::unexpected("the --ech value is not base64");
        return *decoded;
    }();

    if (key) {
        if (const auto usable = ensure_offerable(*key); !usable) {
            key = std::unexpected(usable.error());
        }
    }
    if (!key) {
        return std::unexpected(std::string(NO_ECH_KEY) + std::string(option.purpose) + " (" +
                               key.error() + "); " + std::string(option.refusal));
    }
    return std::optional<std::vector<uint8_t>>(std::move(*key));
}

} // namespace hemera::core
