#pragma once

#include <cstdint>
#include <string_view>

namespace hemera::core {

// Port of hemera/src/consts.rs: the names and numbers the WARP service is reached by.

inline constexpr std::string_view API_URL = "https://api.cloudflareclient.com";
inline constexpr std::string_view API_VERSION = "v0a4471";

inline constexpr std::string_view CONNECT_SNI = "consumer-masque.cloudflareclient.com";
inline constexpr std::string_view L4_CONNECT_SNI = "consumer-masque-proxy.cloudflareclient.com";
inline constexpr std::string_view CONNECT_URI = "https://cloudflareaccess.com";

inline constexpr std::string_view ECH_PUBLIC_NAME = "cloudflare-ech.com";

inline constexpr std::string_view DEFAULT_MODEL = "PC";
inline constexpr std::string_view DEFAULT_LOCALE = "en_US";

inline constexpr std::string_view KEY_TYPE_MASQUE = "secp256r1";
inline constexpr std::string_view TUN_TYPE_MASQUE = "masque";

inline constexpr std::string_view UA_REGISTER = "WARP for Android";
inline constexpr std::string_view CF_CLIENT_VERSION = "a-6.35-4471";

inline constexpr std::string_view ALPN_H3 = "h3";

inline constexpr std::string_view CF_CONNECT_PROTOCOL = "cf-connect-ip";

inline constexpr std::uint64_t H3_DATAGRAM_00 = 0x276;
inline constexpr std::uint64_t CONNECT_IP_CONTEXT_ID = 0;

inline constexpr std::uint16_t QUIC_PORT = 443;

// The CDN anycast /24s a MASQUE edge answers on.
inline constexpr std::string_view CDN_ANYCAST_POOL[] = {
    "104.16.0.0",  "104.17.0.0",  "104.18.0.0",  "104.19.0.0",  "104.20.0.0",
    "104.21.0.0",  "104.22.0.0",  "104.24.0.0",  "104.25.0.0",  "104.26.0.0",
    "104.27.0.0",  "104.28.0.0",  "172.64.0.0",  "172.65.0.0",  "172.66.0.0",
    "172.67.0.0",  "188.114.96.0","188.114.97.0","188.114.98.0","188.114.99.0",
};

// SHA-256 of the SubjectPublicKeyInfo of the Cloudflare MASQUE edge certificates, hex-pinned
// so the handshake can verify without trusting a system root: the edges serve a different
// certificate per SNI and some are self-signed.
//
// 0: masque.cloudflareclient.com, Cloudflare's own 2024-02-27 self-signed root, served when the
//    SNI is empty or unrecognized. 1: cloudflareaccess.com, issued by Google Trust Services WE1.
inline constexpr std::uint8_t MASQUE_PINS[][32] = {
    {0xeb, 0x59, 0x1b, 0x36, 0xab, 0x26, 0xba, 0x61, 0x7e, 0x98, 0x37, 0x19, 0x18, 0xc1, 0x0b,
     0xcd, 0xea, 0xe3, 0x74, 0x2d, 0xb6, 0xe7, 0x65, 0x43, 0xf9, 0x4b, 0xe5, 0x24, 0xdc, 0xe1,
     0xd5, 0x55},
    {0x3f, 0xbb, 0x1d, 0x74, 0x52, 0xd3, 0x2b, 0x38, 0x81, 0xeb, 0x4b, 0x5d, 0x48, 0x42, 0x14,
     0x45, 0xb6, 0xb9, 0xd8, 0xf5, 0x22, 0x59, 0x59, 0xf0, 0x33, 0x53, 0x2d, 0x50, 0x26, 0x37,
     0xb0, 0x40},
};

} // namespace hemera::core
