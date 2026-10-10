#include "settings.hpp"

namespace hemera::core {

// Usage block of hemera/src/cli.rs lines 4-456, commit 6175b67, with the tor and
// psiphon sections dropped — this port has no tor or psiphon support.
const char* usage_text() {
    // One literal cannot hold the whole block: MSVC truncates a single literal past 16K.
    static const char* const text =
        R"USAGE(Hemera — a censorship circumvention client. It finds a way out of a filtered
network, opens an encrypted tunnel, and serves it as a local SOCKS5 proxy.

Usage:
  hemera [OPTIONS]
  hemera help              show this text

Run it with no options and it asks for what it needs: protocol, scan mode, IP
version. Every question has a flag, and every flag has an environment variable
of its own. Setting either one is what stops the question being asked, and a
flag beats a variable.

  hemera                                   answer the questions as they come
  hemera --masque --turbo -4               nothing asked, straight to work
  hemera --wg --thorough --noize gfw       classic wireguard on a strict network
  hemera --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
  hemera --mim                             two masque hops, for a different exit

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --http-proxy <addr>      also expose an HTTP CONNECT proxy on this address
                           (off by default, e.g. 127.0.0.1:1820)
  --upstream <url>         dial out through a proxy already running here, e.g.
                           socks5://127.0.0.1:1080 or http://user:pass@host:8080
  --mark <n>               put this firewall mark (SO_MARK) on every socket hemera
                           opens to the internet, e.g. 0xff, so a tun front end on
                           the same Linux router can let them past instead of
                           looping them back in (Linux and Android, needs root or
                           CAP_NET_ADMIN); a name is looked up outside the mark, so
                           without --upstream the calls to the WARP API take an IP
                           address only, see --enroll-address
  --exit-loc <spec>        refuse a tunnel whose exit country is not wanted, checked
                           through the finished tunnel before socks5 opens and again
                           every minute after: !IR,AZ,RU blocks those, DE,SE allows
                           only those. Off unless you pass this flag: without it
                           nothing is looked up and no tunnel is refused
  --exit-loc-secs <n>      how often to recheck the exit country (default 60)
  --stats                  log how much has gone up and down and how long the
                           tunnel has been up (off by default)
  --stats-secs <n>         how often to log that line (default 60)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --ip <v4|v6|both>        the same choice written out
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard, --warp
                           use classic WireGuard
  --gool, --wiw            use gool: a wireguard warp tunnel carried inside a
                           masque one, with its own identity registered from
                           inside warp, so it leaves from a foreign address
  --gool-peer <ip:port>    the wireguard endpoint gool dials inside the tunnel
                           (default: the one its registration names, port 2408)
  --gool-classic           the older gool: wireguard tunneled in wireguard
  --api-fragment           reach the warp api only over the fragmented route,
                           for networks that filter the key domain
  --mim, --masque-in-masque
                           use MASQUE-in-MASQUE: a masque tunnel carried inside
                           another one, which changes the address you come out
                           of the way gool does, on the same carrier for both
                           hops (HTTP/3 in HTTP/3, or --h2 for HTTP/2 in HTTP/2)
  --protocol <name>        masque | wg | gool | mim

Classic gool (WARP-in-WARP) endpoints:
  Naming any of these selects the classic gool. Both hops are found by the
  scan unless you name them here. The port is
  required: which port gets through is exactly what differs between networks,
  so none is assumed for you. Name one hop and the scan finds the other,
  keeping your address out of the sweep. The two hops must be different
  addresses, and naming one selects warp-in-warp on its own, so --gool
  alongside is optional.
  --wiw-outer <ip:port>    the outer hop, the one your network sees
  --wiw-inner <ip:port>    the inner hop, reached through the outer one
  --wiw-peers <out[,in]>   both hops in one value, or only the outer one
  --wiw-scan               scan for both, ignoring any endpoint left in the
                           environment

MASQUE-in-MASQUE endpoints:
  The outer hop is found by the scan and the inner one is picked for you, both
  unless you name them here. The port is required, and the two hops must be
  different addresses. Naming one selects masque-in-masque on its own.
  --mim-outer <ip:port>    the outer hop, the one your network sees
  --mim-inner <ip:port>    the inner hop, reached through the outer one
  --mim-peers <out[,in]>   both hops in one value, or only the outer one
  --mim-scan               find the outer hop by scanning, ignoring any endpoint
                           left in the environment

Scan mode:
  --scan <mode>            turbo | balanced | thorough | verified | ironclad
  --turbo                  stop at the first candidate that answers
  --balanced               default: collect a few, keep the fastest
  --thorough               sweep whole ranges, for when everything looks blocked
  --verified               dial only the edges measured to answer connect-ip,
                           never a guessed neighbour. On --gool and --mim it also
                           keeps the two hops in separate ranges, which is what
                           moves the exit address; the plain modes are untouched
  --ironclad               open a real tunnel and make a real HTTP request per
                           candidate, so a gateway is only trusted once it has
                           genuinely carried traffic

Obfuscation:
  --noize <profile>        off | light | firewall | balanced | gfw | aggressive
                           firewall is the default for MASQUE, balanced for
                           WireGuard and gool; reach for gfw when the default
                           does not get through

MASQUE transport:
  --h2, --http2            use HTTP/2 (TCP) instead of HTTP/3 (QUIC)
  --h3, --quic             use HTTP/3 (QUIC), without asking
  --no-quic-v2             do not send the QUIC v2 version-negotiation opener
                           (it is on by default; it opens a path for HTTP/3 on
                           networks that block QUIC v1 but let QUIC v2 through)
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --startup-secs <n>       total MASQUE startup deadline (default 30)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --dns <list>             resolvers used inside the tunnel (default 1.1.1.1,1.0.0.1)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
                           (on by default; Iran's firewall resets a whole
)USAGE"
        R"USAGE(                           ClientHello whose SNI ends in cloudflareclient.com)
  --no-fragment            send the ClientHello in one piece on HTTP/2
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

TLS:
  the TLS handshakes of the tunnel and its setup, MASQUE over HTTP/2 and HTTP/3,
  the calls to the WARP API and the DoH lookup of --ech-dns, have Chrome's
  fingerprint as BoringSSL writes it, with what these change; certificates go
  unchecked
  --ech <auto|base64>      enable Encrypted Client Hello on the MASQUE handshakes
                           and the calls to the WARP API, with the key looked up
                           (auto) or given in base64; without a key it can
                           offer, neither goes ahead rather than send a name in
                           the clear. The DoH lookup of the key goes without it
  --ech-dns <url>          the resolver --ech auto asks for the key:
                           udp://ip[:port] or tcp://ip[:port], port 53 unless
                           given, or a DNS-over-HTTPS https:// URL, port 443
                           unless given (default udp://1.1.1.1). After the URL,
                           @address=<ip|name> sends the connection there and
                           @sni=<name> puts that name in the ClientHello; the
                           URL's host stays the HTTP host, e.g.
                           https://doq.dns4all.eu/dns-query@address=2.2.2.2@sni=google.com
  --ech-domain <name>      the domain whose key --ech auto takes
                           (default cloudflare-ech.com)
  --tls-ciphers <list>     TLS 1.2 cipher suites, listed after the TLS 1.3 ones,
                           which stay as they are; names separated by ':', e.g.
                           "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
                           (default Chrome's, "ALL:!aPSK:!ECDSA+SHA1:!3DES").
                           HTTP/3 lists none: QUIC offers TLS 1.3 alone
  --tls-groups <list>      TLS groups, in order, the first with a key share
                           (default "P-256:X25519:P-384")
  --disable-grease         leave out the GREASE values (RFC 8701) the cipher
                           suites, extensions, groups, key shares and versions
                           carry by default, as Chrome's do

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan
)USAGE"
        R"USAGE(
Zero Trust (WARP for organizations):
  --team <name>            enrol into a Zero Trust organization by team name
  --access-id <id>         service token client id (headless enrolment)
  --access-secret <secret> service token client secret (headless enrolment)
  --access-email <addr>    sign in with a one-time code emailed to this address
  --access-token <jwt>     an enrolment token you already obtained by signing in
                           at https://<team>.cloudflareaccess.com/warp
  --gateway                send http and https through the organization's gateway
                           proxy so its filtering and logging apply (off by default:
                           it adds a hop inside the tunnel and logs your browsing)

Routing (which traffic goes where):
  --route-block <list>     never let these reach the network at all
  --route-direct <list>    send these straight out, bypassing the tunnel
  --routes <path>          load both lists from a file with [block] and [direct]
                           sections
  --tun                    route all system traffic through native Wintun (VPN mode)
                           list entries are comma or newline separated and may be:
                             example.com          the name and every subdomain
                             full:example.com     that exact name only
                             keyword:doubleclick  any name containing it
                             regexp:^ad[0-9]+     a regular expression
                             10.0.0.0/8           a network, or a bare address
                             port:25              a port, or port:3000-3010
                             private              lan, loopback and cgnat space
                           block is checked first, then direct, otherwise the
                           tunnel is used

Config files:
  --config <path>          base identity config path (default hemera.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE
                           warp-in-warp adds a second identity of its own beside
                           the wireguard one, named <config>-secondary.toml
  --register <which>       register identities and exit, with no scan and no
                           tunnel: masque, wg, gool (both wireguard hops), mim
                           (both masque hops) or all. An identity file already
                           there is kept, never replaced; point the config paths
                           at new files to get new keys
  --enroll-address <ip|name[:port]>
                           where the calls to the WARP API, which register and
                           enroll the keys, go: port 443 unless one follows the
                           address, an IPv6 one then in brackets, e.g.
                           188.114.97.6:443 or [2606:4700::1]:8443 (default
                           api.cloudflareclient.com); the server name and the
                           HTTP host stay api.cloudflareclient.com. With --mark
                           and no --upstream, an IP address only

Advanced:
  --perf <low|medium|high> force a resource profile instead of auto-detecting from cpu/ram
                           (low: routers/small boards, medium: typical desktop, high: servers)
  --log-level <level>      error | warn | info | debug | trace (default info)
                           info: connection stages, validation, reconnects, retries
                           debug: adds per-tunnel internals useful for troubleshooting
                           trace: everything, including per-packet noise
  --verbose                shortcut for --log-level debug (RUST_LOG overrides both)

  -v, --version            show version and exit
  -h, --help, help         show this help and exit

Environment variables:
  Every flag above has one, for scripts and services. The last few have no flag
  of their own.

  HEMERA_SOCKS                     --bind
  HEMERA_HTTP_PROXY                --http-proxy
  HEMERA_UPSTREAM                  --upstream
  HEMERA_MARK                      --mark
  HEMERA_STATS                     --stats
  HEMERA_STATS_SECS                --stats-secs
  HEMERA_EXIT_LOC                  --exit-loc
  HEMERA_EXIT_LOC_SECS             --exit-loc-secs
  HEMERA_QUICK_RECONNECT           1 or 0, for --quick-reconnect
  HEMERA_IP                        --ip: v4, v6 or both
  HEMERA_PEER                      --peer
  HEMERA_WG_PEER                   --wg-peer
  HEMERA_PROTOCOL                  --protocol: masque, wg, gool or mim
  HEMERA_GOOL_INNER                --gool-peer
  HEMERA_GOOL_MODE                 classic for --gool-classic
  HEMERA_API_FRAGMENT              --api-fragment
  HEMERA_WIW_OUTER_PEER            --wiw-outer
  HEMERA_WIW_INNER_PEER            --wiw-inner
  HEMERA_WIW_PEERS                 --wiw-peers, or auto for --wiw-scan
  HEMERA_MIM_OUTER_PEER            --mim-outer
  HEMERA_MIM_INNER_PEER            --mim-inner
  HEMERA_MIM_PEERS                 --mim-peers, or auto for --mim-scan
  HEMERA_SCAN                      --scan
)USAGE"
        R"USAGE(  HEMERA_NOIZE                     --noize
  HEMERA_MASQUE_HTTP2              --h2 (1), or --h3 (0)
  HEMERA_QUIC_V2                   0 for --no-quic-v2 (the opener is on by default)
  HEMERA_MASQUE_H2_PEER            --h2-peer
  HEMERA_MASQUE_NO_DATA_CHECK      --no-data-check, MASQUE side
  HEMERA_WG_NO_DATA_CHECK          --no-data-check, WireGuard side
  HEMERA_MASQUE_VALIDATE_SECS      --validate-secs, MASQUE side
  HEMERA_WG_VALIDATE_SECS          --validate-secs, WireGuard side
  HEMERA_MASQUE_STARTUP_SECS       --startup-secs
  HEMERA_MASQUE_RECONNECT_SECS     --reconnect-secs, MASQUE side
  HEMERA_WG_RECONNECT_SECS         --reconnect-secs, WireGuard side
  HEMERA_DNS                       --dns
  HEMERA_MASQUE_H2_FRAGMENT        --fragment / --no-fragment (default on)
  HEMERA_MASQUE_H2_FRAGMENT_SIZE   --fragment-size
  HEMERA_MASQUE_H2_FRAGMENT_DELAY  --fragment-delay
  HEMERA_ECH                       --ech
  HEMERA_ECH_DNS                   --ech-dns
  HEMERA_ECH_DOMAIN                --ech-domain
  HEMERA_TLS_CIPHERS               --tls-ciphers
  HEMERA_TLS_GROUPS                --tls-groups
  HEMERA_DISABLE_GREASE            --disable-grease
  HEMERA_WG_KEEPALIVE              --keepalive
  HEMERA_WG_NO_PROFILE_RETRY       --no-profile-retry
  HEMERA_TEAM                      --team
  HEMERA_ACCESS_CLIENT_ID          --access-id
  HEMERA_ACCESS_CLIENT_SECRET      --access-secret
  HEMERA_ACCESS_TOKEN              --access-token
  HEMERA_ACCESS_EMAIL              --access-email
  HEMERA_GATEWAY                   --gateway
  HEMERA_ROUTE_BLOCK               --route-block
  HEMERA_ROUTE_DIRECT              --route-direct
  HEMERA_ROUTES_FILE               --routes
  HEMERA_TUN_MODE                  --tun
  HEMERA_CONFIG                    --config
  HEMERA_WG_CONFIG                 --wg-config
  HEMERA_MASQUE_CONFIG             --masque-config
  HEMERA_REGISTER                  --register
  HEMERA_ENROLL_ADDRESS            --enroll-address
  HEMERA_PERF_PROFILE              --perf
  HEMERA_LOG_LEVEL                 --log-level

  HEMERA_ROUTE_SNIFF               0 to stop reading the server name from the
                                   first bytes of a connection (on by default,
                                   which is what makes routing rules work behind
                                   a tun front end)
  HEMERA_ROUTE_SNIFF_MS            how long to wait for those bytes (default 400)
  HEMERA_WG_ENDPOINT_COOLDOWN_SECS how long an endpoint that failed twice is left
                                   out of rescans (default 300)
  HEMERA_WG_STALE_SECS             silence on a wireguard tunnel before it counts
                                   as dead (default 10)
  HEMERA_MASQUE_H2_KEEPALIVE_SECS  HTTP/2 keepalive interval (default 15)
  HEMERA_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS
                                   how long a keepalive may go unanswered (default 20)
  HEMERA_IRONCLAD_PORT             port the ironclad scan makes its real HTTP
                                   request to (default 80)
  HEMERA_MAX_CLIENTS               proxy clients served at once; past it new ones
                                   wait for a free slot (default by resources,
                                   512 to 8192)
  HEMERA_HALF_CLOSE_SECS           how long a connection the client has finished
                                   sending on may sit silent before it is closed
                                   (default 30)
  HEMERA_TCP_KEEPALIVE_SECS        idle time before a keep-alive checks that the
                                   other end of a connection is still there;
                                   three unanswered ones close it (default 60)
  HEMERA_TCP_CONNECT_SECS          how long a connection through the tunnel may
                                   take to open (default 30)
  HEMERA_REPROVISION               0 to stop replacing an identity Cloudflare has
                                   refused with a freshly registered one
  RUST_LOG                         standard rust log filter; overrides --log-level

After startup the proxy is at the address --bind names, 127.0.0.1:1819 by
default. Check it with:

  curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace

The reply should show a Cloudflare colo and warp=on. The proxy has no
authentication, so bind it to 0.0.0.0 only when you mean to share the tunnel
with your network.
)USAGE";
    return text;
}
} // namespace hemera::core
