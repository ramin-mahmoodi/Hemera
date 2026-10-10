#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "tun_device.hpp"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace hemera::core::tun {

namespace {

// Wintun driver API definitions matching the official WireGuard Wintun DLL ABI
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_OPEN_ADAPTER_FUNC)(LPCWSTR Name);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef void (WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
typedef BYTE* (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);

struct WintunLib {
    HMODULE module = nullptr;
    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC OpenAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLUID = nullptr;
    WINTUN_START_SESSION_FUNC StartSession = nullptr;
    WINTUN_END_SESSION_FUNC EndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC SendPacket = nullptr;

    bool load() {
        if (module) return true;

        // 1. Check next to the running executable
        wchar_t exe_path[MAX_PATH] = {0};
        if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH) > 0) {
            std::filesystem::path p(exe_path);
            auto dll = p.parent_path() / "wintun.dll";
            module = LoadLibraryW(dll.c_str());
        }

        // 2. Check binaries/wintun.dll relative to current working directory
        if (!module) {
            module = LoadLibraryW(L"binaries\\wintun.dll");
        }

        // 3. Fallback to standard DLL search paths
        if (!module) {
            module = LoadLibraryW(L"wintun.dll");
        }

        if (!module) return false;

        CreateAdapter = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC>(GetProcAddress(module, "WintunCreateAdapter"));
        OpenAdapter = reinterpret_cast<WINTUN_OPEN_ADAPTER_FUNC>(GetProcAddress(module, "WintunOpenAdapter"));
        CloseAdapter = reinterpret_cast<WINTUN_CLOSE_ADAPTER_FUNC>(GetProcAddress(module, "WintunCloseAdapter"));
        GetAdapterLUID = reinterpret_cast<WINTUN_GET_ADAPTER_LUID_FUNC>(GetProcAddress(module, "WintunGetAdapterLUID"));
        StartSession = reinterpret_cast<WINTUN_START_SESSION_FUNC>(GetProcAddress(module, "WintunStartSession"));
        EndSession = reinterpret_cast<WINTUN_END_SESSION_FUNC>(GetProcAddress(module, "WintunEndSession"));
        GetReadWaitEvent = reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC>(GetProcAddress(module, "WintunGetReadWaitEvent"));
        ReceivePacket = reinterpret_cast<WINTUN_RECEIVE_PACKET_FUNC>(GetProcAddress(module, "WintunReceivePacket"));
        ReleaseReceivePacket = reinterpret_cast<WINTUN_RELEASE_RECEIVE_PACKET_FUNC>(GetProcAddress(module, "WintunReleaseReceivePacket"));
        AllocateSendPacket = reinterpret_cast<WINTUN_ALLOCATE_SEND_PACKET_FUNC>(GetProcAddress(module, "WintunAllocateSendPacket"));
        SendPacket = reinterpret_cast<WINTUN_SEND_PACKET_FUNC>(GetProcAddress(module, "WintunSendPacket"));

        return CreateAdapter && OpenAdapter && CloseAdapter && GetAdapterLUID &&
               StartSession && EndSession && GetReadWaitEvent && ReceivePacket &&
               ReleaseReceivePacket && AllocateSendPacket && SendPacket;
    }
};

WintunLib g_wintun;

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

void run_silent_cmd(const std::wstring& cmd) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::wstring mutable_cmd = cmd;
    if (CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

} // namespace

class TunDeviceImpl final : public TunDevice {
public:
    TunDeviceImpl(WINTUN_ADAPTER_HANDLE adapter, WINTUN_SESSION_HANDLE session, NET_LUID luid, const TunConfig& config)
        : adapter_(adapter), session_(session), luid_(luid), config_(config) {
        if (g_wintun.GetReadWaitEvent && session_) {
            read_event_ = g_wintun.GetReadWaitEvent(session_);
        }
    }

    ~TunDeviceImpl() override {
        cleanup();
    }

    bool write_packet(std::span<const uint8_t> packet) override {
        std::lock_guard<std::mutex> lock(device_mutex_);
        if (!session_ || !g_wintun.AllocateSendPacket || !g_wintun.SendPacket) return false;
        if (packet.empty() || packet.size() > 65535) return false;

        BYTE* buf = g_wintun.AllocateSendPacket(session_, static_cast<DWORD>(packet.size()));
        if (!buf) return false;

        std::memcpy(buf, packet.data(), packet.size());
        g_wintun.SendPacket(session_, buf);
        return true;
    }

    std::vector<uint8_t> read_packet(uint32_t wait_ms) override {
        if (wait_ms > 0 && read_event_) {
            WaitForSingleObject(read_event_, wait_ms);
        }

        std::lock_guard<std::mutex> lock(device_mutex_);
        if (!session_ || !g_wintun.ReceivePacket || !g_wintun.ReleaseReceivePacket) return {};

        DWORD size = 0;
        BYTE* pkt = g_wintun.ReceivePacket(session_, &size);
        if (!pkt) return {};

        std::vector<uint8_t> result(pkt, pkt + size);
        g_wintun.ReleaseReceivePacket(session_, pkt);
        return result;
    }

    size_t drain_read_packets(
        size_t max_packets,
        const std::function<void(std::span<const uint8_t>)>& on_packet) override {
        std::lock_guard<std::mutex> lock(device_mutex_);
        if (!session_ || !g_wintun.ReceivePacket || !g_wintun.ReleaseReceivePacket) return 0;

        size_t count = 0;
        while (count < max_packets) {
            DWORD size = 0;
            BYTE* pkt = g_wintun.ReceivePacket(session_, &size);
            if (!pkt) break;

            if (on_packet && size > 0) {
                on_packet(std::span<const uint8_t>(pkt, size));
            }
            g_wintun.ReleaseReceivePacket(session_, pkt);
            count++;
        }
        return count;
    }

    [[nodiscard]] void* read_wait_event() const override {
        return read_event_;
    }

    bool setup_network() {
        // 1. Assign IP address to Wintun adapter
        if (!setup_ip()) {
            return false;
        }

        // 2. Configure MTU (1280 bytes to match tunnel MTU and prevent fragmentation)
        setup_mtu();

        // 3. Add peer endpoint host route (/32) to avoid routing loop
        setup_peer_bypass();

        // 4. Add default routes (0.0.0.0/1 & 128.0.0.0/1)
        setup_default_routes();

        // 5. Configure DNS
        setup_dns();

        return true;
    }

private:
    void setup_mtu() {
        const uint32_t target_mtu = config_.mtu > 0 ? config_.mtu : 1280;
        MIB_IPINTERFACE_ROW if_row{};
        InitializeIpInterfaceEntry(&if_row);
        if_row.InterfaceLuid = luid_;
        if_row.Family = AF_INET;
        if (GetIpInterfaceEntry(&if_row) == NO_ERROR) {
            if_row.NlMtu = target_mtu;
            SetIpInterfaceEntry(&if_row);
        }

        MIB_IPINTERFACE_ROW if_row6{};
        InitializeIpInterfaceEntry(&if_row6);
        if_row6.InterfaceLuid = luid_;
        if_row6.Family = AF_INET6;
        if (GetIpInterfaceEntry(&if_row6) == NO_ERROR) {
            if_row6.NlMtu = target_mtu;
            SetIpInterfaceEntry(&if_row6);
        }
    }
    void cleanup() {
        // Remove installed default routes
        if (has_r1_) {
            DeleteIpForwardEntry2(&r1_);
            has_r1_ = false;
        }
        if (has_r2_) {
            DeleteIpForwardEntry2(&r2_);
            has_r2_ = false;
        }
        if (has_r6_1_) {
            DeleteIpForwardEntry2(&r6_1_);
            has_r6_1_ = false;
        }
        if (has_r6_2_) {
            DeleteIpForwardEntry2(&r6_2_);
            has_r6_2_ = false;
        }

        // Remove bypass route
        if (has_bypass_) {
            DeleteIpForwardEntry2(&bypass_route_);
            has_bypass_ = false;
        }

        // End session & close adapter under lock
        WINTUN_SESSION_HANDLE sess_to_end = nullptr;
        WINTUN_ADAPTER_HANDLE adpt_to_close = nullptr;
        {
            std::lock_guard<std::mutex> lock(device_mutex_);
            sess_to_end = session_;
            session_ = nullptr;
            adpt_to_close = adapter_;
            adapter_ = nullptr;
        }
        if (sess_to_end && g_wintun.EndSession) {
            g_wintun.EndSession(sess_to_end);
        }
        if (adpt_to_close && g_wintun.CloseAdapter) {
            g_wintun.CloseAdapter(adpt_to_close);
        }
    }

    bool setup_ip() {
        std::string ip = config_.ipv4;
        uint8_t prefix = 32;
        if (const auto slash = ip.find('/'); slash != std::string::npos) {
            try {
                prefix = static_cast<uint8_t>(std::stoi(ip.substr(slash + 1)));
            } catch (...) {
                prefix = 32;
            }
            ip = ip.substr(0, slash);
        }

        MIB_UNICASTIPADDRESS_ROW row{};
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = luid_;
        row.Address.Ipv4.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &row.Address.Ipv4.sin_addr) != 1) {
            return false;
        }
        row.OnLinkPrefixLength = prefix;
        row.DadState = IpDadStatePreferred;

        DWORD res = CreateUnicastIpAddressEntry(&row);
        if (res != NO_ERROR && res != ERROR_OBJECT_ALREADY_EXISTS) {
            // Non-fatal if already set, but log or check
        }

        // IPv6 assignment if present
        if (!config_.ipv6.empty()) {
            std::string ip6 = config_.ipv6;
            uint8_t p6 = 128;
            if (const auto slash = ip6.find('/'); slash != std::string::npos) {
                try {
                    p6 = static_cast<uint8_t>(std::stoi(ip6.substr(slash + 1)));
                } catch (...) {
                    p6 = 128;
                }
                ip6 = ip6.substr(0, slash);
            }
            MIB_UNICASTIPADDRESS_ROW row6{};
            InitializeUnicastIpAddressEntry(&row6);
            row6.InterfaceLuid = luid_;
            row6.Address.Ipv6.sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, ip6.c_str(), &row6.Address.Ipv6.sin6_addr) == 1) {
                row6.OnLinkPrefixLength = p6;
                row6.DadState = IpDadStatePreferred;
                CreateUnicastIpAddressEntry(&row6);
            }
        }

        return true;
    }

    void setup_peer_bypass() {
        if (config_.peer_endpoint.port == 0) return;

        SOCKADDR_INET peer_addr{};
        if (config_.peer_endpoint.ip.v4) {
            peer_addr.si_family = AF_INET;
            std::memcpy(&peer_addr.Ipv4.sin_addr, config_.peer_endpoint.ip.bytes.data() + 12, 4);
        } else {
            peer_addr.si_family = AF_INET6;
            std::memcpy(&peer_addr.Ipv6.sin6_addr, config_.peer_endpoint.ip.bytes.data(), 16);
        }

        MIB_IPFORWARD_ROW2 best_route{};
        SOCKADDR_INET best_src{};
        if (GetBestRoute2(nullptr, 0, nullptr, &peer_addr, 0, &best_route, &best_src) == NO_ERROR) {
            MIB_IPFORWARD_ROW2 bypass{};
            InitializeIpForwardEntry(&bypass);
            bypass.InterfaceLuid = best_route.InterfaceLuid;
            bypass.DestinationPrefix.Prefix = peer_addr;
            bypass.DestinationPrefix.PrefixLength = config_.peer_endpoint.ip.v4 ? 32 : 128;
            bypass.NextHop = best_route.NextHop;
            bypass.Metric = 1; // Prioritize over 0.0.0.0/1

            DWORD err = CreateIpForwardEntry2(&bypass);
            if (err == NO_ERROR) {
                bypass_route_ = bypass;
                has_bypass_ = true;
            }
        }
    }

    void setup_default_routes() {
        // 0.0.0.0/1 via Wintun
        InitializeIpForwardEntry(&r1_);
        r1_.InterfaceLuid = luid_;
        r1_.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        r1_.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
        r1_.DestinationPrefix.PrefixLength = 1;
        r1_.Metric = 5;
        if (CreateIpForwardEntry2(&r1_) == NO_ERROR) {
            has_r1_ = true;
        }

        // 128.0.0.0/1 via Wintun
        InitializeIpForwardEntry(&r2_);
        r2_.InterfaceLuid = luid_;
        r2_.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        r2_.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(0x80000000);
        r2_.DestinationPrefix.PrefixLength = 1;
        r2_.Metric = 5;
        if (CreateIpForwardEntry2(&r2_) == NO_ERROR) {
            has_r2_ = true;
        }

        // If IPv6 enabled, route ::/1 and 8000::/1
        if (!config_.ipv6.empty()) {
            InitializeIpForwardEntry(&r6_1_);
            r6_1_.InterfaceLuid = luid_;
            r6_1_.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            r6_1_.DestinationPrefix.PrefixLength = 1;
            r6_1_.Metric = 5;
            if (CreateIpForwardEntry2(&r6_1_) == NO_ERROR) has_r6_1_ = true;

            InitializeIpForwardEntry(&r6_2_);
            r6_2_.InterfaceLuid = luid_;
            r6_2_.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            r6_2_.DestinationPrefix.Prefix.Ipv6.sin6_addr.s6_addr[0] = 0x80;
            r6_2_.DestinationPrefix.PrefixLength = 1;
            r6_2_.Metric = 5;
            if (CreateIpForwardEntry2(&r6_2_) == NO_ERROR) has_r6_2_ = true;
        }
    }

    void setup_dns() {
        std::wstring adapter = to_wide(config_.adapter_name);
        std::string dns1 = config_.dns.empty() ? "1.1.1.1" : config_.dns;
        std::string dns2 = "1.0.0.1";

        // Extract host if dns has port/scheme
        if (const auto s = dns1.find("://"); s != std::string::npos) dns1.erase(0, s + 3);
        if (const auto slash = dns1.find('/'); slash != std::string::npos) dns1.erase(slash);
        if (const auto col = dns1.find(':'); col != std::string::npos) dns1.erase(col);

        std::wstring cmd1 = std::format(L"netsh interface ipv4 set dnsservers name=\"{}\" static {} primary validate=no",
                                        adapter, to_wide(dns1));
        run_silent_cmd(cmd1);

        std::wstring cmd2 = std::format(L"netsh interface ipv4 add dnsservers name=\"{}\" {} index=2 validate=no",
                                        adapter, to_wide(dns2));
        run_silent_cmd(cmd2);
    }

    std::mutex device_mutex_;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    HANDLE read_event_ = nullptr;
    NET_LUID luid_{};
    TunConfig config_;

    bool has_bypass_ = false;
    MIB_IPFORWARD_ROW2 bypass_route_{};

    bool has_r1_ = false;
    MIB_IPFORWARD_ROW2 r1_{};

    bool has_r2_ = false;
    MIB_IPFORWARD_ROW2 r2_{};

    bool has_r6_1_ = false;
    MIB_IPFORWARD_ROW2 r6_1_{};

    bool has_r6_2_ = false;
    MIB_IPFORWARD_ROW2 r6_2_{};
};

bool TunDevice::is_wintun_available() {
    return g_wintun.load();
}

bool TunDevice::is_elevated() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin != FALSE;
}

void TunDevice::cleanup_stale_adapter(const std::string& name) {
    if (!g_wintun.load()) return;
    std::wstring wname = to_wide(name);
    WINTUN_ADAPTER_HANDLE existing = g_wintun.OpenAdapter(wname.c_str());
    if (existing) {
        g_wintun.CloseAdapter(existing);
    }
}

std::expected<std::unique_ptr<TunDevice>, std::string> TunDevice::create(const TunConfig& config) {
    if (!is_elevated()) {
        return std::unexpected("TUN mode requires Administrator privileges. Please run Hemera as Administrator.");
    }

    if (!g_wintun.load()) {
        return std::unexpected("Failed to load wintun.dll. Please ensure wintun.dll is present.");
    }

    // Clean up any lingering adapter from previous abnormal termination
    std::wstring wname = to_wide(config.adapter_name);
    std::wstring wtype = to_wide(config.tunnel_type);
    WINTUN_ADAPTER_HANDLE existing = g_wintun.OpenAdapter(wname.c_str());
    if (existing) {
        g_wintun.CloseAdapter(existing);
        Sleep(50);
    }

    // Create fresh Wintun adapter
    WINTUN_ADAPTER_HANDLE adapter = g_wintun.CreateAdapter(wname.c_str(), wtype.c_str(), nullptr);
    if (!adapter) {
        // Retry opening if create reports existing
        adapter = g_wintun.OpenAdapter(wname.c_str());
        if (!adapter) {
            DWORD err = GetLastError();
            return std::unexpected(std::format("WintunCreateAdapter failed with error code {}", err));
        }
    }

    NET_LUID luid{};
    g_wintun.GetAdapterLUID(adapter, &luid);

    // Start Wintun session
    WINTUN_SESSION_HANDLE session = g_wintun.StartSession(adapter, config.ring_capacity);
    if (!session) {
        DWORD err = GetLastError();
        g_wintun.CloseAdapter(adapter);
        return std::unexpected(std::format("WintunStartSession failed with error code {}", err));
    }

    auto dev = std::make_unique<TunDeviceImpl>(adapter, session, luid, config);
    if (!dev->setup_network()) {
        return std::unexpected("Failed to configure IP address or routing for Wintun adapter.");
    }

    return dev;
}

} // namespace hemera::core::tun
