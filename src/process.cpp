#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "process.hpp"
#include "resource.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <thread>
#include <fstream>
#include <sstream>
#include <regex>
#include <vector>
#include <map>
#include <cctype>
#include <format>
#include <iostream>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace hemera::process {

namespace {

std::filesystem::path get_current_exe_dir() {
    std::vector<wchar_t> buffer(MAX_PATH);
    DWORD length = 0;
    while (true) {
        length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return std::filesystem::current_path();
        if (length < buffer.size()) break;
        buffer.resize(buffer.size() * 2);
    }
    return std::filesystem::path(buffer.data()).parent_path();
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size);
    return out;
}

std::string to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), size, nullptr, nullptr);
    return out;
}

// Strip ANSI escape codes from terminal output
std::string strip_ansi(std::string_view input) {
    static const std::regex ansi_re("\x1B\\[[0-?]*[ -/]*[@-~]");
    return std::regex_replace(std::string(input), ansi_re, "");
}

bool is_process_alive(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    DWORD exit_code = 0;
    BOOL ok = GetExitCodeProcess(hProcess, &exit_code);
    CloseHandle(hProcess);
    return ok && exit_code == STILL_ACTIVE;
}

std::vector<std::filesystem::path> get_candidate_bin_dirs() {
    std::vector<std::filesystem::path> dirs;
    PWSTR local_path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local_path))) {
        dirs.push_back(std::filesystem::path(local_path) / "Hemera" / "bin");
        CoTaskMemFree(local_path);
    }
    const wchar_t* env_local = _wgetenv(L"LOCALAPPDATA");
    if (env_local) {
        auto p = std::filesystem::path(env_local) / "Hemera" / "bin";
        if (std::find(dirs.begin(), dirs.end(), p) == dirs.end()) dirs.push_back(p);
    }
    PWSTR roaming_path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &roaming_path))) {
        auto p = std::filesystem::path(roaming_path) / "Hemera" / "bin";
        if (std::find(dirs.begin(), dirs.end(), p) == dirs.end()) dirs.push_back(p);
        CoTaskMemFree(roaming_path);
    }
    const wchar_t* env_roaming = _wgetenv(L"APPDATA");
    if (env_roaming) {
        auto p = std::filesystem::path(env_roaming) / "Hemera" / "bin";
        if (std::find(dirs.begin(), dirs.end(), p) == dirs.end()) dirs.push_back(p);
    }
    dirs.push_back(std::filesystem::temp_directory_path() / "Hemera" / "bin");
    return dirs;
}

bool extract_resource_to_file(int res_id, const std::filesystem::path& dest_path) {
    HMODULE hMod = GetModuleHandleW(nullptr);
    HRSRC hRes = FindResourceW(hMod, MAKEINTRESOURCEW(res_id), RT_RCDATA);
    if (!hRes) {
        return false;
    }

    DWORD res_size = SizeofResource(hMod, hRes);
    if (res_size == 0) {
        return false;
    }

    HGLOBAL hGlobal = LoadResource(hMod, hRes);
    if (!hGlobal) {
        return false;
    }

    const void* pData = LockResource(hGlobal);
    if (!pData) {
        return false;
    }

    std::error_code ec;
    if (std::filesystem::exists(dest_path, ec)) {
        if (std::filesystem::is_regular_file(dest_path, ec)) {
            auto current_size = std::filesystem::file_size(dest_path, ec);
            if (!ec && current_size == static_cast<std::uintmax_t>(res_size)) {
                return true;
            }
        }
    }

    std::filesystem::create_directories(dest_path.parent_path(), ec);

    // Write to a temporary file first for atomic replacement
    auto tmp_path = dest_path;
    tmp_path += L".tmp";

    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return false;
        }
        out.write(reinterpret_cast<const char*>(pData), res_size);
        out.flush();
        if (!out.good()) {
            std::filesystem::remove(tmp_path, ec);
            return false;
        }
    }

    // Atomic replace via Win32 MoveFileExW
    if (!MoveFileExW(tmp_path.c_str(), dest_path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        std::filesystem::copy_file(tmp_path, dest_path, std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(tmp_path, ec);
        if (std::filesystem::file_size(dest_path, ec) != static_cast<std::uintmax_t>(res_size)) {
            return false;
        }
    }

    return true;
}

bool extract_embedded_binaries(const std::filesystem::path& bin_dir) {
    bool ok1 = extract_resource_to_file(IDR_HEMERA_BIN, bin_dir / "hemera.exe");
    bool ok2 = extract_resource_to_file(IDR_TUN2SOCKS, bin_dir / "tun2socks.exe");
    bool ok3 = extract_resource_to_file(IDR_WINTUN, bin_dir / "wintun.dll");
    return ok1 && ok2 && ok3;
}

} // namespace

std::expected<std::filesystem::path, std::string> resolve_binary() {
    auto bin_dirs = get_candidate_bin_dirs();
    for (const auto& dir : bin_dirs) {
        if (extract_embedded_binaries(dir)) {
            auto hemera_path = dir / "hemera.exe";
            std::error_code ec;
            if (std::filesystem::is_regular_file(hemera_path, ec)) {
                auto can = std::filesystem::canonical(hemera_path, ec);
                return ec ? hemera_path : can;
            }
        }
    }

    auto exe_dir = get_current_exe_dir();
    std::vector<std::filesystem::path> candidates;
    for (const auto& dir : bin_dirs) {
        candidates.push_back(dir / "hemera.exe");
    }
    candidates.push_back(exe_dir / "binaries" / "hemera.exe");
    candidates.push_back(exe_dir / "hemera.exe");
    candidates.push_back(std::filesystem::current_path() / "binaries" / "hemera.exe");
    candidates.push_back(std::filesystem::current_path() / "hemera.exe");
    candidates.push_back(exe_dir / ".." / "src-tauri" / "binaries" / "hemera.exe");
    candidates.push_back(std::filesystem::current_path() / ".." / "Hemera-main" / "src-tauri" / "binaries" / "hemera.exe");

    for (const auto& path : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) {
            auto can = std::filesystem::canonical(path, ec);
            return ec ? path : can;
        }
    }

    std::string candidate_list;
    for (const auto& path : candidates) {
        candidate_list += "  - " + path.string() + "\n";
    }
    return std::unexpected("Hemera core binary (hemera.exe) not found. Searched in:\n" + candidate_list);
}

std::expected<std::filesystem::path, std::string> resolve_tun2socks() {
    auto bin_dirs = get_candidate_bin_dirs();
    for (const auto& dir : bin_dirs) {
        if (extract_embedded_binaries(dir)) {
            auto tun_path = dir / "tun2socks.exe";
            std::error_code ec;
            if (std::filesystem::is_regular_file(tun_path, ec)) {
                auto can = std::filesystem::canonical(tun_path, ec);
                return ec ? tun_path : can;
            }
        }
    }

    auto exe_dir = get_current_exe_dir();
    std::vector<std::filesystem::path> candidates;
    for (const auto& dir : bin_dirs) {
        candidates.push_back(dir / "tun2socks.exe");
    }
    candidates.push_back(exe_dir / "binaries" / "tun2socks.exe");
    candidates.push_back(exe_dir / "tun2socks.exe");
    candidates.push_back(std::filesystem::current_path() / "binaries" / "tun2socks.exe");
    candidates.push_back(std::filesystem::current_path() / "tun2socks.exe");

    for (const auto& path : candidates) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) {
            auto can = std::filesystem::canonical(path, ec);
            return ec ? path : can;
        }
    }

    std::string candidate_list;
    for (const auto& path : candidates) {
        candidate_list += "  - " + path.string() + "\n";
    }
    return std::unexpected("tun2socks binary (tun2socks.exe) not found. Searched in:\n" + candidate_list);
}

void write_pid_file(const std::filesystem::path& data_dir, uint32_t pid, std::string_view filename) {
    std::error_code ec;
    std::filesystem::create_directories(data_dir, ec);
    std::ofstream out(data_dir / filename);
    if (out.is_open()) {
        out << pid << "\n";
    }
}

void clear_pid_file(const std::filesystem::path& data_dir, std::string_view filename) {
    std::error_code ec;
    std::filesystem::remove(data_dir / filename, ec);
}

bool run_and_wait(std::wstring_view command_line, uint32_t timeout_ms) {
    std::wstring cmd(command_line);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return false;
    }
    const DWORD waited = WaitForSingleObject(pi.hProcess, timeout_ms);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    if (waited != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return waited == WAIT_OBJECT_0 && code == 0;
}

void kill_process_tree(uint32_t pid) {
    if (pid == 0) return;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ParentProcessID == pid) {
                    kill_process_tree(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
    }
}

void reap_orphan(const std::filesystem::path& data_dir) {
    for (const char* name : {"hemera.pid", "tun2socks.pid"}) {
        auto pid_path = data_dir / name;
        if (!std::filesystem::exists(pid_path)) continue;

        std::ifstream in(pid_path);
        uint32_t pid = 0;
        if (in >> pid && pid > 0) {
            if (is_process_alive(pid)) {
                kill_process_tree(pid);
            }
        }
        in.close();
        clear_pid_file(data_dir, name);
    }
}

struct ProcessSession::Impl {
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    HANDLE hJob = nullptr;
    HANDLE hStdinWrite = nullptr;
    HANDLE hStdoutRead = nullptr;
    uint32_t pid = 0;

    std::atomic<bool> engine_started{false};
    std::atomic<bool> access_code_required{false};
    std::atomic<uint32_t> scan_budget_secs{0};

    std::thread reader_thread;

    ~Impl() {
        close_all();
    }

    void close_all() {
        if (hStdinWrite) {
            CloseHandle(hStdinWrite);
            hStdinWrite = nullptr;
        }
        if (hStdoutRead) {
            CloseHandle(hStdoutRead);
            hStdoutRead = nullptr;
        }
        if (reader_thread.joinable()) {
            reader_thread.join();
        }
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        if (hThread) {
            CloseHandle(hThread);
            hThread = nullptr;
        }
        if (hJob) {
            CloseHandle(hJob);
            hJob = nullptr;
        }
    }

    SpawnResult spawn_process(
        const std::filesystem::path& binary_path,
        const std::vector<std::string>& args,
        const std::filesystem::path& work_dir,
        const std::vector<std::pair<std::wstring, std::wstring>>& env_vars,
        LogCallback log_cb,
        bool inspect_hemera_logs
    ) {
        close_all();
        engine_started.store(false);
        access_code_required.store(false);
        scan_budget_secs.store(0);

        // Create Job Object with KILL_ON_JOB_CLOSE to guarantee zero orphan leaks
        hJob = CreateJobObjectW(nullptr, nullptr);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        }

        // Setup Anonymous Pipes
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        HANDLE hStdinRead = nullptr;
        HANDLE hStdoutWrite = nullptr;

        if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
            return {.success = false, .error_message = "Failed to create stdin pipe"};
        }
        SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);

        if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
            CloseHandle(hStdinRead);
            CloseHandle(hStdinWrite);
            hStdinWrite = nullptr;
            return {.success = false, .error_message = "Failed to create stdout pipe"};
        }
        SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

        // Build command line string
        std::wstring cmd_line = L"\"" + binary_path.wstring() + L"\"";
        for (const auto& arg : args) {
            cmd_line += L" " + to_wide(arg);
        }

        // Build Environment Block (Unicode)
        struct CaseInsensitiveWLess {
            bool operator()(const std::wstring& a, const std::wstring& b) const noexcept {
                return _wcsicmp(a.c_str(), b.c_str()) < 0;
            }
        };
        std::map<std::wstring, std::wstring, CaseInsensitiveWLess> all_env;

        LPWCH cur_env = GetEnvironmentStringsW();
        if (cur_env) {
            for (LPWCH p = cur_env; *p != L'\0';) {
                std::wstring entry(p);
                p += entry.size() + 1;
                size_t eq = entry.find(L'=');
                if (eq != std::wstring::npos && eq > 0) {
                    all_env[entry.substr(0, eq)] = entry.substr(eq + 1);
                }
            }
            FreeEnvironmentStringsW(cur_env);
        }

        for (const auto& [k, v] : env_vars) {
            all_env[k] = v;
        }

        auto bin_dir_path = binary_path.parent_path();
        std::wstring extra_path = bin_dir_path.wstring();
        auto path_it = all_env.find(L"PATH");
        if (path_it != all_env.end()) {
            path_it->second = extra_path + L";" + path_it->second;
        } else {
            all_env[L"PATH"] = extra_path;
        }

        std::vector<wchar_t> env_block;
        for (const auto& [k, v] : all_env) {
            std::wstring line = k + L"=" + v;
            for (wchar_t wc : line) env_block.push_back(wc);
            env_block.push_back(L'\0');
        }
        env_block.push_back(L'\0'); // double-null terminator

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hStdinRead;
        si.hStdOutput = hStdoutWrite;
        si.hStdError = hStdoutWrite;

        PROCESS_INFORMATION pi{};
        std::wstring work_dir_w = work_dir.wstring();

        BOOL spawned = CreateProcessW(
            nullptr,
            cmd_line.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env_block.data(),
            work_dir_w.empty() ? nullptr : work_dir_w.c_str(),
            &si,
            &pi
        );

        CloseHandle(hStdinRead);
        CloseHandle(hStdoutWrite);

        if (!spawned) {
            CloseHandle(hStdinWrite);
            CloseHandle(hStdoutRead);
            hStdinWrite = nullptr;
            hStdoutRead = nullptr;
            DWORD err = GetLastError();
            return {.success = false, .error_message = std::format("CreateProcessW failed with error {}", err)};
        }

        hProcess = pi.hProcess;
        hThread = pi.hThread;
        pid = pi.dwProcessId;

        if (hJob) {
            AssignProcessToJobObject(hJob, hProcess);
        }

        reader_thread = std::thread([this, log_cb, inspect_hemera_logs]() {
            char buffer[4096];
            std::string line_buffer;
            DWORD bytes_read = 0;
            static const std::regex budget_regex(R"(budget=(\d+)s)");

            while (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytes_read, nullptr) && bytes_read > 0) {
                buffer[bytes_read] = '\0';
                line_buffer.append(buffer, bytes_read);

                if (inspect_hemera_logs) {
                    std::string partial_clean = strip_ansi(line_buffer);
                    if (partial_clean.find("Enter the code:") != std::string::npos ||
                        partial_clean.find("Enter access code:") != std::string::npos ||
                        partial_clean.find("[gui] Zero Trust access code required") != std::string::npos) {
                        access_code_required.store(true, std::memory_order_relaxed);
                    }
                }

                size_t newline_pos = 0;
                while ((newline_pos = line_buffer.find('\n')) != std::string::npos) {
                    std::string line = line_buffer.substr(0, newline_pos);
                    line_buffer.erase(0, newline_pos + 1);

                    if (!line.empty() && line.back() == '\r') {
                        line.pop_back();
                    }

                    std::string clean_line = strip_ansi(line);
                    if (clean_line.empty()) continue;

                    if (inspect_hemera_logs) {
                        std::string lower_line = clean_line;
                        for (char& c : lower_line) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                        if (clean_line.find("budget=") != std::string::npos) {
                            std::smatch m;
                            if (std::regex_search(clean_line, m, budget_regex) && m.size() > 1) {
                                try {
                                    uint32_t b = std::stoul(m[1].str());
                                    scan_budget_secs.store(b, std::memory_order_relaxed);
                                } catch (...) {}
                            }
                        }

                        if (clean_line.find("[gui] Zero Trust access code required") != std::string::npos ||
                            clean_line.find("Enter the code:") != std::string::npos ||
                            clean_line.find("Enter access code:") != std::string::npos) {
                            access_code_required.store(true, std::memory_order_relaxed);
                        }

                        if (clean_line.find("Hemera v") != std::string::npos ||
                            lower_line.find("starting tunnel engine") != std::string::npos ||
                            clean_line.find("[+]") != std::string::npos) {
                            engine_started.store(true, std::memory_order_relaxed);
                        }
                    }

                    if (log_cb) {
                        log_cb(clean_line);
                    }
                }
            }
        });

        return {.success = true, .pid = pid};
    }
};

ProcessSession::ProcessSession() : impl_(std::make_unique<Impl>()) {}
ProcessSession::~ProcessSession() = default;

uint32_t ProcessSession::pid() const noexcept {
    return impl_->pid;
}

bool ProcessSession::is_running() const noexcept {
    if (!impl_->hProcess) return false;
    DWORD exit_code = 0;
    if (GetExitCodeProcess(impl_->hProcess, &exit_code)) {
        return exit_code == STILL_ACTIVE;
    }
    return false;
}

std::optional<uint32_t> ProcessSession::exit_code() const noexcept {
    if (!impl_->hProcess) return std::nullopt;
    DWORD code = 0;
    if (GetExitCodeProcess(impl_->hProcess, &code)) {
        if (code != STILL_ACTIVE) return code;
    }
    return std::nullopt;
}

bool ProcessSession::engine_started() const noexcept {
    return impl_->engine_started.load(std::memory_order_relaxed);
}

bool ProcessSession::access_code_required() const noexcept {
    return impl_->access_code_required.load(std::memory_order_relaxed);
}

std::optional<uint32_t> ProcessSession::scan_budget_secs() const noexcept {
    uint32_t b = impl_->scan_budget_secs.load(std::memory_order_relaxed);
    if (b > 0) return b;
    return std::nullopt;
}

void ProcessSession::send_ctrl_c() {
    if (impl_->hStdinWrite) {
        char ctrl_c = 0x03;
        DWORD written = 0;
        WriteFile(impl_->hStdinWrite, &ctrl_c, 1, &written, nullptr);
    }
}

bool ProcessSession::send_access_code(std::string_view code) {
    if (!impl_->hStdinWrite || code.empty() || code.size() > 512) return false;
    std::string payload = std::string(code) + "\r\n";
    DWORD written = 0;
    BOOL ok = WriteFile(impl_->hStdinWrite, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
    return ok && (written == payload.size());
}

void ProcessSession::kill() {
    if (impl_->pid > 0) {
        kill_process_tree(impl_->pid);
    }
    if (impl_->hProcess) {
        TerminateProcess(impl_->hProcess, 1);
    }
}

SpawnResult ProcessSession::spawn(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& work_dir,
    const ConnectionProfile& profile,
    LogCallback log_cb
) {
    std::vector<std::pair<std::wstring, std::wstring>> env_vars;
    env_vars.emplace_back(L"HEMERA_MASQUE_HTTP2", profile.masque_http2 ? L"1" : L"0");

    if (!profile.zero_trust_team.empty()) {
        switch (profile.zero_trust_auth) {
            case ZeroTrustAuth::Email:
                if (!profile.access_email.empty()) {
                    env_vars.emplace_back(L"HEMERA_ACCESS_EMAIL", to_wide(profile.access_email));
                }
                break;
            case ZeroTrustAuth::Service:
                if (!profile.access_client_id.empty()) {
                    env_vars.emplace_back(L"HEMERA_ACCESS_CLIENT_ID", to_wide(profile.access_client_id));
                }
                if (!profile.access_client_secret.empty()) {
                    env_vars.emplace_back(L"HEMERA_ACCESS_CLIENT_SECRET", to_wide(profile.access_client_secret));
                }
                break;
            case ZeroTrustAuth::Token:
                if (!profile.access_token.empty()) {
                    env_vars.emplace_back(L"HEMERA_ACCESS_TOKEN", to_wide(profile.access_token));
                }
                break;
        }
    }

    return impl_->spawn_process(binary_path, profile.as_args(), work_dir, env_vars, std::move(log_cb), true);
}

SpawnResult ProcessSession::spawn_command(
    const std::filesystem::path& binary_path,
    const std::vector<std::string>& args,
    const std::filesystem::path& work_dir,
    LogCallback log_cb
) {
    return impl_->spawn_process(binary_path, args, work_dir, {}, std::move(log_cb), false);
}

} // namespace hemera::process
