# Hemera

<p align="center">
  <img src="icon.png" alt="Hemera Logo" width="120" height="120">
</p>

<h3 align="center">Ultra-Fast, Lightweight, Native Windows Circumvention Client</h3>

<p align="center">
  A pure, modern <b>C++26</b> native desktop client for <a href="https://github.com/CluvexStudio/Aether"><b>Aether</b></a> censorship-circumvention tunnels.<br>
  Engineered from scratch with <b>Direct2D hardware acceleration</b>, zero web runtimes, and minimal memory footprint.
</p>

<p align="center">
  <a href="https://github.com/ramin-mahmoodi/Hemera/releases"><img src="https://img.shields.io/github/v/release/ramin-mahmoodi/Hemera?sort=semver&style=flat-square&color=0078D6" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ramin-mahmoodi/Hemera?style=flat-square&color=2ea44f" alt="License: AGPL v3"></a>
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/C%2B%2B-26-00599C?style=flat-square&logo=c%2B%2B&logoColor=white" alt="C++26">
  <img src="https://img.shields.io/badge/Direct2D-Hardware%20Accelerated-orange?style=flat-square" alt="Direct2D">
  <img src="https://img.shields.io/badge/arch-x64%20%7C%20ARM64-lightgrey?style=flat-square" alt="Arch">
  <a href="https://github.com/ramin-mahmoodi/Hemera/actions"><img src="https://img.shields.io/github/actions/workflow/status/ramin-mahmoodi/Hemera/build-and-release.yml?style=flat-square&logo=githubactions&logoColor=white" alt="Build Status"></a>
</p>

<p align="center">
  <b>English</b> · <a href="README_fa.md"><b>فارسی</b></a>
</p>

---

<p align="center">
  <img src="docs/screenshot.png" alt="Hemera Native — One-Click Connect Screen" width="460">
</p>

## Overview

**Hemera** is a pure native Windows port and standalone client for [**Aether**](https://github.com/CluvexStudio/Aether) — a next-generation censorship-circumvention tunnel built for heavily restricted, adversarial networks where Deep Packet Inspection (DPI), protocol fingerprinting, and UDP throttling are aggressive.

Unlike traditional desktop clients built on heavy runtimes (Electron, WebView2, Qt, or WebKit), **Hemera** is re-engineered from the ground up in modern **ISO C++26** and rendered directly through **Windows Direct2D & DirectWrite**. The result is a single, self-contained native executable that consumes **less than 15 MB of RAM**, causes **0% idle CPU usage**, and delivers butter-smooth **60–120+ FPS** hardware-accelerated animations.

---

## ⚡ Performance Benchmark

| Metric | Hemera (Native C++26) | Typical Web/Tauri Clients | Typical Electron Clients |
| :--- | :---: | :---: | :---: |
| **RAM Consumption** | **< 15 MB** | 70 – 160 MB | 200 – 450 MB |
| **Idle CPU Usage** | **0.0%** | 0.8 – 3.0% | 2.0 – 6.0% |
| **Rendering Pipeline** | **Direct2D Hardware-Accelerated** | WebView2 / WebKit DOM | Chromium GPU / Blink |
| **Startup Time** | **< 300 ms (Instant)** | 1.5 – 3.0 s | 2.5 – 6.0 s |
| **Binary Architecture** | **Single Native `.exe` (~12 MB)** | Multi-file Bundle | 100+ MB Framework Files |
| **Framework Dependencies** | **None (Pure Win32 API)** | WebView2 Runtime | Node.js + Chromium |
| **Display Refresh Sync** | **Adaptive 60 / 120 / 144 Hz** | Fixed 60 Hz | Fixed 60 Hz |

---

## Features

### 🚀 One-Click Simplicity
- **Zero Configuration Needed:** Press **Connect**, and Hemera automatically discovers optimal endpoints, negotiates encrypted handshakes, and routes your traffic.
- **Smart Reconnect:** Caches the last verified working gateway and re-tests it first, connecting in seconds without rescanning.

### 🛡️ Advanced Protocol Engine
- **MASQUE (HTTP/3 & HTTP/2):** Encapsulates raw IP datagrams inside genuine QUIC and HTTP/2 TLS streams. Features ClientHello fragmentation to completely evade TLS SNI-based firewalls.
- **WireGuard:** Ultra-fast, minimal overhead modern UDP tunnel.
- **WARP-in-WARP (`gool`):** Dual nested WireGuard hops discovered automatically or configured manually for clean egress IPs.
- **MASQUE-in-MASQUE (`mim`):** Two chained MASQUE tunnels for maximum censorship resistance and exit country diversity.

### 🌐 System-Wide Routing & Proxy
- **Native Wintun TUN Driver:** Optional full-system L3 virtual network adapter that captures and routes all OS traffic, preventing any DNS leaks or UDP bypasses.
- **Seamless Windows System Proxy (SysProxy):** Automatically configures WinINet registry settings with instant atomic notification (`InternetSetOptionW`) without requiring browser restarts.
- **Crash-Proof Proxy Restoration:** Automatically restores your original network proxy settings upon disconnect, normal exit, and even after system crashes.

### 🔍 Multi-Tier Intelligent Route Discovery
- **Turbo / Balanced / Thorough:** Balances candidate scan budgets against endpoint discovery depth.
- **Verified / Ironclad:** End-to-end data-plane validation. Candidate gateways are only trusted after successfully passing a live encrypted HTTP request, eliminating dead routes before you connect.

### 🧠 Zero-Spin Event-Driven NetStack
- **RFC 6298 Jacobson/Karn RTT Estimator:** Dynamic RTT and variance calculation with adaptive RTO bounds (100 ms – 10 s) to eliminate stalled connections on jittery networks.
- **RFC 6582 NewReno Fast Recovery:** Recovers from multiple packet losses within a single burst window without triggering pipeline resets.
- **Condition-Variable Signaling:** Zero mutex-spinning or artificial sleeps, eliminating lock contention.
- **Windows 11 EcoQoS-Aware:** Automatically disables background `PowerThrottling` so timer resolution and throughput remain peak even when minimized to the System Tray.

### 🎛️ Windows Integration
- **System Tray:** Minimizes cleanly to tray with dynamic connection state badges and right-click quick controls.
- **Windows Job Object:** Sandboxes helper processes to guarantee zero orphaned background tasks.
- **Live Diagnostic Logs:** Clean, timestamped diagnostic logs with one-click clipboard copy.

---

## Download

Prebuilt binaries are available on the [**Releases**](https://github.com/ramin-mahmoodi/Hemera/releases) page:

| Architecture | Package | Description |
| :--- | :--- | :--- |
| **Windows x64** | [`Hemera-v1.0.6-windows-x64.zip`](https://github.com/ramin-mahmoodi/Hemera/releases/latest) | For standard 64-bit Intel / AMD PCs |
| **Windows ARM64** | [`Hemera-v1.0.6-windows-arm64.zip`](https://github.com/ramin-mahmoodi/Hemera/releases/latest) | For Surface Pro, Snapdragon X Elite & ARM PCs |

> **No installation required.** Simply extract the zip archive and run `Hemera.exe`.

---

## Building from Source

### Prerequisites
- **Windows 10 / 11** (x64 or ARM64)
- **Visual Studio 2022** (v17.10 or newer) with the *Desktop development with C++* workload
- **CMake 3.25+**

### Build Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ramin-mahmoodi/Hemera.git
   cd Hemera
   ```

2. **Configure CMake:**
   ```cmd
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   ```

3. **Build Hemera (Release):**
   ```cmd
   cmake --build build --config Release
   ```
   The compiled executable will be located at `build/Release/Hemera.exe`.

4. **Run Unit Tests (54 Test Suites):**
   ```cmd
   .\build\Release\test_runner.exe
   ```

---

## Project Structure

```
Hemera/
├── include/                 # Public engine headers & data contracts
├── src/                     # Win32 Direct2D GUI, engine coordinator & main entry
│   ├── gui.cpp              # Direct2D hardware-accelerated rendering engine
│   ├── engine.cpp           # Process orchestration & proxy manager
│   ├── sysproxy.cpp         # Windows registry proxy integration
│   └── main.cpp             # DPI awareness, EcoQoS & WinMain lifecycle
├── core/                    # C++ NetStack & protocol implementations
│   ├── src/                 # NetStack, MASQUE, WireGuard, DNS, ECH
│   └── vendor/              # Vendored dependencies (BoringSSL, nghttp2, ngtcp2, RE2)
├── tests/                   # 54 comprehensive unit test suites
├── docs/                    # Screenshots and documentation assets
├── scripts/                 # Build helper scripts & ARM64 vendor builders
├── CMakeLists.txt           # Modern CMake configuration
└── build.bat                # Quick build launcher
```

---

## Credits & Acknowledgements

- [**CluvexStudio/Aether**](https://github.com/CluvexStudio/Aether) — Original censorship-circumvention tunnel & protocol architecture.
- [**MatinSenPai/Aether-GUI**](https://github.com/MatinSenPai/Aether-GUI) — Inspiration for the clean desktop user experience.
- [**Wintun**](https://www.wintun.net/) — High-performance TUN driver for Windows.

---

## License

This project is licensed under the [**GNU Affero General Public License v3.0 (AGPL-3.0)**](LICENSE).
