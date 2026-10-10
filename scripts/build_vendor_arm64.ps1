# Build script for ARM64 third-party libraries (BoringSSL, nghttp2, nghttp3, ngtcp2)
# Designed to run inside an MSVC ARM64 developer environment (e.g. ilammy/msvc-dev-cmd with arch: arm64)

$ErrorActionPreference = "Stop"

$root = (Get-Item $PSScriptRoot).Parent.FullName
Write-Host "Project root: $root"

$vendor = Join-Path $root "core/vendor"
$bossSrc = Join-Path $vendor "boringssl"
$bossBuild = Join-Path $bossSrc "build_arm64"
$ng2Src = Join-Path $vendor "nghttp2"
$ng2Build = Join-Path $ng2Src "build_arm64"
$ng3Src = Join-Path $vendor "nghttp3"
$ng3Build = Join-Path $ng3Src "build_arm64"
$tcpSrc = Join-Path $vendor "ngtcp2"
$tcpBuild = Join-Path $tcpSrc "build_arm64"

# 1. BoringSSL (ARM64, pure C/C++ without ASM)
Write-Host "=== 1/4 Building BoringSSL for ARM64 ===" -ForegroundColor Cyan
cmake -S "$bossSrc" -B "$bossBuild" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DOPENSSL_NO_ASM=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
cmake --build "$bossBuild" --config Release

# Copy libraries so they can be linked directly
Copy-Item "$bossBuild/crypto/crypto.lib" -Destination "$bossBuild/crypto.lib" -Force
Copy-Item "$bossBuild/ssl/ssl.lib" -Destination "$bossBuild/ssl.lib" -Force
if (Test-Path "$bossBuild/pki/pki.lib") {
    Copy-Item "$bossBuild/pki/pki.lib" -Destination "$bossBuild/pki.lib" -Force
}

# 2. nghttp2 (ARM64)
Write-Host "=== 2/4 Building nghttp2 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng2Src" -B "$ng2Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_LIB_ONLY=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF
cmake --build "$ng2Build" --target nghttp2_static

# 3. nghttp3 (ARM64)
Write-Host "=== 3/4 Building nghttp3 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng3Src" -B "$ng3Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON -DBUILD_TESTING=OFF
cmake --build "$ng3Build"

# 4. ngtcp2 with BoringSSL backend (ARM64)
Write-Host "=== 4/4 Building ngtcp2 for ARM64 ===" -ForegroundColor Cyan
$bossFwd = $bossSrc.Replace("\", "/")
$bossBuildFwd = $bossBuild.Replace("\", "/")
cmake -S "$tcpSrc" -B "$tcpBuild" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF `
  -DENABLE_BORINGSSL=ON -DENABLE_OPENSSL=OFF `
  -DBORINGSSL_INCLUDE_DIR="$bossFwd/include" `
  -DBORINGSSL_LIBRARIES="$bossBuildFwd/ssl.lib;$bossBuildFwd/crypto.lib"
cmake --build "$tcpBuild"

Write-Host "=== All ARM64 vendor libraries built successfully! ===" -ForegroundColor Green
