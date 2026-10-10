# Build script for ARM64 third-party libraries (BoringSSL, nghttp2, nghttp3, ngtcp2)
# Designed to run inside an MSVC ARM64 developer environment (e.g. ilammy/msvc-dev-cmd with arch: x64_arm64)

$ErrorActionPreference = "Stop"

$root = (Get-Item $PSScriptRoot).Parent.FullName
Write-Host "Project root: $root"

$vendor = Join-Path $root "core/vendor"
$bossSrc = Join-Path $vendor "boringssl"

# BoringSSL source tree is omitted from git to keep repo size small; clone if not present
if (-not (Test-Path "$bossSrc/gen/sources.cmake")) {
    $bossSrc = Join-Path $vendor "boringssl_src"
    if (-not (Test-Path "$bossSrc/CMakeLists.txt")) {
        Write-Host "Cloning BoringSSL source for ARM64 build..." -ForegroundColor Cyan
        git clone --depth 1 https://github.com/google/boringssl.git "$bossSrc"
    }
}

$bossBuild = Join-Path $vendor "boringssl/build_arm64"
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

# Ensure all libraries are accessible at top-level build dir
Get-ChildItem -Path "$bossBuild" -Recurse -Filter "*.lib" | ForEach-Object {
    Copy-Item $_.FullName -Destination "$bossBuild/$($_.Name)" -Force
}

# 2. nghttp2 (ARM64)
Write-Host "=== 2/4 Building nghttp2 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng2Src" -B "$ng2Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_LIB_ONLY=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF
cmake --build "$ng2Build" --target nghttp2_static

New-Item -ItemType Directory -Path "$ng2Build/lib" -Force | Out-Null
Get-ChildItem -Path "$ng2Build" -Recurse -Filter "*.lib" | ForEach-Object {
    Copy-Item $_.FullName -Destination "$ng2Build/lib/$($_.Name)" -Force
    Copy-Item $_.FullName -Destination "$ng2Build/$($_.Name)" -Force
}

# 3. nghttp3 (ARM64)
Write-Host "=== 3/4 Building nghttp3 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng3Src" -B "$ng3Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON -DBUILD_TESTING=OFF
cmake --build "$ng3Build"

New-Item -ItemType Directory -Path "$ng3Build/lib" -Force | Out-Null
Get-ChildItem -Path "$ng3Build" -Recurse -Filter "*.lib" | ForEach-Object {
    Copy-Item $_.FullName -Destination "$ng3Build/lib/$($_.Name)" -Force
    Copy-Item $_.FullName -Destination "$ng3Build/$($_.Name)" -Force
}

# 4. ngtcp2 with BoringSSL backend (ARM64)
Write-Host "=== 4/4 Building ngtcp2 for ARM64 ===" -ForegroundColor Cyan
$bossIncludeFwd = (Join-Path $bossSrc "include").Replace("\", "/")
$bossBuildFwd = $bossBuild.Replace("\", "/")
cmake -S "$tcpSrc" -B "$tcpBuild" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF `
  -DENABLE_BORINGSSL=ON -DENABLE_OPENSSL=OFF `
  -DBORINGSSL_INCLUDE_DIR="$bossIncludeFwd" `
  -DBORINGSSL_LIBRARIES="$bossBuildFwd/ssl.lib;$bossBuildFwd/crypto.lib"
cmake --build "$tcpBuild"

New-Item -ItemType Directory -Path "$tcpBuild/lib" -Force | Out-Null
New-Item -ItemType Directory -Path "$tcpBuild/crypto/boringssl" -Force | Out-Null
Get-ChildItem -Path "$tcpBuild" -Recurse -Filter "*.lib" | ForEach-Object {
    Copy-Item $_.FullName -Destination "$tcpBuild/lib/$($_.Name)" -Force
    Copy-Item $_.FullName -Destination "$tcpBuild/crypto/boringssl/$($_.Name)" -Force
    Copy-Item $_.FullName -Destination "$tcpBuild/$($_.Name)" -Force
}

Write-Host "=== All ARM64 vendor libraries built successfully! ===" -ForegroundColor Green
