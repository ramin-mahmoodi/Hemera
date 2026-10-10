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
if ($LASTEXITCODE -ne 0) { throw "BoringSSL cmake configure failed with code $LASTEXITCODE" }

cmake --build "$bossBuild" --config Release
if ($LASTEXITCODE -ne 0) { throw "BoringSSL build failed with code $LASTEXITCODE" }

Get-ChildItem -Path "$bossBuild" -Recurse -Filter "*.lib" | ForEach-Object {
    $target = Join-Path $bossBuild $_.Name
    if ($_.FullName -ne $target) {
        Copy-Item $_.FullName -Destination $target -Force
    }
}

# 2. nghttp2 (ARM64)
Write-Host "=== 2/4 Building nghttp2 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng2Src" -B "$ng2Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_LIB_ONLY=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF
if ($LASTEXITCODE -ne 0) { throw "nghttp2 cmake configure failed with code $LASTEXITCODE" }

cmake --build "$ng2Build" --config Release --target nghttp2_static
if ($LASTEXITCODE -ne 0) { throw "nghttp2 build failed with code $LASTEXITCODE" }

New-Item -ItemType Directory -Path "$ng2Build/lib" -Force | Out-Null
Get-ChildItem -Path "$ng2Build" -Recurse -Filter "*.lib" | ForEach-Object {
    $target1 = Join-Path "$ng2Build/lib" $_.Name
    if ($_.FullName -ne $target1) { Copy-Item $_.FullName -Destination $target1 -Force }
    $target2 = Join-Path $ng2Build $_.Name
    if ($_.FullName -ne $target2) { Copy-Item $_.FullName -Destination $target2 -Force }
}

# Also ensure nghttp2.lib exists alongside nghttp2_static.lib
Get-ChildItem -Path "$ng2Build" -Recurse -Filter "*_static.lib" | ForEach-Object {
    $plain = $_.Name.Replace("_static.lib", ".lib")
    $dest = Join-Path $_.DirectoryName $plain
    if (-not (Test-Path $dest)) { Copy-Item $_.FullName -Destination $dest -Force }
}
Get-ChildItem -Path "$ng2Build" -Recurse -Filter "nghttp2.lib" | ForEach-Object {
    $staticName = "nghttp2_static.lib"
    $dest = Join-Path $_.DirectoryName $staticName
    if (-not (Test-Path $dest)) { Copy-Item $_.FullName -Destination $dest -Force }
}

# 3. nghttp3 (ARM64)
Write-Host "=== 3/4 Building nghttp3 for ARM64 ===" -ForegroundColor Cyan
cmake -S "$ng3Src" -B "$ng3Build" -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl `
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON -DBUILD_TESTING=OFF
if ($LASTEXITCODE -ne 0) { throw "nghttp3 cmake configure failed with code $LASTEXITCODE" }

cmake --build "$ng3Build" --config Release
if ($LASTEXITCODE -ne 0) { throw "nghttp3 build failed with code $LASTEXITCODE" }

New-Item -ItemType Directory -Path "$ng3Build/lib" -Force | Out-Null
Get-ChildItem -Path "$ng3Build" -Recurse -Filter "*.lib" | ForEach-Object {
    $target1 = Join-Path "$ng3Build/lib" $_.Name
    if ($_.FullName -ne $target1) { Copy-Item $_.FullName -Destination $target1 -Force }
    $target2 = Join-Path $ng3Build $_.Name
    if ($_.FullName -ne $target2) { Copy-Item $_.FullName -Destination $target2 -Force }
}

# Ensure both nghttp3.lib and nghttp3_static.lib exist everywhere
Get-ChildItem -Path "$ng3Build" -Recurse -Filter "*_static.lib" | ForEach-Object {
    $plain = $_.Name.Replace("_static.lib", ".lib")
    $dest = Join-Path $_.DirectoryName $plain
    if (-not (Test-Path $dest)) { Copy-Item $_.FullName -Destination $dest -Force }
}
Get-ChildItem -Path "$ng3Build" -Recurse -Filter "nghttp3.lib" | ForEach-Object {
    $staticName = "nghttp3_static.lib"
    $dest = Join-Path $_.DirectoryName $staticName
    if (-not (Test-Path $dest)) { Copy-Item $_.FullName -Destination $dest -Force }
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
if ($LASTEXITCODE -ne 0) { throw "ngtcp2 cmake configure failed with code $LASTEXITCODE" }

cmake --build "$tcpBuild" --config Release
if ($LASTEXITCODE -ne 0) { throw "ngtcp2 build failed with code $LASTEXITCODE" }

New-Item -ItemType Directory -Path "$tcpBuild/lib" -Force | Out-Null
New-Item -ItemType Directory -Path "$tcpBuild/crypto/boringssl" -Force | Out-Null
Get-ChildItem -Path "$tcpBuild" -Recurse -Filter "*.lib" | ForEach-Object {
    $target1 = Join-Path "$tcpBuild/lib" $_.Name
    if ($_.FullName -ne $target1) { Copy-Item $_.FullName -Destination $target1 -Force }
    $target2 = Join-Path "$tcpBuild/crypto/boringssl" $_.Name
    if ($_.FullName -ne $target2) { Copy-Item $_.FullName -Destination $target2 -Force }
    $target3 = Join-Path $tcpBuild $_.Name
    if ($_.FullName -ne $target3) { Copy-Item $_.FullName -Destination $target3 -Force }
}

# Ensure both static and plain library names exist
Get-ChildItem -Path "$tcpBuild" -Recurse -Filter "*_static.lib" | ForEach-Object {
    $plain = $_.Name.Replace("_static.lib", ".lib")
    $dest = Join-Path $_.DirectoryName $plain
    if (-not (Test-Path $dest)) { Copy-Item $_.FullName -Destination $dest -Force }
}

Write-Host "=== Verifying all required ARM64 libraries ===" -ForegroundColor Cyan
$requiredLibs = @(
    "$bossBuild/ssl.lib",
    "$bossBuild/crypto.lib",
    "$ng2Build/lib/nghttp2.lib",
    "$ng3Build/lib/nghttp3.lib",
    "$tcpBuild/lib/ngtcp2.lib",
    "$tcpBuild/crypto/boringssl/ngtcp2_crypto_boringssl.lib"
)

foreach ($lib in $requiredLibs) {
    if (-not (Test-Path $lib)) {
        throw "CRITICAL: Required ARM64 library was not found: $lib"
    }
    $info = Get-Item $lib
    Write-Host "  OK: $lib ($($info.Length) bytes)" -ForegroundColor Green
}

Write-Host "=== All ARM64 vendor libraries built and verified successfully! ===" -ForegroundColor Green
