cmake_minimum_required(VERSION 3.25)
project(HemeraNative LANGUAGES CXX RC)

set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_CXX_STANDARD 23)
    add_compile_options(/std:c++latest /permissive- /utf-8 /W4 /EHsc /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS)
else()
    set(CMAKE_CXX_STANDARD 26)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    add_compile_options(-std=c++26 -Wall -Wextra -pedantic -DUNICODE -D_UNICODE)
endif()

include_directories(include)

# Core engine, the C++ port of the Rust hemera crate (AGPL-3.0-only, same as the original).
# Currently the account store and the command line table; the tunnel engine lands here too.
add_library(hemera_core STATIC
    core/src/account.cpp
    core/src/account_live.cpp
    core/src/access_http.cpp
    core/src/ech_transport.cpp
    core/src/hemeranoize.cpp
    core/src/coreflow.cpp
    core/src/encoding.cpp
    core/src/dns.cpp
    core/src/egress.cpp
    core/src/exitloc.cpp
    core/src/ffi.cpp
    core/src/fragment.cpp
    core/src/identity.cpp
    core/src/https.cpp
    # The two carrier runtimes, both compiling clean as standalone TUs and both needed for the
    # product to have a live --h2 and a live WireGuard path at all: masque_h2_runtime.cpp is the
    # socket/nghttp2 half masque_h2.hpp declares, wg_live.cpp is wireguard.rs's live handshake and
    # the four hemeranoize obfuscation sites.
    core/src/masque_h2_runtime.cpp
    core/src/wg_live.cpp
    # https_runtime.cpp is https::send: the socket half -- dial, the SOCKS detour, the fingerprinted
    # ClientHello, h1 and nghttp2, and the fourth ECH retry site (https.rs:103). It compiles clean, so
    # it is registered; account enrolment and the Zero Trust hooks cannot run without it.
    core/src/https_runtime.cpp
    core/src/lastconn.cpp
    core/src/localapi.cpp
    core/src/masque.cpp
    core/src/masque_h2.cpp
    core/src/netpacket.cpp
    core/src/netstack.cpp
    core/src/noize.cpp
    core/src/prober.cpp
    core/src/quic.cpp
    core/src/routing.cpp
    core/src/settings.cpp
    core/src/sniff.cpp
    core/src/socks.cpp
    core/src/stats.cpp
    core/src/sysprofile.cpp
    core/src/tls.cpp
    core/src/transport.cpp
    core/src/upstream.cpp
    core/src/usage.cpp
    core/src/wireguard.cpp
    core/src/zerotrust.cpp
    core/src/hemera_cli.cpp
    core/src/tun_device.cpp
)
target_include_directories(hemera_core PUBLIC core/src)

# BoringSSL is built from core/vendor/boringssl by core/vendor/build-boringssl.bat, always with
# /MD, so this project must not switch the runtime out from under it. ngtcp2, its BoringSSL crypto
# adapter, nghttp3 and nghttp2 are built the same way by their own build scripts under
# core/vendor.
target_include_directories(hemera_core PUBLIC
    core/vendor/boringssl/include
    core/vendor/boringssl_src/include
    core/vendor/ngtcp2/lib/includes
    core/vendor/ngtcp2/build/lib/includes
    core/vendor/ngtcp2/build_arm64/lib/includes
    core/vendor/ngtcp2/crypto/includes
    core/vendor/nghttp3/lib/includes
    core/vendor/nghttp3/build/lib/includes
    core/vendor/nghttp3/build_arm64/lib/includes
    core/vendor/nghttp2/lib/includes
    core/vendor/nghttp2/build/lib/includes
    core/vendor/nghttp2/build_arm64/lib/includes
    core/vendor/asio/include
    core/vendor/re2
)
target_compile_definitions(hemera_core PUBLIC NGTCP2_STATICLIB NGHTTP3_STATICLIB NGHTTP2_STATICLIB ASIO_STANDALONE _WIN32_WINNT=0x0A00
    # nghttp2.h uses ssize_t, which MSVC only declares in BaseTsd.h; the header's own guard typedefs
    # it from intptr_t (same width on x64, so the vendored nghttp2.lib ABI is unchanged). Any TU that
    # includes <nghttp2/nghttp2.h> -- the H2 carrier, the HTTPS client -- needs this.
    NGHTTP2_NO_SSIZE_T)

set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(core/vendor/re2 EXCLUDE_FROM_ALL)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|arm64" OR CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
    target_link_directories(hemera_core PUBLIC
        core/vendor/boringssl/build_arm64
        core/vendor/boringssl/build_arm64/crypto
        core/vendor/boringssl/build_arm64/ssl
        core/vendor/boringssl/build_arm64/pki
        core/vendor/nghttp3/build_arm64/lib
        core/vendor/nghttp2/build_arm64/lib
        core/vendor/ngtcp2/build_arm64/lib
        core/vendor/ngtcp2/build_arm64/crypto/boringssl
    )
else()
    target_link_directories(hemera_core PUBLIC
        core/vendor/boringssl/build
        core/vendor/nghttp3/build/lib
        core/vendor/nghttp2/build/lib
        core/vendor/ngtcp2/build/lib
        core/vendor/ngtcp2/build/crypto/boringssl
    )
endif()
target_link_libraries(hemera_core PUBLIC
    re2 nghttp3 nghttp2 ngtcp2_crypto_boringssl ngtcp2 ssl pki crypto ws2_32 mswsock bcrypt iphlpapi
)

# Windows Native GUI Application (WIN32 Subsystem, No Qt, Zero external dependencies)
add_executable(Hemera WIN32
    src/main.cpp
    src/gui.cpp
    src/engine.cpp
    src/network.cpp
    src/sysproxy.cpp
    src/autostart.cpp
    gui_resources.rc
)

target_link_options(Hemera PRIVATE "/SUBSYSTEM:WINDOWS" "/ENTRY:wWinMainCRTStartup")

target_include_directories(Hemera PRIVATE
    include
    core/src
    core/vendor/asio/include
)

target_link_libraries(Hemera PRIVATE
    hemera_core
    d2d1
    dwrite
    windowscodecs
    ws2_32
    mswsock
    wininet
    dwmapi
    uxtheme
    comctl32
    shell32
    gdi32
    user32
    advapi32
    ole32
    winmm
    psapi
    iphlpapi
)

# Copy wintun.dll to build outputs if present (architecture-aware)
set(WINTUN_SRC "")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|arm64" OR CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/binaries/arm64/wintun.dll")
        set(WINTUN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/binaries/arm64/wintun.dll")
    endif()
else()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/binaries/x64/wintun.dll")
        set(WINTUN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/binaries/x64/wintun.dll")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/binaries/wintun.dll")
        set(WINTUN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/binaries/wintun.dll")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wintun.dll")
        set(WINTUN_SRC "${CMAKE_CURRENT_SOURCE_DIR}/wintun.dll")
    endif()
endif()

if(WINTUN_SRC)
    file(COPY "${WINTUN_SRC}" DESTINATION "${CMAKE_BINARY_DIR}")
    if(EXISTS "${CMAKE_BINARY_DIR}/Release")
        file(COPY "${WINTUN_SRC}" DESTINATION "${CMAKE_BINARY_DIR}/Release")
    endif()
endif()

add_custom_target(Hemera-GUI DEPENDS Hemera)

add_custom_command(TARGET Hemera POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:Hemera>
        "${CMAKE_CURRENT_SOURCE_DIR}/Hemera.exe"
)

if(WINTUN_SRC)
    add_custom_command(TARGET Hemera POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINTUN_SRC}"
            "$<TARGET_FILE_DIR:Hemera>/wintun.dll"
    )
endif()

# Automated Test Suite (Console executable) - built only if tests exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_runner.cpp")
    add_executable(test_runner
        tests/test_runner.cpp
        tests/account_tests.cpp
        tests/coreflow_tests.cpp
        tests/exitloc_tests.cpp
        tests/ffi_tests.cpp
        tests/localapi_tests.cpp
        tests/masque_tests.cpp
        tests/masque_h2_tests.cpp
        tests/netpacket_tests.cpp
        tests/netstack_tests.cpp
        tests/noize_tests.cpp
        tests/prober_tests.cpp
        tests/socks_tests.cpp
        tests/transport_tests.cpp
        tests/upstream_tests.cpp
        tests/wireguard_tests.cpp
        tests/zerotrust_tests.cpp
        src/network.cpp
        src/process.cpp
        src/sysproxy.cpp
        resources.rc
    )

    target_link_libraries(test_runner PRIVATE
        hemera_core
        ws2_32
        mswsock
        shell32
        ole32
        advapi32
        wininet
    )
    target_link_options(test_runner PRIVATE "/MAP" "/DEBUG")

    # The suite is assert-based, so the release build must not switch the checks off.
    target_compile_options(test_runner PRIVATE $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<CONFIG:Release>>:/UNDEBUG>)

    enable_testing()
    add_test(NAME CoreUnitTests COMMAND test_runner)
endif()

