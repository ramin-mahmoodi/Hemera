@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo  Building Aether Native (C++26) - Zero Dependencies
echo =======================================================

:: 0. Check and automatically initialize MSVC environment if cl is not in PATH
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo MSVC cl.exe not in PATH. Searching for vcvarsall.bat...
    if exist "D:\Studio\Product\VC\Auxiliary\Build\vcvarsall.bat" (
        call "D:\Studio\Product\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    )
)

:: 1. If CMake is available in PATH, prefer CMake build
where cmake >nul 2>&1
if !ERRORLEVEL! equ 0 (
    echo [1/3] Configuring with CMake...
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    if !ERRORLEVEL! neq 0 (
        echo CMake configuration failed.
        exit /b !ERRORLEVEL!
    )

    echo [2/3] Building Release binaries...
    cmake --build build --config Release
    if !ERRORLEVEL! neq 0 (
        echo CMake build failed.
        exit /b !ERRORLEVEL!
    )

    echo [3/3] Running Automated Verification Tests...
    if exist "build\Release\test_runner.exe" (
        "build\Release\test_runner.exe"
    ) else if exist "build\test_runner.exe" (
        "build\test_runner.exe"
    )
    if !ERRORLEVEL! neq 0 (
        echo Automated tests failed.
        exit /b !ERRORLEVEL!
    )

    if exist "build\Hemera.exe" (
        copy /y "build\Hemera.exe" "Hemera.exe" >nul
    ) else if exist "build\Release\Hemera.exe" (
        copy /y "build\Release\Hemera.exe" "Hemera.exe" >nul
    )

    if exist "build\test_runner.exe" (
        copy /y "build\test_runner.exe" "test_runner.exe" >nul
    ) else if exist "build\Release\test_runner.exe" (
        copy /y "build\Release\test_runner.exe" "test_runner.exe" >nul
    )

    echo =======================================================
    echo  Build Successful! Target: Hemera.exe
    echo =======================================================
    exit /b 0
)

:: 2. Fallback to direct MSVC compilation
echo CMake not detected in PATH. Checking for MSVC cl.exe...
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Neither CMake nor MSVC cl.exe was found.
    echo Please run this from a Visual Studio Developer Command Prompt.
    exit /b 1
)

echo Compiling resources with rc.exe...
rc.exe /nologo /i include /fo resources.res gui_resources.rc
if %ERRORLEVEL% neq 0 (
    echo Resource compilation failed.
    exit /b %ERRORLEVEL%
)

echo Compiling Hemera.exe using MSVC cl.exe (/std:c++latest)...
cl /std:c++latest /EHsc /utf-8 /DUNICODE /D_UNICODE /O2 /Iinclude src\main.cpp src\gui.cpp src\engine.cpp src\process.cpp src\network.cpp src\sysproxy.cpp src\autostart.cpp resources.res /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib shell32.lib comctl32.lib dwmapi.lib uxtheme.lib wininet.lib ws2_32.lib advapi32.lib ole32.lib /OUT:Hemera.exe
if %ERRORLEVEL% neq 0 (
    echo Hemera.exe compilation failed.
    exit /b %ERRORLEVEL%
)

if exist "tests\test_runner.cpp" (
    echo Compiling test_runner.exe and running tests...
    cl /std:c++latest /EHsc /utf-8 /DUNICODE /D_UNICODE /Iinclude /Icore\src tests\test_runner.cpp src\network.cpp src\process.cpp src\sysproxy.cpp core\src\encoding.cpp core\src\identity.cpp core\src\settings.cpp core\src\usage.cpp resources.res /link ws2_32.lib shell32.lib ole32.lib advapi32.lib wininet.lib /OUT:test_runner.exe
    if %ERRORLEVEL% neq 0 (
        echo test_runner.exe compilation failed.
        exit /b %ERRORLEVEL%
    )

    test_runner.exe
    if %ERRORLEVEL% neq 0 (
        echo Automated tests failed.
        exit /b %ERRORLEVEL%
    )
)

echo =======================================================
echo  Build Complete! Standalone Single Executable: Hemera.exe
echo =======================================================
exit /b 0
