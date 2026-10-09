@echo off
rem Builds msquic with the OpenSSL TLS backend (Rust-free transport path).
rem Needs: VS Build Tools, NASM, a full Perl (Git's stripped msys perl cannot configure OpenSSL).
rem Local patch: msquic CMakeLists.txt line ~278 has /WX removed (SAL false positive C28020).
rem Usage: build-msquic.bat [path-to-perl-bin] [path-to-nasm]
setlocal

set "SRC=%~dp0msquic"
set "BUILD=%SRC%\build"
set "PERL_BIN=%~1"
set "NASM=%~2"
if "%PERL_BIN%"=="" set "PERL_BIN=C:\Users\Ramin\buildtools\strawberry\Strawberry\perl\bin"
if "%NASM%"=="" set "NASM=%~dp0tools\nasm-3.01"

set "VCVARS=E:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" echo vcvars64.bat not found & exit /b 1
if not exist "%PERL_BIN%\perl.exe" echo perl not found at %PERL_BIN% & exit /b 1
if not exist "%NASM%\nasm.exe" echo nasm not found at %NASM% & exit /b 1

call "%VCVARS%" >nul || exit /b 1
set "LC_ALL="
set "LANG="
set "PATH=%PERL_BIN%;%NASM%;%PATH%"

set "CMAKE_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%CMAKE_DIR%\cmake.exe" set "CMAKE_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
if not exist "%NINJA_DIR%\ninja.exe" set "NINJA_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
set "PATH=%NINJA_DIR%;%PATH%"
set "CMAKE=%CMAKE_DIR%\cmake.exe"

"%CMAKE%" -S "%SRC%" -B "%BUILD%" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl ^
  -DQUIC_TLS_LIB=openssl ^
  -DQUIC_ENABLE_LOGGING=OFF ^
  -DQUIC_BUILD_TEST=OFF -DQUIC_BUILD_TOOLS=OFF -DQUIC_BUILD_PERF=OFF ^
  || exit /b 1

"%CMAKE%" --build "%BUILD%" --config Release || exit /b 1

echo.
echo msquic built: %BUILD%\bin\Release\msquic.dll  import lib %BUILD%\obj\Release\msquic.lib
