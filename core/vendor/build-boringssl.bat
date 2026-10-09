@echo off
rem Builds BoringSSL (C) as static libs for the ngtcp2 crypto backend.
rem Needs: VS Build Tools + NASM (core\vendor\tools\nasm-3.01). Go is only needed for FIPS mode.
setlocal

set "SRC=%~dp0boringssl"
set "BUILD=%SRC%\build"
set "NASM=%~dp0tools\nasm-3.01"
if not exist "%NASM%\nasm.exe" echo nasm not found at %NASM% & exit /b 1

call "E:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "LC_ALL="
set "LANG="
set "PATH=%NASM%;%PATH%"

set "CMAKE_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%CMAKE_DIR%\cmake.exe" set "CMAKE_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
if not exist "%NINJA_DIR%\ninja.exe" set "NINJA_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
set "PATH=%NINJA_DIR%;%PATH%"

"%CMAKE_DIR%\cmake.exe" -S "%SRC%" -B "%BUILD%" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl ^
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF ^
  || exit /b 1

"%CMAKE_DIR%\cmake.exe" --build "%BUILD%" || exit /b 1

echo.
echo BoringSSL built: %BUILD%\crypto\crypto.lib %BUILD%\ssl\ssl.lib
