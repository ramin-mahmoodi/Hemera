@echo off
rem Builds nghttp2 (HTTP/2 framing + HPACK), the carrier the MASQUE-over-H2 option runs on.
rem Clone it first: git clone --depth 1 --branch v1.64.0 https://github.com/nghttp2/nghttp2.git
setlocal

set "V=%~dp0"
set "CMAKE_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%CMAKE_DIR%\cmake.exe" set "CMAKE_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
if not exist "%NINJA_DIR%\ninja.exe" set "NINJA_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%V%nghttp2\lib\includes\nghttp2\nghttp2.h" echo nghttp2 source not found: clone v1.64.0 into core\vendor\nghttp2 & exit /b 1

call "D:\Studio\Product\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul || exit /b 1
set "PATH=%NINJA_DIR%;%PATH%"

"%CMAKE_DIR%\cmake.exe" -S "%V%nghttp2" -B "%V%nghttp2\build" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl ^
  -DENABLE_LIB_ONLY=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_TESTING=OFF ^
  -DENABLE_WERROR=OFF ^
  || exit /b 1
"%CMAKE_DIR%\cmake.exe" --build "%V%nghttp2\build" --target nghttp2_static || exit /b 1

echo.
echo nghttp2 built: nghttp2\build\lib
