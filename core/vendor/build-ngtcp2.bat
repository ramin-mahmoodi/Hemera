@echo off
rem Builds the C QUIC + HTTP/3 layer: nghttp3 (framing, QPACK, Extended CONNECT) and
rem ngtcp2 (transport, datagrams) with its BoringSSL crypto backend.
rem Run core\vendor\build-boringssl.bat first.
setlocal

set "V=%~dp0"
rem CMake embeds these paths in generated code, so they must use forward slashes
rem (a backslash path like C:\Users\... becomes an invalid \U escape there).
set "VF=%V:\=/%"
set "BOSS=%VF%boringssl"
set "CMAKE_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "NINJA_DIR=D:\Studio\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%CMAKE_DIR%\cmake.exe" set "CMAKE_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
if not exist "%NINJA_DIR%\ninja.exe" set "NINJA_DIR=E:\VSBuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if not exist "%BOSS%\build\ssl.lib" echo build BoringSSL first: call core\vendor\build-boringssl.bat & exit /b 1

call "E:\VSBuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "LC_ALL="
set "LANG="
set "PATH=%NINJA_DIR%;%PATH%"

"%CMAKE_DIR%\cmake.exe" -S "%V%nghttp3" -B "%V%nghttp3\build" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl ^
  -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DENABLE_LIB_ONLY=ON -DBUILD_TESTING=OFF ^
  || exit /b 1
"%CMAKE_DIR%\cmake.exe" --build "%V%nghttp3\build" || exit /b 1

"%CMAKE_DIR%\cmake.exe" -S "%V%ngtcp2" -B "%V%ngtcp2\build" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl ^
  -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF ^
  -DENABLE_BORINGSSL=ON -DENABLE_OPENSSL=OFF ^
  -DBORINGSSL_INCLUDE_DIR="%BOSS%/include" ^
  -DBORINGSSL_LIBRARIES="%BOSS%/build/ssl.lib;%BOSS%/build/crypto.lib" ^
  || exit /b 1
"%CMAKE_DIR%\cmake.exe" --build "%V%ngtcp2\build" || exit /b 1

echo.
echo C QUIC stack built: nghttp3\build\lib, ngtcp2\build\lib
