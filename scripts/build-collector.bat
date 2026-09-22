@echo off
REM kellect collector build - x86 /MT static CRT (Ninja + vcvars cl 14.29 / SDK 19041)
REM
REM WHY x86:  lib\librdkafka*.lib are 32-bit import libs; an x64 link fails
REM           (LNK4272 -> LNK2019). Building x86 matches them and links clean.
REM WHY /MT:  root CMakeLists sets CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ->
REM           self-contained exe, no VC++ 2015-2022 redist on target.
REM Uses a dedicated build-core-x86 dir so an old x64 build-core cache can't
REM contaminate the x86 configure (CMake refuses a compiler-arch change in-place).
REM
REM Usage:   cmd /c scripts\build-collector.bat
REM Output:  bin\kellect.exe (+ DLLs + config\ copied there by CMake)
setlocal
chcp 65001 >nul
REM --- locate VS2022 via vswhere (any edition incl. BuildTools; no hardcoded path) ---
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found - no Visual Studio 2017+ install detected 1>&2
    exit /b 1
)
REM vswhere: write output to a temp file and read it back - a for /f
REM parse gets truncated by the ")" that %ProgramFiles(x86)% expands to.
"%VSWHERE%" -latest -version "[17.0,18.0)" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\kellect-vswhere.txt" 2>nul
set "VSINSTALL="
set /p VSINSTALL=<"%TEMP%\kellect-vswhere.txt"
del "%TEMP%\kellect-vswhere.txt" 2>nul
if not defined VSINSTALL (
    echo ERROR: VS2022 with C++ workload ^(VC.Tools.x86.x64^) not found 1>&2
    exit /b 1
)
echo [env] VS: %VSINSTALL%
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x86 10.0.19041.0 -vcvars_ver=14.29
if errorlevel 1 exit /b 1
cmake -B build-core-x86 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_VERSION=10.0.19041.0
if errorlevel 1 exit /b 1
cmake --build build-core-x86
if errorlevel 1 exit /b 1
echo === build-collector OK: bin\kellect.exe (x86 /MT) linked ===
