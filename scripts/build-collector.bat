@echo off
REM kellect collector build - x86 /MT static CRT (Ninja + vcvars cl 14.29 / SDK 19041)
REM
REM WHY x86:  lib\librdkafka*.lib are 32-bit import libs; an x64 link fails
REM           (LNK4272 -> LNK2019). Building x86 matches them and links clean.
REM WHY /MT:  root CMakeLists sets CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ->
REM           self-contained exe, no VC++ 2015-2022 redist on target.
REM WHY SERVICE=OFF: the service is x64 (/MT); it must NOT be rebuilt x86 here
REM           or bin\KellectService.exe gets clobbered.
REM Uses a dedicated build-core-x86 dir so an old x64 build-core cache can't
REM contaminate the x86 configure (CMake refuses a compiler-arch change in-place).
REM
REM Usage:   cmd /c scripts\build-collector.bat
REM Output:  bin\kellect.exe (+ DLLs + config\ copied there by CMake)
setlocal
chcp 65001 >nul
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86 10.0.19041.0 -vcvars_ver=14.29
if errorlevel 1 exit /b 1
cmake -B build-core-x86 -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_VERSION=10.0.19041.0 -DKELLECT_BUILD_SERVICE=OFF
if errorlevel 1 exit /b 1
cmake --build build-core-x86
if errorlevel 1 exit /b 1
echo === build-collector OK: bin\kellect.exe (x86 /MT) linked ===