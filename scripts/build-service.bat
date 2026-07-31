@echo off
REM kellect service wrapper build (Ninja + vcvars cl 14.29 / SDK 19041)
REM Usage:   cmd //c scripts\build-service.bat
REM Output:  bin\KellectService.exe
REM Builds service/ STANDALONE (cmake -S service) so the collector's ATL gap
REM (task #11) does not block this target.
setlocal
chcp 65001 >nul
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 10.0.19041.0 -vcvars_ver=14.29
if errorlevel 1 exit /b 1
cmake -S service -B build-service -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_VERSION=10.0.19041.0
if errorlevel 1 exit /b 1
cmake --build build-service
if errorlevel 1 exit /b 1
echo === build-service OK: KellectService.exe built ===
