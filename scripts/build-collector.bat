@echo off
REM kellect collector build - x86 /MT static CRT (MSVC + Ninja).
REM
REM WHY /MT:  root CMakeLists sets CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ->
REM           self-contained exe, no VC++ 2015-2022 redist on target.
REM
REM Works with VS2022 (17.x) and VS2026 (18.x): vswhere range is [17.0,) and
REM CMake/Ninja are taken from the VS installation when they are not on PATH.
REM
REM Usage:   cmd /c scripts\build-collector.bat
REM Output:  bin\kellect.exe (+ config\ copied there by CMake)
REM
REM   powershell -ExecutionPolicy Bypass -File scripts\build-single.ps1
setlocal
cd /d "%~dp0.." || exit /b 1
chcp 65001 >nul

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found - no Visual Studio 2017+ install detected 1>&2
    exit /b 1
)

REM vswhere: write output to a temp file and read it back - a for /f
REM parse gets truncated by the ")" that %ProgramFiles(x86)% expands to.
"%VSWHERE%" -latest -version "[17.0,)" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\kellect-vswhere.txt" 2>nul
set "VSINSTALL="
set /p VSINSTALL=<"%TEMP%\kellect-vswhere.txt"
del "%TEMP%\kellect-vswhere.txt" 2>nul
if not defined VSINSTALL (
    echo ERROR: Visual Studio with C++ workload ^(VC.Tools.x86.x64^) not found 1>&2
    exit /b 1
)
echo [env] VS: %VSINSTALL%

call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x86
if errorlevel 1 exit /b 1

REM CMake/Ninja are bundled with VS but not necessarily on PATH.
set "CMAKE=cmake"
where cmake >nul 2>&1 || set "CMAKE=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
if exist "%NINJA%\ninja.exe" set "PATH=%NINJA%;%PATH%"

"%CMAKE%" -B build\collector-x86 -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1
"%CMAKE%" --build build\collector-x86
if errorlevel 1 exit /b 1
echo === build-collector OK: bin\kellect.exe + bin\KellectService.exe (x86 /MT) linked ===
