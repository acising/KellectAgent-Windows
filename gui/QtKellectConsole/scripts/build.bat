@echo off
REM KellectConsole Qt5.15 build/test (Ninja + vcvars cl 14.29 / SDK 19041)
REM Dynamic Qt (official 5.15.2 msvc2019_64): DLLs are copied beside the exe
REM after build so the local build dir runs standalone.
REM Usage: cmd //c scripts\build.bat        build only
REM        cmd //c scripts\build.bat test   build + ctest
setlocal
if not defined QTDIR set "QTDIR=D:\Code\Qt\5.15.2\msvc2019_64"
if not exist "%QTDIR%\bin\Qt5Core.dll" (
    echo ERROR: dynamic Qt not found at %QTDIR% ^(set QTDIR to override^) 1>&2
    exit /b 1
)
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
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" x64 10.0.19041.0 -vcvars_ver=14.29
if errorlevel 1 exit /b 1
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=%QTDIR% -DCMAKE_SYSTEM_VERSION=10.0.19041.0 -DCMAKE_EXE_LINKER_FLAGS=/MANIFEST:NO
if errorlevel 1 exit /b 1
cmake --build build
if errorlevel 1 exit /b 1

REM --- deploy Qt runtime beside the exe (Widgets+Network app: fixed minimal set) ---
copy /y "%QTDIR%\bin\Qt5Core.dll"    build\ >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Gui.dll"     build\ >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Widgets.dll" build\ >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Network.dll" build\ >nul || goto :err
if not exist build\platforms mkdir build\platforms
copy /y "%QTDIR%\plugins\platforms\qwindows.dll" build\platforms\ >nul || goto :err

if not "%1"=="" (
    set "PATH=%QTDIR%\bin;%PATH%"
    ctest --test-dir build --output-on-failure
)
exit /b 0

:err
echo FAILED to copy Qt runtime DLLs 1>&2
exit /b 1
