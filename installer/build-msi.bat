@echo off
REM ===========================================================================
REM  build-msi.bat ? assemble stage\ and build the kellect MSI with WiX v4/v5.
REM  Run from anywhere:  cmd /c installer\build-msi.bat
REM
REM  Prereqs on the machine (one-time):
REM    dotnet tool install -g wix        (WiX CLI, ~7.x)
REM  Binary prereqs (produced by the other build steps):
REM    (collector)                        -> bin\kellect.exe + bin\KellectService.exe + bin\config\
REM    gui\QtKellectConsole\scripts\build.bat -> gui\QtKellectConsole\build\KellectConsole.exe
REM ===========================================================================
setlocal enableextensions enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.." >nul
set "REPO_ROOT=%CD%"
popd >nul
set "STAGE=%SCRIPT_DIR%stage"
set "OUT=%SCRIPT_DIR%build-msi"

echo === kellect MSI build ===
echo repo:   %REPO_ROOT%
echo stage:  %STAGE%
echo.

REM --- clean + recreate stage ---
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"          2>nul
mkdir "%STAGE%\config"   2>nul

REM ---------------------------------------------------------------------------
REM Collector artifacts: bin.
REM ---------------------------------------------------------------------------
set "COLLECTOR_SRC="
if exist "%REPO_ROOT%\bin\kellect.exe"                            set "COLLECTOR_SRC=%REPO_ROOT%\bin"
if not defined COLLECTOR_SRC (
    echo ERROR: kellect.exe not found. Run scripts\build-collector.bat. 1>&2
    exit /b 1
)
echo [stage] collector from %COLLECTOR_SRC%
copy /y "%COLLECTOR_SRC%\kellect.exe"            "%STAGE%\" >nul || goto :err

REM Service host (product 2). Built by the same CMake run as kellect.exe.
if not exist "%COLLECTOR_SRC%\KellectService.exe" (
    echo ERROR: KellectService.exe not found next to kellect.exe in 1>&2
    echo        %COLLECTOR_SRC% - rebuild with scripts\build-collector.bat 1>&2
    exit /b 1
)
copy /y "%COLLECTOR_SRC%\KellectService.exe"     "%STAGE%\" >nul || goto :err

copy /y "%SCRIPT_DIR%kellect.exe.manifest" "%STAGE%\" >nul || goto :err

REM ---------------------------------------------------------------------------
REM GUI binary
REM ---------------------------------------------------------------------------
set "GUI_SRC="
if exist "%REPO_ROOT%\gui\QtKellectConsole\build\KellectConsole.exe" set "GUI_SRC=%REPO_ROOT%\gui\QtKellectConsole\build"
if not defined GUI_SRC (
    echo ERROR: KellectConsole.exe not found. Run gui\QtKellectConsole\scripts\build.bat first. 1>&2
    exit /b 1
)
echo [stage] GUI from %GUI_SRC%
mkdir "%STAGE%\gui" 2>nul
copy /y "%GUI_SRC%\KellectConsole.exe"           "%STAGE%\gui\" >nul ||goto :err

REM ---------------------------------------------------------------------------
REM Qt runtime + CRT/UCRT for the dynamic-Qt GUI (must match kellect.wxs
REM cg.QtRuntime). All into stage\gui\ - the MSI installs them as an INSTALLDIR
REM \gui\ subfolder so the root stays clean. Win7 lacks system UCRT/CRT copies
REM -> app-local deployment beside the GUI exe.
REM ---------------------------------------------------------------------------
if not defined QTDIR set "QTDIR=D:\Code\Qt\5.15.2\msvc2019_64"
if not exist "%QTDIR%\bin\Qt5Core.dll" (
    echo ERROR: dynamic Qt not found at %QTDIR% ^(set QTDIR to override^) 1>&2
    exit /b 1
)
echo [stage] Qt runtime from %QTDIR%
copy /y "%QTDIR%\bin\Qt5Core.dll"    "%STAGE%\gui\" >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Gui.dll"     "%STAGE%\gui\" >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Widgets.dll" "%STAGE%\gui\" >nul || goto :err
copy /y "%QTDIR%\bin\Qt5Network.dll" "%STAGE%\gui\" >nul || goto :err
mkdir "%STAGE%\gui\platforms" 2>nul
copy /y "%QTDIR%\plugins\platforms\qwindows.dll" "%STAGE%\gui\platforms\" >nul || goto :err

set "VCCRT_SRC=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Redist\MSVC\14.29.30133\x64\Microsoft.VC142.CRT"
set "UCRT_SRC=C:\Program Files (x86)\Windows Kits\10\Redist\10.0.19041.0\ucrt\DLLs\x64"
if not exist "%VCCRT_SRC%\vcruntime140.dll" (
    echo ERROR: VC142 CRT redist not found at !VCCRT_SRC! 1>&2
    exit /b 1
)
if not exist "%UCRT_SRC%\ucrtbase.dll" (
    echo ERROR: UCRT redist not found at !UCRT_SRC! 1>&2
    exit /b 1
)
echo [stage] CRT from VC Redist 14.29.30133 + SDK 19041 UCRT
copy /y "%VCCRT_SRC%\*.dll" "%STAGE%\gui\" >nul || goto :err
copy /y "%UCRT_SRC%\*.dll"  "%STAGE%\gui\" >nul || goto :err
REM Drop 9 redist files that are in NO shipped binary's import closure
REM (verified 2026-09-19; re-check if Qt or code changes): concrt140, vccorlib140,
REM msvcp140_2, msvcp140_atomic_wait, msvcp140_codecvt_ids,
REM api-ms-win-crt-{conio,multibyte,private,process}-l1-1-0.
del /q "%STAGE%\gui\concrt140.dll"            2>nul
del /q "%STAGE%\gui\vccorlib140.dll"          2>nul
del /q "%STAGE%\gui\msvcp140_2.dll"           2>nul
del /q "%STAGE%\gui\msvcp140_atomic_wait.dll" 2>nul
del /q "%STAGE%\gui\msvcp140_codecvt_ids.dll" 2>nul
del /q "%STAGE%\gui\api-ms-win-crt-conio-l1-1-0.dll"     2>nul
del /q "%STAGE%\gui\api-ms-win-crt-multibyte-l1-1-0.dll" 2>nul
del /q "%STAGE%\gui\api-ms-win-crt-private-l1-1-0.dll"   2>nul
del /q "%STAGE%\gui\api-ms-win-crt-process-l1-1-0.dll"   2>nul

REM ---------------------------------------------------------------------------
REM config\ - the files kellect.wxs declares (collector's own copy)
REM ---------------------------------------------------------------------------
set "CFG_SRC="
if exist "%REPO_ROOT%\bin\config\eventStruct_win7.xml"            set "CFG_SRC=%REPO_ROOT%\bin\config"
if not defined CFG_SRC if exist "%COLLECTOR_SRC%\config\eventStruct_win7.xml" set "CFG_SRC=%COLLECTOR_SRC%\config"
if not defined CFG_SRC (
    echo ERROR: config\eventStruct_win7.xml not found. 1>&2
    exit /b 1
)
echo [stage] config from %CFG_SRC%
REM Copy the COMPLETE config dir - xcopy so future config files are staged automatically
xcopy /e /i /y "%CFG_SRC%\*" "%STAGE%\config\" >nul
if errorlevel 1 goto :err

echo.
echo [stage] contents:
dir /b "%STAGE%" & dir /b "%STAGE%\config" & dir /b "%STAGE%\gui"
echo.

REM ---------------------------------------------------------------------------
REM WiX toolchain (dotnet global tool) + build
REM ---------------------------------------------------------------------------
set "PATH=%USERPROFILE%\.dotnet\tools;%PATH%"
where wix >nul 2>nul
if errorlevel 1 (
    echo ERROR: wix not on PATH. Install with:  dotnet tool install -g wix 1>&2
    exit /b 1
)
echo [wix] calling: wix --version
call wix --version

REM WiX v7 requires accepting its OSMF EULA (free for open-source use like
REM kellect). Idempotent: writes an acceptance file once per user profile.
call wix eula accept wix7 >nul 2>nul

if not exist "%OUT%" mkdir "%OUT%"
echo [wix] building %OUT%\Kellect-win-x64.msi ...
REM WiX UI extension: provides WixUI_Common (BrowseDlg folder picker, ProgressDlg,
REM text styles, bitmaps). The extensionRef MUST carry an explicit version —
REM without it `wix extension add` fails silently (exit 2). Idempotent: re-adding
REM to an already-cached extension returns non-zero, which we ignore.
call wix extension add -g "WixToolset.UI.wixext/7.0.0" >nul 2>nul
call wix build "%SCRIPT_DIR%kellect.wxs" -ext WixToolset.UI.wixext -o "%OUT%\Kellect-win-x64.msi" || goto :err

echo.
echo SUCCESS: %OUT%\Kellect-win-x64.msi
endlocal & exit /b 0

:err
echo.
echo FAILED. See output above. 1>&2
endlocal & exit /b 1
