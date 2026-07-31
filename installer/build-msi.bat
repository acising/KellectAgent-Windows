@echo off
REM ===========================================================================
REM  build-msi.bat ? assemble stage\ and build the kellect MSI with WiX v4/v5.
REM  Run from anywhere:  cmd /c installer\build-msi.bat
REM
REM  Prereqs on the machine (one-time):
REM    dotnet tool install -g wix        (WiX CLI, ~7.x)
REM  Binary prereqs (produced by the other build steps):
REM    scripts\build-service.bat          -> bin\KellectService.exe
REM    (collector)                        -> bin\kellect.exe + DLLs + bin\config\
REM    gui\QtKellectConsole\scripts\build.bat -> gui\QtKellectConsole\build\KellectConsole.exe
REM  If bin\kellect.exe is absent (collector ATL toolchain gap), the script falls
REM  back to release\ then KellectConsole-win-x64\ as a prebuilt collector source.
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
REM Collector artifacts: bin > release > KellectConsole-win-x64 (prebuilt)
REM ---------------------------------------------------------------------------
set "COLLECTOR_SRC="
if exist "%REPO_ROOT%\bin\kellect.exe"                            set "COLLECTOR_SRC=%REPO_ROOT%\bin"
if not defined COLLECTOR_SRC if exist "%REPO_ROOT%\release\kellect.exe"              set "COLLECTOR_SRC=%REPO_ROOT%\release"
if not defined COLLECTOR_SRC if exist "%REPO_ROOT%\KellectConsole-win-x64\kellect.exe" set "COLLECTOR_SRC=%REPO_ROOT%\KellectConsole-win-x64"
if not defined COLLECTOR_SRC (
    echo ERROR: kellect.exe not found. Build the collector, or drop a prebuilt 1>&2
    echo        copy into release\. Aborting. 1>&2
    exit /b 1
)
echo [stage] collector from %COLLECTOR_SRC%
copy /y "%COLLECTOR_SRC%\kellect.exe"            "%STAGE%\" >nul || goto :err
copy /y "%COLLECTOR_SRC%\librdkafka.dll"         "%STAGE%\" >nul || goto :err
copy /y "%COLLECTOR_SRC%\librdkafkacpp.dll"      "%STAGE%\" >nul || goto :err
copy /y "%COLLECTOR_SRC%\libzstd.dll"            "%STAGE%\" >nul || goto :err
copy /y "%COLLECTOR_SRC%\zlib.dll"               "%STAGE%\" >nul || goto :err

REM --- kellect.exe.manifest sidecar: bin\ doesn't ship it (CMake copies only
REM     config + dlls), so resolve from the other collector-source candidates. ---
set "MANIFEST_SRC="
if exist "%COLLECTOR_SRC%\kellect.exe.manifest"            set "MANIFEST_SRC=%COLLECTOR_SRC%\kellect.exe.manifest"
if not defined MANIFEST_SRC if exist "%REPO_ROOT%\release\kellect.exe.manifest"            set "MANIFEST_SRC=%REPO_ROOT%\release\kellect.exe.manifest"
if not defined MANIFEST_SRC if exist "%REPO_ROOT%\KellectConsole-win-x64\kellect.exe.manifest" set "MANIFEST_SRC=%REPO_ROOT%\KellectConsole-win-x64\kellect.exe.manifest"
if not defined MANIFEST_SRC (
    echo ERROR: kellect.exe.manifest sidecar not found. 1>&2
    exit /b 1
)
copy /y "%MANIFEST_SRC%"                          "%STAGE%\" >nul || goto :err

REM ---------------------------------------------------------------------------
REM Service binary (Step 1 output)
REM ---------------------------------------------------------------------------
if not exist "%REPO_ROOT%\bin\KellectService.exe" (
    echo ERROR: bin\KellectService.exe not found. Run scripts\build-service.bat first. 1>&2
    exit /b 1
)
echo [stage] service from %REPO_ROOT%\bin
copy /y "%REPO_ROOT%\bin\KellectService.exe"     "%STAGE%\" >nul || goto :err

REM ---------------------------------------------------------------------------
REM GUI binary
REM ---------------------------------------------------------------------------
set "GUI_SRC="
if exist "%REPO_ROOT%\gui\QtKellectConsole\build\KellectConsole.exe" set "GUI_SRC=%REPO_ROOT%\gui\QtKellectConsole\build"
if not defined GUI_SRC if exist "%REPO_ROOT%\KellectConsole-win-x64\KellectConsole.exe" set "GUI_SRC=%REPO_ROOT%\KellectConsole-win-x64"
if not defined GUI_SRC (
    echo ERROR: KellectConsole.exe not found. Run gui\QtKellectConsole\scripts\build.bat first. 1>&2
    exit /b 1
)
echo [stage] GUI from %GUI_SRC%
copy /y "%GUI_SRC%\KellectConsole.exe"           "%STAGE%\" >nul ||goto :err

REM ---------------------------------------------------------------------------
REM config\ ? the 4 files kellect.wxs declares (collector's own copy)
REM ---------------------------------------------------------------------------
set "CFG_SRC="
if exist "%REPO_ROOT%\bin\config\eventStruct_win7.xml"            set "CFG_SRC=%REPO_ROOT%\bin\config"
if not defined CFG_SRC if exist "%COLLECTOR_SRC%\config\eventStruct_win7.xml" set "CFG_SRC=%COLLECTOR_SRC%\config"
if not defined CFG_SRC (
    echo ERROR: config\eventStruct_win7.xml not found. 1>&2
    exit /b 1
)
echo [stage] config from %CFG_SRC%
REM Copy the COMPLETE config dir (9 files) - xcopy so future config files are staged automatically
xcopy /e /i /y "%CFG_SRC%\*" "%STAGE%\config\" >nul
if errorlevel 1 goto :err

echo.
echo [stage] contents:
dir /b "%STAGE%" & dir /b "%STAGE%\config"
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
