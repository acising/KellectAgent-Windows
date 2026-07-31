@echo off
REM ===========================================================================
REM  build-all.bat - one-command kellect package pipeline.
REM  Order: collector (x86/MT) -> GUI (x64) -> service (x64) -> MSI.
REM
REM  Each step is its own cmd process with its own vcvars, so the x86 collector
REM  build and the x64 GUI/service builds do not conflict (the GUI/service spawn
REM  the collector as a child process; cross-bitness is fine on x64 Windows).
REM
REM  Usage:   cmd /c scripts\build-all.bat
REM  Output:  installer\build-msi\Kellect-win-x64.msi
REM           (+ bin\kellect.exe, gui\QtKellectConsole\build\KellectConsole.exe,
REM             bin\KellectService.exe)
REM ===========================================================================
setlocal enableextensions enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.." >nul
set "REPO_ROOT=%CD%"
popd >nul

echo ############################################################
echo ## kellect build-all: collector -^> GUI -^> service -^> MSI
echo ############################################################
echo repo: %REPO_ROOT%
echo.

REM ---------------------------------------------------------------------------
REM [1/4] Collector (x86 /MT static CRT) - staged to bin\ for the MSI
REM ---------------------------------------------------------------------------
echo === [1/4] collector: bin\kellect.exe (x86 /MT) ===
pushd "%REPO_ROOT%"
call scripts\build-collector.bat
set "RC=%errorlevel%"
popd
if not "%RC%"=="0" goto :col_fail
if not exist "%REPO_ROOT%\bin\kellect.exe" goto :col_fail
REM size guard: a 0-byte exe (stale ninja graph / interrupted link) must NOT pass
for %%I in ("%REPO_ROOT%\bin\kellect.exe") do if %%~zI LSS 102400 goto :col_fail
echo     OK: bin\kellect.exe
echo.

REM ---------------------------------------------------------------------------
REM [2/4] GUI (Qt 5.15 static, x64) - must run from gui\QtKellectConsole
REM ---------------------------------------------------------------------------
echo === [2/4] GUI: KellectConsole.exe ===
pushd "%REPO_ROOT%\gui\QtKellectConsole"
call scripts\build.bat
set "RC=%errorlevel%"
popd
if not "%RC%"=="0" goto :gui_fail
if not exist "%REPO_ROOT%\gui\QtKellectConsole\build\KellectConsole.exe" goto :gui_fail
for %%I in ("%REPO_ROOT%\gui\QtKellectConsole\build\KellectConsole.exe") do if %%~zI LSS 1048576 goto :gui_fail
echo     OK: gui\QtKellectConsole\build\KellectConsole.exe
echo.

REM ---------------------------------------------------------------------------
REM [3/4] Service wrapper (x64 /MT, standalone; bypasses collector ATL/lib gap)
REM ---------------------------------------------------------------------------
echo === [3/4] service: KellectService.exe ===
pushd "%REPO_ROOT%"
call scripts\build-service.bat
set "RC=%errorlevel%"
popd
if not "%RC%"=="0" goto :svc_fail
if not exist "%REPO_ROOT%\bin\KellectService.exe" goto :svc_fail
for %%I in ("%REPO_ROOT%\bin\KellectService.exe") do if %%~zI LSS 51200 goto :svc_fail
echo     OK: bin\KellectService.exe
echo.

REM ---------------------------------------------------------------------------
REM [4/4] MSI (stages collector+GUI+service+DLLs+config, accepts WiX v7 EULA)
REM ---------------------------------------------------------------------------
echo === [4/4] MSI: Kellect-win-x64.msi ===
pushd "%REPO_ROOT%"
call installer\build-msi.bat
set "RC=%errorlevel%"
popd
if not "%RC%"=="0" goto :msi_fail
if not exist "%REPO_ROOT%\installer\build-msi\Kellect-win-x64.msi" goto :msi_fail
echo.

echo ############################################################
echo ## SUCCESS
echo ##   collector: bin\kellect.exe (x86 /MT, from source)
echo ##   GUI:       gui\QtKellectConsole\build\KellectConsole.exe
echo ##   service:   bin\KellectService.exe
echo ##   MSI:       installer\build-msi\Kellect-win-x64.msi
echo ############################################################
endlocal & exit /b 0

:col_fail
echo.
echo FAILED at [1/4] collector build. 1>&2
endlocal & exit /b 1
:gui_fail
echo.
echo FAILED at [2/4] GUI build. 1>&2
endlocal & exit /b 1
:svc_fail
echo.
echo FAILED at [3/4] service build. 1>&2
endlocal & exit /b 1
:msi_fail
echo.
echo FAILED at [4/4] MSI build. 1>&2
endlocal & exit /b 1