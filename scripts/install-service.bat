@echo off
REM ===========================================================================
REM  install-service.bat - register + start KellectAgent (the headless product).
REM
REM  The service reads its configuration from <install dir>\config\agent.ini and
REM  runs the same collector core as kellect.exe. Requires an elevated prompt.
REM
REM  Usage:   scripts\install-service.bat
REM           scripts\install-service.bat "D:\kellect\bin\KellectService.exe"
REM ===========================================================================
setlocal enableextensions
chcp 65001 >nul

net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: this script must run from an elevated prompt. 1>&2
    exit /b 1
)

set "SVC="
if not "%~1"=="" set "SVC=%~1"
if not defined SVC if exist "%~dp0..\bin\KellectService.exe" set "SVC=%~dp0..\bin\KellectService.exe"
if not defined SVC if exist "%~dp0..\KellectService.exe"     set "SVC=%~dp0..\KellectService.exe"
if not defined SVC (
    echo ERROR: KellectService.exe not found next to this script or in bin\. 1>&2
    echo        Build it first:  cmd /c scripts\build-collector.bat 1>&2
    exit /b 1
)

echo [service] %SVC%
"%SVC%" --install
if errorlevel 1 (
    echo ERROR: service installation failed. 1>&2
    exit /b 1
)

"%SVC%" --status
echo.
echo Events: see "file=" in %~dp0..\config\agent.ini  (default %%ProgramData%%\Kellect\events\)
echo Logs  : %%ProgramData%%\Kellect\log\agent.log
echo Config: %~dp0..\config\agent.ini
echo Stop  : net stop KellectAgent   /   sc stop KellectAgent
endlocal & exit /b 0
