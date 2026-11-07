@echo off
REM ===========================================================================
REM  uninstall-service.bat - stop + delete KellectAgent.
REM  Usage: scripts\uninstall-service.bat [path\to\KellectService.exe]
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
    echo ERROR: KellectService.exe not found; pass its path as the first argument. 1>&2
    exit /b 1
)

"%SVC%" --uninstall
if errorlevel 1 (
    echo ERROR: uninstall failed. 1>&2
    exit /b 1
)
endlocal & exit /b 0
