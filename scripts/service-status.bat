@echo off
REM  service-status.bat - print the SCM state of KellectAgent.
setlocal enableextensions
chcp 65001 >nul

set "SVC="
if not "%~1"=="" set "SVC=%~1"
if not defined SVC if exist "%~dp0..\bin\KellectService.exe" set "SVC=%~dp0..\bin\KellectService.exe"
if not defined SVC if exist "%~dp0..\KellectService.exe"     set "SVC=%~dp0..\KellectService.exe"
if not defined SVC (
    echo ERROR: KellectService.exe not found; pass its path as the first argument. 1>&2
    exit /b 1
)

"%SVC%" --status
endlocal & exit /b %errorlevel%
