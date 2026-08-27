@echo off
setlocal

set "SCRIPT_PATH=%~dp0hypervisor.ps1"
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%SCRIPT_PATH%" (
    echo Could not find "%SCRIPT_PATH%".
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    "%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -STA -File "%SCRIPT_PATH%"
if errorlevel 1 (
    echo.
    echo The VBS manager exited with an error.
    pause
)
