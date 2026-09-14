@echo off
setlocal
set "PS1=%~dp0Invoke-FleetRunner.ps1"
if "%~1"=="" (
    echo Run from PowerShell using -Script and -ComputerName or -ComputerListPath.
    echo Read README.txt for examples. Add -WhatIf to preview.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
