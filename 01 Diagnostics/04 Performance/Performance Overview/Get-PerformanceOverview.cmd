@echo off
setlocal
set "PS1=%~dp0Get-PerformanceOverview.ps1"
if not exist "%PS1%" (
    echo Get-PerformanceOverview.ps1 must be beside this launcher.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
