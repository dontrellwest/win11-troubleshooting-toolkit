@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS1=%~dp010-Find-Enabled-Users-in-Disabled-OU.ps1"
if not exist "%PS1%" (
    echo Missing matching PowerShell script. Keep the CMD and PS1 together.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Interactive -Display
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Check could not complete. Read the error and report above.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
