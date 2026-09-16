@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS1=%~dp006-Restart-or-Reset-OneDrive.ps1"
if not exist "%PS1%" (
    echo Missing matching PowerShell script. Keep the full toolkit together.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Interactive -Display
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Tool could not complete. Read the report and error above.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
