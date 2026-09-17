@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS1=%~dp011-Check-Profile-Sign-In-Age.ps1"
if not exist "%PS1%" (
    echo Missing matching PowerShell script. Keep the CMD and PS1 together.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
fltmc >nul 2>&1
if errorlevel 1 goto :elevate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Display
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Check failed. Read the error and report above.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
:elevate
echo Requesting administrator access to read Security sign-in events.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',('\"{0}\"' -f $env:PS1),'-Display')"
if errorlevel 1 (
    echo Elevation failed or was declined. No check was run.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 1
)
echo The check runs in the new administrator window; its report path is shown there.
endlocal & exit /b 0
