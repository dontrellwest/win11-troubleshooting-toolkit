@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS1=%~dp005-Repair-Selected-Network-Problem.ps1"
if not exist "%PS1%" (
    echo Missing matching PowerShell script. Keep the full toolkit together.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
fltmc >nul 2>&1
if errorlevel 1 goto :elevate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Interactive -Display
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Tool could not complete. Read the report and error above.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
:elevate
echo Requesting administrator access. Approve the Windows prompt.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',('\"{0}\"' -f $env:PS1),'-Interactive','-Display')"
if errorlevel 1 (
    echo Elevation failed or was declined. No tool was run.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 1
)
endlocal & exit /b 0
