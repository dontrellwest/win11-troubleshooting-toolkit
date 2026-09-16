@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PS1=%~dp005-Check-Storage-Errors-and-Reliability.ps1"
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
echo Requesting administrator access for the dirty-bit query. Decline to run without it.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',('\"{0}\"' -f $env:PS1),'-Interactive','-Display')"
if errorlevel 1 (
    echo Running without administrator access; the dirty-bit query will be unavailable.
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Interactive -Display
    set "RC=%ERRORLEVEL%"
    if not defined TOOLKIT_NOPAUSE pause
    endlocal & exit /b %RC%
)
endlocal & exit /b 0
