@echo off
setlocal
REM Read-only profile inventory. Keep the BAT and PS1 together.
REM Set TOOLKIT_NOPAUSE=1 to finish without a final pause.
set "PS1=%~dp0Get-ProfileInventory.ps1"
if not exist "%PS1%" (
    echo Missing: "%PS1%"
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
fltmc >nul 2>&1
if errorlevel 1 goto :elevate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo PowerShell exited with code %RC%.
endlocal & exit /b %RC%

:elevate
echo Requesting administrator access for read-only inventory.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',('\"{0}\"' -f $env:PS1))"
if errorlevel 1 (
    echo Elevation was declined or failed. Nothing ran.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 1
)
endlocal & exit /b 0
