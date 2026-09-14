@echo off
setlocal
REM Get-UpdateState.cmd  -  launcher for Get-UpdateState.ps1  (READ-ONLY, asks for admin)
REM Shows the report and saves a copy under C:\Temp\Toolkit. Set TOOLKIT_NOPAUSE=1 to skip the final pause.
set "PS1=%~dp0Get-UpdateState.ps1"
set "OUTDIR=C:\Temp\Toolkit"
if "%OUTDIR:~-1%"=="\" set "OUTDIR=%OUTDIR:~0,-1%"
if not exist "%PS1%" (
    echo Missing: "%PS1%"  -  keep the .cmd and .ps1 in the same folder.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
fltmc >nul 2>&1
if errorlevel 1 goto :elevate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Display -ReportPath "%OUTDIR%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo PowerShell exited with code %RC%.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%

:elevate
echo Requesting administrator elevation. Approve the UAC prompt; the report opens in a new window.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File',('\"{0}\"' -f $env:PS1),'-Display','-ReportPath',('\"{0}\"' -f $env:OUTDIR.TrimEnd('\')))"
if errorlevel 1 (
    echo Elevation was declined or failed. Nothing ran.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 1
)
endlocal & exit /b 0
