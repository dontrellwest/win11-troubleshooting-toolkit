@echo off
setlocal
REM Get-MappedDriveAudit.cmd  -  launcher for Get-MappedDriveAudit.ps1  (READ-ONLY)
REM Runs as the signed-in user. Shows the report and saves a copy under C:\Temp\Toolkit.
REM Set TOOLKIT_NOPAUSE=1 to skip the final pause.
set "PS1=%~dp0Get-MappedDriveAudit.ps1"
set "OUTDIR=C:\Temp\Toolkit"
if "%OUTDIR:~-1%"=="\" set "OUTDIR=%OUTDIR:~0,-1%"
if not exist "%PS1%" (
    echo Missing: "%PS1%"  -  keep the .cmd and .ps1 in the same folder.
    if not defined TOOLKIT_NOPAUSE pause
    exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Display -ReportPath "%OUTDIR%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo PowerShell exited with code %RC%.
if not defined TOOLKIT_NOPAUSE pause
endlocal & exit /b %RC%
