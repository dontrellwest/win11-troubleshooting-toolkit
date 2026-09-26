@echo off
setlocal
title Outlook - Check Outlook
rem Classic Outlook (profiles, data files, sync) and new Outlook (app, service,
rem default mail app). Run it as the affected user (just double-click). Read-only.

set "RC=0"
rem A 32-bit window (some remote tools) still runs the 64-bit PowerShell.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Check-Classic-Outlook.ps1" -Display -ReportPath "C:\Temp\Toolkit"
if errorlevel 1 set "RC=1"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Check-New-Outlook.ps1" -Display -ReportPath "C:\Temp\Toolkit"
if errorlevel 1 set "RC=1"
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
