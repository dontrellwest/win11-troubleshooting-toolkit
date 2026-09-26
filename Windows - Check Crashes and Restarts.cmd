@echo off
setlocal
title Windows - Check Crashes and Restarts
rem Blue screens, program crashes and hangs, failed drivers and services, then the
rem restart and shutdown timeline (who or what restarted the PC). Read-only.

set "RC=0"
rem A 32-bit window (some remote tools) still runs the 64-bit PowerShell.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Check-Windows-Crashes.ps1" -Display -ReportPath "C:\Temp\Toolkit"
if errorlevel 1 set "RC=1"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Check-Restarts-and-Shutdowns.ps1" -Display -ReportPath "C:\Temp\Toolkit"
if errorlevel 1 set "RC=1"
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
