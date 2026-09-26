@echo off
setlocal
title Admin - Find Enabled Users in Disabled OU
rem Finds user accounts that are still enabled inside a "disabled users" OU in Active
rem Directory. Run it on a domain PC with RSAT (the ActiveDirectory module). Read-only.

set "MODE=-Interactive"
if defined TOOLKIT_UNATTENDED set "MODE="
rem A 32-bit window (some remote tools) still runs the 64-bit PowerShell.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Find-Enabled-Users-in-Disabled-OU.ps1" %MODE% -Display
set "RC=%ERRORLEVEL%"
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
