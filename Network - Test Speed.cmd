@echo off
setlocal
title Network - Test Speed
rem Download and upload speed and latency, using Cloudflare's public speed test.
rem Takes about 30 seconds. Installs nothing. Read-only.

set "ARGS=%*"
if defined TOOLKIT_UNATTENDED set "ARGS=NoPause %*"
rem A 32-bit window (some remote tools) still runs the 64-bit PowerShell.
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Test-Internet-Speed.ps1" %ARGS%
exit /b %ERRORLEVEL%
