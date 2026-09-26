@echo off
setlocal
title Network - Reset Network
rem Clears the DNS cache and renews the IP address. Optionally resets Winsock and
rem TCP/IP, which needs a restart.

rem --- Needs administrator rights: ask for them, or say how to get them.
fltmc >nul 2>&1 && goto :start
if "%~1"=="/elevated" goto :noadmin
echo Asking for administrator rights...
set "SELF=%~f0"
powershell.exe -NoProfile -Command "Start-Process -FilePath $env:SELF -ArgumentList '/elevated' -Verb RunAs" >nul 2>&1 && exit /b 0
:noadmin
echo.
echo This needs administrator rights, and they were not granted.
echo Right-click this file and choose "Run as administrator".
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b 1

:start
echo.
echo Clears the DNS cache and renews the IP address of each network adapter.
echo The address is renewed, not released first, so a remote session stays connected.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
ipconfig /flushdns || set "RC=1"
rem The renew output is kept for a moment so a failed adapter can be found in it.
set "OUT=%TEMP%\Toolkit-renew-%RANDOM%.txt"
ipconfig /renew >"%OUT%" 2>&1
type "%OUT%"
findstr /i /c:"An error occurred while renewing" "%OUT%" >nul && set "RC=1"
del "%OUT%" >nul 2>&1
echo.
echo Lines saying "media disconnected" are normal for adapters that are not in use.
if "%RC%"=="0" echo Done. The DNS cache is cleared and the IP address is renewed.
if not "%RC%"=="0" echo Something above failed (for example "An error occurred while renewing").
if not "%RC%"=="0" echo Check the cable or Wi-Fi and the router, then run Network - Check Connection.
if defined TOOLKIT_UNATTENDED goto :end
echo.
echo If the network is still broken, a deeper reset of Winsock and TCP/IP can help.
echo It needs a restart and may clear static IP settings on this PC.
choice /c YN /n /m "Also reset Winsock and TCP/IP now? [Y/N] "
if errorlevel 2 goto :end
set "NRC=0"
netsh winsock reset || set "NRC=1"
netsh int ip reset || set "NRC=1"
if "%NRC%"=="1" echo netsh reported a failure above; the reset may be partial.& set "RC=1"
echo Restart the PC to finish the reset.
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
