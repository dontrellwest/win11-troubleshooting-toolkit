@echo off
setlocal
title Windows - Restart Explorer and Icons
rem Restarts Windows Explorer and clears the icon and thumbnail caches: for a stuck
rem taskbar or Start menu, or blank or wrong icons.

rem --- Changes the signed-in user's own files, so it must run as that user (just
rem double-click it). With administrator rights it could change an admin's files instead.
fltmc >nul 2>&1 || goto :start
echo.
echo This window has administrator rights. This tool changes the signed-in user's
echo own files, so run it by double-clicking it, without "Run as administrator".
if defined TOOLKIT_UNATTENDED exit /b 1
choice /c YN /n /m "Continue anyway, because this window belongs to the affected user? [Y/N] "
if errorlevel 2 exit /b 1

:start
echo.
echo Restarts Windows Explorer and clears the icon and thumbnail caches.
echo The taskbar and File Explorer windows close for a few seconds.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
echo Closing Explorer...
taskkill /f /im explorer.exe /fi "username eq %USERDOMAIN%\%USERNAME%" >nul 2>&1
ping -n 3 127.0.0.1 >nul
echo Clearing the icon and thumbnail caches...
del /a /f /q "%LOCALAPPDATA%\IconCache.db" >nul 2>&1
del /a /f /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db" >nul 2>&1
del /a /f /q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db" >nul 2>&1
echo Starting Explorer...
tasklist /fi "imagename eq explorer.exe" /fi "username eq %USERDOMAIN%\%USERNAME%" 2>nul | find /i "explorer.exe" >nul || goto :startexplorer
goto :done
:startexplorer
rem Started through Windows' shell so Explorer does not keep this window's output handles open.
powershell.exe -NoProfile -Command "Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe')" >nul 2>&1 || start "" "%SystemRoot%\explorer.exe"
:done
echo Done. Icons are rebuilt as folders open again; this can take a minute.
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
