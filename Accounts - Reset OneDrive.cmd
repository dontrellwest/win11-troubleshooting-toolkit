@echo off
setlocal
title Accounts - Reset OneDrive
rem Microsoft's OneDrive reset (onedrive.exe /reset): disconnects and reconnects all
rem sync for this user. Files are not deleted.

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
set "OD=%LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe"
if not exist "%OD%" set "OD=%ProgramFiles%\Microsoft OneDrive\OneDrive.exe"
if not exist "%OD%" set "OD=%ProgramFiles(x86)%\Microsoft OneDrive\OneDrive.exe"
if exist "%OD%" goto :found
echo OneDrive is not installed for this user, so there is nothing to reset.
set "RC=1"
goto :end
:found
echo.
echo Resets OneDrive for this user: it disconnects and reconnects all sync, then
echo checks every file again. No files are deleted. Large OneDrives take a while.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
echo Resetting OneDrive...
rem Started through Windows' shell so OneDrive does not keep this window's output handles open.
powershell.exe -NoProfile -Command "Start-Process -FilePath $env:OD -ArgumentList '/reset'" >nul 2>&1 || "%OD%" /reset
ping -n 16 127.0.0.1 >nul
tasklist /fi "imagename eq OneDrive.exe" 2>nul | find /i "OneDrive.exe" >nul || powershell.exe -NoProfile -Command "Start-Process -FilePath $env:OD" >nul 2>&1 || start "" "%OD%"
echo Done. OneDrive starts again and re-checks the files. If it asks, sign in again.
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
