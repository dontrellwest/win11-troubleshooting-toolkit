@echo off
setlocal
title Performance - Clean Temp Files
rem Deletes files older than 7 days from this user's Temp folder. Files in use are
rem skipped. Nothing else is touched.

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
echo Deletes files older than 7 days from this user's Temp folder:
echo   "%TEMP%"
echo Files in use are skipped. For Windows' own temporary files, use Settings,
echo System, Storage, Temporary files.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
forfiles /p "%TEMP%" /s /d -7 /c "cmd /c if @isdir==FALSE del /f /q @path" >nul 2>&1
forfiles /p "%TEMP%" /s /d -7 /c "cmd /c if @isdir==TRUE rd @path" >nul 2>&1
echo Done. Old temp files were deleted; files in use were left alone.
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
