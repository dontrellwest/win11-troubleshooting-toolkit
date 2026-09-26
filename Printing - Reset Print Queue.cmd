@echo off
setlocal
title Printing - Reset Print Queue
rem Stops the print spooler, deletes every waiting print job and starts it again.

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
set "SYS=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\cmd.exe" set "SYS=%SystemRoot%\Sysnative"
echo.
echo Stops the print spooler, deletes every waiting print job and starts it again.
echo Jobs still in the queue are lost; print them again afterwards.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
set "DEPS="
for /f "tokens=2" %%s in ('sc enumdepend Spooler 4096 ^| findstr /b /c:"SERVICE_NAME:"') do call :remember %%s
net stop spooler /y
sc query spooler | find "STOPPED" >nul || goto :notstopped
echo Deleting waiting print jobs...
if exist "%SYS%\spool\PRINTERS\*.*" del /f /q "%SYS%\spool\PRINTERS\*.*"
set "LEFT="
if exist "%SYS%\spool\PRINTERS\*.SHD" set "LEFT=1"
if exist "%SYS%\spool\PRINTERS\*.SPL" set "LEFT=1"
net start spooler
for %%s in (spooler %DEPS%) do call :startsvc %%s
if defined LEFT echo Some print jobs could not be deleted. Restart the PC, then run this again.& set "RC=1"
if "%RC%"=="0" echo Done. The print spooler is running again with an empty queue.
echo Next: print a test page (Settings, Printers and scanners, the printer, Print test page).
goto :end
:notstopped
echo The print spooler would not stop, so no print jobs were deleted.
echo Restart the PC, then run this again.
set "RC=1"
for %%s in (%DEPS%) do call :startsvc %%s
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%

rem Remembers a dependent service that is running now, so it can be started again.
:remember
sc query "%~1" | find "RUNNING" >nul && set "DEPS=%DEPS% %~1"
exit /b

rem Starts a service again unless it is running, and reports one that stays stopped.
:startsvc
sc query "%~1" | find "RUNNING" >nul && exit /b
sc qc "%~1" | find "DISABLED" >nul && goto :startsvc_disabled
net start "%~1"
sc query "%~1" | find "RUNNING" >nul && exit /b
echo The %~1 service did not start again. Restart the PC.
set "RC=1"
exit /b
:startsvc_disabled
echo The %~1 service is disabled, so it was not started. Check whether a policy or a
echo management tool disables it.
set "RC=1"
exit /b
