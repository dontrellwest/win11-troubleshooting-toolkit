@echo off
setlocal
title Windows - Reset Windows Update
rem The standard Windows Update reset: stop the update services, rename the
rem SoftwareDistribution and catroot2 cache folders, then start the services again.

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
echo Resets Windows Update: stops its services, renames its cache folders
echo (SoftwareDistribution and catroot2) and starts the services again.
echo Installed updates stay installed; the update history list in Settings starts empty.
echo The copies left by an earlier reset (ending in .old) are deleted first.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
set "SD=%SystemRoot%\SoftwareDistribution"
set "CR=%SYS%\catroot2"
rem The copies from a previous reset are removed first.
if exist "%SD%.old" rd /s /q "%SD%.old"
if exist "%CR%.old" rd /s /q "%CR%.old"
if exist "%SD%.old" goto :oldcopy
if exist "%CR%.old" goto :oldcopy
rem Services that depend on these (such as Application Identity) are started again afterwards.
set "DEPS="
for %%v in (wuauserv bits cryptsvc) do for /f "tokens=2" %%s in ('sc enumdepend %%v 4096 ^| findstr /b /c:"SERVICE_NAME:"') do call :remember %%s
echo Stopping the update services and renaming the cache folders...
set "TRY=0"
:again
set /a TRY+=1
net stop wuauserv /y >nul 2>&1
net stop bits /y >nul 2>&1
net stop cryptsvc /y >nul 2>&1
if not exist "%SD%.old" ren "%SD%" SoftwareDistribution.old >nul 2>&1
if not exist "%CR%.old" ren "%CR%" catroot2.old >nul 2>&1
rem Windows may create a new, empty folder at once; the .old copy shows the rename worked.
if exist "%SD%" if not exist "%SD%.old" goto :retry
if exist "%CR%" if not exist "%CR%.old" goto :retry
goto :renamed
:retry
if %TRY% geq 5 goto :stuck
ping -n 4 127.0.0.1 >nul
goto :again
:oldcopy
echo Could not delete the copy from the last reset (a folder ending in .old).
echo Restart the PC and run this again.
set "RC=1"
goto :end
:stuck
echo Could not rename the cache folders: Windows kept them in use.
echo Restart the PC and run this again.
set "RC=1"
goto :restart
:renamed
echo Renamed SoftwareDistribution and catroot2 (the old copies end in .old).
:restart
echo Starting the update services...
net start cryptsvc
net start bits
net start wuauserv
for %%s in (cryptsvc bits wuauserv %DEPS%) do call :startsvc %%s
echo.
echo Next: open Settings, Windows Update and click "Check for updates".
echo If the same update still fails, run "Windows - Repair System Files with DISM and SFC".
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
