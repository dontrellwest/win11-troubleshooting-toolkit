@echo off
setlocal
title Devices - Restart Audio
rem Restarts the Windows audio services (and the audio driver services that depend
rem on them). Sound stops for a few seconds.

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
echo Restarts the Windows audio services. Sound stops for a few seconds.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
set "DEPS="
for /f "tokens=2" %%s in ('sc enumdepend AudioEndpointBuilder 4096 ^| findstr /b /c:"SERVICE_NAME:"') do call :remember %%s
net stop AudioEndpointBuilder /y
net start AudioEndpointBuilder
net start Audiosrv
for %%s in (AudioEndpointBuilder Audiosrv %DEPS%) do call :startsvc %%s
if "%RC%"=="0" echo Done. The audio services are running again; test the sound.
if not "%RC%"=="0" echo Then check the sound device in Settings.
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
