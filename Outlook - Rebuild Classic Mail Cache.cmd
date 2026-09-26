@echo off
setlocal
title Outlook - Rebuild Classic Mail Cache
rem Closes classic Outlook and renames this user's offline mail files (.ost), so
rem Outlook downloads the mailbox again. Mail stays on the server.

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
set "OST=%LOCALAPPDATA%\Microsoft\Outlook"
if exist "%OST%\*.ost" goto :found
echo No .ost files in "%OST%".
echo If Outlook keeps them elsewhere, see File, Account Settings, Data Files.
set "RC=1"
goto :end
:found
echo.
echo Closes Outlook and renames these offline mail files (.ost):
dir /b "%OST%\*.ost"
echo Outlook downloads the mailbox again when it next opens. Mail stays on the
echo server. Large mailboxes can take hours to finish downloading. The old files
echo are kept (ending in .old).
echo Caution: an IMAP account's "This computer only" calendar and contacts are
echo only in its .ost. Renaming the .old copy back brings them back.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
call :closeapp OUTLOOK.EXE
if errorlevel 1 goto :busy
for %%f in ("%OST%\*.ost") do call :rename "%%f"
echo Next: open Outlook. It rebuilds the mail cache while the user works.
goto :end
:busy
echo Outlook would not close. Close it (and anything using Outlook), then run this again.
set "RC=1"
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%

rem Renames a file to a free name, so an earlier copy is never replaced: .old, then .old2 and so on.
:rename
set "NEW=%~nx1.old"
set "N=1"
:rename_free
if not exist "%~dp1%NEW%" goto :rename_go
set /a N+=1
set "NEW=%~nx1.old%N%"
goto :rename_free
:rename_go
ren "%~1" "%NEW%" >nul 2>&1
if exist "%~1" echo Could not rename "%~nx1": something still has it open.& set "RC=1"& exit /b
echo Renamed "%~nx1" to "%NEW%"
exit /b

rem Closes this user's copy of a program (other users' copies are left alone): politely first,
rem then forcefully after the given number of seconds (15 if none is given; 0 = forcefully at once).
:closeapp
set "WAIT=%~2"
if not defined WAIT set "WAIT=15"
tasklist /fi "imagename eq %~1" /fi "username eq %USERDOMAIN%\%USERNAME%" 2>nul | find /i "%~1" >nul || exit /b 0
echo Closing %~1...
if "%WAIT%"=="0" goto :closeapp_force
taskkill /im %~1 /fi "username eq %USERDOMAIN%\%USERNAME%" >nul 2>&1
set "N=0"
:closeapp_wait
set /a N+=1
ping -n 2 127.0.0.1 >nul
tasklist /fi "imagename eq %~1" /fi "username eq %USERDOMAIN%\%USERNAME%" 2>nul | find /i "%~1" >nul || exit /b 0
if %N% lss %WAIT% goto :closeapp_wait
:closeapp_force
rem This user's copies are listed first and closed by process ID with their child processes (such as
rem WebView2): taskkill /t with a user-name filter takes about 40 seconds.
set "PIDS=%TEMP%\Toolkit-pids-%RANDOM%.txt"
tasklist /fi "imagename eq %~1" /fi "username eq %USERDOMAIN%\%USERNAME%" /fo csv /nh >"%PIDS%" 2>nul
for /f "usebackq tokens=2 delims=," %%p in ("%PIDS%") do if not "%%~p"=="" taskkill /f /t /pid %%~p >nul 2>&1
del "%PIDS%" >nul 2>&1
ping -n 4 127.0.0.1 >nul
tasklist /fi "imagename eq %~1" /fi "username eq %USERDOMAIN%\%USERNAME%" 2>nul | find /i "%~1" >nul && exit /b 1
exit /b 0
