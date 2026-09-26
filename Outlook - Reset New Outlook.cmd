@echo off
setlocal
title Outlook - Reset New Outlook
rem Closes new Outlook and moves its local data aside, like Settings, Apps, Reset.
rem Mail, calendar and contacts stay in the mailbox.

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
set "OLK=%LOCALAPPDATA%\Microsoft\Olk"
set "PKG=%LOCALAPPDATA%\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe"
if exist "%OLK%" goto :found
if exist "%PKG%" goto :found
echo New Outlook has no data for this user, so there is nothing to reset.
set "RC=1"
goto :end
:found
echo.
echo Closes new Outlook and moves its local data aside (the copies end in .old and
echo earlier copies are kept):
echo   "%OLK%"
echo   the LocalCache, LocalState, RoamingState, TempState and Settings folders in
echo   "%PKG%"
echo Mail, calendar and contacts stay in the mailbox. The user may need to sign in
echo again, and new Outlook downloads its cache again.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
call :closeapp olk.exe
if errorlevel 1 goto :busy
call :moveaside "%OLK%"
for %%n in (LocalCache LocalState RoamingState TempState Settings) do call :moveaside "%PKG%\%%n"
echo Next: open new Outlook and sign in if it asks.
goto :end
:busy
echo New Outlook would not close. Close it, then run this again.
set "RC=1"
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%

rem Renames a folder to a free name, so an earlier copy is never replaced: .old, then .old2 and so on.
:moveaside
if not exist "%~1" exit /b
set "NEW=%~nx1.old"
set "N=1"
:moveaside_free
if not exist "%~dp1%NEW%" goto :moveaside_go
set /a N+=1
set "NEW=%~nx1.old%N%"
goto :moveaside_free
:moveaside_go
ren "%~1" "%NEW%" >nul 2>&1
if exist "%~1" echo Could not move "%~1": something still has it open.& set "RC=1"& exit /b
echo Moved aside: "%~1" (now %NEW%)
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
