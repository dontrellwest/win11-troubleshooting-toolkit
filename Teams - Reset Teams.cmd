@echo off
setlocal
title Teams - Reset Teams
rem Closes new Teams, moves its cache aside and starts Teams again. Chats, files and
rem meetings are kept in the cloud.

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
set "CACHE=%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
if exist "%CACHE%" goto :found
echo New Teams has no cache for this user, so there is nothing to reset.
set "RC=1"
goto :end
:found
echo.
echo Closes Teams, moves its cache aside and starts Teams again. Chats, files and
echo meetings are kept in the cloud. The user may need to sign in again.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
rem Teams ignores a polite close (it hides in the tray), so it is closed forcefully at once.
rem Chats and files are in the cloud.
call :closeapp ms-teams.exe 0
if errorlevel 1 goto :busy
if exist "%CACHE%.old" rd /s /q "%CACHE%.old"
ren "%CACHE%" MSTeams.old >nul 2>&1
if exist "%CACHE%" goto :busy
echo Moved the Teams cache aside (MSTeams.old).
echo Starting Teams...
rem Started through Windows' shell so Teams does not keep this window's output handles open.
powershell.exe -NoProfile -Command "Start-Process -FilePath (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\ms-teams.exe')" >nul 2>&1 || start "" explorer.exe "shell:AppsFolder\MSTeams_8wekyb3d8bbwe!MSTeams"
echo Done. Teams rebuilds its cache as it starts; the first start is slower.
goto :end
:busy
echo Teams would not let go of its cache. Quit Teams from its tray icon, then run this again.
set "RC=1"
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%

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
