@echo off
setlocal DisableDelayedExpansion
if /i "%~1"=="/?" goto :help
if /i "%~1"=="/whatif" goto :preview
if not "%~1"=="" goto :help

whoami /user /fo csv /nh | findstr /c:"S-1-5-18" >nul
if not errorlevel 1 (
  echo SYSTEM is refused. Run as the affected signed-in user.
  exit /b 1
)
fltmc >nul 2>&1
if not errorlevel 1 (
  echo Run this native tool without elevation in the affected user session.
  exit /b 1
)
if /i not "%SESSIONNAME%"=="Console" (
  echo A local console session is required. Use the PowerShell tool for RDP.
  exit /b 1
)
set "TARGETSESSION="
for /f "tokens=4 delims=," %%A in ('tasklist /v /fo csv /nh /fi "IMAGENAME eq explorer.exe" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" /fi "SESSIONNAME eq Console" 2^>nul') do set "TARGETSESSION=%%~A"
if not defined TARGETSESSION (
  echo Cannot verify the affected user's desktop. Refusing.
  exit /b 1
)
if "%TARGETSESSION%"=="0" exit /b 1
for /f "delims=0123456789" %%A in ("%TARGETSESSION%") do exit /b 1
set "NATIVEPATH=%LOCALAPPDATA%"
call :CheckPath
if errorlevel 1 (
  echo The local profile path is unavailable or linked. Refusing.
  exit /b 1
)
set "OLKDIR=%LOCALAPPDATA%\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe"
set "NATIVEPATH=%OLKDIR%"
call :CheckPath
if errorlevel 1 (
  echo New Outlook data folder is unavailable or linked. Refusing.
  exit /b 1
)
set "FOUND="
for %%D in (LocalCache LocalState RoamingState TempState Settings) do if exist "%OLKDIR%\%%D\" set "FOUND=1"
if not defined FOUND (
  echo Nothing to do: no new Outlook data folders for this user.
  exit /b 1
)
echo This closes new Outlook and moves its data folders aside under
echo "%OLKDIR%".
echo The app signs in again through Windows. Unsent drafts may be lost.
choice /c YN /n /m "Continue? Y or N: "
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 0
set "STAMP=%RANDOM%-%RANDOM%-%RANDOM%"
set "LOG=%TEMP%\NewOutlookCacheReset_%STAMP%.log"
echo Started %date% %time%>"%LOG%"
if errorlevel 1 exit /b 1
taskkill /im olk.exe /fi "SESSION eq %TARGETSESSION%" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" >>"%LOG%" 2>&1
timeout /t 20 /nobreak >nul 2>&1
if errorlevel 1 ping.exe -n 21 127.0.0.1 >nul 2>&1
taskkill /f /im olk.exe /fi "SESSION eq %TARGETSESSION%" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" >>"%LOG%" 2>&1
set "NATIVEPATH=%OLKDIR%"
call :CheckPath
if errorlevel 1 goto :restart
for %%D in (LocalCache LocalState RoamingState TempState Settings) do if exist "%OLKDIR%\%%D\" (
  echo Move "%OLKDIR%\%%D" to "%%D.old-%STAMP%">>"%LOG%"
  ren "%OLKDIR%\%%D" "%%D.old-%STAMP%" >>"%LOG%" 2>&1
)
:restart
start "" explorer.exe shell:AppsFolder\Microsoft.OutlookForWindows_8wekyb3d8bbwe!Microsoft.OutlookforWindows
echo Log: "%LOG%"
echo Sign in if asked, let the app load, and verify mail before removing backups.
echo Backups are the .old-* folders beside the originals.
exit /b 0
:preview
echo WhatIf: would verify your console session and the new Outlook data folder.
echo WhatIf: would close new Outlook, move its data folders aside, then reopen it.
echo No processes were stopped and no folders were moved.
exit /b 0
:help
echo Reset-NewOutlookCache-NoPowerShell.cmd
echo Run unelevated as the affected user at the local console.
echo Moves new Outlook's local data folders aside and reopens the app.
echo The app signs in again through Windows. Unsent drafts may be lost.
echo Logs to your Temp folder. /whatif prints the plan. /? displays this help.
exit /b 0

:CheckPath
for %%A in ("%NATIVEPATH%") do set "CHECKPATH=%%~fA"
if not "%CHECKPATH:~1,2%"==":\" exit /b 1
:CheckParent
if not exist "%CHECKPATH%" exit /b 1
for %%A in ("%CHECKPATH%") do set "ATTR=%%~aA"
if not defined ATTR exit /b 1
if not "%ATTR:l=%"=="%ATTR%" exit /b 1
if "%CHECKPATH:~3%"=="" exit /b 0
for %%A in ("%CHECKPATH%\..") do set "PARENT=%%~fA"
if /i "%PARENT%"=="%CHECKPATH%" exit /b 1
set "CHECKPATH=%PARENT%"
goto :CheckParent
