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

reg query "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook" /v ForceOSTPath >nul 2>&1
if not errorlevel 1 (
  echo ForceOSTPath is configured. Use the PowerShell tool to inspect it.
  exit /b 1
)
reg query "HKCU\Software\Microsoft\Office\16.0\Outlook" /v ForceOSTPath >nul 2>&1
if not errorlevel 1 (
  echo ForceOSTPath is configured. Use the PowerShell tool to inspect it.
  exit /b 1
)
set "OSTDIR=%LOCALAPPDATA%\Microsoft\Outlook"
set "NATIVEPATH=%OSTDIR%"
call :CheckPath
if errorlevel 1 (
  echo OST folder is unavailable or linked. Refusing.
  exit /b 1
)
if not exist "%OSTDIR%\*.ost" (
  echo Nothing to do: no OST files in the default Outlook folder.
  exit /b 1
)
echo This closes classic Outlook and renames OST caches in "%OSTDIR%".
echo Confirm all important mail and drafts are synced to the server first.
choice /c YN /n /m "Continue? Y or N: "
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 0
set "STAMP=%RANDOM%-%RANDOM%-%RANDOM%"
set "LOG=%TEMP%\OutlookOSTRebuild_%STAMP%.log"
echo Started %date% %time%>"%LOG%"
if errorlevel 1 exit /b 1
taskkill /im outlook.exe /fi "SESSION eq %TARGETSESSION%" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" >>"%LOG%" 2>&1
timeout /t 20 /nobreak >nul 2>&1
if errorlevel 1 ping.exe -n 21 127.0.0.1 >nul 2>&1
taskkill /f /im outlook.exe /fi "SESSION eq %TARGETSESSION%" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" >>"%LOG%" 2>&1
set "NATIVEPATH=%OSTDIR%"
call :CheckPath
if errorlevel 1 goto :restartoutlook
for %%F in ("%OSTDIR%\*.ost") do if exist "%%~fF" (
  echo Rename "%%~fF" to "%%~nxF.old-%STAMP%">>"%LOG%"
  ren "%%~fF" "%%~nxF.old-%STAMP%" >>"%LOG%" 2>&1
)
:restartoutlook
start "" outlook.exe
echo Log: "%LOG%"
echo Read rename errors, allow Outlook to resync and verify mail.
echo PST files and previous backups were not removed.
exit /b 0
:preview
echo WhatIf: would verify your console session, default OST path and confirm.
echo WhatIf: would close your Outlook, rename OST files, then reopen Outlook.
echo No processes were stopped and no files were written or renamed.
exit /b 0
:help
echo Rebuild-OutlookOST-NoPowerShell.cmd
echo Run unelevated as the affected user at the local console.
echo Renames default-folder OST caches. Sync mail first. PST files untouched.
echo Logs to your Temp folder. Custom OST policy paths are refused.
echo /whatif prints the plan. /? displays this help.
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
