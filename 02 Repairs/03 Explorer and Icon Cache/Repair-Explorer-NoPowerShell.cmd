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

set "CACHEDIR=%LOCALAPPDATA%\Microsoft\Windows\Explorer"
set "NATIVEPATH=%CACHEDIR%"
call :CheckPath
if errorlevel 1 (
  echo Cache directory is missing or linked. Use the PowerShell tool.
  exit /b 1
)
echo This closes Explorer and clears icon and thumbnail caches in session %TARGETSESSION%.
choice /c YN /n /m "Continue? Y or N: "
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 0
set "LOG=%TEMP%\ShellRepair_%RANDOM%-%RANDOM%.log"
echo Started %date% %time%>"%LOG%"
if errorlevel 1 exit /b 1
taskkill /f /im explorer.exe /fi "SESSION eq %TARGETSESSION%" /fi "USERNAME eq %USERDOMAIN%\%USERNAME%" >>"%LOG%" 2>&1
timeout /t 2 /nobreak >nul 2>&1
if errorlevel 1 ping.exe -n 3 127.0.0.1 >nul 2>&1
set "NATIVEPATH=%CACHEDIR%"
call :CheckPath
if errorlevel 1 goto :restart
if exist "%LOCALAPPDATA%\IconCache.db" del /f /q "%LOCALAPPDATA%\IconCache.db" >>"%LOG%" 2>&1
if exist "%CACHEDIR%\iconcache_*.db" del /f /q "%CACHEDIR%\iconcache_*.db" >>"%LOG%" 2>&1
if exist "%CACHEDIR%\thumbcache_*.db" del /f /q "%CACHEDIR%\thumbcache_*.db" >>"%LOG%" 2>&1
:restart
start "" "%SystemRoot%\explorer.exe"
echo Log: "%LOG%"
echo If Explorer does not return: Ctrl+Shift+Esc, Run new task, explorer.exe.
exit /b 0
:preview
echo WhatIf: would verify your local console session, profile paths and confirm.
echo WhatIf: would restart only your Explorer and clear icon/thumbnail caches.
echo No processes were stopped and no files were written or removed.
exit /b 0
:help
echo Repair-Explorer-NoPowerShell.cmd
echo Run without elevation as the affected user at the local console.
echo Restarts Explorer and clears icon/thumbnail caches. Logs to your Temp.
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
