@echo off
setlocal DisableDelayedExpansion
if /i "%~1"=="/?" goto :help
if /i "%~1"=="/whatif" goto :preview
if not "%~1"=="" goto :help

fltmc >nul 2>&1
if errorlevel 1 (
  echo Administrator rights required. Right-click and Run as administrator.
  exit /b 1
)
set "SPOOL=%SystemRoot%\System32\spool\PRINTERS"
set "REGSPOOL="
for /f "tokens=2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers" /v DefaultSpoolDirectory 2^>nul') do if /i "%%A"=="REG_SZ" set "REGSPOOL=%%B"
for /f "tokens=2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers" /v DefaultSpoolDirectory 2^>nul') do if /i "%%A"=="REG_EXPAND_SZ" set "REGSPOOL=%%B"
if defined REGSPOOL if /i not "%REGSPOOL%"=="%SPOOL%" (
  echo Custom spool path detected. Use the PowerShell tool for validation.
  exit /b 1
)
set "NATIVEPATH=%SPOOL%"
call :CheckPath
if errorlevel 1 (
  echo Spool path is unavailable or linked. Refusing.
  exit /b 1
)
echo This cancels queued jobs in "%SPOOL%" and restarts Spooler.
choice /c YN /n /m "Continue? Y or N: "
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 0
if not exist "C:\Temp\Toolkit\" mkdir "C:\Temp\Toolkit"
set "LOG=C:\Temp\Toolkit\PrintSpoolerReset_%COMPUTERNAME%_%RANDOM%-%RANDOM%.log"
echo Started %date% %time%>"%LOG%"
if errorlevel 1 exit /b 1
rem No /y: do not approve stopping dependent services automatically.
net stop spooler <nul >>"%LOG%" 2>&1
sc query spooler | findstr /r /c:"STATE *: *1 " >nul
if errorlevel 1 (
  echo Spooler is not confirmed stopped. No files removed.
  echo Log: "%LOG%"
  exit /b 1
)
set "NATIVEPATH=%SPOOL%"
call :CheckPath
if errorlevel 1 goto :startspool
if exist "%SPOOL%\*.SPL" del /f /q "%SPOOL%\*.SPL" >>"%LOG%" 2>&1
if exist "%SPOOL%\*.SHD" del /f /q "%SPOOL%\*.SHD" >>"%LOG%" 2>&1
:startspool
net start spooler >>"%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
sc query spooler >>"%LOG%" 2>&1
echo Log: "%LOG%"
echo Check Spooler is running, then send a test page.
exit /b %RC%
:preview
echo WhatIf: would validate the standard spool path, require admin and confirm.
echo WhatIf: would stop Spooler, clear SPL/SHD jobs, and start Spooler.
echo No service commands were run and no files were written.
exit /b 0
:help
echo Reset-PrintSpooler-NoPowerShell.cmd
echo Run as administrator. Cancels queued jobs in the standard spool folder.
echo Custom or linked spool folders are refused. Logs to C:\Temp\Toolkit.
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
