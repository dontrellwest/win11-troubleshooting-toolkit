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
tasklist /fo csv /nh | findstr /i /c:"dism.exe" /c:"sfc.exe" /c:"TiWorker.exe" >nul
if not errorlevel 1 (
  echo Windows servicing or another repair is running. Wait and retry.
  exit /b 1
)
echo This runs DISM RestoreHealth and SFC. Allow 10-40 minutes.
choice /c YN /n /m "Continue? Y or N: "
if errorlevel 2 exit /b 0
if not errorlevel 1 exit /b 0
set "LOGDIR=C:\Temp\Toolkit"
if not exist "%LOGDIR%\" mkdir "%LOGDIR%"
if not exist "%LOGDIR%\" exit /b 1
set "LOG=%LOGDIR%\WindowsSystemFiles_%COMPUTERNAME%_%RANDOM%-%RANDOM%.log"
echo Started %date% %time%>"%LOG%"
if errorlevel 1 exit /b 1
echo Running DISM. Progress is in "%LOG%".
"%SystemRoot%\System32\dism.exe" /Online /Cleanup-Image /RestoreHealth >>"%LOG%" 2>&1
set "DISMRC=%ERRORLEVEL%"
echo Running SFC. Progress is in "%LOG%".
"%SystemRoot%\System32\sfc.exe" /scannow >>"%LOG%" 2>&1
set "SFCRC=%ERRORLEVEL%"
echo DISM exit: %DISMRC%; SFC exit: %SFCRC%>>"%LOG%"
findstr /l /c:"[SR]" "%SystemRoot%\Logs\CBS\CBS.log" | findstr /i /c:"Repair" /c:"Cannot repair" >"%LOG%.CBS-SR.txt"
echo Log: "%LOG%"
echo CBS history extract: "%LOG%.CBS-SR.txt"
echo The native CBS extract includes older runs. Check dates before using it.
echo SFC output may use a different encoding. Read its section in Notepad.
if not "%SFCRC%"=="0" exit /b 1
if "%DISMRC%"=="0" exit /b 0
if "%DISMRC%"=="3010" exit /b 0
exit /b 1
:preview
echo WhatIf: would require admin, check for running repairs, and ask to continue.
echo WhatIf: would run DISM RestoreHealth then SFC /scannow and save logs.
echo No commands were run and no files were written.
exit /b 0
:help
echo Repair-WindowsSystemFiles-NoPowerShell.cmd
echo Run as administrator for DISM RestoreHealth and SFC. Saves logs.
echo /whatif prints the plan. /? displays this help.
exit /b 0
