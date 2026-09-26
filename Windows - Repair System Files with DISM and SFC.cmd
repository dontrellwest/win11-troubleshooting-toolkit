@echo off
setlocal
title Windows - Repair System Files with DISM and SFC
rem Runs the two standard Windows repair commands, one after the other:
rem   DISM /Online /Cleanup-Image /RestoreHealth   repairs the Windows component store
rem   sfc /scannow                                 repairs system files from that store
rem Both show their own progress and result in this window. Nothing restarts the PC.

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
rem A 32-bit window (some remote tools) has to call the 64-bit programs.
set "SYS=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\dism.exe" set "SYS=%SystemRoot%\Sysnative"
echo.
echo Repairs Windows system files: DISM first, then SFC.
echo Takes about 15-40 minutes. The PC stays usable but slower. Nothing restarts.
echo.
set "RC=0"
if defined TOOLKIT_UNATTENDED goto :go
choice /c YN /n /m "Start now? [Y/N] "
if errorlevel 2 goto :end
:go
echo.
echo === Step 1 of 2: DISM /Online /Cleanup-Image /RestoreHealth ===
"%SYS%\dism.exe" /Online /Cleanup-Image /RestoreHealth
set "DISMRC=%ERRORLEVEL%"
echo.
echo === Step 2 of 2: sfc /scannow ===
"%SYS%\sfc.exe" /scannow
set "SFCRC=%ERRORLEVEL%"
echo.
echo === What the results mean ===
if "%DISMRC%"=="0" echo DISM: completed without errors.
if "%DISMRC%"=="3010" echo DISM: completed. Restart the PC to finish.
if not "%DISMRC%"=="0" if not "%DISMRC%"=="3010" echo DISM: failed with code %DISMRC%. Its message is above; details are in C:\Windows\Logs\DISM\dism.log.
if "%DISMRC%"=="-2146498529" echo       Code 0x800f081f means DISM could not get repair files. Check the internet connection and Windows Update, then run this again.
echo SFC: read its last message above.
echo   "did not find any integrity violations" = nothing was damaged.
echo   "found corrupt files and successfully repaired them" = restart the PC.
echo   "found corrupt files but was unable to fix some" = restart, then run this again.
echo   "There is a system repair pending" = restart the PC, then run this again.
echo   SFC details are in C:\Windows\Logs\CBS\CBS.log.
if not "%DISMRC%"=="0" if not "%DISMRC%"=="3010" set "RC=1"
if not "%SFCRC%"=="0" set "RC=1"
:end
echo.
if not defined TOOLKIT_UNATTENDED pause
exit /b %RC%
