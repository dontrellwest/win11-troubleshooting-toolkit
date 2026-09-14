@echo off
setlocal
REM Native read-only triage. Writes a report; no settings are changed.
REM WMIC is optional. Use the PowerShell tools for current CPU and disk load.
if /i "%~1"=="/?" goto :help
if not "%~1"=="" (
    echo Unknown option. Use /? for help.
    exit /b 2
)
if not exist "C:\Temp" mkdir "C:\Temp"
set "LOG=C:\Temp\PerformanceOverview_%COMPUTERNAME%.txt"
echo Running triage. This may take about 30 seconds.
call :report > "%LOG%" 2>&1
if not exist "%LOG%" (
    echo Could not write "%LOG%".
    exit /b 1
)
type "%LOG%"
echo.
echo Log saved to "%LOG%"
if not defined TOOLKIT_NOPAUSE pause
exit /b 0

:help
echo Get-PerformanceOverview-NoPowerShell.cmd
echo Creates a system, memory, disk, startup and service report.
echo No settings are changed. Missing commands may leave sections unavailable.
echo Run without arguments. Report: C:\Temp\PerformanceOverview_COMPUTERNAME.txt
echo Administrator access may expose additional information.
exit /b 0

:report
echo ================================================================
echo PERFORMANCE OVERVIEW - %COMPUTERNAME%
echo Generated: %DATE% %TIME%
echo ================================================================
echo.
echo MACHINE, RAM, UPTIME
REM Keep the full localized systeminfo report; English filters drop data.
systeminfo
echo.
echo RUNNING PROCESSES - MEMORY IS SHOWN, LIST IS UNSORTED
tasklist /fi "STATUS eq running"
echo.
where wmic.exe >nul 2>&1
if errorlevel 1 goto :withoutwmic
echo DISK - MODEL AND REPORTED HEALTH
wmic diskdrive get model,mediatype,size,status
echo.
echo DISK - FREE SPACE
wmic logicaldisk get caption,volumename,size,freespace
echo.
echo STARTUP COMMANDS
wmic startup get caption,command,location
goto :reboot

:withoutwmic
echo WMIC is not installed. Disk model/health and full startup data unavailable.
echo Use the PowerShell tools for those details.
echo.
echo SYSTEM DRIVE - FREE SPACE IN BYTES
fsutil volume diskfree %SystemDrive%
if errorlevel 1 echo Free-space query unavailable; try an administrator prompt.
echo.
echo MOUNTED VOLUMES
mountvol
echo.
echo STARTUP REGISTRY ENTRIES - CURRENT ACCOUNT AND MACHINE
echo Missing keys are normal. This does not include tasks or startup folders.
for %%K in ("HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce") do (
    echo.
    echo %%~K
    reg query "%%~K" 2>nul
    if errorlevel 1 echo Key absent or unreadable.
)

:reboot
echo.
echo PENDING REBOOT - TWO COMMON FLAGS
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" 2>nul
if errorlevel 1 (echo CBS flag absent or unreadable.) else (echo CBS reboot flag present.)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" 2>nul
if errorlevel 1 (echo Windows Update flag absent or unreadable.) else (echo Windows Update reboot flag present.)
echo Other reboot causes are not checked.
echo.
echo RUNNING SERVICES
net start
echo.
echo WHAT TO LOOK FOR
echo Compare available memory, free space and current workload.
echo An HDD or a single threshold alone does not establish the cause.
echo Use the Resource Usage folder to measure CPU and disk load while the PC is slow.
echo Native commands above may report unavailable sections; review the text.
exit /b 0
