@echo off
REM ===========================================================================
REM  Test-NetworkSpeed.cmd
REM  Double-click this to run Test-NetworkSpeed.ps1 at the machine.
REM
REM  It exists because Windows will not run a .ps1 on double-click, and
REM  right-clicking "Run with PowerShell" gives you no way to set the
REM  execution policy, which blocks unsigned scripts by default.
REM
REM  -ExecutionPolicy Bypass is per-process. It writes nothing and changes
REM  nothing on the machine. If GPO enforces AllSigned, GPO wins and this
REM  will fail. That is a signing conversation, not something to work around.
REM
REM  Any options are passed straight through, so this works too:
REM      Test-NetworkSpeed.cmd KeyValue NoPause
REM
REM  Keep Test-NetworkSpeed.ps1 in the same folder as this file.
REM ===========================================================================

setlocal
set "PS1=%~dp0Test-NetworkSpeed.ps1"

if not exist "%PS1%" goto :missing

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto :failed
endlocal & exit /b 0

:missing
echo.
echo   Test-NetworkSpeed.ps1 was not found next to this file:
echo     %PS1%
echo   Put both files in the same folder.
echo.
pause
endlocal & exit /b 2

:failed
echo.
echo   PowerShell exited with code %RC%.
echo   If nothing printed above, the script was blocked before it ran.
echo   Run this by hand to see the actual error:
echo     powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause
endlocal & exit /b %RC%
