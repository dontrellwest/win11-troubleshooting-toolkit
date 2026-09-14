@echo off
setlocal EnableExtensions
REM ===========================================================================
REM  Test-NetworkSpeed-NoPowerShell.cmd  -  network speed test, pure CMD, installs nothing
REM
REM  Run it straight off the flash drive. Double-click, or from a prompt:
REM      Test-NetworkSpeed-NoPowerShell.cmd            interactive report, pauses at the end
REM      Test-NetworkSpeed-NoPowerShell.cmd /q         unattended, KEY=VALUE lines, never pauses
REM      Test-NetworkSpeed-NoPowerShell.cmd /noup      skip the upload leg
REM      Test-NetworkSpeed-NoPowerShell.cmd /?         help
REM
REM  /q is the mode for RMM tasks, N-central, or anything scripted. It never
REM  prompts, so it cannot hang a task waiting on a keypress.
REM  Exit code 0 if the download leg produced a number, 1 if it did not.
REM
REM  Uses curl.exe, which ships with Windows 10 1803 and later, against
REM  Cloudflare's public speed test endpoints. The only thing written to disk
REM  is a temp payload for the upload leg, and it gets deleted.
REM
REM  Two caveats worth saying out loud:
REM    - Single stream, so the download number is a floor, not the line max.
REM    - curl ignores the per-user WinINET proxy. On a network with a
REM      user-scoped proxy this measures the direct path, which may not be
REM      what the logged-on user experiences. Test-NetworkSpeed.ps1 does honor that
REM      proxy, so when the two disagree, a proxy is usually the reason.
REM
REM  Run ONE machine at a time per site. Concurrent tests contend with each
REM  other and every one of them reads low.
REM ===========================================================================

set "MODE=TEXT"
set "DOUP=1"
set "DOWNBYTES=25000000"
set "UPBYTES=10000000"
set "PAYLOAD=%TEMP%\speedtest_up_%RANDOM%.bin"

:parseargs
if "%~1"=="" goto :parsed
if /i "%~1"=="/q"       set "MODE=KV" & shift & goto :parseargs
if /i "%~1"=="/quiet"   set "MODE=KV" & shift & goto :parseargs
if /i "%~1"=="KeyValue" set "MODE=KV" & shift & goto :parseargs
if /i "%~1"=="/noup"    set "DOUP=0"  & shift & goto :parseargs
if /i "%~1"=="/?"       goto :help
if /i "%~1"=="/help"    goto :help
if /i "%~1"=="-h"       goto :help
echo Unknown option: %~1
echo Run  Test-NetworkSpeed-NoPowerShell.cmd /?  for help.
endlocal & exit /b 2
:parsed

REM --- curl has to be there. On anything older than 1803 it will not be.
where curl.exe >nul 2>&1
if errorlevel 1 goto :nocurl

if "%MODE%"=="KV" goto :kvheader
echo.
echo   Network speed test  -  %COMPUTERNAME%
echo   ------------------------------------------------
echo   Testing, give it a few seconds...
echo.
goto :measure

:kvheader
echo COMPUTER=%COMPUTERNAME%
echo USER=%USERNAME%
echo TIMESTAMP=%DATE% %TIME%

:measure
REM --- Download leg. The same curl call hands back the timing breakdown.
REM     time_connect minus time_namelookup is the TCP handshake, which is one
REM     round trip, so it is a fair stand-in for latency. TTFB is reported
REM     separately because it also carries TLS setup and server think time.
set "NS=" & set "CN=" & set "TT=" & set "DS=" & set "SZ=" & set "HC="
for /f "tokens=1,2,3,4,5,6" %%a in ('curl.exe -s -o NUL --max-time 90 -w "%%{time_namelookup} %%{time_connect} %%{time_starttransfer} %%{speed_download} %%{size_download} %%{http_code}" "https://speed.cloudflare.com/__down?bytes=%DOWNBYTES%" 2^>NUL') do set "NS=%%a" & set "CN=%%b" & set "TT=%%c" & set "DS=%%d" & set "SZ=%%e" & set "HC=%%f"

if not "%HC%"=="200" goto :downfailed
if "%SZ%"=="0" goto :downfailed

call :us "%NS%" NS_US
call :us "%CN%" CN_US
call :us "%TT%" TT_US

REM --- Latency, best of five TCP handshakes.
REM     A single handshake is noisy, easily 3x the real figure, so take the
REM     lowest of several. "Connection: close" forces curl to open a fresh
REM     connection per URL, which is what makes each one measurable. The
REM     bytes=0 endpoint returns an empty body, so the only thing reaching
REM     stdout is the -w line, one per sample.
set "BEST_US=999999999"
set "PROBE=https://speed.cloudflare.com/__down?bytes=0"
for /f "tokens=1,2" %%a in ('curl.exe -s -o NUL -H "Connection: close" --max-time 30 -w "%%{time_namelookup} %%{time_connect}\n" "%PROBE%" "%PROBE%" "%PROBE%" "%PROBE%" "%PROBE%" 2^>NUL') do call :sample "%%a" "%%b"

REM  Fall back to the handshake from the download leg if the probe got nothing.
if "%BEST_US%"=="999999999" set /a BEST_US=CN_US-NS_US 2>nul
if %BEST_US% LSS 0 set "BEST_US=0"
set "RTT_US=%BEST_US%"
call :usms "%RTT_US%" RTT_MS
call :usms "%TT_US%" TTFB_MS
call :mbps "%DS%" DOWN_MBPS
call :mbs "%DS%" DOWN_MBS
goto :downdone

:downfailed
set "RTT_MS=?"
set "TTFB_MS=?"
set "DOWN_MBPS="
set "DOWN_MBS=?"
:downdone

REM --- Upload leg. fsutil builds the payload instantly, no admin rights.
if "%DOUP%"=="0" goto :noupload
if exist "%PAYLOAD%" del /f /q "%PAYLOAD%" >nul 2>&1
fsutil file createnew "%PAYLOAD%" %UPBYTES% >nul 2>&1
if not exist "%PAYLOAD%" goto :nopayload

set "US=" & set "UHC="
for /f "tokens=1,2" %%a in ('curl.exe -s -o NUL --max-time 90 -w "%%{speed_upload} %%{http_code}" -X POST -H "Content-Type: application/octet-stream" -H "Expect:" --data-binary "@%PAYLOAD%" "https://speed.cloudflare.com/__up" 2^>NUL') do set "US=%%a" & set "UHC=%%b"

del /f /q "%PAYLOAD%" >nul 2>&1
if not "%UHC%"=="200" goto :upfailed
call :mbps "%US%" UP_MBPS
call :mbs "%US%" UP_MBS
goto :report

:upfailed
set "UP_MBPS="
set "UP_MBS=?"
set "UPNOTE=upload rejected, HTTP %UHC%"
goto :report

:nopayload
set "UP_MBPS="
set "UP_MBS=?"
set "UPNOTE=could not create the temp payload at %PAYLOAD%"
goto :report

:noupload
set "UP_MBPS=skipped"
set "UP_MBS="
set "UPNOTE="

:report
if "%MODE%"=="KV" goto :kvreport

REM  :pad right-fills to 11 chars so the trailing notes line up.
call :pad "%RTT_MS% ms" C1
call :pad "%TTFB_MS% ms" C2
echo   Latency   %C1%  ^(one TCP round trip^)
echo   TTFB      %C2%  ^(includes TLS setup^)
if not defined DOWN_MBPS goto :rep_downfail
call :pad "%DOWN_MBPS% Mbps" C3
echo   Down      %C3%  ^(%DOWN_MBS% MB/s^)
goto :rep_up
:rep_downfail
call :pad "FAILED" C3
echo   Down      %C3%  ^(HTTP %HC%^)
:rep_up
if "%UP_MBPS%"=="skipped" goto :rep_upskip
if not defined UP_MBPS goto :rep_upfail
call :pad "%UP_MBPS% Mbps" C4
echo   Up        %C4%  ^(%UP_MBS% MB/s^)
goto :rep_tail
:rep_upskip
echo   Up        skipped
goto :rep_tail
:rep_upfail
echo   Up        FAILED
:rep_tail
echo.
if defined UPNOTE echo   Note: %UPNOTE%
echo   Single stream. Treat Down as a floor, not the line's capacity.
echo   Latency is a TCP round trip, not an ICMP ping.
echo.
pause
goto :finish

:kvreport
echo LATENCY_MS=%RTT_MS%
echo TTFB_MS=%TTFB_MS%
echo DOWN_MBPS=%DOWN_MBPS%
echo DOWN_MB_S=%DOWN_MBS%
echo UP_MBPS=%UP_MBPS%
echo UP_MB_S=%UP_MBS%
echo HTTP_CODE=%HC%
if defined UPNOTE echo UP_NOTE=%UPNOTE%
echo NOTE=Single stream, DOWN_MBPS is a floor. LATENCY_MS is a TCP round trip.

:finish
if not defined DOWN_MBPS endlocal & exit /b 1
endlocal & exit /b 0

:nocurl
if "%MODE%"=="KV" goto :nocurl_kv
echo.
echo   curl.exe was not found on this machine.
echo   It ships with Windows 10 1803 and later, so this is either a very old
echo   build or a stripped image. Use Test-NetworkSpeed.ps1 instead.
echo.
pause
endlocal & exit /b 3
:nocurl_kv
echo ERROR=curl.exe not found, use Test-NetworkSpeed.ps1 instead
endlocal & exit /b 3

:help
echo.
echo   Test-NetworkSpeed-NoPowerShell.cmd  -  network speed test using curl and Cloudflare
echo.
echo     Test-NetworkSpeed-NoPowerShell.cmd           interactive report, pauses at the end
echo     Test-NetworkSpeed-NoPowerShell.cmd /q        unattended KEY=VALUE output, never pauses
echo     Test-NetworkSpeed-NoPowerShell.cmd /noup     skip the upload leg
echo.
echo   Exit codes:  0 ok   1 download failed   2 bad option   3 no curl
echo.
endlocal & exit /b 0


REM ==========================================================================
REM  Subroutines.
REM  set /a cannot parse a decimal point, and reads a leading zero as octal,
REM  so both get handled before any arithmetic. The 1%%f%%-1000000 trick
REM  forces a zero-padded fraction to be read as base 10.
REM  Deliberately no parenthesized if-blocks below: a literal ")" inside an
REM  echo would close the block early.
REM ==========================================================================

REM  :sample  one "namelookup connect" pair -> keep it if it beats BEST_US.
REM  No setlocal here on purpose, it has to write BEST_US in the caller.
:sample
call :us "%~1" S_NS
call :us "%~2" S_CN
if %S_CN% LEQ 0 goto :eof
set /a S_D=S_CN-S_NS
if %S_D% LSS 0 goto :eof
if %S_D% LSS %BEST_US% set "BEST_US=%S_D%"
goto :eof

REM  :pad  right-fill a string to 11 characters
:pad
setlocal
set "s=%~1           "
set "s=%s:~0,11%"
endlocal & set "%~2=%s%"
goto :eof

REM  :us  "1.234567" -> integer microseconds
:us
setlocal
set "v=%~1"
set "w=" & set "f="
for /f "tokens=1,2 delims=." %%x in ("%v%") do set "w=%%x" & set "f=%%y"
if not defined w goto :us_bad
if not defined f set "f=000000"
set "f=%f%000000"
set "f=%f:~0,6%"
REM  The whole-seconds part never carries a leading zero, so it needs no
REM  guard. The fraction is zero-padded, so it does: 1%%f%% - 1000000.
set /a m=(w*1000000)+(1%f%-1000000) 2>nul
if errorlevel 1 goto :us_bad
endlocal & set "%~2=%m%"
goto :eof
:us_bad
endlocal & set "%~2=0"
goto :eof

REM  :usms  microseconds -> "12.3" milliseconds
:usms
setlocal
set /a w=%~1/1000 2>nul
if errorlevel 1 goto :usms_bad
set /a r=%~1%%1000
set /a t=r/100
endlocal & set "%~2=%w%.%t%"
goto :eof
:usms_bad
endlocal & set "%~2=?"
goto :eof

REM  :mbps  bytes/sec -> "123.4" megabits/sec
:mbps
setlocal
set "v=%~1"
for /f "tokens=1 delims=." %%x in ("%v%") do set "v=%%x"
if not defined v goto :mbps_bad
set /a w=v/125000 2>nul
if errorlevel 1 goto :mbps_bad
set /a r=v%%125000
set /a t=(r*10)/125000
endlocal & set "%~2=%w%.%t%"
goto :eof
:mbps_bad
endlocal & set "%~2=?"
goto :eof

REM  :mbs  bytes/sec -> "12.3" megabytes/sec
:mbs
setlocal
set "v=%~1"
for /f "tokens=1 delims=." %%x in ("%v%") do set "v=%%x"
if not defined v goto :mbs_bad
set /a w=v/1000000 2>nul
if errorlevel 1 goto :mbs_bad
set /a r=v%%1000000
set /a t=(r*10)/1000000
endlocal & set "%~2=%w%.%t%"
goto :eof
:mbs_bad
endlocal & set "%~2=?"
goto :eof
