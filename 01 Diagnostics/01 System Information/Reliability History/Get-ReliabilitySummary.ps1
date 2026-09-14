<#
.SYNOPSIS
    Scriptable Reliability Monitor: counts app crashes, hangs, driver/service failures and bugchecks over the last N days.
.DESCRIPTION
    Reads the Application log (Application Error 1000, Application Hang 1002, Windows Error Reporting 1001) and the
    System log (Kernel-PnP 219, Service Control Manager 7000/7001/7009/7011/7034, WER-SystemErrorReporting 1001,
    Kernel-Power 41) plus the Reliability Monitor stability index, and returns counts, the worst application and
    module and a rough Verdict, so a genuinely sick machine stands out from one bad ticket.
    Names come from the events' language-neutral data fields, never from the localised message text.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER Days
    How many days back to count (default 30).
.PARAMETER RecentCount
    How many individual events to list in RecentEvents, newest first (default 25).
.PARAMETER MaxWerEvents
    Safety cap on how many Windows Error Reporting records are read (default 50000). A machine stuck in a
    LiveKernelEvent loop can log hundreds of thousands; when the cap is hit WerReports is a floor, not a total,
    and a Warning says so.
.EXAMPLE
    .\Get-ReliabilitySummary.ps1
.EXAMPLE
    .\Get-ReliabilitySummary.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Get-ReliabilitySummary.ps1 -Days 7 | Select-Object -ExpandProperty ByApplication
.NOTES
    Toolkit-Class:     ReadOnly
    Toolkit-Context:   Machine
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [ValidateRange(1, 3650)][int]$Days = 30,
    [ValidateRange(1, 1000)][int]$RecentCount = 25,
    [ValidateRange(100, 1000000)][int]$MaxWerEvents = 50000
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-ReliabilitySummary'          # <-- set per tool
$script:Warnings  = New-Object System.Collections.Generic.List[string]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Runs a block; on failure records a warning and returns $Default instead of killing the script.
function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, $Default = $null)
    try { & $Script } catch { Add-Warning ("{0}: {1}" -f $Name, $_.Exception.Message.Trim()); $Default }
}

# External commands: stderr merged as text, exit code captured, safe under $ErrorActionPreference = 'Stop'.
function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList = @())
    $ErrorActionPreference = 'Continue'
    $lines = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Lines = $lines }
}

function Round1 { param($Value) if ($null -eq $Value) { $null } else { [math]::Round([double]$Value, 1) } }

function Format-Bytes {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { '{0:N1} TB' -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { '{0:N1} GB' -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { '{0:N1} MB' -f ($Bytes / 1MB) }
    elseif ($Bytes -ge 1KB) { '{0:N1} KB' -f ($Bytes / 1KB) }
    else { '{0} B' -f [int64]$Bytes }
}

function Format-Duration {
    param([TimeSpan]$Span)
    if ($Span.TotalDays -ge 1) { '{0}d {1}h {2}m' -f [int]$Span.Days, $Span.Hours, $Span.Minutes }
    elseif ($Span.TotalHours -ge 1) { '{0}h {1}m' -f [int]$Span.Hours, $Span.Minutes }
    else { '{0}m {1}s' -f [int]$Span.Minutes, $Span.Seconds }
}

# FILETIME helpers (registry DWORD pairs may arrive as negative Int32; the L suffix matters in PS 5.1).
function ConvertFrom-FileTimePair { param($High, $Low) [DateTime]::FromFileTime(([int64]$High -shl 32) -bor ([int64]$Low -band 0xFFFFFFFFL)) }
function ConvertFrom-FileTimeBytes { param([byte[]]$Bytes) [DateTime]::FromFileTime([BitConverter]::ToInt64($Bytes, 0)) }

# TCP reachability with a real timeout (Test-Path on a dead UNC host can hang 20+ s).
function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async) | Out-Null
        return $true
    } catch { return $false } finally { $client.Close() }
}

# The interactive (console) user, resolved even when this process runs as another account, SYSTEM, or remotely.
# Source: Console (Win32_ComputerSystem.UserName) | Desktop (owner of a live explorer.exe) | Override (-TargetUser) | Process (nobody found; fell back to this process's identity).
function Get-ConsoleUser {
    param([string]$OverrideName)
    $name = $null; $sid = $null; $source = $null; $sessionId = $null; $logonId = $null
    $desktops = @()   # one explorer.exe per live desktop; owner + logon session come from LSA (no DC round trip)
    try { foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
        $o = $null; $ls = $null
        try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop } catch { }
        try { $ls = Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in 2,10,11 } | Select-Object -First 1 } catch { }
        if ($o -and $o.User) { $desktops += [PSCustomObject]@{ Name = ('{0}\{1}' -f $o.Domain, $o.User); SessionId = $p.SessionId; LogonId = $ls.LogonId; LogonType = $ls.LogonType; StartTime = $ls.StartTime } }
    } } catch { }
    if ($OverrideName) { $name = $OverrideName; $source = 'Override' }
    if (-not $name) { try { $name = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch { }; if ($name) { $source = 'Console' } }
    if (-not $name -and $desktops.Count) {
        $pick = $desktops | Sort-Object @{e={$_.LogonType -eq 10}}, @{e={$_.StartTime}; Descending=$true} | Select-Object -First 1
        $name = $pick.Name; $source = 'Desktop'
    }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $name) { $name = $me.Name; $sid = $me.User.Value; $source = 'Process' }
    if ($name -and -not $sid) { try { $sid = ([System.Security.Principal.NTAccount]$name).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { } }
    $mine = $desktops | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if ($mine) { $sessionId = $mine.SessionId; $logonId = $mine.LogonId }
    $hive = $null; $profilePath = $null
    if ($sid) {
        if (-not (Get-PSDrive HKU -ErrorAction SilentlyContinue)) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null }
        try { $k = [Microsoft.Win32.Registry]::Users.OpenSubKey($sid); if ($k) { $hive = "HKU:\$sid"; $k.Close() } } catch { }
        try { $profilePath = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction Stop).ProfileImagePath) } catch { }
    }
    [PSCustomObject]@{
        Name          = $name            # DOMAIN\user of the person at the desk
        Sid           = $sid
        Hive          = $hive            # HKU:\S-1-5-21-... (openable) or $null. Use INSTEAD of HKCU:
        ProfilePath   = $profilePath     # C:\Users\jdoe. Use INSTEAD of $env:USERPROFILE / APPDATA / LOCALAPPDATA
        SessionId     = $sessionId       # session of that user's live desktop ($null = no desktop found)
        LogonId       = $logonId         # decimal LUID of that logon session (klist -li ('0x{0:x}' -f [int64]$logonId))
        Source        = $source          # Console | Desktop | Override | Process
        OtherDesktops = (($desktops | Where-Object { $_.Name -ne $name } | ForEach-Object { '{0} (session {1})' -f $_.Name, $_.SessionId }) -join ', ')
        IsMe          = ($sid -eq $me.User.Value)
        IsSystem      = ($me.User.Value -eq 'S-1-5-18')
        RunningAs     = $me.Name
    }
}

# Readable report for -Display. Scalars as a list, array properties as tables (never silently dropping columns).
function Show-Result {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Title, [string]$ReportPath)
    begin { $items = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        $width = 250
        $table = {
            param($src)
            $rows = @($src)
            $ft = ($rows | Format-Table -Property * -AutoSize -Wrap | Out-String -Width $width).TrimEnd()
            $hdr = ($ft -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
            $dropped = @($rows[0].PSObject.Properties.Name | Where-Object { $hdr -notmatch ('(^|\s)' + [regex]::Escape($_) + '(\s|$)') })
            if ($dropped.Count) { $ft = ($rows | Format-List -Property * | Out-String -Width $width).TrimEnd() }
            $ft
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine(('  {0}   {1}   {2}' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')))
        [void]$sb.AppendLine(('=' * 78))
        $isList = { param($p) ($p.Value -is [System.Collections.IEnumerable]) -and ($p.Value -isnot [string]) -and ($p.Value -isnot [System.Collections.IDictionary]) }
        $allFlat = $true
        foreach ($i in $items) { foreach ($p in $i.PSObject.Properties) { if (& $isList $p) { $allFlat = $false } } }
        if ($items.Count -gt 1 -and $allFlat) {
            [void]$sb.AppendLine((& $table $items.ToArray()))
            [void]$sb.AppendLine(''); [void]$sb.AppendLine(('  {0} row(s)' -f $items.Count))
        } elseif ($items.Count -eq 0) {
            [void]$sb.AppendLine('  (no results)')
        } else {
            foreach ($i in $items) {
                $scalars = [ordered]@{}; $lists = @()
                foreach ($p in $i.PSObject.Properties) { if (& $isList $p) { $lists += $p } else { $scalars[$p.Name] = $p.Value } }
                if ($scalars.Count) { [void]$sb.AppendLine(([PSCustomObject]$scalars | Format-List | Out-String -Width $width).Trim()) }
                foreach ($l in $lists) {
                    $rows = @($l.Value)
                    [void]$sb.AppendLine(''); [void]$sb.AppendLine(('--- {0} ({1}) ---' -f $l.Name, $rows.Count))
                    if ($rows.Count) { [void]$sb.AppendLine((& $table $rows)) } else { [void]$sb.AppendLine('  (none)') }
                }
                [void]$sb.AppendLine('')
            }
        }
        $text = $sb.ToString()
        Write-Host $text
        if ($ReportPath) {
            try {
                $ReportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ReportPath)
                if (-not (Test-Path -LiteralPath $ReportPath)) { New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null }
                $file = Join-Path $ReportPath ('{0}_{1}_{2}.txt' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyyMMdd-HHmm'))
                [System.IO.File]::WriteAllText($file, $text, [System.Text.Encoding]::UTF8)
                Write-Host ("Report saved: {0}" -f $file)
            } catch { Write-Host ("Could not save report to {0}: {1}" -f $ReportPath, $_.Exception.Message) }
        }
    }
}
# ---------------------------------------------------------------- end toolkit helpers

# ---------------------------------------------------------------- tool-specific helpers
# Event data by index. Verified against live events on Win11 26200; these indices are the event's own data fields,
# so they are identical on every language. $null when the event has fewer fields than expected or the field is binary.
function Get-EventData {
    param($Properties, [int]$Index)
    if ($null -eq $Properties -or $Index -ge $Properties.Count) { return $null }
    $v = $Properties[$Index].Value
    if ($null -eq $v -or $v -is [byte[]]) { return $null }
    $v
}
function Get-Text { param($Value) $s = "$Value".Trim(); if ($s) { $s } else { $null } }
function Join-Parts { param([string[]]$Parts) (@($Parts | Where-Object { $_ }) -join ', ') }

# Service Control Manager stores Win32 error codes as '%%1053'; render them with the OS's own text for that code.
function ConvertTo-ErrorText {
    param($Raw)
    $s = "$Raw".Trim()
    if ($s -match '^%%(\d+)$') {
        $code = [int]$matches[1]; $msg = $null
        try { $msg = (New-Object System.ComponentModel.Win32Exception($code)).Message } catch { }
        if ($msg) { return ('error {0}: {1}' -f $code, $msg) } else { return ('error {0}' -f $code) }
    }
    if ($s) { $s } else { $null }
}

# A few exception codes every tech sees; anything else is shown as the raw hex.
$script:ExceptionNames = @{
    'c0000005' = 'access violation'; 'c0000409' = 'stack buffer overrun / fail-fast'; 'e0434352' = '.NET exception'
    'c00000fd' = 'stack overflow'; 'c0000374' = 'heap corruption'; '80000003' = 'breakpoint'; 'c000001d' = 'illegal instruction'
    'c0000142' = 'DLL initialization failed'; 'e06d7363' = 'C++ exception'; 'c0000006' = 'in-page error (bad disk or memory)'
    'c000027b' = 'unhandled WinRT exception'
}
function Get-ExceptionText {
    param($Code)
    $c = ("$Code").Trim().ToLower()
    if (-not $c) { return $null }
    if ($script:ExceptionNames.ContainsKey($c)) { '0x{0} ({1})' -f $c, $script:ExceptionNames[$c] } else { '0x' + $c }
}

# WER event names whose P1 is the failing program. Used only to decide which WER field is the "Name" column.
$script:WerAppEventNames = @('APPCRASH', 'AppHangB1', 'AppHangTransient', 'AppHangXProcB1', 'BEX', 'BEX64',
                             'MoAppCrash', 'MoAppHang', 'CLR20r3', 'RADAR_PRE_LEAK_64', 'WERVerticalAppCrash', 'crashpad_log')

function Get-IssueRow {
    param([datetime]$Time, [string]$Category, $Name, $Version, $Module, [string]$Detail)
    $n = Get-Text $Name
    [PSCustomObject]@{
        Time     = $Time
        Category = $Category
        Name     = $(if ($n) { $n } else { '(unknown)' })
        Version  = (Get-Text $Version)
        Module   = (Get-Text $Module)
        Detail   = $Detail
    }
}

# ---------------------------------------------------------------- collect
$start = [DateTime]::Now.AddDays(-$Days)
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# Application log: crashes and hangs. The provider filter is mandatory: Winlogon also writes Id 1002 (shell restart).
$wc = $script:Warnings.Count
$appEvents = @(Invoke-Section 'Application log' {
    $filter = @{ LogName = 'Application'; Id = @(1000, 1002); ProviderName = @('Application Error', 'Application Hang'); StartTime = $start }
    try { @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
} -Default @())
$appOk = ($script:Warnings.Count -eq $wc)
Write-Verbose ('Application log: {0} event(s), {1} ms' -f $appEvents.Count, $sw.ElapsedMilliseconds)

# System log: driver load failures, service failures, bugchecks, unexpected power loss.
# The provider filter is mandatory: Winlogon writes Id 7001 (logon notification) and some drivers write Id 7011.
$wc = $script:Warnings.Count
$sysEvents = @(Invoke-Section 'System log' {
    $filter = @{ LogName = 'System'; Id = @(219, 7034, 7000, 7001, 7009, 7011, 1001, 41)
                 ProviderName = @('Microsoft-Windows-Kernel-PnP', 'Service Control Manager', 'Microsoft-Windows-WER-SystemErrorReporting', 'Microsoft-Windows-Kernel-Power')
                 StartTime = $start }
    try { @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
} -Default @())
$sysOk = ($script:Warnings.Count -eq $wc)
Write-Verbose ('System log: {0} event(s), {1} ms' -f $sysEvents.Count, $sw.ElapsedMilliseconds)

# WER reports (Application, Id 1001): counted and grouped, never listed individually - a machine stuck in a
# LiveKernelEvent loop logs tens of thousands of them (8329 in 30 days on the machine this was built against).
# Two deliberate choices keep this inside the 15 s budget on exactly the noisy machines the tool exists to find:
#   - EventLogReader instead of Get-WinEvent for the bulk read. Get-WinEvent spends ~0.35 ms per record building a
#     PSObject (measured: 2.8 s for 8329 records); the reader does it in ~0.05 ms.
#   - the loop body touches nothing but array indexes. Calling Get-EventData/Get-Text per record cost 8 s on the
#     same 8329 records, so the three raw fields are keyed as-is and classified once per DISTINCT key afterwards
#     (18 distinct keys here, not 8329).
# TolerateQueryErrors is deliberately left at its default $false: with it on, a missing log, an access denial and
# a malformed query all return a silent count of 0. As written they throw and Invoke-Section turns them into a Warning.
$wc = $script:Warnings.Count
$werData = Invoke-Section 'WER reports' {
    $xpath = "*[System[Provider[@Name='Windows Error Reporting'] and (EventID=1001) and TimeCreated[@SystemTime>='{0}']]]" -f
             $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $reader = $null
    try {
        $query  = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Application', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
    } catch {
        $ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }
        throw ('Application log could not be opened ({0})' -f $ex.Message.Trim())
    }
    $total = 0; $capped = $false
    $acc = @{}                       # key -> object[] @(eventName, P1, P2, count, firstSeen, lastSeen)
    $fallback = [DateTime]::Now      # only used if an event somehow carries no timestamp
    try {
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            $total++
            $p = $e.Properties       # [2]=Event Name  [5]=P1 (the program, for app reports)  [6]=P2 (usually its version)
            if ($p.Count -gt 6) { $a = $p[2].Value; $b = $p[5].Value; $c = $p[6].Value } else { $a = $null; $b = $null; $c = $null }
            $t = $e.TimeCreated
            $e.Dispose()
            if ($null -eq $t) { $t = $fallback }
            $k = '{0}|{1}|{2}' -f $a, $b, $c
            $slot = $acc[$k]
            if ($null -eq $slot) { $acc[$k] = @($a, $b, $c, 1, $t, $t) }
            else {
                $slot[3] = [int]$slot[3] + 1
                if ($t -lt $slot[4]) { $slot[4] = $t }
                if ($t -gt $slot[5]) { $slot[5] = $t }
            }
            if ($total -ge $MaxWerEvents) { $capped = $true; break }
        }
    } finally { $reader.Dispose() }

    # One pass over the distinct keys: decide which field is the program name and which is the discriminator.
    # P1 is only a program name for the app-crash families; for LiveKernelEvent it is a watchdog code.
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($slot in $acc.Values) {
        $evName = Get-Text $slot[0]; $p1 = Get-Text $slot[1]; $p2 = Get-Text $slot[2]
        $isApp = $false
        if ($p1) { $isApp = ($p1 -match '\.(exe|dll|sys|scr|com|msi|ocx)$') -or ($script:WerAppEventNames -contains $evName) }
        if ($isApp) { $nm = $p1; $md = $evName } else { $nm = $(if ($evName) { $evName } else { '(unknown)' }); $md = $p1 }
        $rows.Add([PSCustomObject]@{
            Category = 'WerReport'; Name = $nm
            Version  = $(if ($isApp -and $p2 -and $p2 -match '^\d+(\.\d+){1,3}$') { $p2 })
            Module   = $md; Count = [int]$slot[3]; FirstSeen = [datetime]$slot[4]; LastSeen = [datetime]$slot[5] })
    }
    [PSCustomObject]@{ Total = [int]$total; Capped = $capped; Rows = $rows.ToArray() }
}
$werOk = (($script:Warnings.Count -eq $wc) -and $null -ne $werData)
if ($werOk -and $werData.Capped) {
    Add-Warning ('Stopped reading Windows Error Reporting records at the -MaxWerEvents cap of {0}; WerReports is a floor, not a total' -f $MaxWerEvents)
}
Write-Verbose ('WER reports: {0} record(s), {1} ms' -f $(if ($werOk) { $werData.Total } else { 'n/a' }), $sw.ElapsedMilliseconds)

# ---------------------------------------------------------------- classify (one flat row per event)
$issues = @(Invoke-Section 'Classify events' {
    $rows = New-Object System.Collections.Generic.List[object]
    $skipped = 0
    foreach ($e in $appEvents) {
        try {
            $p = $e.Properties
            if ($e.Id -eq 1000 -and $e.ProviderName -eq 'Application Error') {
                # [0]=app [1]=app version [3]=faulting module [4]=module version [6]=exception code
                $ver = Get-Text (Get-EventData $p 1); $mod = Get-Text (Get-EventData $p 3); $modVer = Get-Text (Get-EventData $p 4)
                $exc = Get-ExceptionText (Get-EventData $p 6)
                $detail = Join-Parts @($(if ($ver) { "v$ver" }), $(if ($mod) { ("module $mod $modVer").Trim() }), $(if ($exc) { "exception $exc" }))
                $rows.Add((Get-IssueRow -Time $e.TimeCreated -Category 'AppCrash' -Name (Get-EventData $p 0) -Version $ver -Module $mod -Detail $detail))
            } elseif ($e.Id -eq 1002 -and $e.ProviderName -eq 'Application Hang') {
                # [0]=app [1]=version [9]=hang type (e.g. 'Top level window is idle')
                $ver = Get-Text (Get-EventData $p 1); $kind = Get-Text (Get-EventData $p 9)
                $detail = Join-Parts @($(if ($ver) { "v$ver" }), $kind)
                $rows.Add((Get-IssueRow -Time $e.TimeCreated -Category 'AppHang' -Name (Get-EventData $p 0) -Version $ver -Module $null -Detail $detail))
            }
        } catch { $skipped++ }
    }
    foreach ($e in $sysEvents) {
        try {
            $p = $e.Properties; $prov = $e.ProviderName; $row = $null
            switch ($e.Id) {
                219 {   # Kernel-PnP: [4]=driver [1]=device instance path [2]=NTSTATUS
                    if ($prov -eq 'Microsoft-Windows-Kernel-PnP') {
                        $dev = Get-Text (Get-EventData $p 1); $st = Get-EventData $p 2
                        $stText = $(if ($null -ne $st) { '0x{0:X8}' -f [int64]$st })
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'DriverLoadFailure' -Name (Get-EventData $p 4) -Version $null -Module $dev `
                                            -Detail (Join-Parts @($(if ($dev) { "device $dev" }), $(if ($stText) { "status $stText" })))
                    }; break }
                7034 {  # SCM: [0]=service [1]=how many times
                    if ($prov -eq 'Service Control Manager') {
                        $n = Get-Text (Get-EventData $p 1)
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'ServiceCrash' -Name (Get-EventData $p 0) -Version $null -Module 'terminated unexpectedly' `
                                            -Detail (Join-Parts @('terminated unexpectedly', $(if ($n) { "$n time(s)" })))
                    }; break }
                7000 {  # SCM: [0]=service [1]=error (as '%%1053')
                    if ($prov -eq 'Service Control Manager') {
                        $err = ConvertTo-ErrorText (Get-EventData $p 1)
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'ServiceStartFailure' -Name (Get-EventData $p 0) -Version $null -Module $err `
                                            -Detail (Join-Parts @('failed to start', $err))
                    }; break }
                7001 {  # SCM: [0]=service [1]=dependency [2]=error
                    if ($prov -eq 'Service Control Manager') {
                        $dep = Get-Text (Get-EventData $p 1); $err = ConvertTo-ErrorText (Get-EventData $p 2)
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'ServiceStartFailure' -Name (Get-EventData $p 0) -Version $null -Module $(if ($dep) { "dependency $dep" }) `
                                            -Detail (Join-Parts @($(if ($dep) { "dependency $dep failed to start" } else { 'dependency failed to start' }), $err))
                    }; break }
                7009 {  # SCM: [0]=timeout ms [1]=service
                    if ($prov -eq 'Service Control Manager') {
                        $ms = Get-Text (Get-EventData $p 0)
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'ServiceTimeout' -Name (Get-EventData $p 1) -Version $null -Module "no connect within $ms ms" `
                                            -Detail "timeout: service did not connect within $ms ms"
                    }; break }
                7011 {  # SCM: [0]=timeout ms [1]=service
                    if ($prov -eq 'Service Control Manager') {
                        $ms = Get-Text (Get-EventData $p 0)
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'ServiceTimeout' -Name (Get-EventData $p 1) -Version $null -Module "no response within $ms ms" `
                                            -Detail "timeout: no transaction response within $ms ms"
                    }; break }
                1001 {  # WER-SystemErrorReporting: [0]=bugcheck text '0x0000009f (p1, p2, p3, p4)' [1]=dump path [2]=report id
                    if ($prov -eq 'Microsoft-Windows-WER-SystemErrorReporting') {
                        $bc = Get-Text (Get-EventData $p 0); $dump = Get-Text (Get-EventData $p 1)
                        $code = $(if ($bc -and $bc -match '0x[0-9a-fA-F]+') { $matches[0] } else { $bc })
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'BugCheck' -Name 'BugCheck' -Version $null -Module $code `
                                            -Detail (Join-Parts @($(if ($bc) { "bugcheck $bc" }), $(if ($dump) { "dump $dump" })))
                    }; break }
                41 {    # Kernel-Power: [0]=BugcheckCode [5]=SleepInProgress [15]=LongPowerButtonPressDetected
                    if ($prov -eq 'Microsoft-Windows-Kernel-Power') {
                        $code = Get-EventData $p 0; $sleep = Get-EventData $p 5; $longPress = Get-EventData $p 15
                        $codeText = $(if ($null -ne $code -and [int64]$code -ne 0) { 'bugcheck 0x{0:X}' -f [int64]$code } else { 'no bugcheck code (power loss, hard reset or hang)' })
                        $row = Get-IssueRow -Time $e.TimeCreated -Category 'KernelPower' -Name 'Kernel-Power 41' -Version $null -Module $codeText `
                                            -Detail (Join-Parts @($codeText, $(if ($null -ne $sleep -and [int64]$sleep -ne 0) { 'during sleep transition' }), $(if ($longPress -eq $true) { 'long power-button press detected' })))
                    }; break }
            }
            if ($row) { $rows.Add($row) }
        } catch { $skipped++ }
    }
    if ($skipped) { Add-Warning ('{0} event(s) had an unexpected layout and were skipped' -f $skipped) }
    $rows.ToArray()
} -Default @())
Write-Verbose ('Classified {0} issue row(s), {1} ms' -f $issues.Count, $sw.ElapsedMilliseconds)

# ---------------------------------------------------------------- Reliability Monitor (RAC) data
$stab = Invoke-Section 'Stability index' {
    $m = @(Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -Property SystemStabilityIndex, TimeGenerated -ErrorAction Stop)
    if ($m.Count -eq 0) { Add-Warning 'Reliability metrics not available (RacTask disabled?)'; $null }
    else { $m | Sort-Object TimeGenerated -Descending | Select-Object -First 1 }
}
if ($stab -and $stab.TimeGenerated -and (([DateTime]::Now - [datetime]$stab.TimeGenerated).TotalHours -gt 48)) {
    Add-Warning ('Stability index was last computed {0:yyyy-MM-dd HH:mm} (RacTask not running?)' -f [datetime]$stab.TimeGenerated)
}
Write-Verbose ('Stability metrics, {0} ms' -f $sw.ElapsedMilliseconds)

# Cross-check: what Reliability Monitor itself recorded in the same window, by source.
$rac = Invoke-Section 'Reliability records' {
    $dt = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($start)
    $recs = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dt'" -Property SourceName, TimeGenerated -ErrorAction Stop)
    $by = @($recs | Group-Object SourceName | Sort-Object Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
    [PSCustomObject]@{ Total = [int]$recs.Count; BySource = ($by -join '; ') }
}
Write-Verbose ('Reliability records, {0} ms' -f $sw.ElapsedMilliseconds)

# How far back each log actually reaches: a busy Application log often wraps well inside 30 days, which makes
# every count below a floor rather than a total.
$cov = Invoke-Section 'Log coverage' {
    $out = [ordered]@{}
    foreach ($ln in 'Application', 'System') {
        $old = $null
        try { $old = Get-WinEvent -LogName $ln -Oldest -MaxEvents 1 -ErrorAction Stop }
        catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $old = $null } else { throw } }
        $out[$ln] = $(if ($old) { [datetime]$old.TimeCreated } else { $null })
    }
    [PSCustomObject]$out
}
$coverageDays = $null
if ($cov) {
    $coverageDays = [double]$Days
    foreach ($ln in 'Application', 'System') {
        $oldest = $cov.$ln
        if ($null -ne $oldest -and $oldest -gt $start) {
            $d = ([DateTime]::Now - $oldest).TotalDays
            if ($d -lt $coverageDays) { $coverageDays = $d }
            Add-Warning ('{0} log only reaches back to {1:yyyy-MM-dd} ({2:N1} of {3} days); earlier events in the window are gone' -f $ln, $oldest, $d, $Days)
        }
    }
    $coverageDays = Round1 $coverageDays
}

# ---------------------------------------------------------------- totals, worst offenders, verdict
$counts = @{}
foreach ($r in $issues) { $counts[$r.Category] = 1 + [int]$counts[$r.Category] }
function Get-CategoryCount { param([string[]]$Categories, [bool]$Ok) if (-not $Ok) { return $null }; $n = 0; foreach ($c in $Categories) { $n += [int]$counts[$c] }; [int]$n }

$appCrashes  = Get-CategoryCount -Categories 'AppCrash' -Ok $appOk
$appHangs    = Get-CategoryCount -Categories 'AppHang' -Ok $appOk
$driverFails = Get-CategoryCount -Categories 'DriverLoadFailure' -Ok $sysOk
$serviceFail = Get-CategoryCount -Categories 'ServiceCrash', 'ServiceStartFailure', 'ServiceTimeout' -Ok $sysOk
$bugChecks   = Get-CategoryCount -Categories 'BugCheck' -Ok $sysOk
$kernelPower = Get-CategoryCount -Categories 'KernelPower' -Ok $sysOk
$werReports  = $(if ($werOk) { [int]$werData.Total } else { $null })

# WER reports are deliberately NOT in TotalIssues: every APPCRASH is already counted as an AppCrash, and a
# LiveKernelEvent loop would swamp the rate on its own.
$totalIssues = $null; $issuesPerDay = $null; $verdict = 'Unknown'
if ($appOk -and $sysOk) {
    $totalIssues  = [int]($appCrashes + $appHangs + $driverFails + $serviceFail + $bugChecks + $kernelPower)
    $issuesPerDay = Round1 ($totalIssues / $Days)
    $verdict = $(if ($issuesPerDay -le 0.2 -and $bugChecks -eq 0) { 'Healthy' } elseif ($issuesPerDay -le 1) { 'Watch' } else { 'Sick' })
}

$worstApp = Invoke-Section 'WorstApp' {
    $g = @($issues | Where-Object { $_.Category -in 'AppCrash', 'AppHang' } | Group-Object Name | Sort-Object Count -Descending | Select-Object -First 1)
    if ($g.Count) { '{0} ({1})' -f $g[0].Name, $g[0].Count } else { $null }
}
$worstModule = Invoke-Section 'WorstModule' {
    $g = @($issues | Where-Object { $_.Category -eq 'AppCrash' -and $_.Module } | Group-Object Module | Sort-Object Count -Descending | Select-Object -First 1)
    if ($g.Count) { '{0} ({1})' -f $g[0].Name, $g[0].Count } else { $null }
}

# ---------------------------------------------------------------- result (shape A)
$o = [ordered]@{
    ComputerName       = $env:COMPUTERNAME
    CollectedAt        = [DateTime]::Now
    Days               = [int]$Days
    StabilityIndex     = $(if ($stab) { Round1 $stab.SystemStabilityIndex } else { $null })
    StabilityIndexDate = $(if ($stab -and $stab.TimeGenerated) { [datetime]$stab.TimeGenerated } else { $null })
    AppCrashes         = $appCrashes
    AppHangs           = $appHangs
    DriverFailures     = $driverFails
    ServiceFailures    = $serviceFail
    BugChecks          = $bugChecks
    KernelPowerEvents  = $kernelPower
    WerReports         = $werReports
    TotalIssues        = $totalIssues
    IssuesPerDay       = $issuesPerDay
    WorstApp           = $worstApp
    WorstModule        = $worstModule
    Verdict            = $verdict
    LogCoverageDays    = $coverageDays
    RecordsTotal       = $(if ($rac) { [int]$rac.Total } else { $null })
    RecordsBySource    = $(if ($rac) { $rac.BySource } else { $null })
}

# Every distinct (Category, Name, Version, Module) with its count and first/last time, busiest first.
$o.ByApplication = @(Invoke-Section 'ByApplication' {
    $groups = @{}
    foreach ($r in $issues) {
        $key = '{0}|{1}|{2}|{3}' -f $r.Category, $r.Name, $r.Version, $r.Module
        if ($groups.ContainsKey($key)) {
            $g = $groups[$key]; $g.Count = [int]$g.Count + 1
            if ($r.Time -lt $g.FirstSeen) { $g.FirstSeen = $r.Time }
            if ($r.Time -gt $g.LastSeen)  { $g.LastSeen  = $r.Time }
        } else {
            $groups[$key] = [PSCustomObject]@{ Category = $r.Category; Name = $r.Name; Version = $r.Version; Module = $r.Module
                                               Count = [int]1; FirstSeen = [datetime]$r.Time; LastSeen = [datetime]$r.Time }
        }
    }
    $all = @($groups.Values) + $(if ($werOk) { @($werData.Rows) } else { @() })
    @($all | Sort-Object @{ e = 'Count'; Descending = $true }, @{ e = 'LastSeen'; Descending = $true }, Category, Name |
             Select-Object Category, Name, Version, Module, Count, FirstSeen, LastSeen)
} -Default @())

# Newest individual events. WER reports are excluded: they duplicate the crash events and would fill the list.
$o.RecentEvents = @(Invoke-Section 'RecentEvents' {
    @($issues | Sort-Object Time -Descending | Select-Object -First $RecentCount | ForEach-Object {
        [PSCustomObject]@{ Time = [datetime]$_.Time; Category = $_.Category; Name = $_.Name; Detail = $_.Detail }
    })
} -Default @())
Write-Verbose ('Done, {0} ms' -f $sw.ElapsedMilliseconds)

$o.Warnings = ($script:Warnings -join '; ')          # shape A only
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
