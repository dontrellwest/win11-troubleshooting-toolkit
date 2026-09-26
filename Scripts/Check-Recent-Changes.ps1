<#
.SYNOPSIS
    Everything that changed on this machine in the last N days: Windows updates, drivers, programs.
.DESCRIPTION
    One row per change, newest first. Reads the Windows Update history (COM), Get-HotFix and the
    WindowsUpdateClient events, driver installs from the UserPnp events, program installs/updates/
    removals from the MsiInstaller events and the Uninstall registry keys (HKLM plus every loaded
    user hive), and in-place feature updates. The first thing to check when "it worked last week".
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER Days
    How many days back to look. Default 14.
.PARAMETER IncludeStoreApps
    Also list Microsoft Store (Appx) packages whose folder changed inside the window. Off by default: noisy.
.EXAMPLE
    .\Check-Recent-Changes.ps1
.EXAMPLE
    .\Check-Recent-Changes.ps1 -Days 30 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Check-Recent-Changes.ps1 | Where-Object Type -ne 'Defender update' | Format-Table Date,Type,Name,Version,Result
.NOTES
    Toolkit-Class:     ReadOnly
    Toolkit-Context:   Machine
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [ValidateRange(1, 3650)][int]$Days = 14,
    [switch]$IncludeStoreApps
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-Recent-Changes'          # <-- set per tool
$script:Warnings  = New-Object System.Collections.Generic.List[string]
$script:Findings  = New-Object System.Collections.Generic.List[object]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

# '1 crash' / '3 crashes': a count with the singular or plural noun, for summary text.
function Format-Count { param([int]$Count, [string]$One, [string]$Many) if ($Count -eq 1) { '1 ' + $One } else { '{0} {1}' -f $Count, $Many } }

# Plain-language summary line for -Display. Level: Problem | Warning | NotChecked | Info | OK. Next: what to do about it.
function Add-Finding {
    param([ValidateSet('Problem', 'Warning', 'NotChecked', 'Info', 'OK')][string]$Level, [string]$Text, [string]$Next)
    $script:Findings.Add([PSCustomObject]@{ Level = $Level; Text = $Text; Next = $Next })
}

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

# Readable report for -Display. With -About/-Findings/-NextSteps/-Result a plain-language SUMMARY comes first
# (result line, then findings ranked by severity, each with its next step) and the RESULT is repeated at the end.
# DETAILS: scalars as a list, array properties as tables (never silently dropping columns).
function Show-Result {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Title, [string]$ReportPath,
          [string]$About, [object[]]$Findings, [string[]]$NextSteps, [string]$Result)
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
        # Word-wraps summary text at 78 columns: the first line starts with $Lead, later lines align under it.
        $wrap = {
            param([string]$Text, [string]$Lead)
            $pad = ' ' * $Lead.Length; $line = $Lead; $has = $false
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($word in @(('{0}' -f $Text).Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)') -split '\s+' | Where-Object { $_ })) {
                if ($has -and ($line.Length + 1 + $word.Length) -gt 78) { $out.Add($line); $line = $pad; $has = $false }
                if ($has) { $line += ' ' + $word } else { $line += $word; $has = $true }
            }
            if ($has) { $out.Add($line) }
            $out.ToArray()
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine(('  {0}   {1}   {2}' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')))
        [void]$sb.AppendLine(('=' * 78))
        $found = @($Findings | Where-Object { $null -ne $_ })
        $summary = [bool]($About -or $found.Count -or $NextSteps -or $Result)
        if ($summary) {
            if ($About) { foreach ($l in (& $wrap $About '  ')) { [void]$sb.AppendLine($l) }; [void]$sb.AppendLine('') }
            $rank  = @{ Problem = 0; Warning = 1; NotChecked = 2; Info = 3; OK = 4 }
            $label = @{ Problem = 'PROBLEM'; Warning = 'WARNING'; NotChecked = 'NOT CHECKED'; Info = 'INFO'; OK = 'OK' }
            $n = @{}; foreach ($k in @($rank.Keys)) { $n[$k] = @($found | Where-Object { [string]$_.Level -eq $k }).Count }
            $counts = @()
            if ($n.Problem)    { $counts += $(if ($n.Problem -eq 1) { '1 problem' } else { '{0} problems' -f $n.Problem }) }
            if ($n.Warning)    { $counts += $(if ($n.Warning -eq 1) { '1 warning' } else { '{0} warnings' -f $n.Warning }) }
            if ($n.NotChecked) { $counts += $(if ($n.NotChecked -eq 1) { '1 item not checked' } else { '{0} items not checked' -f $n.NotChecked }) }
            if (-not $Result) {
                if ($n.Problem)        { $Result = 'ACTION NEEDED - {0}.' -f ($counts -join ', ') }
                elseif ($n.Warning)    { $Result = 'REVIEW - {0}. No problems found.' -f ($counts -join ', ') }
                elseif ($n.NotChecked) { $Result = 'INCOMPLETE - {0}. Nothing else needs attention.' -f ($counts -join ', ') }
                else                   { $Result = 'NO PROBLEMS FOUND by this check.' }
            }
            [void]$sb.AppendLine('SUMMARY'); [void]$sb.AppendLine('-------')
            foreach ($l in (& $wrap $Result '  RESULT: ')) { [void]$sb.AppendLine($l) }
            $ranked = New-Object System.Collections.Generic.List[object]
            for ($k = 0; $k -lt $found.Count; $k++) {
                $lv = [string]$found[$k].Level; $r = 3; if ($rank.ContainsKey($lv)) { $r = $rank[$lv] }
                $ranked.Add([PSCustomObject]@{ Rank = $r; Index = $k; Finding = $found[$k] })
            }
            if ($ranked.Count) { [void]$sb.AppendLine('') }
            foreach ($e in @($ranked | Sort-Object Rank, Index)) {
                $lv = [string]$e.Finding.Level; $tag = $lv.ToUpper(); if ($label.ContainsKey($lv)) { $tag = $label[$lv] }
                foreach ($l in (& $wrap $e.Finding.Text ('  ' + $tag.PadRight(13)))) { [void]$sb.AppendLine($l) }
                if ($e.Finding.Next) { foreach ($l in (& $wrap $e.Finding.Next ((' ' * 15) + 'Next: '))) { [void]$sb.AppendLine($l) } }
            }
            if ($NextSteps) {
                [void]$sb.AppendLine(''); [void]$sb.AppendLine('NEXT STEPS'); [void]$sb.AppendLine('----------')
                foreach ($s in $NextSteps) { if ($s) { foreach ($l in (& $wrap $s '  - ')) { [void]$sb.AppendLine($l) } } }
            }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('DETAILS'); [void]$sb.AppendLine('-------')
        }
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
        if ($summary) {
            [void]$sb.AppendLine(('-' * 78))
            foreach ($l in (& $wrap ($Result + ' The summary and next steps are at the top of this report.') '  RESULT: ')) { [void]$sb.AppendLine($l) }
        }
        # Registered, trademark and copyright signs (from device and product names) and invisible direction marks, as ASCII.
        $text = $sb.ToString().Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)').Replace([string][char]0x200E, '').Replace([string][char]0x200F, '')
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
$script:CollectedAt  = [DateTime]::Now
$script:Cutoff       = $script:CollectedAt.AddDays(-$Days)
$script:StoreService = '855e8a7c-ecb4-4ca3-b045-1dfa50104289'   # Microsoft Store service id in the WU history and in event 19/20
$script:AccountCache = @{}
$script:BadDates     = 0

# Every row has exactly these ten properties, in this order (shape B).
function ConvertTo-ChangeRow {
    param([datetime]$Date, [string]$Type, [string]$Name, $Version, $Publisher, [string]$Result, [string]$Source, [string]$Detail)
    if ($Detail.Length -gt 160) { $Detail = $Detail.Substring(0, 157) + '...' }
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectedAt  = $script:CollectedAt
        Date         = $Date
        Type         = $Type
        Name         = $Name
        Version      = $(if ("$Version".Trim()) { "$Version".Trim() } else { $null })
        Publisher    = $(if ("$Publisher".Trim()) { "$Publisher".Trim() } else { $null })
        Result       = $Result
        Source       = $Source
        Detail       = $Detail
    }
}

# Get-WinEvent pattern from the conventions: no match is empty, a missing log still throws.
function Get-EventList {
    param([hashtable]$Filter)
    try { @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
}

# SID -> DOMAIN\user (cached; falls back to the SID text).
function ConvertTo-AccountName {
    param($Sid)
    if ($null -eq $Sid) { return 'unknown' }
    $s = "$Sid"
    if (-not $s) { return 'unknown' }
    if (-not $script:AccountCache.ContainsKey($s)) {
        $n = $s
        try { $n = (New-Object System.Security.Principal.SecurityIdentifier $s).Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $script:AccountCache[$s] = $n
    }
    $script:AccountCache[$s]
}

# Classifies a Windows Update history / event title. Categories are usually EMPTY on Windows 11
# (verified on the target machine), so the title patterns below do the real work. Shapes seen live:
#   'Intel Corporation Display Driver Update (32.0.101.8826)'     publisher + device class + version
#   'Intel Driver Update (9.1.10001.173)'                         publisher + version only
#   'AVerMedia - Extension - 4.0.39.0'                            publisher - class - version
#   'ViewSonic - Monitor - 2/19/2013 12:00:00 AM - 1.5.0.0'       publisher - class - date - version
#   '9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2'                  Store product id - package name
function Resolve-UpdateTitle {
    param([string]$Title, [string[]]$Categories = @(), [string]$ServiceId = '')
    $type = 'Windows Update'; $name = $Title; $ver = $null; $pub = 'Microsoft'
    if ($ServiceId -eq $script:StoreService -or $Title -match '^[0-9A-Z]{12}-\S') {
        $type = 'Store app'; $pub = $null
        if ($Title -match '^[0-9A-Z]{12}-(.+)$') { $name = $Matches[1] }
    }
    elseif ($Title -match 'Security Intelligence|Defender Antivirus|Antimalware Platform|Windows Security platform') {
        $type = 'Defender update'
    }
    elseif (($Categories -contains 'Upgrades') -or $Title -match '^(Feature update to|Windows 1[01], version)') {
        $type = 'Feature update'
    }
    elseif (($Categories -contains 'Drivers') -or $Title -match '\bDriver Update\b|^.+ - .+ - (\d+(\.\d+)+)$') {
        $type = 'Driver'; $pub = $null
        if ($Title -match '^(.+?)(?:\s+\S+)?\s+Driver Update\s+\((\d+(?:\.\d+)+)\)$') { $pub = $Matches[1]; $ver = $Matches[2] }
        elseif ($Title -match '^(.+?) - .+? - (?:.+ - )?(\d+(?:\.\d+)+)$') { $pub = $Matches[1]; $ver = $Matches[2] }
    }
    if (-not $ver) {
        if ($Title -match '\(Version ([\d.]+)\)') { $ver = $Matches[1] }
        elseif ($Title -match '\((\d{5}\.\d+)\)') { $ver = $Matches[1] }
    }
    [PSCustomObject]@{ Type = $type; Name = $name; Version = $ver; Publisher = $pub }
}

function ConvertTo-WuResult {
    param([int]$Code, [int]$HResult = 0)
    $s = switch ($Code) {
        0 { 'Not started' } 1 { 'In progress' } 2 { 'Succeeded' } 3 { 'Succeeded with errors' }
        4 { 'Failed' } 5 { 'Aborted' } default { 'Unknown ({0})' -f $Code }
    }
    if ($Code -in 3, 4, 5 -and $HResult -ne 0) { $s += (' (0x{0:X8})' -f $HResult) }
    $s
}

function ConvertTo-MsiResult {
    param([string]$Status)
    switch ($Status) {
        '0'    { 'Succeeded' }
        '3010' { 'Succeeded (reboot required)' }
        '1641' { 'Succeeded (reboot initiated)' }
        '1602' { 'Cancelled by user (1602)' }
        '1603' { 'Failed (1603 fatal error)' }
        default { if ($Status -match '^\d+$') { 'Failed ({0})' -f $Status } else { 'Unknown' } }
    }
}

# InstallDate as written in an Uninstall key. Always 'yyyyMMdd' on a healthy machine; other shapes are tolerated.
function ConvertFrom-InstallDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($s -match '^\d{8}$') { try { return [DateTime]::ParseExact($s, 'yyyyMMdd', $inv) } catch { return $null } }
    if ($s -match '^\d{9,10}$') { try { return [DateTimeOffset]::FromUnixTimeSeconds([int64]$s).LocalDateTime } catch { return $null } }
    foreach ($fmt in 'yyyy-MM-dd', 'yyyy/MM/dd', 'yyyyMMddHHmmss', 'MM/dd/yyyy', 'dd/MM/yyyy') {
        try { return [DateTime]::ParseExact($s, $fmt, $inv) } catch { }
    }
    try { return [DateTime]::Parse($s, $inv) } catch { }
    $null
}

# Name|Version|day key used to merge the registry view with the installer events.
function Get-MergeKey {
    param($Name, $Version, [datetime]$Date)
    '{0}|{1}|{2:yyyyMMdd}' -f "$Name".Trim().ToLower(), "$Version".Trim().ToLower(), $Date
}

# Reads one Uninstall key tree into $script:RegRows. Access denied propagates to the caller.
function Read-UninstallKeys {
    param([Microsoft.Win32.RegistryKey]$Base, [string]$SubPath, [string]$Label, [string]$Owner)
    $key = $Base.OpenSubKey($SubPath)
    if (-not $key) { return }
    try {
        foreach ($n in $key.GetSubKeyNames()) {
            $sub = $null
            try { $sub = $key.OpenSubKey($n) } catch { continue }
            if (-not $sub) { continue }
            try {
                $name = "$($sub.GetValue('DisplayName'))".Trim()
                if (-not $name) { continue }
                $raw  = $sub.GetValue('InstallDate')
                $date = ConvertFrom-InstallDate $raw
                if ($null -eq $date) { if ($null -ne $raw -and "$raw".Trim()) { $script:BadDates++ }; continue }
                if ($date -lt $script:Cutoff.Date) { continue }
                $detail = '{0}\{1}' -f $Label, $n
                if ($Owner) { $detail = 'per-user ({0}); {1}' -f $Owner, $detail }
                if ("$($sub.GetValue('SystemComponent'))" -eq '1') { $detail += '; hidden from Apps list' }
                $script:RegRows.Add((ConvertTo-ChangeRow -Date $date -Type 'Program installed' -Name $name `
                    -Version $sub.GetValue('DisplayVersion') -Publisher $sub.GetValue('Publisher') `
                    -Result 'Present' -Source 'Registry' -Detail $detail))
            } finally { $sub.Close() }
        }
    } finally { $key.Close() }
}

# ---------------------------------------------------------------- collection
$rows    = New-Object System.Collections.Generic.List[object]
$isAdmin = Test-IsAdmin
Write-Verbose ('Window: {0:yyyy-MM-dd HH:mm} to now ({1} days); elevated={2}' -f $script:Cutoff, $Days, $isAdmin)
if (-not $isAdmin) {
    Add-Warning ('Not elevated (running as {0}): per-user installs in another signed-in user''s registry hive are unreadable, and -IncludeStoreApps can only list this account''s packages.' -f [Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

# --- Windows Update history (COM). Dates arrive as UTC with Kind=Unspecified: convert explicitly.
Write-Progress -Activity $script:ToolName -Status 'Windows Update history (COM)'
$comRows = @(Invoke-Section 'Windows Update history' {
    $out = New-Object System.Collections.Generic.List[object]
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $total = [int]$searcher.GetTotalHistoryCount()
    if ($total -gt 0) {
        foreach ($e in $searcher.QueryHistory(0, $total)) {
            $date = [DateTime]::SpecifyKind([datetime]$e.Date, [DateTimeKind]::Utc).ToLocalTime()
            if ($date -lt $script:Cutoff) { continue }
            $cats = @(); try { $cats = @($e.Categories | ForEach-Object { "$($_.Name)" }) } catch { }
            $cls = Resolve-UpdateTitle -Title "$($e.Title)" -Categories $cats -ServiceId "$($e.ServiceID)"
            $op  = if ([int]$e.Operation -eq 2) { 'Uninstalled' } else { 'Installed' }
            $out.Add((ConvertTo-ChangeRow -Date $date -Type $cls.Type -Name $cls.Name -Version $cls.Version `
                -Publisher $cls.Publisher -Result (ConvertTo-WuResult -Code ([int]$e.ResultCode) -HResult ([int]$e.HResult)) `
                -Source 'Windows Update history' -Detail ('{0}; requested by {1}' -f $op, $e.ClientApplicationID)))
        }
    }
    $out.ToArray()
} -Default @())
$seen = @{}
foreach ($r in $comRows) {
    # A Store install logs the same title 2-3 times within a second; keep one per name/result/day.
    if ($r.Type -eq 'Store app') {
        $k = Get-MergeKey $r.Name $r.Result $r.Date
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
    }
    $rows.Add($r)
}

# --- WindowsUpdateClient events 19 (installed) / 20 (failed). On Win11 25H2 these land in the System log;
#     the Operational channel is read too so the tool still works where they are routed there. Verified
#     layouts: 19 = [0] title [1] update guid [2] revision [3] service guid;
#              20 = [0] error code (Int32) [1] title [2] update guid [3] revision [4] service guid.
Write-Progress -Activity $script:ToolName -Status 'Windows Update events'
$wuEvents = @()
foreach ($log in 'System', 'Microsoft-Windows-WindowsUpdateClient/Operational') {
    $wuEvents += @(Invoke-Section ('Windows Update events ({0})' -f $log) {
        Get-EventList @{ LogName = $log; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 19, 20; StartTime = $script:Cutoff }
    } -Default @())
}
$seenEv = @{}
$badWu  = 0
foreach ($e in @($wuEvents | Sort-Object TimeCreated -Descending)) {
    $p = $e.Properties
    if ([int]$e.Id -eq 19) {
        if ($p.Count -lt 4) { $badWu++; continue }
        $title = "$($p[0].Value)"; $svc = "$($p[3].Value)"; $result = 'Succeeded'
    } else {
        if ($p.Count -lt 5) { $badWu++; continue }
        $title = "$($p[1].Value)"; $svc = "$($p[4].Value)"; $result = 'Failed (0x{0:X8})' -f $p[0].Value
    }
    $k = '{0}|{1}|{2:yyyyMMddHHmmss}' -f $e.Id, $title, $e.TimeCreated
    if ($seenEv.ContainsKey($k)) { continue }
    $seenEv[$k] = $true
    $cls = Resolve-UpdateTitle -Title $title -ServiceId $svc
    $t = $e.TimeCreated
    $dup = $rows | Where-Object { $_.Source -eq 'Windows Update history' -and $_.Name -eq $cls.Name -and [math]::Abs(($_.Date - $t).TotalMinutes) -le 2 } | Select-Object -First 1
    if ($dup) { continue }
    $rows.Add((ConvertTo-ChangeRow -Date $t -Type $cls.Type -Name $cls.Name -Version $cls.Version -Publisher $cls.Publisher `
        -Result $result -Source 'WindowsUpdateClient event' -Detail ('Event {0}; not present in the Windows Update history list' -f $e.Id)))
}
if ($badWu) { Add-Warning ('Windows Update events: {0} event(s) had an unexpected property layout and were skipped' -f $badWu) }

# --- Get-HotFix: date only (no time), deduped by KB number against everything above.
Write-Progress -Activity $script:ToolName -Status 'Installed hotfixes'
$hotfixes = @(Invoke-Section 'Get-HotFix' { @(Get-HotFix -ErrorAction Stop) } -Default @())
foreach ($h in $hotfixes) {
    if (-not $h.InstalledOn) { continue }
    $when = [datetime]$h.InstalledOn
    if ($when -lt $script:Cutoff.Date) { continue }
    $kb = "$($h.HotFixID)"
    if ($kb -match 'KB\d+') {
        $pat = '\b' + [regex]::Escape($Matches[0]) + '\b'
        if ($rows | Where-Object { $_.Name -match $pat } | Select-Object -First 1) { continue }
    }
    $rows.Add((ConvertTo-ChangeRow -Date $when -Type 'Windows Update' -Name ('{0} ({1})' -f $kb, $h.Description) `
        -Version $null -Publisher 'Microsoft' -Result 'Succeeded' -Source 'Get-HotFix' `
        -Detail ('Installed by {0}; date only, no time of day' -f $h.InstalledBy)))
}

# --- Drivers: UserPnp 20001 / 20003. Indices below come from the provider manifest on this build
#     (Get-WinEvent -ListProvider Microsoft-Windows-UserPnp).
#     20001: [0] DriverName [1] DriverVersion [2] DriverProvider [3] DeviceInstanceID [4] SetupClass
#            [5] RebootOption [6] UpgradeDevice [7] IsDriverOEM [8] InstallStatus [9] DriverDescription
#     20003: [0] ServiceName [1] DriverFileName [2] DeviceInstanceID [3] PrimaryService [4] UpdateService [5] AddServiceStatus
Write-Progress -Activity $script:ToolName -Status 'Driver events'
$pnp = @(Invoke-Section 'Driver events' {
    Get-EventList @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-UserPnp'; Id = 20001, 20003; StartTime = $script:Cutoff }
} -Default @())
$badPnp = 0
foreach ($e in $pnp) {
    $p = $e.Properties
    if ([int]$e.Id -eq 20001 -and $p.Count -ge 10) {
        $name = "$($p[9].Value)".Trim(); if (-not $name) { $name = "$($p[0].Value)" }
        $mode = if ("$($p[6].Value)" -eq 'True') { 'replaced the previous driver' } else { 'first install for this device' }
        $oem  = if ("$($p[7].Value)" -eq 'True') { 'third-party' } else { 'inbox' }
        $st   = $p[8].Value
        $res  = if ("$st" -eq '0') { 'Succeeded' } else { 'Failed (0x{0:X8})' -f $st }
        $rows.Add((ConvertTo-ChangeRow -Date $e.TimeCreated -Type 'Driver' -Name $name -Version $p[1].Value -Publisher $p[2].Value `
            -Result $res -Source 'UserPnp event 20001' -Detail ('{0}; {1}; {2} driver; {3}' -f $p[0].Value, $mode, $oem, $p[3].Value)))
    } elseif ([int]$e.Id -eq 20003 -and $p.Count -ge 6) {
        $leaf = "$($p[1].Value)"; try { $leaf = [System.IO.Path]::GetFileName($leaf) } catch { }
        $mode = if ("$($p[4].Value)" -eq 'True') { 'driver service updated' } else { 'driver service attached to a device' }
        $st   = $p[5].Value
        $res  = if ("$st" -eq '0') { 'Succeeded' } else { 'Failed ({0})' -f $st }
        $rows.Add((ConvertTo-ChangeRow -Date $e.TimeCreated -Type 'Driver' -Name ('{0} ({1})' -f $p[0].Value, $leaf) `
            -Version $null -Publisher $null -Result $res -Source 'UserPnp event 20003' -Detail ('{0}; {1}' -f $mode, $p[2].Value)))
    } else { $badPnp++ }
}
if ($badPnp) { Add-Warning ('Driver events: {0} event(s) had an unexpected property layout and were skipped' -f $badPnp) }

# --- Programs: MsiInstaller events. Verified layouts on this build:
#     1033 install / 1034 removal: [0] name [1] version [2] language [3] status [4] manufacturer
#     1036 product update:         [0] name [1] version [2] language [3] update name [4] status [5] manufacturer
#     11707/11708/11724 carry only the message text and are used when no structured event matches.
#     1035/11728 (reconfigure / repair) are deliberately ignored: they duplicate 1036 and fire on every repair.
Write-Progress -Activity $script:ToolName -Status 'Windows Installer events'
$msi = @(Invoke-Section 'MsiInstaller events' {
    Get-EventList @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033, 1034, 1036, 11707, 11708, 11724; StartTime = $script:Cutoff }
} -Default @())
$msiRows = New-Object System.Collections.Generic.List[object]
$badMsi  = 0
foreach ($e in @($msi | Where-Object { [int]$_.Id -in 1033, 1034, 1036 })) {
    $p = $e.Properties
    if ($p.Count -lt 5) { $badMsi++; continue }
    $who = ConvertTo-AccountName $e.UserId
    $type = $null; $status = $null; $pub = $null; $extra = ''
    switch ([int]$e.Id) {
        1033 { $type = 'Program installed'; $status = "$($p[3].Value)"; $pub = "$($p[4].Value)" }
        1034 { $type = 'Program removed';   $status = "$($p[3].Value)"; $pub = "$($p[4].Value)" }
        1036 { $type = 'Program updated';   $status = "$($p[4].Value)"; $pub = $(if ($p.Count -ge 6) { "$($p[5].Value)" } else { $null }); $extra = 'patch "{0}"; ' -f $p[3].Value }
    }
    $msiRows.Add((ConvertTo-ChangeRow -Date $e.TimeCreated -Type $type -Name "$($p[0].Value)" -Version $p[1].Value -Publisher $pub `
        -Result (ConvertTo-MsiResult $status) -Source 'MsiInstaller' -Detail ('{0}event {1}; run by {2}' -f $extra, $e.Id, $who)))
}
foreach ($e in @($msi | Where-Object { [int]$_.Id -in 11707, 11708, 11724 })) {
    $msg = $(if ($e.Properties.Count -ge 1) { "$($e.Properties[0].Value)" } else { '' })
    if ($msg -notmatch '^[^:]+:\s*(.+?)\s+--\s+(.+?)\s*$') { $badMsi++; continue }
    $name = $Matches[1]; $text = $Matches[2]
    $t = $e.TimeCreated
    if ($msiRows | Where-Object { $_.Name -eq $name -and [math]::Abs(($_.Date - $t).TotalMinutes) -le 2 } | Select-Object -First 1) { continue }
    $type   = if ([int]$e.Id -eq 11724) { 'Program removed' } else { 'Program installed' }
    $result = if ([int]$e.Id -eq 11708) { 'Failed' } else { 'Succeeded' }
    $msiRows.Add((ConvertTo-ChangeRow -Date $t -Type $type -Name $name -Version $null -Publisher $null -Result $result `
        -Source 'MsiInstaller' -Detail ('{0}; event {1}; run by {2}' -f $text, $e.Id, (ConvertTo-AccountName $e.UserId))))
}
if ($badMsi) { Add-Warning ('MsiInstaller events: {0} event(s) had an unexpected layout and were skipped' -f $badMsi) }

# --- Programs: Uninstall registry keys (HKLM 64-bit + 32-bit, and every loaded S-1-5-21-* user hive).
Write-Progress -Activity $script:ToolName -Status 'Uninstall registry keys'
$script:RegRows = New-Object System.Collections.Generic.List[object]
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
    [void](Invoke-Section 'Uninstall keys (HKLM 64-bit)' {
        Read-UninstallKeys -Base $hklm -SubPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -Label 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' })
    [void](Invoke-Section 'Uninstall keys (HKLM 32-bit)' {
        Read-UninstallKeys -Base $hklm -SubPath 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Label 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' })

    $users = [Microsoft.Win32.Registry]::Users
    $sids = @(Invoke-Section 'Loaded user hives' { @($users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }) } -Default @())
    $denied = @()
    foreach ($sid in $sids) {
        $owner = ConvertTo-AccountName $sid
        try {
            Read-UninstallKeys -Base $users -SubPath ($sid + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') `
                -Label ('HKU:\{0}\...\Uninstall' -f $sid) -Owner $owner
        } catch {
            $inner = $_.Exception.InnerException
            if ($_.Exception -is [System.Security.SecurityException] -or $inner -is [System.Security.SecurityException] -or
                $inner -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'not allowed|Access is denied') { $denied += $owner }
            else { Add-Warning ('Uninstall keys of {0}: {1}' -f $owner, $_.Exception.Message.Trim()) }
        }
    }
    if ($denied.Count) { Add-Warning ('Per-user installs of {0}: (needs admin)' -f (($denied | Sort-Object -Unique) -join ', ')) }

    # --- Feature updates: HKLM:\SYSTEM\Setup\'Source OS (Updated on <date>)' describes the build that was replaced.
    Write-Progress -Activity $script:ToolName -Status 'Feature update history'
    $nowBuild = Invoke-Section 'Current build' {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        '{0} build {1}.{2}' -f $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR
    } -Default 'unknown build'
    $featRows = @(Invoke-Section 'Feature update history' {
        $out = New-Object System.Collections.Generic.List[object]
        $setup = $hklm.OpenSubKey('SYSTEM\Setup')
        if ($setup) {
            try {
                foreach ($n in @($setup.GetSubKeyNames() | Where-Object { $_ -like 'Source OS*' })) {
                    $k = $setup.OpenSubKey($n); if (-not $k) { continue }
                    try {
                        $date = $null; $raw = $k.GetValue('InstallDate')
                        if ($null -ne $raw) { try { $date = [DateTimeOffset]::FromUnixTimeSeconds([int64]$raw -band 0xFFFFFFFFL).LocalDateTime } catch { } }
                        if ($null -eq $date -and $n -match '\(Updated on (.+)\)') { try { $date = [DateTime]::Parse($Matches[1]) } catch { } }
                        if ($null -eq $date -or $date -lt $script:Cutoff) { continue }
                        $prev = ('{0} {1}' -f $k.GetValue('ProductName'), $k.GetValue('DisplayVersion')).Trim()
                        $out.Add((ConvertTo-ChangeRow -Date $date -Type 'Feature update' -Name ('Upgraded from {0}' -f $prev) `
                            -Version ('{0}.{1}' -f $k.GetValue('CurrentBuild'), $k.GetValue('UBR')).Trim('.') -Publisher 'Microsoft' `
                            -Result 'Succeeded' -Source 'Registry (Source OS)' `
                            -Detail ('now {0}; previous BuildLabEx {1}' -f $nowBuild, $k.GetValue('BuildLabEx'))))
                    } finally { $k.Close() }
                }
            } finally { $setup.Close() }
        }
        $out.ToArray()
    } -Default @())
    foreach ($f in $featRows) { $rows.Add($f) }
} finally { $hklm.Close() }

# Merge: same Name + Version + day as an installer event -> keep the event row, name both sources.
$msiKeys = @{}
foreach ($m in $msiRows) { $msiKeys[(Get-MergeKey $m.Name $m.Version $m.Date)] = $m }
foreach ($r in $script:RegRows) {
    $ev = $msiKeys[(Get-MergeKey $r.Name $r.Version $r.Date)]
    if ($ev) { if ($ev.Source -notmatch 'Registry') { $ev.Source = $ev.Source + '; Registry' }; continue }
    $rows.Add($r)
}
foreach ($m in $msiRows) { $rows.Add($m) }
if ($script:BadDates) { Add-Warning ('Uninstall keys: {0} entr(y/ies) had an InstallDate that could not be read and were skipped' -f $script:BadDates) }

# --- Store apps (opt-in): the package folder's last-write time is the only per-machine install date available.
if ($IncludeStoreApps) {
    Write-Progress -Activity $script:ToolName -Status 'Store apps'
    $pkgs = @(Invoke-Section 'Store apps' {
        if ($isAdmin) { @(Get-AppxPackage -AllUsers -ErrorAction Stop) } else { @(Get-AppxPackage -ErrorAction Stop) }
    } -Default @())
    $appxRows = New-Object System.Collections.Generic.List[object]
    $seenPkg = @{}; $skipped = 0
    foreach ($pkg in $pkgs) {
        $loc = "$($pkg.InstallLocation)"
        if (-not $loc) { $skipped++; continue }
        $d = $null
        try { if ([System.IO.Directory]::Exists($loc)) { $d = [System.IO.Directory]::GetLastWriteTime($loc) } } catch { }
        if ($null -eq $d) { $skipped++; continue }
        if ($d -lt $script:Cutoff) { continue }
        $k = Get-MergeKey $pkg.Name $pkg.Version $d
        if ($seenPkg.ContainsKey($k)) { continue }
        $seenPkg[$k] = $true
        $pub = $null; if ("$($pkg.Publisher)" -match '(?:^|,\s*)CN=("[^"]+"|[^,]+)') { $pub = $Matches[1].Trim('"') }
        $detail = 'date = package folder last write; signature {0}' -f $pkg.SignatureKind
        if ($pkg.IsFramework) { $detail += '; framework package' }
        $appxRows.Add((ConvertTo-ChangeRow -Date $d -Type 'Store app' -Name "$($pkg.Name)" -Version $pkg.Version -Publisher $pub `
            -Result 'Present' -Source 'Appx' -Detail $detail))
    }
    if ($skipped) { Add-Warning ('Store apps: {0} package(s) had no readable install folder and were skipped' -f $skipped) }
    $merged = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if ($r.Type -eq 'Store app') {
            $match = $appxRows | Where-Object { $_.Name -eq $r.Name -and $_.Date.Date -eq $r.Date.Date } | Select-Object -First 1
            if ($match) { if ($match.Source -notmatch 'Windows Update history') { $match.Source = $match.Source + '; Windows Update history' }; continue }
        }
        $merged.Add($r)
    }
    foreach ($a in $appxRows) { $merged.Add($a) }
    $rows = $merged
} else {
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) { if ($r.Type -ne 'Store app') { $kept.Add($r) } }
    $rows = $kept
}
Write-Progress -Activity $script:ToolName -Completed

# ---------------------------------------------------------------- output (shape B: rows only)
$result = @($rows | Sort-Object -Property @{ Expression = { $_.Date }; Descending = $true },
                                          @{ Expression = { $_.Type } },
                                          @{ Expression = { $_.Name } })
# With -Display the warnings appear in SUMMARY instead of as loose lines above the report.
if (-not $Display) { foreach ($w in $script:Warnings) { Write-Warning $w } }

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = ('Everything that changed on this PC in the last {0} days: Windows and driver updates, program installs, updates and removals, and Windows upgrades. Use it when something "worked last week".' -f $Days)
$script:SummaryNext = @(
    'Ask the user when the problem started. Changes on or just before that date are the likely cause.',
    'Driver: roll it back in Device Manager (device > Properties > Driver > Roll Back Driver).',
    'Windows update: Settings > Windows Update > Update history > Uninstall updates, with the site''s approval.',
    'Program: repair it from Settings > Apps > Installed apps (Modify, or Advanced options > Repair), or uninstall it if it is not needed.',
    'To look further back, from PowerShell in the Scripts folder: .\Check-Recent-Changes.ps1 -Days 30 -Display'
)
# Driver titles from Windows Update read "Maker - Class - 4/22/2009 12:00:00 AM - 1.2.3"; the date is the driver's
# nominal date, not an install time, and the version is shown separately.
function Get-DriverLabel {
    param($Row)
    $n = [string]$Row.Name
    if ($n -match '^(.+?) - (.+?) - \d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}\s*[AP]M - (.+)$') { return ('{0} {1} driver {2}' -f $Matches[1], $Matches[2], $Matches[3]) }
    if ($n -match '^(.+?) - (.+?) - ([\d.]+)$') { return ('{0} {1} driver {2}' -f $Matches[1], $Matches[2], $Matches[3]) }
    $n
}
# Short summary names: long update titles trimmed, version added once.
function Get-ShortName {
    param($Row)
    $n = [string]$Row.Name; $v = [string]$Row.Version
    switch ($Row.Type) {
        'Defender update' { if ($n -match 'antimalware platform') { return 'Defender platform ' + $v }; return 'Defender definitions ' + $v }
        'Driver' { return (Get-DriverLabel $Row) }
        'Windows Update' { return ($n -replace '\s*\(\d+\.\d+\)$', '') }
    }
    if ($v -and $n.IndexOf($v, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return ('{0} {1}' -f $n, $v) }
    $n
}
function Add-SummaryFindings {
    param($Rows)
    $Rows = @($Rows)
    $when = { param($r) '{0:yyyy-MM-dd}' -f $r.Date }
    $names = { param($list, [int]$Max = 3) (@($list | Select-Object -First $Max | ForEach-Object { '{0} ({1})' -f (Get-ShortName $_), (& $when $_) }) -join '; ') + $(if (@($list).Count -gt $Max) { '; and {0} more' -f (@($list).Count - $Max) } else { '' }) }
    if (-not $Rows.Count) { Add-Finding OK ('No updates, drivers or program changes were found in the last {0} days.' -f $Days) 'If the problem started recently, the cause is probably not an install; run Windows - Check Crashes and Restarts.' }
    # A failure is settled when the same item (same name and version) installed successfully afterwards.
    $failed = @($Rows | Where-Object { [string]$_.Result -like 'Failed*' })
    $retried = @($failed | Where-Object { $f = $_; @($Rows | Where-Object { [string]$_.Result -eq 'Succeeded' -and $_.Name -eq $f.Name -and [string]$_.Version -eq [string]$f.Version -and $_.Date -gt $f.Date }).Count })
    $open = @($failed | Where-Object { $_ -notin $retried })
    if ($open.Count) { Add-Finding Warning ('{0}: {1}' -f (Format-Count $open.Count 'change failed' 'changes failed'), (& $names $open)) 'Failed updates: run Windows - Check Updates. Failed program installs: retry the install and read its error.' }
    if ($retried.Count) { Add-Finding Info ('{0}, then installed on retry: {1}. No action needed.' -f (Format-Count $retried.Count 'change failed' 'changes failed'), (& $names $retried)) }
    $feature = @($Rows | Where-Object { $_.Type -eq 'Feature update' })
    if ($feature.Count) { Add-Finding Warning ('Windows was upgraded: {0}.' -f (& $names $feature)) 'If the problem started after this date, the upgrade is a likely cause: check drivers and programs for updated versions.' }
    # WUDFWpdFs is installed each time a phone, camera or USB drive is connected; it is not a driver to roll back.
    $drivers = @($Rows | Where-Object { $_.Type -eq 'Driver' -and [string]$_.Name -notlike 'WUDFWpdFs*' })
    if ($drivers.Count) { Add-Finding Info ('{0}: {1}' -f (Format-Count $drivers.Count 'driver change' 'driver changes'), (& $names $drivers 4)) 'If a device misbehaves since then, roll that driver back in Device Manager.' }
    # The update history can list one update more than once; count each KB once, at its latest date.
    $updates = @($Rows | Where-Object { $_.Type -eq 'Windows Update' -and [string]$_.Result -notlike 'Failed*' } | Group-Object { if ([string]$_.Name -match 'KB\d+') { $Matches[0] } else { [string]$_.Name } } | ForEach-Object { $_.Group | Sort-Object Date -Descending | Select-Object -First 1 } | Sort-Object Date -Descending)
    if ($updates.Count) { Add-Finding Info ('{0}: {1}' -f (Format-Count $updates.Count 'Windows update installed' 'Windows updates installed'), (& $names $updates 4)) }
    # A removal followed within 10 minutes by an install of the same program is an upgrade.
    $removedAll = @($Rows | Where-Object { $_.Type -eq 'Program removed' -and [string]$_.Result -notlike 'Failed*' })
    $upgrades = @(foreach ($r in $removedAll) {
        $new = @($Rows | Where-Object { $_.Type -in 'Program installed', 'Program updated' -and $_.Name -eq $r.Name -and [string]$_.Version -ne [string]$r.Version -and [math]::Abs(($_.Date - $r.Date).TotalMinutes) -le 10 } | Select-Object -First 1)
        if ($new.Count) { [pscustomobject]@{ Removed = $r; Installed = $new[0] } }
    })
    $installed = @($Rows | Where-Object { $_.Type -in 'Program installed', 'Program updated' -and [string]$_.Result -notlike 'Failed*' -and $_ -notin @($upgrades | ForEach-Object { $_.Installed }) })
    $changes = @(@($upgrades | ForEach-Object { [pscustomobject]@{ Text = '{0} updated from {1} to {2} ({3:yyyy-MM-dd})' -f $_.Installed.Name, $_.Removed.Version, $_.Installed.Version, $_.Installed.Date; Ms = [string]$_.Installed.Publisher -match 'Microsoft'; Date = $_.Installed.Date } }) + @($installed | ForEach-Object { [pscustomobject]@{ Text = '{0} ({1:yyyy-MM-dd})' -f (Get-ShortName $_), $_.Date; Ms = [string]$_.Publisher -match 'Microsoft'; Date = $_.Date } }))
    # Non-Microsoft programs first: they are the usual suspects after "it worked last week".
    $changes = @($changes | Sort-Object -Property Ms, @{ Expression = { $_.Date }; Descending = $true })
    if ($changes.Count) { Add-Finding Info ('{0}, non-Microsoft first: {1}' -f (Format-Count $changes.Count 'program installed or updated' 'programs installed or updated'), ((@($changes | Select-Object -First 6 | ForEach-Object { $_.Text })) -join '; ') + $(if ($changes.Count -gt 6) { '; and {0} more' -f ($changes.Count - 6) } else { '' })) }
    $removed = @($removedAll | Where-Object { $_ -notin @($upgrades | ForEach-Object { $_.Removed }) })
    if ($removed.Count) { Add-Finding Info ('{0}: {1}' -f (Format-Count $removed.Count 'program removed' 'programs removed'), (& $names $removed)) }
    $defender = @($Rows | Where-Object { $_.Type -eq 'Defender update' })
    if ($defender.Count) { Add-Finding Info ('{0} (routine; rarely the cause of a problem).' -f (Format-Count $defender.Count 'Defender definition update' 'Defender definition updates')) }
    $store = @($Rows | Where-Object { $_.Type -eq 'Store app' })
    if ($store.Count) { Add-Finding Info ('{0}.' -f (Format-Count $store.Count 'Store app change' 'Store app changes')) }
    foreach ($w in $script:Warnings) {
        if ($w -like 'Not elevated*') { Add-Finding NotChecked 'Programs installed for other signed-in users could not be read without admin rights.' 'Run Windows - Check Recent Changes.cmd again and approve the admin prompt.' }
        else { Add-Finding NotChecked $w 'Some changes may be missing from the list; the rest is still valid.' }
    }
}

if ($Display) {
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    # Identity, publisher and source columns are left out so the list stays a readable table; the object output keeps them.
    $result | Select-Object Date, Type, Name, Version, Result, Detail |
        Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}
else          { $result }
