<#
.SYNOPSIS
    Timeline of boots, shutdowns, crashes and power losses from the System log, with who or what started each shutdown.
.DESCRIPTION
    Reads the System log for the last -Days days and returns one row per boot/shutdown event (EventLog 6005/6006/6008,
    Kernel-Power 41, User32 1074/1076, WER 1001, Kernel-Boot 27, Kernel-General 12/13), decoded into plain English:
    bugcheck code, whether the power button was held, the last-alive time before an unexpected shutdown, boot type
    (cold boot vs Fast Startup), and the user, process and reason behind each requested shutdown.
    Answers "did it crash, lose power, or did someone hold the power button" without opening Event Viewer.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER Days
    How many days back to read (default 30). The System log may not reach that far; a warning says how far it goes.
.EXAMPLE
    .\Check-Restarts-and-Shutdowns.ps1
.EXAMPLE
    .\Check-Restarts-and-Shutdowns.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Check-Restarts-and-Shutdowns.ps1 -Days 90 | Where-Object Kind -in 'Crash or power loss','Unexpected shutdown','BugCheck'
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
    [ValidateRange(1, 3650)]
    [int]$Days = 30
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-Restarts-and-Shutdowns'      # <-- set per tool
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
# Event Id + provider -> row Kind. Ids 12 and 13 are also raised by Microsoft-Windows-Wininit on every boot, so the
# provider must match as well as the Id (verified on this build: 24 Kernel-General 12s and 24 Wininit 12s in 30 days).
$script:KindByKey = @{
    '6005|EventLog'                                   = 'Boot'
    '6006|EventLog'                                   = 'Clean shutdown'
    '6008|EventLog'                                   = 'Unexpected shutdown'
    '41|Microsoft-Windows-Kernel-Power'               = 'Crash or power loss'
    '1074|User32'                                     = 'Shutdown initiated'
    '1076|User32'                                     = 'Reason given for unexpected shutdown'
    '1001|Microsoft-Windows-WER-SystemErrorReporting' = 'BugCheck'
    '27|Microsoft-Windows-Kernel-Boot'                = 'Boot type'
    '12|Microsoft-Windows-Kernel-General'             = 'OS started'
    '13|Microsoft-Windows-Kernel-General'             = 'OS shutting down'
}
# Logged while the dying session is still running: Time IS the moment it went down.
$script:ShutdownKinds   = @('Clean shutdown', 'Shutdown initiated', 'OS shutting down')
# Logged by the NEXT startup about the session that died: Time is a few seconds into the following boot.
$script:PostMortemKinds = @('Unexpected shutdown', 'Crash or power loss', 'BugCheck')

# Properties[Index] as a trimmed string ($null when absent); byte[] payloads are returned as-is.
function Get-Prop {
    param($Event, [int]$Index)
    if ($null -eq $Event.Properties -or $Event.Properties.Count -le $Index) { return $null }
    $v = $Event.Properties[$Index].Value
    if ($null -eq $v) { return $null }
    if ($v -is [byte[]]) { return $v }
    return ([string]$v).Trim()
}

# EventData <Data Name="X"> values by name (manifest providers: Kernel-Power, Kernel-General, Kernel-Boot).
# Safer than positional indexes: the Kernel-Power 41 template has grown from 8 to 21 fields across Windows releases.
function Get-EventDataMap {
    param($Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) {
            if ($null -ne $d -and $d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    $map
}

# '0', '0x9F', '159' -> [uint64]; anything unparseable or missing -> 0.
function ConvertTo-UInt64 {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return [uint64]0 }
    try {
        if ($Text -match '^\s*0x([0-9A-Fa-f]+)\s*$') { return [Convert]::ToUInt64($Matches[1], 16) }
        return [uint64]$Text.Trim()
    } catch { return [uint64]0 }
}

# 16-byte Win32 SYSTEMTIME (year, month, dayOfWeek, day, hour, minute, second, ms; little-endian UInt16) -> [datetime].
# EventLog 6008 carries two of them in Properties[7]: offset 0 = local time, offset 16 = UTC. Returns $null if unusable.
function ConvertFrom-SystemTimeBytes {
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Bytes.Length -lt ($Offset + 16)) { return $null }
    try {
        $y  = [BitConverter]::ToUInt16($Bytes, $Offset);      $mo = [BitConverter]::ToUInt16($Bytes, $Offset + 2)
        $d  = [BitConverter]::ToUInt16($Bytes, $Offset + 6);  $h  = [BitConverter]::ToUInt16($Bytes, $Offset + 8)
        $mi = [BitConverter]::ToUInt16($Bytes, $Offset + 10); $s  = [BitConverter]::ToUInt16($Bytes, $Offset + 12)
        $ms = [BitConverter]::ToUInt16($Bytes, $Offset + 14)
        if ($y -lt 1990 -or $y -gt 2200 -or $mo -lt 1 -or $mo -gt 12 -or $d -lt 1 -or $d -gt 31) { return $null }
        if ($h -gt 23 -or $mi -gt 59 -or $s -gt 59 -or $ms -gt 999) { return $null }
        return New-Object DateTime ([int]$y, [int]$mo, [int]$d, [int]$h, [int]$mi, [int]$s, [int]$ms)
    } catch { return $null }
}

# Strips Unicode format characters (Windows embeds LRM marks inside the localized date strings in event 6008).
function ConvertTo-PlainText { param([string]$Text) if ($null -eq $Text) { $null } else { $Text -replace '\p{Cf}', '' } }

# Decodes one event into Detail / User / Process / Reason (+ LastAlive for 6008).
# Property indexes verified on this machine against live events (1074, 6008, 41, 27, 12, 13) and, for the two events
# that had no live example, against the provider's own definition read from this machine:
#   User32 1076 message = "The reason supplied by user %6 ... is: %1  Reason Code: %2  Problem ID: %3  Bugcheck String: %4  Comment: %5"
#   WER 1001 template   = param1 bugcheck string, param2 dump path, param3 report id.
function Read-EventFields {
    param($Event, [string]$Kind)
    $f = [ordered]@{ Detail = $null; User = $null; Process = $null; Reason = $null; LastAlive = $null }
    switch ($Kind) {
        'Boot' { $f.Detail = 'Event Log service started (the machine is up)' }

        'Clean shutdown' { $f.Detail = 'Event Log service stopped normally (orderly shutdown or restart)' }

        'Unexpected shutdown' {
            $bin = Get-Prop $Event 7
            if ($bin -is [byte[]]) { $f.LastAlive = ConvertFrom-SystemTimeBytes -Bytes $bin -Offset 0 }
            if ($null -eq $f.LastAlive) {
                try { $f.LastAlive = [datetime]::Parse(((ConvertTo-PlainText (Get-Prop $Event 1)) + ' ' + (ConvertTo-PlainText (Get-Prop $Event 0))), [Globalization.CultureInfo]::CurrentCulture) } catch { }
            }
            $f.Reason = 'Not shut down cleanly'
            if ($f.LastAlive) {
                $f.Detail = 'Windows was last known running at {0:yyyy-MM-dd HH:mm:ss} and never shut down cleanly (that stamp is refreshed every few minutes, so the real stop was slightly later)' -f $f.LastAlive
            } else {
                $tPart = ConvertTo-PlainText (Get-Prop $Event 0); $dPart = ConvertTo-PlainText (Get-Prop $Event 1)
                $f.Detail = if ($tPart -or $dPart) { ('Previous shutdown at {0} {1} was unexpected' -f $dPart, $tPart).Replace('  ', ' ').Trim() }
                            else { 'The previous shutdown was unexpected (this event carried no usable timestamp)' }
            }
        }

        'Crash or power loss' {
            $m = Get-EventDataMap $Event
            $code = if ($m.ContainsKey('BugcheckCode')) { ConvertTo-UInt64 $m['BugcheckCode'] } else { ConvertTo-UInt64 (Get-Prop $Event 0) }
            $pbt  = if ($m.ContainsKey('PowerButtonTimestamp')) { ConvertTo-UInt64 $m['PowerButtonTimestamp'] }
                    elseif ($Event.Properties.Count -ge 7) { ConvertTo-UInt64 (Get-Prop $Event 6) } else { [uint64]0 }
            $held  = ($pbt -ne 0) -or ($m['LongPowerButtonPressDetected'] -eq 'true')
            $sleep = ConvertTo-UInt64 $m['SleepInProgress']
            $whea  = ConvertTo-UInt64 $m['WHEABootErrorCount']
            if ($code -eq 0) {
                $f.Detail = 'BugcheckCode 0 = no crash dump: power was cut, the reset or power button was used, or Windows hung and was forced off'
            } else {
                $params = @(1..4 | ForEach-Object { $m['BugcheckParameter' + $_] } | Where-Object { $_ })
                $f.Detail = if ($params.Count) { 'Bugcheck 0x{0:X8} (params {1}); the BugCheck row has the dump path' -f $code, ($params -join ', ') }
                            else                { 'Bugcheck 0x{0:X8}; the BugCheck row has the dump path' -f $code }
            }
            if ($held)       { $f.Detail += '; POWER BUTTON WAS HELD (someone forced it off)' }
            if ($sleep -ne 0){ $f.Detail += '; it failed during a sleep transition' }
            if ($whea -gt 0) { $f.Detail += ('; {0} WHEA hardware error record(s) found at the next boot' -f $whea) }
            $f.Reason = if ($held) { 'Power button held' } elseif ($code -ne 0) { 'Bugcheck (blue screen)' } else { 'Power loss, hard reset or hang' }
        }

        'Shutdown initiated' {
            $proc = Get-Prop $Event 0
            $onHost = Get-Prop $Event 1          # never name this $host: that is an automatic variable
            if ($proc -and $onHost -and $proc.EndsWith(" ($onHost)")) { $proc = $proc.Substring(0, $proc.Length - $onHost.Length - 3) }
            $f.Process = $proc
            $f.Reason  = Get-Prop $Event 2
            $f.User    = Get-Prop $Event 6
            $type = Get-Prop $Event 4; $code = Get-Prop $Event 3; $comment = Get-Prop $Event 5
            $parts = @()
            if ($type)     { $parts += $type }
            if ($f.Reason) { $parts += $f.Reason }
            $f.Detail = if ($parts.Count) { $parts -join ' - ' } else { 'Shutdown or restart requested' }
            if ($code)    { $f.Detail += ' ({0})' -f $code }
            if ($comment) { $f.Detail += ' - ' + $comment }
        }

        'Reason given for unexpected shutdown' {
            $f.Reason = Get-Prop $Event 0
            $f.User   = Get-Prop $Event 5
            $f.Detail = 'Someone answered the shutdown-reason prompt: {0} ({1})' -f $f.Reason, (Get-Prop $Event 1)
            $problemId = Get-Prop $Event 2; $bcs = Get-Prop $Event 3; $comment = Get-Prop $Event 4
            if ($problemId) { $f.Detail += '; problem id ' + $problemId }
            if ($bcs)       { $f.Detail += '; bugcheck string ' + $bcs }
            if ($comment)   { $f.Detail += '; comment: ' + $comment }
        }

        'BugCheck' {
            $s = Get-Prop $Event 0; $dump = Get-Prop $Event 1; $rep = Get-Prop $Event 2
            if (-not $dump -and $Event.Message -match 'saved in:\s*(.+?)\.\s') { $dump = $Matches[1].Trim() }
            $code = $null
            if ($s -match '0x[0-9A-Fa-f]{8}') { $code = $Matches[0] } elseif ($Event.Message -match '0x[0-9A-Fa-f]{8}') { $code = $Matches[0] }
            $f.Reason = if ($code) { 'Bugcheck ' + $code } else { 'Bugcheck' }
            $f.Detail = 'Rebooted from bugcheck {0}' -f $s
            if ($dump) { $f.Detail += '; dump saved in ' + $dump }
            if ($rep)  { $f.Detail += '; report id ' + $rep }
        }

        'Boot type' {
            $m = Get-EventDataMap $Event
            $bt = if ($m.ContainsKey('BootType')) { ConvertTo-UInt64 $m['BootType'] } else { ConvertTo-UInt64 (Get-Prop $Event 0) }
            $f.Detail = switch ($bt) {
                0 { 'Cold boot (a real restart: kernel and drivers were reloaded)' }
                1 { 'Fast Startup (hybrid boot: the previous "shut down" only hibernated the kernel, drivers were NOT reloaded)' }
                2 { 'Resume from hibernation' }
                default { 'Unknown boot type {0}' -f $bt }
            }
        }

        'OS started' {
            $m = Get-EventDataMap $Event
            $ver = '{0}.{1}.{2}.{3}' -f (Get-Prop $Event 0), (Get-Prop $Event 1), (Get-Prop $Event 2), (Get-Prop $Event 3)
            $st = $null
            if ($Event.Properties.Count -ge 7 -and $Event.Properties[6].Value -is [datetime]) { $st = $Event.Properties[6].Value }
            elseif ($m['StartTime']) { try { $st = [datetime]$m['StartTime'] } catch { } }
            $f.Detail = if ($st) { 'Windows {0} started; kernel start time {1:yyyy-MM-dd HH:mm:ss}' -f $ver, $st } else { 'Windows {0} started' -f $ver }
        }

        'OS shutting down' {
            $m = Get-EventDataMap $Event
            $st = $null
            if ($Event.Properties.Count -ge 1 -and $Event.Properties[0].Value -is [datetime]) { $st = $Event.Properties[0].Value }
            elseif ($m['StopTime']) { try { $st = [datetime]$m['StopTime'] } catch { } }
            $f.Detail = if ($st) { 'Kernel shutdown started at {0:yyyy-MM-dd HH:mm:ss}' -f $st } else { 'Kernel shutdown started' }
        }
    }
    [PSCustomObject]$f
}

# Latest time in $Times at or before $At (strictly before with -Strict); $null when there is none.
function Get-LatestBefore {
    param([datetime[]]$Times, [datetime]$At, [switch]$Strict)
    $best = $null
    foreach ($t in @($Times)) {
        if (($Strict -and $t -lt $At) -or (-not $Strict -and $t -le $At)) { if ($null -eq $best -or $t -gt $best) { $best = $t } }
    }
    $best
}

# ---------------------------------------------------------------- collect
$collectedAt = [DateTime]::Now
$since  = $collectedAt.AddDays(-$Days)
$filter = @{ LogName = 'System'; Id = @(6005, 6006, 6008, 41, 1074, 1076, 1001, 27, 12, 13); StartTime = $since }

$events = @(Invoke-Section 'System log query' {
    try { @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
} -Default @())

$oldest = Invoke-Section 'System log range' { (Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated }
if ($oldest -is [datetime] -and $oldest -gt $since) {
    Add-Warning ('The System log only reaches back to {0:yyyy-MM-dd HH:mm} (it wrapped or was cleared), so the {1}-day window is cut short' -f $oldest, $Days)
}

$wanted = @($events | Where-Object { $script:KindByKey.ContainsKey(('{0}|{1}' -f $_.Id, $_.ProviderName)) } | Sort-Object TimeCreated, RecordId)
$rows = New-Object System.Collections.Generic.List[object]
$meta = New-Object System.Collections.Generic.List[object]   # parallel to $rows: decoded fields incl. LastAlive
foreach ($e in $wanted) {
    $kind = $script:KindByKey[('{0}|{1}' -f $e.Id, $e.ProviderName)]
    $f = Invoke-Section ('Event {0} record {1}' -f $e.Id, $e.RecordId) { Read-EventFields -Event $e -Kind $kind }
    if ($null -eq $f) {
        $line = Invoke-Section ('Event {0} message' -f $e.Id) { if ($e.Message) { ($e.Message -split "`r?`n")[0].Trim() } else { $null } }
        if (-not $line) { $line = 'Event {0} ({1})' -f $e.Id, $e.ProviderName }
        $f = [PSCustomObject]@{ Detail = $line; User = $null; Process = $null; Reason = $null; LastAlive = $null }
    }
    $meta.Add($f)
    $rows.Add([PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        CollectedAt        = $collectedAt
        Time               = $e.TimeCreated
        EventId            = [int]$e.Id
        Kind               = $kind
        Detail             = $f.Detail
        User               = $f.User
        Process            = $f.Process
        Reason             = $f.Reason
        SinceLastBootHours = $null
    })
}

# ---------------------------------------------------------------- SinceLastBootHours
# Shutdown rows: hours from the newest Boot row (6005) at or before the row's own time.
# Post-mortem rows (41 / 6008 / 1001) are written by the FOLLOWING startup, so the session that died is the one before
# that startup (delimited by its 'OS started' row) and the 6008 last-alive stamp, when there is one, is the best
# estimate of when that session actually stopped.
[void](Invoke-Section 'SinceLastBootHours' {
    $bootTimes  = @($rows | Where-Object { $_.Kind -eq 'Boot' }       | ForEach-Object { $_.Time })
    $startTimes = @($rows | Where-Object { $_.Kind -eq 'OS started' } | ForEach-Object { $_.Time })
    $lastAlive  = @()   # (time of the 6008 row, decoded last-alive time) pairs
    for ($j = 0; $j -lt $rows.Count; $j++) {
        if ($rows[$j].Kind -eq 'Unexpected shutdown' -and $meta[$j].LastAlive -is [datetime]) {
            $lastAlive += [PSCustomObject]@{ Time = $rows[$j].Time; LastAlive = $meta[$j].LastAlive }
        }
    }
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $r = $rows[$i]; $ref = $null; $boot = $null
        if ($r.Kind -in $script:ShutdownKinds) {
            $ref = $r.Time; $boot = Get-LatestBefore -Times $bootTimes -At $ref
        } elseif ($r.Kind -in $script:PostMortemKinds) {
            if ($r.Kind -eq 'Unexpected shutdown' -and $meta[$i].LastAlive -is [datetime]) {
                $ref = $meta[$i].LastAlive; $boot = Get-LatestBefore -Times $bootTimes -At $ref
            } else {
                $sessionStart = Get-LatestBefore -Times $startTimes -At $r.Time
                if ($sessionStart) {
                    $boot = Get-LatestBefore -Times $bootTimes -At $sessionStart -Strict
                    $partner = $lastAlive | Where-Object { $_.Time -ge $sessionStart -and $_.Time -le $sessionStart.AddMinutes(10) } | Select-Object -First 1
                    $ref = if ($partner) { $partner.LastAlive } else { $r.Time }
                } else {
                    $ref = $r.Time; $boot = Get-LatestBefore -Times $bootTimes -At $ref
                }
            }
        }
        if ($ref -is [datetime] -and $boot -is [datetime]) {
            $h = ($ref - $boot).TotalHours
            if ($h -ge 0) { $r.SinceLastBootHours = Round1 $h }
        }
    }
})

# ---------------------------------------------------------------- result (shape B)
if ($rows.Count -eq 0) { Add-Warning ('No boot or shutdown events found in the last {0} day(s)' -f $Days) }
# With -Display the warnings appear in SUMMARY instead of as loose lines above the report.
if (-not $Display) { foreach ($w in $script:Warnings) { Write-Warning $w } }
$result = $rows.ToArray()

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = ('Timeline of boots, restarts, shutdowns, crashes and power losses over the last {0} days, with who or what asked for each restart.' -f $Days)
$script:SummaryNext = @(
    'Blue screens: run Windows - Check Crashes and Restarts, then update drivers and BIOS from the PC maker.',
    'Forced power-offs or power losses: ask the user what happened at those times. Check the charger, battery or UPS; repeated freezes point to drivers or hardware.',
    'Restarts nobody expected: the Process column shows what asked for each one. TrustedInstaller.exe or MoNotificationUx.exe = Windows Update; StartMenuExperienceHost.exe = the user used Start; shutdown.exe = a script or admin command; msiexec.exe = an installer.',
    'To look further back, from PowerShell in the Scripts folder: .\Check-Restarts-and-Shutdowns.ps1 -Days 90 -Display'
)
# Who asked for a shutdown, in words: the requesting process of event 1074.
function Get-ShutdownRequester {
    param([string]$Process)
    switch -Regex (($Process -split '\\')[-1]) {
        '^(StartMenuExperienceHost|explorer|ShellExperienceHost)\.exe$' { return 'on the Start menu' }
        '^LogonUI\.exe$' { return 'on the sign-in screen' }
        '^(TrustedInstaller|MoNotificationUx|MusNotification|MusNotificationUx|wuauclt|UsoClient)\.exe$' { return 'through Windows Update' }
        '^shutdown\.exe$' { return 'with a script or admin command (shutdown.exe)' }
        '^msiexec\.exe$' { return 'through an installer (msiexec.exe)' }
        '^$' { return '' }
        default { return ('using ' + ($Process -split '\\')[-1]) }
    }
}
function Add-SummaryFindings {
    param($Rows)
    $Rows = @($Rows)
    $when = { param($r) '{0:yyyy-MM-dd HH:mm}' -f $r.Time }
    $boots = @($Rows | Where-Object { $_.Kind -eq 'Boot' })
    $crashes = @($Rows | Where-Object { $_.Kind -eq 'Crash or power loss' } | Sort-Object Time)
    # A blue screen usually logs both a BugCheck row and a Kernel-Power 41 row; count one of them.
    $blue = @($Rows | Where-Object { $_.Kind -eq 'BugCheck' } | Sort-Object Time)
    if (-not $blue.Count) { $blue = @($crashes | Where-Object { $_.Reason -like 'Bugcheck*' }) }
    $held = @($crashes | Where-Object { $_.Reason -eq 'Power button held' })
    $lost = @($crashes | Where-Object { $_.Reason -eq 'Power loss, hard reset or hang' })
    $unexpected = @($Rows | Where-Object { $_.Kind -eq 'Unexpected shutdown' } | Sort-Object Time)
    if ($blue.Count) { Add-Finding Problem ('{0}; the latest at {1}.' -f (Format-Count $blue.Count 'blue screen restart' 'blue screen restarts'), (& $when $blue[-1])) 'Run Windows - Check Crashes and Restarts and update drivers and BIOS.' }
    if ($held.Count) { Add-Finding Warning ('Someone held the power button to force the PC off {0}; the latest at {1}.' -f (Format-Count $held.Count 'time' 'times'), (& $when $held[-1])) 'Ask the user whether the PC froze first. Frozen PCs point to drivers or hardware: run Windows - Check Crashes and Restarts.' }
    if ($lost.Count) { Add-Finding Warning ('{0} (power cut, reset button or a hang); the latest at {1}.' -f (Format-Count $lost.Count 'unexpected power-off' 'unexpected power-offs'), (& $when $lost[-1])) 'Ask the user what happened then. Check the power cable, charger, battery or UPS.' }
    if (-not $crashes.Count -and $unexpected.Count) { Add-Finding Warning ('Windows did not shut down cleanly {0}; the latest was reported at {1}.' -f (Format-Count $unexpected.Count 'time' 'times'), (& $when $unexpected[-1])) 'Ask the user whether the PC lost power or froze at that time.' }
    if (-not $blue.Count -and -not $crashes.Count -and -not $unexpected.Count -and $Rows.Count) { Add-Finding OK ('No crashes, power losses or forced power-offs in the last {0} days.' -f $Days) }
    # Kernel-Boot 27 ('Boot type') is logged by every start, including Fast Startup; EventLog 6005 is not.
    $starts = @($Rows | Where-Object { $_.Kind -eq 'Boot type' } | Sort-Object Time)
    if ($starts.Count) {
        $latest = $starts[-1]
        $full = @($starts | Where-Object { $_.Detail -like 'Cold boot*' })
        $how = switch -Wildcard ($latest.Detail) {
            'Cold boot*'    { 'It was a full restart.' }
            'Fast Startup*' { 'It was a Fast Startup after Shut down, which does not reload drivers.' }
            'Resume*'       { 'It resumed from hibernation.' }
            default         { '' }
        }
        $t = '{0} in {1} days; the latest at {2}. {3}' -f (Format-Count $starts.Count 'start-up' 'start-ups'), $Days, (& $when $latest), $how
        $next = ''
        if ($latest.Detail -notlike 'Cold boot*') {
            $t += $(if ($full.Count) { ' The last full restart was at {0}.' -f (& $when $full[-1]) } else { ' No full restart in this period.' })
            $next = 'When a restart is needed, use Start > Power > Restart: Shut down with Fast Startup on does not reload drivers.'
        }
        Add-Finding Info $t $next
    } elseif ($boots.Count) {
        Add-Finding Info ('{0} in {1} days; the latest at {2}.' -f (Format-Count $boots.Count 'start-up' 'start-ups'), $Days, (& $when $boots[-1]))
    }
    $asked = @($Rows | Where-Object { $_.Kind -eq 'Shutdown initiated' } | Sort-Object Time)
    if ($asked.Count) {
        $a = $asked[-1]
        $what = $(if ([string]$a.Detail -like 'restart*') { 'Restart' } elseif ([string]$a.Detail -like 'power off*') { 'Shut down' } else { '' })
        $how = Get-ShutdownRequester ([string]$a.Process)
        $user = $(if ($a.User) { ($a.User -split '\\')[-1] } else { 'Windows' })
        # Shut down or Restart chosen on Start logs reason "Other (Unplanned) (0x0)"; that is normal, not a fault.
        $t = $(if ($how -eq 'on the Start menu' -and $what) { '{0} chose {1} {2} (normal)' -f $user, $what, $how } elseif ($how) { '{0} {1}: {2}' -f $user, $how, $a.Detail } else { '{0}: {1}' -f $user, $a.Detail })
        $later = @($starts | Where-Object { $_.Time -gt $a.Time }).Count
        Add-Finding Info ('Last shutdown or restart with a recorded reason: {0}, {1}.{2}' -f (& $when $a), $t, $(if ($later -gt 1) { ' Later shutdowns left no reason (Shut down with Fast Startup or the power button).' } else { '' }))
    }
    if (-not $Rows.Count) { Add-Finding NotChecked ('No boot or shutdown events were found in the last {0} days.' -f $Days) 'Check that the System event log is readable and has not been cleared.' }
    foreach ($w in $script:Warnings) {
        if ($w -like 'No boot or shutdown events*') { continue }
        # A part that could not be read is NOT CHECKED; the other warnings are notes about the log.
        if ($w -match '^(System log query|System log range|Event \d+ record \d+|Event \d+ message|SinceLastBootHours): ') { Add-Finding NotChecked ('Not read: {0}' -f $w) 'Run Windows - Check Crashes and Restarts again. If it repeats, open the System log in Event Viewer to see whether it is damaged.' }
        else { Add-Finding Info $w }
    }
}

if ($Display) {
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    # The identity columns repeat on every row and Reason repeats Detail; leaving them out (and showing the
    # process file name only) keeps the timeline a readable table. The full path stays in the object output.
    $result | Select-Object Time, Kind, Detail, User, @{ n = 'Process'; e = { if ($_.Process) { ($_.Process -split '\\')[-1] } } }, SinceLastBootHours |
        Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}
else          { $result }
