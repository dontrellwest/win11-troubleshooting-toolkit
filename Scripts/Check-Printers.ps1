<#
.SYNOPSIS
    Printers, drivers, ports, spooler health, and which printers are GPO-deployed versus user-added.
.DESCRIPTION
    One object covering the whole print stack on this machine: spooler state and start mode, the spool
    folder and what is stuck in it, every printer with its driver, port, TCP address, status and where it
    came from (local, user-added connection, or pushed by Group Policy), every printer driver with its
    version and signature, the ports that matter, and the console user's default printer and network
    printer connections read from their own registry hive. Read-only; the spooler reset lives in
    Printing - Reset Print Queue.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER TargetUser
    DOMAIN\user whose default printer and printer connections to report. Defaults to the console user.
.PARAMETER StuckJobHours
    A queued job older than this many hours counts towards StuckJobs. Default 1.
.PARAMETER AllPorts
    List every printer port, including the unused COM1:/LPT1:/FILE: placeholders Windows always defines.
.EXAMPLE
    .\Check-Printers.ps1
.EXAMPLE
    .\Check-Printers.ps1 -Display -ReportPath C:\Temp\Toolkit
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
    [string]$TargetUser,
    [int]$StuckJobHours = 1,
    [switch]$AllPorts
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-Printers'          # <-- set per tool
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

# ---------------------------------------------------------------- tool-local helpers

# "Could not read" must never look like "not set": name the key and say which it was.
function Add-RegistryReadWarning {
    param([string]$What, [string]$KeyPath, $ErrorRecord)
    $denied = $false
    $detail = ''
    if ($ErrorRecord) {
        $denied = ($ErrorRecord.Exception -is [System.Security.SecurityException]) -or
                  ($ErrorRecord.Exception -is [System.UnauthorizedAccessException])
        $detail = ('{0}' -f $ErrorRecord.Exception.Message).Trim()
    }
    if ($denied) { Add-Warning ('{0}: (needs admin) - {1} is not readable from this account.' -f $What, $KeyPath) }
    elseif ($detail) { Add-Warning ('{0}: {1} could not be read - {2}' -f $What, $KeyPath, $detail) }
    else { Add-Warning ('{0}: {1} could not be read.' -f $What, $KeyPath) }
}

# Policy values that should be DWORDs are routinely written by hand with 'reg add' (REG_SZ) or as a word,
# and [int] on those throws. Parse defensively: anything that is not one integer returns $null + a Warning.
function ConvertTo-PolicyInt {
    param([string]$Name, $Value)
    $n     = 0
    $items = @($Value)
    $text  = ($items | ForEach-Object { '{0}' -f $_ }) -join ','
    if ($items.Count -eq 1 -and [int]::TryParse($text, [ref]$n)) { return $n }
    Add-Warning ('Point and Print: {0} is not a DWORD (value ''{1}'', type {2}); it could not be evaluated - check the policy by hand.' -f $Name, $text, $(if ($null -eq $Value) { 'none' } else { $Value.GetType().Name }))
    return $null
}

# MSFT_PrinterDriver.DriverVersion is a UInt64 holding four 16-bit words -> '10.0.26100.9444'.
function ConvertTo-DriverVersionString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $b = [BitConverter]::GetBytes([uint64]$Value)
        '{0}.{1}.{2}.{3}' -f [BitConverter]::ToUInt16($b, 6), [BitConverter]::ToUInt16($b, 4),
                             [BitConverter]::ToUInt16($b, 2), [BitConverter]::ToUInt16($b, 0)
    } catch { $null }
}

# Registry connection keys store '\\server\printer' with commas in place of backslashes: ',,server,printer'.
function ConvertFrom-ConnectionKeyName {
    param([string]$KeyName)
    if (-not $KeyName) { return $null }
    if ($KeyName -like '\\*') { return $KeyName }
    ($KeyName -replace ',', '\')
}

# '\\server\printer' -> Server '\\server', Printer 'printer'. Anything else comes back whole.
function Split-PrinterConnection {
    param([string]$Connection)
    $server = $null; $printer = $Connection
    if ($Connection -match '^\\\\([^\\]+)\\(.+)$') { $server = '\\' + $Matches[1]; $printer = $Matches[2] }
    [PSCustomObject]@{ Server = $server; Printer = $printer }
}

# Every subkey of a Connections-style policy key, as '\\server\printer' strings. Missing key -> @().
function Get-PolicyConnectionName {
    param([string]$KeyPath)
    if (-not $KeyPath) { return @() }
    if (-not (Test-Path -LiteralPath $KeyPath)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    $gciErr = $null
    $subKeys = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue -ErrorVariable gciErr)
    if (@($gciErr).Count) { Add-RegistryReadWarning -What 'Policy-deployed printers' -KeyPath $KeyPath -ErrorRecord @($gciErr)[0] }
    $unread = 0
    foreach ($k in $subKeys) {
        # The key name is the documented form (',,server,printer'); trust it when it un-mangles cleanly.
        $unc = $null
        $fromKey = ConvertFrom-ConnectionKeyName $k.PSChildName
        if ($fromKey -match '^\\\\[^\\?][^\\]*\\.+$') { $unc = $fromKey }
        if (-not $unc) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { $unread++ }
            if ($props) {
                foreach ($n in @('Printer', 'PrinterPath', 'PrinterName', 'Connection', 'Path')) {
                    if ($null -eq $props.PSObject.Properties[$n]) { continue }
                    $v = '{0}' -f $props.$n
                    if ($v -match '^\\\\[^\\?][^\\]*\\.+$') { $unc = $v; break }
                }
            }
        }
        if (-not $unc) { $unc = $fromKey }
        if ($unc) { $out.Add($unc) }
    }
    if ($unread) {
        Add-Warning ('Policy-deployed printers: the values of {0} key(s) under {1} could not be read, so a GPO-deployed printer may be reported as user-added.' -f $unread, $KeyPath)
    }
    @($out)
}

# Group Policy Preferences leaves a client-side-extension key per CSE it applied. Collect the key names
# and string values under the Printers CSEs so a deployed printer can be recognised by name (best effort).
$script:PrinterCseGuid = @(
    '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}',   # GPP Printers
    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}'    # Deployed Printer Connections
)
function Get-GppPrinterHint {
    param([string]$HistoryRoot)
    $hints = New-Object System.Collections.Generic.List[string]
    if (-not $HistoryRoot) { return @() }
    if (-not (Test-Path -LiteralPath $HistoryRoot)) { return @() }
    $unread = 0
    foreach ($guid in $script:PrinterCseGuid) {
        $cse = Join-Path $HistoryRoot $guid
        if (-not (Test-Path -LiteralPath $cse)) { continue }
        $hints.Add($guid)   # marker: the CSE ran at least once, even if no name could be recovered
        $gciErr = $null
        $cseKeys = @(Get-ChildItem -LiteralPath $cse -Recurse -ErrorAction SilentlyContinue -ErrorVariable gciErr)
        if (@($gciErr).Count) { Add-RegistryReadWarning -What 'Group Policy Preferences printer history' -KeyPath $cse -ErrorRecord @($gciErr)[0] }
        foreach ($k in $cseKeys) {
            if ($hints.Count -ge 2000) { Add-Warning ('Group Policy Preferences printer history under {0} is unusually large; only the first 2000 entries were matched against printer names.' -f $cse); break }
            $hints.Add($k.PSChildName)
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { $unread++ }
            if ($props) {
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    if ($p.Value -is [string] -and $p.Value) { $hints.Add($p.Value) }
                }
            }
        }
    }
    if ($unread) {
        Add-Warning ('Group Policy Preferences printer history: the values of {0} key(s) under {1} could not be read, so a GPP-deployed printer may be reported as user-added.' -f $unread, $HistoryRoot)
    }
    @($hints)
}

# True when any GPP hint string contains this printer's name (or its share half).
function Test-GppHintMatch {
    param([string[]]$Hints, [string]$PrinterName)
    if (-not $PrinterName -or -not $Hints -or $Hints.Count -eq 0) { return $false }
    $short = (Split-PrinterConnection $PrinterName).Printer
    foreach ($h in $Hints) {
        if (-not $h) { continue }
        if ($h.IndexOf($PrinterName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        # Short share names produce false positives against GPO display names; require something distinctive.
        if ($short -and $short.Length -ge 4 -and $h.IndexOf($short, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

# Authenticode status of the driver's render DLL (falls back to the config DLL, then the INF catalog).
function Get-DriverSignature {
    param($Driver)
    foreach ($f in @($Driver.Path, $Driver.ConfigFile, $Driver.InfPath)) {
        if (-not $f) { continue }
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $f -ErrorAction Stop
            if (-not $sig) { continue }
            $status = '{0}' -f $sig.Status
            if ($status -eq 'UnknownError') { continue }
            $signer = $null
            if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject -match 'CN=([^,]+)') { $signer = $Matches[1].Trim() }
            return [PSCustomObject]@{ Signed = [bool]($status -eq 'Valid'); Signer = $signer; Status = $status }
        } catch { }
    }
    [PSCustomObject]@{ Signed = $null; Signer = $null; Status = $null }
}

# ---------------------------------------------------------------- collection
$isAdmin       = Test-IsAdmin
$stuckPattern  = 'Error|Blocked|Offline|PaperOut|UserIntervention'
$defaultSpool  = Join-Path $env:SystemRoot 'System32\spool\PRINTERS'

$console = Invoke-Section 'Console user' { Get-ConsoleUser -OverrideName $TargetUser }
if (-not $console) {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $console = [PSCustomObject]@{ Name = $me.Name; Sid = $me.User.Value; Hive = $null; ProfilePath = $null
                                  SessionId = $null; LogonId = $null; Source = 'Process'; OtherDesktops = ''
                                  IsMe = $true; IsSystem = ($me.User.Value -eq 'S-1-5-18'); RunningAs = $me.Name }
}
if ($console.OtherDesktops -and -not $TargetUser) {
    Add-Warning ('Other signed-in desktops: {0}. Pass -TargetUser DOMAIN\user to report one of those instead.' -f $console.OtherDesktops)
}
if (-not $console.IsMe) {
    Add-Warning ('Running as {0}, reporting for {1}: Get-Printer only sees this account''s printer connections, so {1}''s network printers are listed from the registry (no driver, port, status or job count for those rows).' -f $console.RunningAs, $console.Name)
}

# Fixed property order (spec). Every field exists even when its section fails.
$o = [ordered]@{
    ComputerName            = $env:COMPUTERNAME
    CollectedAt             = [DateTime]::Now
    TargetUser              = $console.Name
    RunningAs               = $console.RunningAs
    SpoolerStatus           = $null
    SpoolerStartMode        = $null
    SpoolFolder             = $null
    SpoolFilesCount         = $null
    SpoolFilesMB            = $null
    OldestSpoolFile         = $null
    StuckJobs               = $null
    PrinterCount            = $null
    DefaultPrinter          = $null
    PointAndPrintRestricted = $null
    PointAndPrintSource     = $null
    Printers                = @()
    Drivers                 = @()
    Ports                   = @()
    UserConnections         = @()
    Warnings                = ''
}

# ---- spooler service
$spooler = Invoke-Section 'Spooler service' {
    Get-CimInstance Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop | Select-Object -First 1
}
if ($spooler) {
    $o.SpoolerStatus    = '{0}' -f $spooler.State
    $o.SpoolerStartMode = '{0}' -f $spooler.StartMode
    if ($o.SpoolerStatus -ne 'Running') { Add-Warning ('Print Spooler is {0}: no printer, driver, port or job data can be read until it starts.' -f $o.SpoolerStatus) }
    if ($o.SpoolerStartMode -eq 'Disabled') { Add-Warning 'Print Spooler start mode is Disabled (policy or a previous hardening step).' }
}

# ---- spool folder
$o.SpoolFolder = Invoke-Section 'Spool folder' {
    $v = $null
    try { $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -Name 'DefaultSpoolDirectory' -ErrorAction Stop).DefaultSpoolDirectory } catch { }
    if ($v) { [Environment]::ExpandEnvironmentVariables($v) } else { $defaultSpool }
}
if (-not $o.SpoolFolder) { $o.SpoolFolder = $defaultSpool }

$spoolInfo = Invoke-Section 'Spool folder contents' {
    if (-not (Test-Path -LiteralPath $o.SpoolFolder)) { throw ('folder not found: {0}' -f $o.SpoolFolder) }
    $gciErr = $null
    $files = @(Get-ChildItem -LiteralPath $o.SpoolFolder -File -Force -ErrorAction SilentlyContinue -ErrorVariable gciErr)
    if (@($gciErr).Count) {
        if ($isAdmin) { Add-Warning ('Spool folder contents: {0}' -f @($gciErr)[0].Exception.Message.Trim()) }
        else          { Add-Warning 'Spool folder contents: (needs admin) - SpoolFilesCount, SpoolFilesMB and OldestSpoolFile are blank.' }
        return $null
    }
    $bytes  = 0L
    $oldest = $null
    foreach ($f in $files) {
        $bytes += [int64]$f.Length
        if ($null -eq $oldest -or $f.CreationTime -lt $oldest) { $oldest = $f.CreationTime }
    }
    [PSCustomObject]@{ Count = [int]$files.Count; MB = (Round1 ($bytes / 1MB)); Oldest = $oldest }
}
if ($spoolInfo) {
    $o.SpoolFilesCount = $spoolInfo.Count
    $o.SpoolFilesMB    = $spoolInfo.MB
    if ($spoolInfo.Oldest) { $o.OldestSpoolFile = [datetime]$spoolInfo.Oldest }
}

# ---- Point and Print (PrintNightmare hardening)
$pnpValues = Invoke-Section 'Point and Print policy' {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    if (Test-Path -LiteralPath $k) { Get-ItemProperty -LiteralPath $k -ErrorAction Stop } else { $null }
}
[void](Invoke-Section 'Point and Print policy values' {
    $name     = 'RestrictDriverInstallationToAdministrators'
    $present  = [bool]($pnpValues -and $null -ne $pnpValues.PSObject.Properties[$name])
    $restrict = $null
    if ($present) { $restrict = ConvertTo-PolicyInt $name $pnpValues.$name }
    if ($null -ne $restrict) {
        $o.PointAndPrintRestricted = [bool]($restrict -ne 0)
        $o.PointAndPrintSource     = 'Policy: {0} = {1}' -f $name, $restrict
        if ($restrict -eq 0) { Add-Warning 'Point and Print: RestrictDriverInstallationToAdministrators = 0 - standard users can install printer drivers from a print server (PrintNightmare exposure).' }
    } elseif ($present) {
        # The value exists but is not a number, so nothing about the machine's behaviour was established.
        $o.PointAndPrintRestricted = $null
        $o.PointAndPrintSource     = 'Policy value {0} is present but is not a DWORD - see Warnings' -f $name
    } else {
        $o.PointAndPrintRestricted = $true
        $o.PointAndPrintSource     = 'Not configured - Windows default since the CVE-2021-34527 fix: only admins may install printer drivers'
    }
    if ($pnpValues) {
        foreach ($n in @('NoWarningNoElevationOnInstall', 'UpdatePromptSettings')) {
            if ($null -eq $pnpValues.PSObject.Properties[$n]) { continue }
            $v = ConvertTo-PolicyInt $n $pnpValues.$n
            if ($null -ne $v -and $v -ne 0) {
                Add-Warning ('Point and Print: {0} = {1} - the driver-install elevation prompt is suppressed.' -f $n, $v)
            }
        }
    }
})

# ---- console user's registry: default printer, connections, per-user policy
$userHive = $null
if ($console.Hive) { $userHive = $console.Hive }
elseif ($console.IsMe) { $userHive = 'HKCU:' }
else { Add-Warning ('{0}''s registry hive is not open or not readable from this account: DefaultPrinter and UserConnections are blank. Run elevated, or sign in as that user.' -f $console.Name) }

$script:UserHiveReadError = $false
$o.DefaultPrinter = Invoke-Section 'Default printer' {
    if (-not $userHive) { return $null }
    $k = Join-Path $userHive 'Software\Microsoft\Windows NT\CurrentVersion\Windows'
    if (-not (Test-Path -LiteralPath $k)) { return $null }
    $d = $null
    # A missing 'Device' value means no default printer; an access error means we do not know. Not the same thing.
    try { $d = (Get-ItemProperty -LiteralPath $k -Name 'Device' -ErrorAction Stop).Device }
    catch {
        if (($_.Exception -is [System.Security.SecurityException]) -or ($_.Exception -is [System.UnauthorizedAccessException])) {
            $script:UserHiveReadError = $true
            Add-RegistryReadWarning -What ('Default printer for {0}' -f $console.Name) -KeyPath $k -ErrorRecord $_
            return '(needs admin)'
        }
    }
    if (-not $d) { return $null }
    # 'name,winspool,port' - the name itself may contain commas, so strip the known two trailing fields.
    $parts = $d -split ','
    if ($parts.Count -ge 3) { ($parts[0..($parts.Count - 3)] -join ',').Trim() } else { $parts[0].Trim() }
}
if ($userHive -and -not $o.DefaultPrinter -and -not $script:UserHiveReadError) { Add-Warning ('No default printer is set for {0}.' -f $console.Name) }

$o.UserConnections = @(Invoke-Section 'UserConnections' {
    if (-not $userHive) { return @() }
    $k = Join-Path $userHive 'Printers\Connections'
    if (-not (Test-Path -LiteralPath $k)) { return @() }
    # List[psobject], not List[object]: @() on a List[object] throws "Argument types do not match" in PS 5.1.
    $rows = New-Object System.Collections.Generic.List[psobject]
    $ucErr = $null
    $connKeys = @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue -ErrorVariable ucErr)
    if (@($ucErr).Count) {
        $script:UserHiveReadError = $true
        Add-RegistryReadWarning -What 'Printer connections' -KeyPath $k -ErrorRecord @($ucErr)[0]
        Add-Warning ('Printer connections: the list below may be short, so a printer missing from it is not proof that it was never deployed.')
    }
    $unread = 0
    foreach ($c in $connKeys) {
        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $c.PSPath -ErrorAction Stop } catch { $unread++ }
        $unc = ConvertFrom-ConnectionKeyName $c.PSChildName
        $srv = $null
        if ($props -and $props.PSObject.Properties['Server']) { $srv = '{0}' -f $props.Server }
        $split = Split-PrinterConnection $unc
        if (-not $srv) { $srv = $split.Server }
        $rows.Add([PSCustomObject]@{
            Connection = $unc
            Server     = $srv
            Printer    = $split.Printer
            Provider   = $(if ($props -and $props.PSObject.Properties['Provider']) { '{0}' -f $props.Provider } else { $null })
        })
    }
    if ($unread) {
        $script:UserHiveReadError = $true
        Add-Warning ('Printer connections: the values of {0} connection key(s) under {1} could not be read, so Server and Provider are blank on those rows.' -f $unread, $k)
    }
    @($rows)
} -Default @())

# ---- policy-deployed connection names (machine + user) and GPP hints
$policyNames = @(Invoke-Section 'Policy-deployed printers' {
    $names = New-Object System.Collections.Generic.List[string]
    $paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\Connections',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Group Policy\PrinterConnections'
    )
    if ($userHive) {
        $paths += (Join-Path $userHive 'Software\Policies\Microsoft\Windows NT\Printers\Connections')
        $paths += (Join-Path $userHive 'Software\Microsoft\Windows NT\CurrentVersion\Group Policy\PrinterConnections')
    }
    foreach ($p in $paths) { foreach ($n in (Get-PolicyConnectionName -KeyPath $p)) { $names.Add($n) } }
    @($names)
} -Default @())

$gppHints = @(Invoke-Section 'Group Policy Preferences printer history' {
    $hints = New-Object System.Collections.Generic.List[string]
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History',
        'HKLM:\SOFTWARE\Microsoft\Group Policy\History'
    )
    if ($userHive) {
        $roots += (Join-Path $userHive 'Software\Microsoft\Windows\CurrentVersion\Group Policy\History')
        $roots += (Join-Path $userHive 'Software\Microsoft\Group Policy\History')
    }
    foreach ($r in $roots) { foreach ($h in (Get-GppPrinterHint -HistoryRoot $r)) { $hints.Add($h) } }
    @($hints)
} -Default @())

# ---- ports (collected in full so PortName -> address can be resolved, filtered for output below)
$allPortObjects = @(Invoke-Section 'Printer ports' { @(Get-PrinterPort -ErrorAction Stop) } -Default @())
$portAddress = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($p in $allPortObjects) {
    if ($p.Name -and $p.PrinterHostAddress) { $portAddress[[string]$p.Name] = '{0}' -f $p.PrinterHostAddress }
}

# ---- print server reachability. Get-Printer and Win32_Printer enumerate every connection with no timeout of
# their own, so a decommissioned print server is the one thing that can stretch this run. We cannot give those
# cmdlets a timeout, but we can name the dead server instead of leaving the tech guessing why it was slow.
$deadServers = @(Invoke-Section 'Print server reachability' {
    $servers = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($uc in @($o.UserConnections)) {
        $s = $null
        if ($uc.Server) { $s = ('{0}' -f $uc.Server) -replace '^\\\\', '' }
        if ($s) { [void]$servers.Add($s) }
    }
    $dead = New-Object System.Collections.Generic.List[string]
    foreach ($s in $servers) { if (-not (Test-TcpPort -ComputerName $s -Port 445 -TimeoutMs 3000)) { $dead.Add($s) } }
    @($dead)
} -Default @())
if ($deadServers.Count) {
    Add-Warning ('Print server(s) not answering on TCP 445: {0}. Queues on those servers explain a slow run, and their rows may be incomplete or show as offline.' -f ($deadServers -join ', '))
}

# ---- printers
$printerObjects = @(Invoke-Section 'Printer list (Get-Printer)' { @(Get-Printer -ErrorAction Stop) } -Default @())

$o.Printers = @(Invoke-Section 'Printers' {
    $rows = New-Object System.Collections.Generic.List[psobject]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $policySet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $policyNames) { if ($n) { [void]$policySet.Add($n) } }

    foreach ($p in $printerObjects) {
        $name = '{0}' -f $p.Name
        [void]$seen.Add($name)
        $type = '{0}' -f $p.Type
        $isPolicy = $policySet.Contains($name) -or (Test-GppHintMatch -Hints $gppHints -PrinterName $name)
        if ($type -eq 'Connection') { $source = $(if ($isPolicy) { 'User connection (GPO)' } else { 'User connection' }) }
        else                        { $source = $(if ($isPolicy) { 'Local (GPO/GPP deployed)' } else { 'Local' }) }
        $rows.Add([PSCustomObject]@{
            Name        = $name
            DriverName  = '{0}' -f $p.DriverName
            PortName    = '{0}' -f $p.PortName
            PortAddress = $(if ($p.PortName -and $portAddress.ContainsKey([string]$p.PortName)) { $portAddress[[string]$p.PortName] } else { $null })
            Type        = $type
            Shared      = [bool]$p.Shared
            Published   = [bool]$p.Published
            Status      = '{0}' -f $p.PrinterStatus
            JobCount    = [int]$p.JobCount
            Source      = $source
            IsDefault   = [bool]($o.DefaultPrinter -and $name -eq $o.DefaultPrinter)
        })
    }

    # Connections that belong to the console user but are invisible to this process (tech elevated with
    # their own account): registry only, so driver/port/status/job count stay blank rather than wrong.
    foreach ($uc in $o.UserConnections) {
        $name = '{0}' -f $uc.Connection
        if (-not $name -or $seen.Contains($name)) { continue }
        [void]$seen.Add($name)
        $isPolicy = $policySet.Contains($name) -or (Test-GppHintMatch -Hints $gppHints -PrinterName $name)
        $rows.Add([PSCustomObject]@{
            Name        = $name
            DriverName  = $null
            PortName    = $null
            PortAddress = $null
            Type        = 'Connection'
            Shared      = $null
            Published   = $null
            Status      = '(registry only)'
            JobCount    = $null
            Source      = $(if ($isPolicy) { 'User connection (GPO)' } else { 'User connection' })
            IsDefault   = [bool]($o.DefaultPrinter -and $name -eq $o.DefaultPrinter)
        })
    }
    @($rows)
} -Default @())
$o.PrinterCount = [int]@($o.Printers).Count

if ($gppHints.Count -and -not @($o.Printers | Where-Object { $_.Source -like '*GPO*' -or $_.Source -like '*GPP*' }).Count) {
    Add-Warning 'Group Policy applied a printer client-side extension on this machine but no printer name could be matched to it: check the GPO/GPP printer items by hand before assuming a printer was user-added.'
}

# ---- stuck jobs (only queues that report a job; an offline server can make Get-PrintJob slow)
$o.StuckJobs = Invoke-Section 'Print jobs' {
    $busy = @($printerObjects | Where-Object { [int]$_.JobCount -gt 0 })
    if (-not $busy.Count) { return 0 }
    $cut   = [DateTime]::Now.AddHours(-[math]::Abs($StuckJobHours))
    $stuck = 0
    foreach ($p in $busy) {
        $jobs = @(Invoke-Section ('Print jobs on {0}' -f $p.Name) {
            @(Get-PrintJob -PrinterName $p.Name -ErrorAction Stop)
        } -Default @())
        foreach ($j in $jobs) {
            $status = '{0}' -f $j.JobStatus
            $old    = ($j.SubmittedTime -is [datetime]) -and ($j.SubmittedTime -lt $cut)
            if ($status -match $stuckPattern -or $old) { $stuck++ }
        }
    }
    [int]$stuck
}
if ($o.StuckJobs -gt 0) {
    Add-Warning ('{0} print job(s) are in an error state or older than {1} hour(s).' -f $o.StuckJobs, [math]::Abs($StuckJobHours))
}

# ---- "Use Printer Offline" is a per-queue flag that PrinterStatus does not expose
$offlineQueues = @(Invoke-Section 'Use Printer Offline flag' {
    @(Get-CimInstance Win32_Printer -ErrorAction Stop | Where-Object { $_.WorkOffline } | ForEach-Object { '{0}' -f $_.Name })
} -Default @())
if ($offlineQueues.Count) {
    Add-Warning ('"Use Printer Offline" is ticked on: {0}. Clear it from the queue window before chasing anything else.' -f ($offlineQueues -join ', '))
}

# ---- drivers
$o.Drivers = @(Invoke-Section 'Drivers' {
    $drivers = @(Get-PrinterDriver -ErrorAction Stop)
    $rows = New-Object System.Collections.Generic.List[psobject]
    foreach ($d in $drivers) {
        $name  = '{0}' -f $d.Name
        $major = $null
        if ($null -ne $d.MajorVersion) { $major = [int]$d.MajorVersion }
        $type = switch ($major) { 3 { 'Type 3' } 4 { 'Type 4 (v4)' } default { $(if ($null -eq $major) { $null } else { 'Type {0}' -f $major }) } }
        $sig  = Get-DriverSignature -Driver $d
        $rows.Add([PSCustomObject]@{
            Name          = $name
            Manufacturer  = '{0}' -f $d.Manufacturer
            DriverVersion = ConvertTo-DriverVersionString $d.DriverVersion
            Type          = $type
            Environment   = '{0}' -f $d.PrinterEnvironment
            PrinterCount  = [int]@($printerObjects | Where-Object { ('{0}' -f $_.DriverName) -eq $name }).Count
            Signed        = $sig.Signed
            Signer        = $sig.Signer
        })
    }
    @($rows)
} -Default @())

$unsigned = @($o.Drivers | Where-Object { $_.Signed -eq $false })
if ($unsigned.Count) { Add-Warning ('Unsigned or untrusted printer driver(s): {0}.' -f (($unsigned | ForEach-Object { $_.Name }) -join ', ')) }

# ---- ports (output view)
$o.Ports = @(Invoke-Section 'Ports' {
    $used = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $printerObjects) { if ($p.PortName) { [void]$used.Add([string]$p.PortName) } }
    $rows = New-Object System.Collections.Generic.List[psobject]
    foreach ($p in $allPortObjects) {
        $name  = '{0}' -f $p.Name
        $class = $null
        try { $class = '{0}' -f $p.CimClass.CimClassName } catch { }
        $interesting = $used.Contains($name) -or $p.PrinterHostAddress -or ($class -and $class -ne 'MSFT_LocalPrinterPort')
        if (-not $AllPorts -and -not $interesting) { continue }
        $rows.Add([PSCustomObject]@{
            Name               = $name
            Description        = '{0}' -f $p.Description
            PrinterHostAddress = $(if ($p.PrinterHostAddress) { '{0}' -f $p.PrinterHostAddress } else { $null })
            PortNumber         = $(if ($null -ne $p.PortNumber) { [int]$p.PortNumber } else { $null })
            Protocol           = $(if ($null -ne $p.Protocol) { '{0}' -f $p.Protocol } else { $null })
            SnmpEnabled        = $(if ($null -ne $p.SNMPEnabled) { [bool]$p.SNMPEnabled } else { $null })
            PortMonitor        = '{0}' -f $p.PortMonitor
            InUse              = [bool]$used.Contains($name)
        })
    }
    @($rows)
} -Default @())
if (-not $AllPorts -and $allPortObjects.Count -gt @($o.Ports).Count) {
    Add-Warning ('Ports: {0} unused local placeholder port(s) (COM/LPT/FILE) hidden - run with -AllPorts to list all {1}.' -f ($allPortObjects.Count - @($o.Ports).Count), $allPortObjects.Count)
}

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Printing health: the Print Spooler service, installed printers and their status, stuck print jobs, default printer, drivers, ports and printer security policy (Point and Print).'
$script:SummaryNext = @(
    'One job stuck: cancel it in the print queue (Settings > Printers & scanners > the printer > Open print queue). Whole queue jammed or the spooler keeps stopping: run Printing - Reset Print Queue.',
    'After a fix, print a test page (Settings > Printers & scanners > the printer > Print test page) and check that it comes out.',
    'Printer offline: check that it is on, has paper and is on the network (print its network settings page, or open its IP address in a browser).'
)
function Add-SummaryFindings {
    param($R)
    $warn = @($script:Warnings)
    if ($R.SpoolerStatus -and $R.SpoolerStatus -ne 'Running') { Add-Finding Problem ('The Print Spooler service is {0}{1}, so nothing can print.' -f $R.SpoolerStatus, $(if ($R.SpoolerStartMode -eq 'Disabled') { ' and disabled' } else { '' })) $(if ($R.SpoolerStartMode -eq 'Disabled') { 'Find out who disabled it (policy or security hardening) before turning it back on.' } else { 'Run Printing - Reset Print Queue, which restarts the spooler.' }) }
    elseif ($R.SpoolerStatus -eq 'Running') { Add-Finding OK ('The Print Spooler service is running; {0} installed.' -f (Format-Count $R.PrinterCount 'printer' 'printers')) }
    if ($R.StuckJobs -gt 0) { Add-Finding Problem ('{0} in an error state or waiting too long.' -f (Format-Count $R.StuckJobs 'print job is' 'print jobs are')) 'Cancel it in the print queue (Settings > Printers & scanners > the printer > Open print queue); if the queue stays jammed, run Printing - Reset Print Queue.' }
    elseif ($R.StuckJobs -eq 0) { Add-Finding OK 'No stuck print jobs.' }
    foreach ($w in @($warn | Where-Object { $_ -like '"Use Printer Offline" is ticked on*' })) { Add-Finding Problem ($w -replace ' Clear it from the queue window before chasing anything else\.$', '') 'Open the printer''s queue window and untick Printer > Use Printer Offline.' }
    foreach ($p in @($R.Printers | Where-Object { $_.Status -and $_.Status -notin 'Normal', '(registry only)' })) { Add-Finding Problem ('Printer {0} reports: {1}.' -f $p.Name, $p.Status) 'Check that the printer is on, has paper and no error on its screen, and is reachable on the network.' }
    foreach ($w in @($warn | Where-Object { $_ -like 'Print server(s) not answering*' })) { Add-Finding Problem ($w -replace ' Queues on those servers.*$', '') 'Check that the print server is up and reachable; off-site users need the VPN.' }
    $wsd = @($R.Printers | Where-Object { [string]$_.PortName -like 'WSD-*' })
    if ($wsd.Count) { Add-Finding Info ('{0} added automatically over the network (a WSD port): {1}. These often show offline after the printer''s network address changes.' -f $(if ($wsd.Count -eq 1) { '1 printer was' } else { '{0} printers were' -f $wsd.Count }), ((@($wsd | ForEach-Object { $_.Name })) -join '; ')) 'If it keeps going offline, reserve the printer''s IP address in the router, then remove it and add it again by that IP address (Add a printer > Add a printer using an IP address).' }
    if ($R.DefaultPrinter) { Add-Finding Info ('Default printer: {0}.' -f $R.DefaultPrinter) }
    foreach ($w in $warn) {
        if ($w -like 'No default printer is set*') { Add-Finding Warning $w 'Set one in Settings > Bluetooth & devices > Printers & scanners.' }
        elseif ($w -like 'Unsigned or untrusted printer driver*') { Add-Finding Warning $w 'Replace it with the manufacturer''s current signed driver or a Microsoft class driver.' }
        elseif ($w -like 'Point and Print:*') { Add-Finding Warning ($w -replace '^Point and Print:\s*', 'Point and Print policy: ') 'This weakens protection against malicious printer drivers. Confirm with the site that it is intended.' }
        elseif ($w -like 'Spool folder contents: (needs admin)*') { Add-Finding NotChecked 'The spool folder (waiting print files) could not be read without admin rights.' 'Run Printing - Check Printers.cmd again and approve the admin prompt.' }
        elseif ($w -match '^("Use Printer Offline"|Print server\(s\) not answering|Print Spooler is|Print Spooler start mode|No default printer|Ports: \d+ unused local placeholder|Other signed-in desktops|\d+ print job)') { continue }
        elseif ($w -like 'Running as *') { Add-Finding Info $w }
        else { Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.' }
    }
}

# ---------------------------------------------------------------- output
$o.Warnings = ($script:Warnings -join '; ')          # shape A only
$result = [PSCustomObject]$o
if ($Display) { try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }; $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext }
else          { $result }
