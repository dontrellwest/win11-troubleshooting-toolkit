<#
.SYNOPSIS
    Mapped drives, persistent drive mappings and stored Windows credentials for the signed-in user, with reachability and credential age.
.DESCRIPTION
    Lists every live mapped drive (Get-SmbMapping, net use as fallback) with SMB port 445 and path reachability, every persistent
    mapping saved in the user's registry hive (Network key), and every Credential Manager entry (cmdkey, vaultcmd and the
    Credential Manager API) with LastWritten and AgeDays. One flat row per item, cross-referenced by host.
    For "drive missing after logon", "access denied after a password change" and "multiple connections to a server" tickets.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER TargetUser
    DOMAIN\user to report on instead of the console user. Live mappings and credentials are only visible when the tool runs as that user.
.EXAMPLE
    .\Check-Mapped-Drives.ps1
.EXAMPLE
    .\Check-Mapped-Drives.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Check-Mapped-Drives.ps1 | Where-Object { $_.Kind -eq 'Stored credential' -and $_.AgeDays -gt 90 }
.NOTES
    Toolkit-Class:     ReadOnly
    Toolkit-Context:   User
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [string]$TargetUser
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-Mapped-Drives'          # <-- set per tool
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
$now     = [DateTime]::Now
$console = Get-ConsoleUser -OverrideName $TargetUser
$isMe    = [bool]$console.IsMe
if ($console.OtherDesktops -and -not $TargetUser) {
    Add-Warning ("Other desktops on this machine: {0}. Results describe {1}; pass -TargetUser DOMAIN\user if the ticket is about someone else" -f $console.OtherDesktops, $console.Name)
}

# One flat row; every Kind carries the same property set (shape B).
function New-Row {
    param([string]$Kind)
    [ordered]@{
        ComputerName     = $env:COMPUTERNAME
        CollectedAt      = $now
        TargetUser       = $console.Name
        RunningAs        = $console.RunningAs
        TargetSource     = $console.Source
        Kind             = $Kind
        Letter           = $null
        RemotePath       = $null
        Host             = $null
        Port445Reachable = $null
        PathReachable    = $null
        Status           = $null
        Persistent       = $null
        Source           = $null
        CredentialTarget = $null
        CredentialUser   = $null
        CredentialType   = $null
        LastWritten      = $null
        AgeDays          = $null
        Detail           = $null
    }
}

function Get-UncHost { param([string]$Path) if ($Path -match '^\\\\([^\\]+)\\') { $Matches[1] } else { $null } }

$script:PortCache = @{}
function Test-Port445 {
    param([string]$HostName)
    if (-not $HostName) { return $null }
    $k = $HostName.ToLower()
    if (-not $script:PortCache.ContainsKey($k)) { $script:PortCache[$k] = [bool](Test-TcpPort -ComputerName $HostName -Port 445) }
    $script:PortCache[$k]
}

# Credential Manager API (advapi32 CredEnumerate). Same store cmdkey lists, but with the LastWritten timestamp.
# Reads TargetName / UserName / Type / Persist / LastWritten only; the secret blob is never touched.
$credApiSource = @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class ToolkitCredList {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public uint Flags; public uint Type; public IntPtr TargetName; public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount;
        public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr pCredentials);
    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
    // One "type|persist|lastWrittenFileTime|targetName|userName" string per credential (flags=1 gives cmdkey-style target names).
    public static string[] List() {
        uint count; IntPtr ptr;
        if (!CredEnumerate(null, 1, out count, out ptr)) {
            int err = Marshal.GetLastWin32Error();
            if (err == 1168) return new string[0]; // ERROR_NOT_FOUND: no credentials stored
            throw new System.ComponentModel.Win32Exception(err);
        }
        var list = new List<string>();
        try {
            for (int i = 0; i < count; i++) {
                IntPtr p = Marshal.ReadIntPtr(ptr, i * IntPtr.Size);
                CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
                long ft = ((long)c.LastWritten.dwHighDateTime << 32) | ((uint)c.LastWritten.dwLowDateTime);
                string t = c.TargetName == IntPtr.Zero ? "" : Marshal.PtrToStringUni(c.TargetName);
                string u = c.UserName == IntPtr.Zero ? "" : Marshal.PtrToStringUni(c.UserName);
                list.Add(c.Type + "|" + c.Persist + "|" + ft + "|" + t + "|" + u);
            }
        } finally { CredFree(ptr); }
        return list.ToArray();
    }
}
'@
$credTypeNames    = @{ 1 = 'Generic'; 2 = 'Domain Password'; 3 = 'Certificate'; 4 = 'Domain Visible Password'; 5 = 'Generic Certificate'; 6 = 'Domain Extended' }
$credPersistNames = @{ 1 = 'Saved for this logon only'; 2 = 'Local machine persistence'; 3 = 'Enterprise persistence' }

function ConvertTo-CredentialType {
    param([string]$Text)
    if (-not $Text) { return $null }
    if ($Text -match 'Certificate') { 'Certificate' } else { $Text.Trim() }
}

# ---------------------------------------------------------------- 1. live mappings (per logon session: only meaningful when IsMe)
$live = @(); $script:LiveOk = $false
if (-not $isMe) {
    Add-Warning ("Live mappings: live mappings not visible from another account; showing registry mappings only (running as {0}, target {1}). Session-only GPP/logon-script drives and their Status are unknown" -f $console.RunningAs, $console.Name)
} else {
    $live = @(Invoke-Section 'Live mappings (Get-SmbMapping)' {
        $found = @(Get-SmbMapping -ErrorAction Stop)
        $script:LiveOk = $true
        foreach ($m in $found) {
            $letter = $null
            if ($m.LocalPath) { $letter = ([string]$m.LocalPath).Trim().TrimEnd('\').ToUpper() }
            [PSCustomObject]@{ Letter = $letter; RemotePath = [string]$m.RemotePath; Status = [string]$m.Status }
        }
    } -Default @())
    if (-not $script:LiveOk) {
        $live = @(Invoke-Section 'Live mappings (net use)' {
            $n = Invoke-Native -FilePath 'net.exe' -ArgumentList @('use')
            if ($n.ExitCode -ne 0) { throw ("net use exit {0}: {1}" -f $n.ExitCode, (@($n.Lines | Where-Object { $_.Trim() })[-1])) }
            $script:LiveOk = $true
            foreach ($line in $n.Lines) {
                if ($line -match '^\s*(\S*)\s+([A-Za-z]):\s+(\\\\\S+)') {
                    $st = $Matches[1]; if (-not $st) { $st = 'Unknown' }
                    [PSCustomObject]@{ Letter = ($Matches[2].ToUpper() + ':'); RemotePath = $Matches[3]; Status = $st }
                }
            }
        } -Default @())
    }
}

# Which account each live connection uses (the "multiple connections to a server" clue). Same per-session limit.
$connByLetter = @{}
if ($isMe) {
    Invoke-Section 'Connection accounts (Win32_NetworkConnection)' {
        foreach ($c in @(Get-CimInstance Win32_NetworkConnection -ErrorAction Stop)) {
            if ($c.LocalName) { $connByLetter[([string]$c.LocalName).Trim().ToUpper()] = [string]$c.UserName }
        }
    } | Out-Null
}

# ---------------------------------------------------------------- 2. persistent mappings (registry: <hive>\Network\<letter>)
$reg = @(); $script:RegOk = $false
$hivePath = $null
if ($console.Hive) { $hivePath = $console.Hive } elseif ($isMe) { $hivePath = 'HKCU:' }
if (-not $hivePath) {
    Add-Warning ("Persistent mappings: registry hive of {0} is not loaded (user not signed in); Letter, RemotePath, Persistent, Source skipped. Sign the user in, or pass -TargetUser for a signed-in account" -f $console.Name)
} else {
    $reg = @(Invoke-Section 'Persistent mappings (registry)' {
        $key = Join-Path $hivePath 'Network'
        if (Test-Path -LiteralPath $key) {
            foreach ($k in @(Get-ChildItem -LiteralPath $key -ErrorAction Stop)) {
                if ($k.PSChildName -notmatch '^[A-Za-z]$') { continue }
                $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
                $u = $null
                if (($p.UserName -is [string]) -and $p.UserName.Trim()) { $u = $p.UserName.Trim() }
                [PSCustomObject]@{ Letter = ($k.PSChildName.ToUpper() + ':'); RemotePath = [string]$p.RemotePath; UserName = $u; ProviderName = [string]$p.ProviderName }
            }
        }
        $script:RegOk = $true
    } -Default @())
}

# ---------------------------------------------------------------- 3. stored credentials (per user: only when IsMe)
$creds = New-Object System.Collections.Generic.List[object]   # Target, Type, User, Persistence, LastWritten
$webCount = $null
if (-not $isMe) {
    Add-Warning ("Stored credentials: cmdkey and vaultcmd only see the account running the tool ({0}); CredentialTarget, CredentialUser, CredentialType, LastWritten, AgeDays skipped for {1}. Run it signed in as the user" -f $console.RunningAs, $console.Name)
} else {
    $ckByTarget = @{}
    Invoke-Section 'Stored credentials (cmdkey)' {
        $ck = Invoke-Native -FilePath 'cmdkey.exe' -ArgumentList @('/list')
        if ($ck.ExitCode -ne 0) { throw ("cmdkey /list exit {0}: {1}" -f $ck.ExitCode, (@($ck.Lines | Where-Object { $_.Trim() })[0])) }
        $cur = $null
        foreach ($line in $ck.Lines) {
            $t = $line.Trim()
            if ($t -match '^Target:\s*(.+)$') {
                $cur = [PSCustomObject]@{ Target = $Matches[1].Trim(); Type = $null; User = $null; Persistence = $null; LastWritten = $null }
                $creds.Add($cur); $ckByTarget[$cur.Target.ToLower()] = $cur
                continue
            }
            if ($null -eq $cur) { continue }
            if     ($t -match '^Type:\s*(.+)$') { $cur.Type = $Matches[1].Trim() }
            elseif ($t -match '^User:\s*(.+)$') { $cur.User = $Matches[1].Trim() }
            elseif ($t -eq '')                  { $cur = $null }
            elseif ($t -notmatch ':')           { $cur.Persistence = $t }     # 'Local machine persistence' / 'Saved for this logon only' / 'Enterprise persistence'
        }
        if ($creds.Count -eq 0 -and -not ($ck.Lines -match 'NONE')) {
            throw ("no 'Target:' lines found (non-English Windows?). First line: {0}" -f (@($ck.Lines | Where-Object { $_.Trim() })[0]))
        }
    } | Out-Null

    $vaultByResource = @{}
    Invoke-Section 'Stored credentials (vaultcmd)' {
        $v = Invoke-Native -FilePath 'vaultcmd.exe' -ArgumentList @('/listcreds:Windows Credentials', '/all')
        if ($v.ExitCode -ne 0) { throw ("vaultcmd exit {0}: {1}" -f $v.ExitCode, (@($v.Lines | Where-Object { $_.Trim() })[0])) }
        if (-not ($v.Lines -match '^Credentials in vault')) { throw ("unexpected vaultcmd output (non-English Windows?): {0}" -f (@($v.Lines | Where-Object { $_.Trim() })[0])) }
        $cur = $null; $badDate = $false
        foreach ($line in $v.Lines) {
            $t = $line.Trim()
            if ($t -match '^Credential schema:\s*(.*)$') { $cur = [PSCustomObject]@{ Schema = $Matches[1].Trim(); Resource = $null; Identity = $null; LastWritten = $null }; continue }
            if ($null -eq $cur) { continue }
            if     ($t -match '^Resource:\s*(.*)$') { $cur.Resource = $Matches[1].Trim(); if ($cur.Resource) { $vaultByResource[$cur.Resource.ToLower()] = $cur } }
            elseif ($t -match '^Identity:\s*(.*)$') { $cur.Identity = $Matches[1].Trim() }
            elseif ($t -match '^Last Written:\s*(.+)$') {
                $s = $Matches[1].Trim(); $d = $null
                try { $d = [DateTime]::Parse($s, [Globalization.CultureInfo]::CurrentCulture) }
                catch { try { $d = [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture) } catch { $badDate = $true } }
                $cur.LastWritten = $d
            }
        }
        if ($badDate) { Add-Warning "vaultcmd: could not parse one or more 'Last Written:' dates" }
    } | Out-Null

    $webCount = Invoke-Section 'Web credentials (vaultcmd)' {
        $v = Invoke-Native -FilePath 'vaultcmd.exe' -ArgumentList @('/listcreds:Web Credentials', '/all')
        if ($v.ExitCode -ne 0) { throw ("vaultcmd exit {0}: {1}" -f $v.ExitCode, (@($v.Lines | Where-Object { $_.Trim() })[0])) }
        if (-not ($v.Lines -match '^Credentials in vault')) { throw ("unexpected vaultcmd output (non-English Windows?): {0}" -f (@($v.Lines | Where-Object { $_.Trim() })[0])) }
        [int]@($v.Lines | Where-Object { $_.Trim() -match '^Resource:' }).Count
    }

    $apiByTarget = @{}
    Invoke-Section 'Stored credentials (Credential Manager API; LastWritten falls back to vaultcmd only)' {
        if (-not ('ToolkitCredList' -as [type])) { Add-Type -TypeDefinition $credApiSource -ErrorAction Stop }
        foreach ($s in @([ToolkitCredList]::List())) {
            $f = $s -split '\|', 5
            $lw = $null
            if ([int64]$f[2] -gt 0) { $lw = [DateTime]::FromFileTime([int64]$f[2]) }
            $apiByTarget[$f[3].ToLower()] = [PSCustomObject]@{ Type = [int]$f[0]; Persist = [int]$f[1]; LastWritten = $lw; Target = $f[3]; User = $f[4] }
        }
    } | Out-Null

    # Merge: cmdkey rows first; vaultcmd and the API fill LastWritten/User; entries only one source saw are still listed.
    foreach ($c in $creds) {
        $k = $c.Target.ToLower()
        if ($vaultByResource.ContainsKey($k) -and $vaultByResource[$k].LastWritten) { $c.LastWritten = $vaultByResource[$k].LastWritten }
        elseif ($apiByTarget.ContainsKey($k)) { $c.LastWritten = $apiByTarget[$k].LastWritten }
        if (-not $c.User -and $vaultByResource.ContainsKey($k) -and $vaultByResource[$k].Identity) { $c.User = $vaultByResource[$k].Identity }
        if (-not $c.User -and $apiByTarget.ContainsKey($k) -and $apiByTarget[$k].User) { $c.User = $apiByTarget[$k].User }
        if (-not $c.Persistence -and $apiByTarget.ContainsKey($k)) { $c.Persistence = $credPersistNames[$apiByTarget[$k].Persist] }
    }
    foreach ($k in @($apiByTarget.Keys)) {
        if ($ckByTarget.ContainsKey($k)) { continue }
        $a = $apiByTarget[$k]
        $creds.Add([PSCustomObject]@{ Target = $a.Target; Type = $credTypeNames[$a.Type]; User = $a.User; Persistence = $credPersistNames[$a.Persist]; LastWritten = $a.LastWritten })
        $ckByTarget[$k] = $true
    }
    foreach ($k in @($vaultByResource.Keys)) {
        if ($ckByTarget.ContainsKey($k)) { continue }
        $v = $vaultByResource[$k]
        $type = 'Generic'
        if ($v.Schema -match 'Certificate') { $type = 'Certificate' } elseif ($v.Schema -match 'Domain') { $type = 'Domain Password' }
        $creds.Add([PSCustomObject]@{ Target = $v.Resource; Type = $type; User = $v.Identity; Persistence = $null; LastWritten = $v.LastWritten })
    }
}

# ---------------------------------------------------------------- 4. rows
$rows = New-Object System.Collections.Generic.List[object]
$driveRows = New-Object System.Collections.Generic.List[object]

$regByLetter = @{}
foreach ($r in $reg) { $regByLetter[$r.Letter] = $r }
$seen = @{}

foreach ($m in ($live | Sort-Object Letter)) {
    $row = New-Row 'Mapped drive'
    $row.Letter = $m.Letter; $row.RemotePath = $m.RemotePath; $row.Host = Get-UncHost $m.RemotePath; $row.Status = $m.Status
    $detail = @()
    $r = $null
    if ($m.Letter -and $regByLetter.ContainsKey($m.Letter)) { $r = $regByLetter[$m.Letter]; $seen[$m.Letter] = $true }
    if ($r) {
        $row.Persistent = $true; $row.Source = 'Registry'
        $detail += 'Reconnects at logon (saved in registry)'
        if ($r.UserName) { $detail += ('saved with user {0}' -f $r.UserName) }
        if ($r.RemotePath -and ($r.RemotePath -ne $m.RemotePath)) { $detail += ('registry points to {0}' -f $r.RemotePath) }
    } else {
        $row.Persistent = $false; $row.Source = 'Session (likely GPP/logon script)'
        $detail += 'Not in registry: mapped by GPP, a logon script or net use without /persistent; returns only when that runs again'
    }
    if ($m.Letter -and $connByLetter.ContainsKey($m.Letter) -and $connByLetter[$m.Letter]) { $detail += ('connected as {0}' -f $connByLetter[$m.Letter]) }
    $row.Detail = ($detail -join '; ')
    $driveRows.Add($row)
}
foreach ($r in ($reg | Sort-Object Letter)) {
    if ($seen.ContainsKey($r.Letter)) { continue }
    $row = New-Row 'Persistent mapping'
    $row.Letter = $r.Letter; $row.RemotePath = $r.RemotePath; $row.Host = Get-UncHost $r.RemotePath
    $row.Persistent = $true; $row.Source = 'Registry'
    if ($script:LiveOk) { $row.Status = 'Registry only (not currently mapped)' } else { $row.Status = 'Registry only (live state not visible)' }
    $detail = @('Windows tries to reconnect this letter at every logon')
    if ($r.UserName) { $detail += ('saved with user {0}' -f $r.UserName) }
    if ($r.ProviderName -and $r.ProviderName -notmatch 'Microsoft Windows Network') { $detail += ('provider {0}' -f $r.ProviderName) }
    $row.Detail = ($detail -join '; ')
    $driveRows.Add($row)
}

# Reachability: one TCP probe per host (3 s timeout), Test-Path only when 445 answered.
foreach ($row in $driveRows) {
    $row.Port445Reachable = Test-Port445 $row.Host
    if ($row.Port445Reachable -and $row.RemotePath) {
        $pr = Invoke-Section ('Path check {0}' -f $row.RemotePath) { Test-Path -LiteralPath $row.RemotePath -ErrorAction Stop }
        if ($null -ne $pr) { $row.PathReachable = [bool]$pr }
    }
}
if (-not $isMe -and $driveRows.Count) { Add-Warning ("PathReachable was tested with {0}'s access, not {1}'s" -f $console.RunningAs, $console.Name) }

# Credential rows, cross-referenced with the drive hosts.
$credRows = New-Object System.Collections.Generic.List[object]
foreach ($c in @($creds | Sort-Object @{e={ $_.Type -notmatch 'Domain|Certificate' }}, Target)) {
    $row = New-Row 'Stored credential'
    $row.CredentialTarget = $c.Target
    if ($c.User) { $row.CredentialUser = $c.User }
    $row.CredentialType = ConvertTo-CredentialType $c.Type
    $row.Source = 'Credential Manager'
    if ($row.CredentialType -match 'Domain|Certificate') {
        $h = $c.Target
        if ($h -match '^[^:]+:target=(.+)$') { $h = $Matches[1] }
        $h = ($h -replace '^TERMSRV/', '').TrimStart('\')
        if ($h) { $row.Host = $h }
    }
    if ($c.LastWritten) { $row.LastWritten = [DateTime]$c.LastWritten; $row.AgeDays = Round1 (($now - $row.LastWritten).TotalDays) }
    if ($c.Persistence) { $row.Persistent = ($c.Persistence -notmatch 'this logon only') }
    $detail = @()
    if ($c.Persistence) { $detail += $c.Persistence }
    if ($row.Host) {
        $used = @($driveRows | Where-Object { $_.Host -and ($_.Host -like $row.Host) } | ForEach-Object { $_.Letter })
        if ($used.Count) { $detail += ('used by drive {0}' -f ($used -join ', ')) }
    }
    if (-not $row.LastWritten) { $detail += 'LastWritten unavailable' }
    $row.Detail = ($detail -join '; ')
    $credRows.Add($row)
}
if ($isMe) {
    foreach ($row in $driveRows) {
        if (-not $row.Host) { continue }
        $match = @($credRows | Where-Object { $_.Host -and ($row.Host -like $_.Host) })
        if ($match.Count) {
            $txt = @($match | ForEach-Object { if ($_.AgeDays -ne $null) { '{0} ({1}, {2} days old)' -f $_.CredentialUser, $_.CredentialType, $_.AgeDays } else { '{0} ({1})' -f $_.CredentialUser, $_.CredentialType } }) -join ', '
            $row.Detail = (@($row.Detail, ('stored credential for this host: {0}' -f $txt)) | Where-Object { $_ }) -join '; '
        } else {
            $row.Detail = (@($row.Detail, 'no stored credential for this host (uses the logon token)') | Where-Object { $_ }) -join '; '
        }
    }
}
if ($null -ne $webCount -and $webCount -gt 0) {
    $row = New-Row 'Stored credential'
    $row.CredentialTarget = '(Web Credentials vault)'; $row.CredentialType = 'Web'; $row.Source = 'Credential Manager'
    $row.Detail = ('{0} web credential(s) stored (browser/app sign-ins; not listed individually)' -f $webCount)
    $credRows.Add($row)
}

foreach ($r in $driveRows) { $rows.Add([PSCustomObject]$r) }
foreach ($r in $credRows)  { $rows.Add([PSCustomObject]$r) }
if ($rows.Count -eq 0) { Add-Warning ("Nothing found for {0}: no mapped drives, no persistent mappings, no stored credentials (see other warnings for anything that could not be read)" -f $console.Name) }

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Mapped drives, drive mappings saved to reconnect at sign-in, and saved Windows passwords (Credential Manager) for the signed-in user, with whether each file server and share can be reached.'
$script:SummaryNext = @(
    'Drive missing or showing a red X: open it in File Explorer to reconnect, or map it again (File Explorer > This PC > Map network drive).',
    'Access denied after a password change: remove the old saved password for that server in Control Panel > Credential Manager > Windows Credentials, then reconnect the drive.',
    'Drive that comes from Group Policy is missing: run gpupdate /target:user /force, then sign out and back in.',
    'Server not reachable at all: run Network - Check Connection. Off-site users need the VPN first.'
)
function Add-SummaryFindings {
    param($Rows)
    $Rows = @($Rows)
    $first = @($Rows | Select-Object -First 1)
    if ($first.Count) { Add-Finding Info ('Checked for {0}{1}.' -f $first[0].TargetUser, $(if ($first[0].RunningAs -and $first[0].RunningAs -ne $first[0].TargetUser) { ' (tool running as {0})' -f $first[0].RunningAs } else { '' })) }
    $drives = @($Rows | Where-Object { $_.Kind -in 'Mapped drive', 'Persistent mapping' })
    foreach ($d in $drives) {
        $name = '{0} ({1})' -f $d.Letter, $d.RemotePath
        if ($d.Port445Reachable -eq $false) { Add-Finding Problem ('Drive {0}: the server {1} does not answer on the file-sharing port (445).' -f $name, $d.Host) 'Check that the server is on and reachable (VPN when off-site), then open the drive in File Explorer to reconnect it.' }
        elseif ($d.PathReachable -eq $false) { Add-Finding Problem ('Drive {0}: the server answers but the share cannot be opened.' -f $name) 'Usually a permission or saved-password problem: check the share permissions, remove any old saved password for this server in Credential Manager, then reconnect.' }
        elseif ($d.Kind -eq 'Persistent mapping' -and $d.Status -like '*not currently mapped*') { Add-Finding Warning ('Drive {0} is saved to reconnect at sign-in but is not connected now.' -f $name) 'Open it in File Explorer to reconnect, or disconnect it (right-click > Disconnect) if the share no longer exists.' }
        elseif ($d.Kind -eq 'Mapped drive' -and $d.Status -and $d.Status -notmatch '^(OK|Connected)$') { Add-Finding Warning ('Drive {0} shows as {1}.' -f $name, $d.Status) 'Open it in File Explorer to reconnect; if that fails, disconnect it and map it again.' }
        elseif ($d.PathReachable) { Add-Finding OK ('Drive {0} is reachable.' -f $name) }
        if ($d.Kind -eq 'Mapped drive' -and $d.Persistent -eq $false) { Add-Finding Info ('Drive {0} comes from Group Policy or a logon script, so it returns only when that runs again.' -f $d.Letter) 'If it is missing after sign-in, run gpupdate /target:user /force, then sign out and back in.' }
    }
    $creds = @($Rows | Where-Object { $_.Kind -eq 'Stored credential' -and $_.CredentialType -ne 'Web' })
    if ($creds.Count) {
        # Most entries are app sign-in tokens; the ones that break drives and remote desktops are the server ones.
        $servers = @($creds | Where-Object { [string]$_.CredentialType -match 'Domain' -or [string]$_.CredentialTarget -match 'TERMSRV/' })
        $xbox = @($creds | Where-Object { [string]$_.CredentialTarget -match 'Xbl' })
        $apps = $creds.Count - $servers.Count - $xbox.Count
        $serverNames = @($servers | ForEach-Object { ([string]$_.CredentialTarget -replace '^(Domain:target=|LegacyGeneric:target=)', '') } | Where-Object { $_ } | Select-Object -First 5)
        $parts = @($(if ($servers.Count) { '{0}{1}' -f (Format-Count $servers.Count 'for a file server or remote desktop' 'for file servers or remote desktops'), $(if ($serverNames.Count) { ' (' + ($serverNames -join ', ') + ')' } else { '' }) } else { 'none for file servers or remote desktops' }))
        if ($xbox.Count) { $parts += Format-Count $xbox.Count 'Xbox Live token' 'Xbox Live tokens' }
        if ($apps -gt 0) { $parts += Format-Count $apps 'other app sign-in' 'other app sign-ins' }
        Add-Finding Info ('{0} in Credential Manager: {1}.' -f (Format-Count $creds.Count 'saved sign-in' 'saved sign-ins'), ($parts -join '; ')) $(if ($servers.Count) { 'After a password change, saved server passwords must be updated or removed, or the user gets access denied or lockouts.' } else { '' })
    }
    if (-not $drives.Count) { Add-Finding Info 'No mapped drives or saved drive mappings for this user.' }
    foreach ($w in $script:Warnings) {
        if ($w -like 'Other desktops on this machine*') { Add-Finding Info $w }
        elseif ($w -like 'PathReachable was tested with*') { Add-Finding Info ($w + '.') }
        elseif ($w -like 'Nothing found for*') { continue }
        elseif ($w -match '^(Live mappings|Stored credentials|Persistent mappings):') { Add-Finding NotChecked $w 'Run Network - Check Mapped Drives.cmd while signed in as the affected user.' }
        else { Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.' }
    }
}

# ---------------------------------------------------------------- output (shape B: rows only; warnings to the warning stream)
$result = $rows.ToArray()
if ($Display) {
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    # Drives and saved passwords as two short tables for reading; the object output keeps every column.
    $first = @($result | Select-Object -First 1)
    $view = [PSCustomObject][ordered]@{
        TargetUser     = $(if ($first.Count) { $first[0].TargetUser } else { $null })
        RunningAs      = $(if ($first.Count) { $first[0].RunningAs } else { $null })
        Drives         = @($result | Where-Object { $_.Kind -in 'Mapped drive', 'Persistent mapping' } | Select-Object Letter, RemotePath, Status, Port445Reachable, PathReachable, Persistent, Source, Detail)
        # Xbox Live tokens (often dozens) are counted in one line so server passwords stay easy to find.
        SavedPasswords = @(@($result | Where-Object { $_.Kind -eq 'Stored credential' -and [string]$_.CredentialTarget -notmatch 'Xbl' } | Select-Object CredentialTarget, CredentialUser, CredentialType, LastWritten, AgeDays, Detail) + @($(
            $xbl = @($result | Where-Object { $_.Kind -eq 'Stored credential' -and [string]$_.CredentialTarget -match 'Xbl' }).Count
            if ($xbl) { [PSCustomObject]@{ CredentialTarget = ('({0} Xbox Live tokens not listed)' -f $xbl); CredentialUser = ''; CredentialType = ''; LastWritten = $null; AgeDays = $null; Detail = '' } }
        )))
    }
    $view | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}
else          { $result }
# With -Display the warnings appear in SUMMARY instead of as loose lines after the report.
if (-not $Display) { foreach ($w in $script:Warnings) { Write-Warning $w } }
