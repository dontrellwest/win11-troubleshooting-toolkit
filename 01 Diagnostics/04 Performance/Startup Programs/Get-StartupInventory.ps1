<#
.SYNOPSIS
    Lists everything that launches at logon or boot, with publisher and signature.
.DESCRIPTION
    One row per startup item: HKLM Run/RunOnce (64-bit and 32-bit), the console user's Run/RunOnce,
    the user and all-users Startup folders, scheduled tasks with a logon or boot trigger, and every
    Automatic service. Resolves the executable behind each entry and checks who signed it.
    Task Manager's Startup tab shows only the Run keys and Startup folders, so the task-triggered and
    service-triggered items - the ones that usually cause a slow logon - are invisible there.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER TargetUser
    DOMAIN\user to report on. Defaults to the interactive (console) user, so a tech who elevates with
    their own credentials still gets the signed-in user's startup items.
.EXAMPLE
    .\Get-StartupInventory.ps1
.EXAMPLE
    .\Get-StartupInventory.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Get-StartupInventory.ps1 | Where-Object { -not $_.IsMicrosoft -and $_.Enabled }
.NOTES
    Toolkit-Class:     ReadOnly            (ReadOnly | Remediation)
    Toolkit-Context:   User                (Machine | User)
    Toolkit-Elevation: Recommended         (Required | Recommended | None)
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
$script:ToolName  = 'Get-StartupInventory'
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
$script:SigCache     = @{}      # lower-cased path -> publisher/signature result (signature checks dominate runtime)
$script:CollectedAt  = [DateTime]::Now
$script:Console      = $null
$script:UserVarMap   = $null    # %var% -> value for the TARGET user (built once, from their profile + hive)
$script:PrincipalCtx = @{}      # task principal string -> runs in the target user's context ([bool])
$script:WarnedUserVars    = $false
$script:WarnedMachineVars = $false
# Variables whose value differs per user. These must never be expanded against this process.
$script:UserVarPattern = '%(USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|USERNAME|USERDOMAIN|HOMEDRIVE|HOMEPATH|HOMESHARE|OneDrive[A-Za-z]*)%'

function Add-WarningOnce { param([string]$Message) if (-not $script:Warnings.Contains($Message)) { $script:Warnings.Add($Message) } }

# [System.IO.File]::Exists never throws, not even on a path with illegal characters.
function Test-FileExists {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [System.IO.File]::Exists($Path) } catch { return $false }
}

# The TARGET user's per-user variables, from their profile path and their own Environment key (which is
# where OneDrive and a redirected TEMP live). Built once; never read from this process's environment.
function Get-UserVarMap {
    if ($null -ne $script:UserVarMap) { return $script:UserVarMap }
    $map = [ordered]@{}
    $profilePath = $script:Console.ProfilePath
    if ($profilePath) {
        $userName = ($script:Console.Name -split '\\')[-1]
        $domain   = $(if ($script:Console.Name -match '\\') { ($script:Console.Name -split '\\')[0] } else { $env:COMPUTERNAME })
        $drive    = ($profilePath -replace '^([A-Za-z]:).*$', '$1')
        $map['%USERPROFILE%']  = $profilePath
        $map['%APPDATA%']      = (Join-Path $profilePath 'AppData\Roaming')
        $map['%LOCALAPPDATA%'] = (Join-Path $profilePath 'AppData\Local')
        $map['%TEMP%']         = (Join-Path $profilePath 'AppData\Local\Temp')
        $map['%TMP%']          = (Join-Path $profilePath 'AppData\Local\Temp')
        $map['%HOMEDRIVE%']    = $drive
        $map['%HOMEPATH%']     = ($profilePath -replace '^[A-Za-z]:', '')
        $map['%USERNAME%']     = $userName
        $map['%USERDOMAIN%']   = $domain
        if ($script:Console.Sid) {
            $envKey = $null
            try { $envKey = [Microsoft.Win32.Registry]::Users.OpenSubKey(('{0}\Environment' -f $script:Console.Sid)) } catch { }
            if ($envKey) {
                try {
                    foreach ($n in $envKey.GetValueNames()) {
                        if ($n -notmatch '^(TEMP|TMP|OneDrive[A-Za-z]*)$') { continue }
                        $v = "$($envKey.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))"
                        if ([string]::IsNullOrWhiteSpace($v)) { continue }
                        # These values usually reference the profile themselves; resolve that with the user's paths.
                        foreach ($pair in @(@('%USERPROFILE%', $profilePath), @('%USERNAME%', $userName), @('%SystemDrive%', $drive))) {
                            $v = [regex]::Replace($v, [regex]::Escape($pair[0]), ([string]$pair[1]).Replace('$', '$$'), 'IgnoreCase')
                        }
                        if ($v -notmatch '%') { $map[('%{0}%' -f $n.ToUpperInvariant())] = $v }
                    }
                } finally { $envKey.Close() }
            }
        }
    }
    $script:UserVarMap = $map
    $map
}

# Expands %vars%. For items that run in the target user's context the USER's own variables win, so an
# elevated tech never sees their OWN profile path substituted into the signed-in user's startup command.
function Expand-StartupVars {
    param([string]$Text, [bool]$UserContext)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $s = $Text
    if ($UserContext) {
        $map = Get-UserVarMap
        foreach ($k in $map.Keys) {
            $with = ([string]$map[$k]).Replace('$', '$$')   # '$' is a substitution char in Regex.Replace
            $s = [regex]::Replace($s, [regex]::Escape($k), $with, 'IgnoreCase')
        }
    }
    # Anything per-user still left (unknown profile, an item that runs as SYSTEM or another account) must
    # NOT reach the expansion below: that reads THIS process's environment - the tech's profile when they
    # elevated with their own account - and would report a path the item never uses. Leave it literal.
    if ($s -match $script:UserVarPattern) {
        if ($UserContext) {
            if (-not $script:WarnedUserVars) {
                $script:WarnedUserVars = $true
                Add-WarningOnce ('Per-user variables could not be resolved for {0} (profile path or user hive unavailable); those commands are shown unexpanded (first: {1}).' -f $script:Console.Name, $Text)
            }
        } elseif (-not $script:WarnedMachineVars) {
            $script:WarnedMachineVars = $true
            Add-WarningOnce ('A startup item that does not run as {0} uses per-user variables; it is shown unexpanded rather than resolved against this process (first: {1}).' -f $script:Console.Name, $Text)
        }
        return $s
    }
    try { return [Environment]::ExpandEnvironmentVariables($s) } catch { return $s }
}

# True when a scheduled task runs in the target user's context: registered for that user, or for a group
# ("Users", "INTERACTIVE"), which means it runs as whoever logs on. Only then may its command be expanded
# with that user's %variables%. SYSTEM / service accounts / other users: $false.
function Test-UserContextPrincipal {
    param($Principal)
    if (-not $Principal) { return $false }
    $id = "$($Principal.UserId)".Trim()
    if ([string]::IsNullOrWhiteSpace($id)) { return (-not [string]::IsNullOrWhiteSpace("$($Principal.GroupId)".Trim())) }
    if (-not $script:Console.Sid) { return $false }
    if ($script:PrincipalCtx.ContainsKey($id)) { return $script:PrincipalCtx[$id] }
    $isUser = $false
    if ($id -match '^S-1-') {
        $isUser = ($id -eq $script:Console.Sid)
    } elseif ($id -match '^(NT AUTHORITY\\)?(SYSTEM|LOCALSYSTEM|LOCAL\s?SERVICE|NETWORK\s?SERVICE)$') {
        $isUser = $false
    } elseif ($id -eq $script:Console.Name -or $id -eq (($script:Console.Name -split '\\')[-1])) {
        $isUser = $true
    } else {
        $sid = $null
        try { $sid = ([System.Security.Principal.NTAccount]$id).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        $isUser = ($sid -and $sid -eq $script:Console.Sid)
    }
    $script:PrincipalCtx[$id] = [bool]$isUser
    [bool]$isUser
}

# A command written as a bare name (cmd, Rundll32, notepad - with or without its extension) is resolved by
# Windows from the system folders. Probe those in Windows' own search order, plus the PowerShell folder that
# is on every machine's default PATH. Never this process's own PATH or current directory.
function Resolve-SystemBinary {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name -match '[\\/]') { return $null }
    foreach ($dir in @("$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\System32\WindowsPowerShell\v1.0", "$env:SystemRoot\SysWOW64")) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        foreach ($cand in @($Name, ($Name + '.exe'), ($Name + '.com'))) {
            $try = $null
            try { $try = Join-Path $dir $cand } catch { }
            if ($try -and (Test-FileExists $try)) { return $try }
        }
    }
    $null
}

# Strips arguments from a command line. Wrappers (rundll32, cmd, msiexec) resolve to the wrapper itself.
function Resolve-ExePath {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $c = $Command.Trim()
    $exe = $null
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $exe = $c.Substring(1, $end - 1) } else { $exe = $c.Trim('"') }
    } elseif (Test-FileExists $c) {
        $exe = $c
    } else {
        # Unquoted path that contains spaces: take the shortest prefix that is a real file.
        $idx = -1
        while (($idx = $c.IndexOf(' ', $idx + 1)) -ge 0) {
            $cand = $c.Substring(0, $idx).Trim()
            if ($cand) {
                if (Test-FileExists $cand) { $exe = $cand; break }
                if (Test-FileExists ($cand + '.exe')) { $exe = $cand + '.exe'; break }
                # First token only (later prefixes contain a space, and a real path contains a separator):
                # 'cmd /c del ...' and 'Rundll32 shell32.dll,...' resolve to the system binary they name.
                $sys = Resolve-SystemBinary $cand
                if ($sys) { $exe = $sys; break }
            }
        }
        # Nothing on disk matched (uninstalled software leaves entries like this): cut at the
        # first executable extension so the whole path is still reported, not just the first word.
        if (-not $exe -and $c -match '^(.*?\.(?:exe|com|bat|cmd|scr|pif|vbs|js|ps1))(?:\s|$)') { $exe = $matches[1] }
        if (-not $exe) { $exe = (($c -split '\s+') | Select-Object -First 1) }
    }
    if (-not $exe) { return $null }
    $exe = $exe.Trim().Trim('"')
    if (-not $exe) { return $null }
    # Bare name with no directory (e.g. rundll32.exe, or 'cmd' written without its extension).
    if (($exe -notmatch '[\\/]') -and -not (Test-FileExists $exe)) {
        $sys = Resolve-SystemBinary $exe
        if ($sys) { return $sys }
    }
    # Command written without its extension (cmd, notepad).
    if (-not (Test-FileExists $exe) -and $exe -notmatch '\.[A-Za-z0-9]{1,4}$' -and (Test-FileExists ($exe + '.exe'))) { return $exe + '.exe' }
    $exe
}

# Authenticode signer CN, else VersionInfo CompanyName + '(unsigned)'. Cached: this is the slow part.
function Get-PublisherInfo {
    param([string]$Path)
    $empty = [PSCustomObject]@{ Publisher = $null; Signed = $false; IsMicrosoft = $false }
    if (-not (Test-FileExists $Path)) { return $empty }
    $key = $Path.ToLowerInvariant()
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }
    $publisher = $null; $signed = $false
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig -and "$($sig.Status)" -eq 'Valid') {
            $signed = $true
            if ($sig.SignerCertificate) {
                $publisher = $sig.SignerCertificate.GetNameInfo(
                    [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                if ([string]::IsNullOrWhiteSpace($publisher)) {
                    $subject = "$($sig.SignerCertificate.Subject)"
                    if ($subject -match 'CN="([^"]+)"') { $publisher = $matches[1] }
                    elseif ($subject -match 'CN=([^,]+)') { $publisher = $matches[1].Trim() }
                }
            }
        }
    } catch {
        Add-WarningOnce ('Signature check failed for at least one file (first: {0}): {1}' -f $Path, $_.Exception.Message.Trim())
    }
    if (-not $signed) {
        $company = $null
        try { $company = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName } catch { }
        if (-not [string]::IsNullOrWhiteSpace($company)) { $publisher = ('{0} (unsigned)' -f $company.Trim()) }
        else { $publisher = '(unsigned)' }
    }
    $result = [PSCustomObject]@{
        Publisher   = $publisher
        Signed      = [bool]$signed
        IsMicrosoft = [bool]($publisher -match 'Microsoft')
    }
    $script:SigCache[$key] = $result
    $result
}

function ConvertTo-StartupRow {
    param(
        [string]$Source, [string]$Name, [bool]$Enabled, [string]$Command, [string]$ExePath,
        $RunAs, $TaskPath, $Delay, $LastRunTime, $LastResult
    )
    $exists = Test-FileExists $ExePath
    $pub = Get-PublisherInfo -Path $ExePath
    if ([string]::IsNullOrWhiteSpace($ExePath)) { $ExePath = $null }
    if ([string]::IsNullOrWhiteSpace($Command)) { $Command = $null }
    [PSCustomObject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        CollectedAt  = $script:CollectedAt
        TargetUser   = $script:Console.Name
        RunningAs    = $script:Console.RunningAs
        Source       = $Source
        Name         = $Name
        Enabled      = [bool]$Enabled
        Command      = $Command
        ExePath      = $ExePath
        ExeExists    = [bool]$exists
        Publisher    = $pub.Publisher
        Signed       = $pub.Signed
        IsMicrosoft  = $pub.IsMicrosoft
        RunAs        = $RunAs
        TaskPath     = $TaskPath
        Delay        = $Delay
        LastRunTime  = $LastRunTime
        LastResult   = $LastResult
        TargetSource = $script:Console.Source
    }
}

# StartupApproved\<Run|Run32|StartupFolder>: first byte 0x02 = enabled, 0x03 = disabled.
function Get-ApprovalMap {
    param([Microsoft.Win32.RegistryKey]$Root, [string]$SubKey)
    $map = @{}
    $key = $null
    try { $key = $Root.OpenSubKey($SubKey) } catch { return $map }
    if (-not $key) { return $map }
    try {
        foreach ($n in $key.GetValueNames()) {
            if ([string]::IsNullOrEmpty($n)) { continue }
            $b = $key.GetValue($n)
            if ($b -is [byte[]] -and $b.Length -ge 1) { $map[$n] = [int]$b[0] }
        }
    } finally { $key.Close() }
    $map
}

function Resolve-Enabled {
    param($Map, [string]$Name)
    if ($null -eq $Map -or -not $Map.ContainsKey($Name)) { return $true }   # no entry = never toggled = enabled
    $b = [int]$Map[$Name]
    if ($b -eq 0x02) { return $true }
    if ($b -eq 0x03) { return $false }
    # Windows also writes 0x00/0x06 (enabled) and 0x01/0x07 (disabled); the low bit carries the state.
    $enabled = (($b -band 1) -eq 0)
    if ($b -notin 0x00, 0x01, 0x06, 0x07) {
        Add-WarningOnce ('StartupApproved: unexpected first byte 0x{0:X2}; read as {1}.' -f $b, $(if ($enabled) { 'Enabled' } else { 'Disabled' }))
    }
    $enabled
}

function Get-RunKeyItems {
    param([Microsoft.Win32.RegistryKey]$Root, [string]$SubKey, [string]$SourceLabel, $ApprovalMap, [bool]$UserContext)
    $rows = New-Object System.Collections.Generic.List[object]
    $key = $null
    try { $key = $Root.OpenSubKey($SubKey) } catch { return $rows }
    if (-not $key) { return $rows }
    try {
        foreach ($n in $key.GetValueNames()) {
            if ([string]::IsNullOrEmpty($n)) { continue }
            $raw = $key.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -eq $raw) { continue }
            if ($raw -isnot [string]) { $raw = ($raw -join ' ') }
            $rows.Add((ConvertTo-StartupRow -Source $SourceLabel -Name $n `
                -Enabled (Resolve-Enabled -Map $ApprovalMap -Name $n) `
                -Command $raw `
                -ExePath (Resolve-ExePath (Expand-StartupVars -Text $raw -UserContext $UserContext)) `
                -RunAs $null -TaskPath $null -Delay $null -LastRunTime $null -LastResult $null))
        }
    } finally { $key.Close() }
    $rows
}

function Get-StartupFolderItems {
    param([string]$Folder, [string]$SourceLabel, $ApprovalMap, [bool]$UserContext)
    $rows = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Folder) -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return $rows }
    $files = @(Get-ChildItem -LiteralPath $Folder -File -Force -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -ne 'desktop.ini' })
    if (-not $files.Count) { return $rows }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch {
        Add-WarningOnce ('Startup folder: WScript.Shell unavailable, .lnk targets not resolved: {0}' -f $_.Exception.Message.Trim())
    }
    try {
        foreach ($f in $files) {
            $command = $f.FullName
            $isShortcut = ($f.Extension -in '.lnk', '.url')
            $target = $null
            if ($shell -and $isShortcut) {
                try {
                    $sc = $shell.CreateShortcut($f.FullName)
                    if (-not [string]::IsNullOrWhiteSpace($sc.TargetPath)) {
                        $target = $sc.TargetPath
                        $command = $target
                        if ($f.Extension -eq '.lnk' -and -not [string]::IsNullOrWhiteSpace($sc.Arguments)) {
                            $command = '{0} {1}' -f $target, $sc.Arguments.Trim()
                        }
                    } else {
                        Add-WarningOnce ('Startup folder: "{0}" has no file target (Store app or URI shortcut); showing the shortcut path instead.' -f $f.Name)
                    }
                } catch {
                    Add-WarningOnce ('Startup folder: could not read "{0}": {1}' -f $f.Name, $_.Exception.Message.Trim())
                }
            }
            # A shortcut can point at a URL or a protocol handler; there is no .exe to check in that case.
            $exe = $null
            if ($isShortcut) {
                if ($target -and ($target -match '^[A-Za-z]:\\' -or $target.StartsWith('\\'))) {
                    $exe = Resolve-ExePath (Expand-StartupVars -Text $command -UserContext $UserContext)
                }
            } else {
                $exe = $f.FullName
            }
            $rows.Add((ConvertTo-StartupRow -Source $SourceLabel -Name $f.Name `
                -Enabled (Resolve-Enabled -Map $ApprovalMap -Name $f.Name) `
                -Command $command -ExePath $exe `
                -RunAs $null -TaskPath $null -Delay $null -LastRunTime $null -LastResult $null))
        }
    } finally {
        if ($shell) { try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch { } }
    }
    $rows
}
# ---------------------------------------------------------------- end tool-specific helpers

$script:Console = Get-ConsoleUser -OverrideName $TargetUser
$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Add-Warning 'Not elevated: scheduled tasks belonging to other users (and some SYSTEM tasks) are hidden from this account, so the task list may be short.'
}
if ($script:Console.OtherDesktops -and -not $TargetUser) {
    Add-Warning ('Other signed-in desktops found ({0}). Reporting on {1}; pass -TargetUser DOMAIN\user to switch.' -f $script:Console.OtherDesktops, $script:Console.Name)
}
if (-not $script:Console.Sid) {
    Add-Warning ('Could not resolve a SID for {0}: per-user Run keys and Startup folder were skipped.' -f $script:Console.Name)
}

$rows = New-Object System.Collections.Generic.List[object]
$hklm = [Microsoft.Win32.Registry]::LocalMachine

# --- Run / RunOnce (machine) -------------------------------------------------------------------
$machineApproval = Invoke-Section 'HKLM StartupApproved' {
    @{
        Run    = (Get-ApprovalMap -Root $hklm -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run')
        Run32  = (Get-ApprovalMap -Root $hklm -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32')
        Folder = (Get-ApprovalMap -Root $hklm -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder')
    }
} -Default @{ Run = @{}; Run32 = @{}; Folder = @{} }

foreach ($item in @(
    @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';                 Label = 'HKLM Run';             Map = $machineApproval.Run },
    @{ Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';     Label = 'HKLM Run (32-bit)';    Map = $machineApproval.Run32 },
    @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';             Label = 'HKLM RunOnce';         Map = $null },
    @{ Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'HKLM RunOnce';         Map = $null }
)) {
    $label = $item.Label
    foreach ($r in @(Invoke-Section ("Registry: " + $label) {
        Get-RunKeyItems -Root $hklm -SubKey $item.Key -SourceLabel $label -ApprovalMap $item.Map -UserContext $true
    } -Default @())) { if ($r) { $rows.Add($r) } }
}

# --- Run / RunOnce (console user's hive) -------------------------------------------------------
if ($script:Console.Sid) {
    $userRoot = Invoke-Section 'User hive' {
        [Microsoft.Win32.Registry]::Users.OpenSubKey($script:Console.Sid)
    }
    if (-not $userRoot) {
        Add-Warning ('User hive HKU:\{0} is not loaded or not readable: {1} Run/RunOnce entries were skipped. The user must be signed in (and you may need admin) to read them.' -f $script:Console.Sid, $script:Console.Name)
    } else {
        try {
            $userApproval = Invoke-Section 'User StartupApproved' {
                @{
                    Run    = (Get-ApprovalMap -Root $userRoot -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run')
                    Folder = (Get-ApprovalMap -Root $userRoot -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder')
                }
            } -Default @{ Run = @{}; Folder = @{} }

            foreach ($item in @(
                @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';     Label = 'User Run';     Map = $userApproval.Run },
                @{ Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Label = 'User RunOnce'; Map = $null }
            )) {
                $label = $item.Label
                foreach ($r in @(Invoke-Section ("Registry: " + $label) {
                    Get-RunKeyItems -Root $userRoot -SubKey $item.Key -SourceLabel $label -ApprovalMap $item.Map -UserContext $true
                } -Default @())) { if ($r) { $rows.Add($r) } }
            }

            # Folder redirection (GPO) moves the real Startup folder; report it rather than reading the wrong one.
            Invoke-Section 'Startup folder redirection check' {
                $sf = $userRoot.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
                if ($sf) {
                    try {
                        $v = $sf.GetValue('Startup', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        if ($v -and ("$v" -notmatch '^%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup$')) {
                            Add-Warning ('The user Startup folder is redirected to "{0}"; this tool reads the default profile location only.' -f $v)
                        }
                    } finally { $sf.Close() }
                }
            } | Out-Null
        } finally { $userRoot.Close() }
    }
}

# --- Startup folders ---------------------------------------------------------------------------
if ($script:Console.ProfilePath) {
    $userStartup = Join-Path $script:Console.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    if (-not (Test-Path -LiteralPath $userStartup -PathType Container)) {
        Add-Warning ('User Startup folder not found: {0}' -f $userStartup)
    } else {
        $userFolderMap = $null
        if ($userApproval) { $userFolderMap = $userApproval.Folder }
        foreach ($r in @(Invoke-Section 'Startup folder (user)' {
            Get-StartupFolderItems -Folder $userStartup -SourceLabel 'Startup folder (user)' -ApprovalMap $userFolderMap -UserContext $true
        } -Default @())) { if ($r) { $rows.Add($r) } }
    }
} else {
    Add-Warning ('Profile path for {0} is unknown: the user Startup folder was skipped.' -f $script:Console.Name)
}

$commonStartup = Invoke-Section 'Common Startup folder path' { [Environment]::GetFolderPath('CommonStartup') }
if ([string]::IsNullOrWhiteSpace($commonStartup)) { $commonStartup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp' }
if (-not (Test-Path -LiteralPath $commonStartup -PathType Container)) {
    Add-Warning ('All-users Startup folder not found: {0}' -f $commonStartup)
}
# All-users Startup runs in the signed-in user's session, so %vars% there are the USER's, not this process's.
foreach ($r in @(Invoke-Section 'Startup folder (common)' {
    Get-StartupFolderItems -Folder $commonStartup -SourceLabel 'Startup folder (common)' -ApprovalMap $machineApproval.Folder -UserContext $true
} -Default @())) { if ($r) { $rows.Add($r) } }

# --- Scheduled tasks with a logon or boot trigger ----------------------------------------------
$taskRows = @(Invoke-Section 'Scheduled tasks' {
    $out = New-Object System.Collections.Generic.List[object]
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        @($_.Triggers | Where-Object { $_ -and $_.CimClass -and ($_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger') }).Count -gt 0
    })
    # One batched call instead of one per task (~4x faster) - keyed by full task path.
    $infoByPath = @{}
    foreach ($i in @($tasks | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)) {
        if ($i) { $infoByPath['{0}{1}' -f $i.TaskPath, $i.TaskName] = $i }
    }
    foreach ($t in $tasks) {
        $triggers = @($t.Triggers | Where-Object { $_ -and $_.CimClass -and ($_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger') })

        $exec = @($t.Actions | Where-Object { $_ -and $_.CimClass -and $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' })
        $command = $null
        if ($exec.Count) {
            $first = $exec[0]
            $command = "$($first.Execute)"
            if (-not [string]::IsNullOrWhiteSpace($first.Arguments)) { $command = '{0} {1}' -f $command, $first.Arguments.Trim() }
            if ($exec.Count -gt 1) { Add-WarningOnce ('Some tasks have more than one action; only the first is shown (first: {0}{1}).' -f $t.TaskPath, $t.TaskName) }
        } elseif (@($t.Actions).Count) {
            # No .exe to check: in-process COM handler, e-mail or message action. Name the handler so it is identifiable.
            $command = '(' + (@($t.Actions | ForEach-Object {
                $kind = $_.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Action$', ''
                if ($_.PSObject.Properties['ClassId'] -and $_.ClassId) { '{0} {1}' -f $kind, $_.ClassId } else { $kind }
            }) -join ', ') + ')'
        }

        $runAs = "$($t.Principal.UserId)"
        if ([string]::IsNullOrWhiteSpace($runAs)) { $runAs = "$($t.Principal.GroupId)" }
        if ([string]::IsNullOrWhiteSpace($runAs)) { $runAs = $null }

        $info = $infoByPath['{0}{1}' -f $t.TaskPath, $t.TaskName]
        $lastRun = $null
        if ($info -and $info.LastRunTime -is [datetime] -and $info.LastRunTime -ge [datetime]'2000-01-01') { $lastRun = [datetime]$info.LastRunTime }
        $lastResult = $null
        if ($info -and $null -ne $info.LastTaskResult) { $lastResult = [int64]$info.LastTaskResult }

        $enabled = ("$($t.State)" -ne 'Disabled')
        $exe = $null
        # A task registered for the target user (or for a group, i.e. whoever logs on) expands its %vars%
        # with that user's paths; a SYSTEM/service task must not borrow them from this process.
        $userCtx = Invoke-Section 'Task principal' { Test-UserContextPrincipal -Principal $t.Principal } -Default $false
        if ($exec.Count) { $exe = Resolve-ExePath (Expand-StartupVars -Text "$($exec[0].Execute)" -UserContext ([bool]$userCtx)) }

        foreach ($kind in @('MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger')) {
            $matching = @($triggers | Where-Object { $_.CimClass.CimClassName -eq $kind })
            if (-not $matching.Count) { continue }
            $label = $(if ($kind -eq 'MSFT_TaskLogonTrigger') { 'Scheduled task (logon)' } else { 'Scheduled task (boot)' })
            $delay = @($matching | ForEach-Object { "$($_.Delay)" } | Where-Object { $_ }) | Select-Object -First 1
            if (-not $delay) { $delay = $null }
            $out.Add((ConvertTo-StartupRow -Source $label -Name $t.TaskName -Enabled $enabled `
                -Command $command -ExePath $exe -RunAs $runAs -TaskPath $t.TaskPath `
                -Delay $delay -LastRunTime $lastRun -LastResult $lastResult))
        }
    }
    $out
} -Default @())
foreach ($r in $taskRows) { if ($r) { $rows.Add($r) } }

# --- Automatic services ------------------------------------------------------------------------
$serviceRows = @(Invoke-Section 'Automatic services' {
    $out = New-Object System.Collections.Generic.List[object]
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -like 'Auto*' })
    foreach ($s in $services) {
        # "Automatic (Trigger Start)" is not exposed by CIM; the TriggerInfo subkey is what services.msc reads.
        $hasTrigger = $false
        $tk = $null
        try { $tk = $hklm.OpenSubKey('SYSTEM\CurrentControlSet\Services\{0}\TriggerInfo' -f $s.Name) } catch { }
        if ($tk) { $hasTrigger = $true; $tk.Close() }

        $label = 'Service (Automatic)'
        $delay = $null
        if ($s.DelayedAutoStart) { $label = 'Service (Automatic, Delayed)'; $delay = 'Delayed' }
        elseif ($hasTrigger)     { $label = 'Service (Automatic, Trigger)'; $delay = 'Trigger' }
        if ($s.DelayedAutoStart -and $hasTrigger) { $delay = 'Delayed, Trigger' }

        $out.Add((ConvertTo-StartupRow -Source $label -Name $s.Name -Enabled $true `
            -Command "$($s.PathName)" `
            -ExePath (Resolve-ExePath (Expand-StartupVars -Text "$($s.PathName)" -UserContext $false)) `
            -RunAs "$($s.StartName)" -TaskPath $null -Delay $delay -LastRunTime $null -LastResult $null))
    }
    $out
} -Default @())
foreach ($r in $serviceRows) { if ($r) { $rows.Add($r) } }

# --- Output ------------------------------------------------------------------------------------
# Default sort: non-Microsoft first (the things a tech actually changes), then Source, then Name.
$result = @($rows | Sort-Object -Property IsMicrosoft, Source, Name)

if ($Display) {
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath
    Write-Host 'Items per source:'
    foreach ($g in @($result | Group-Object -Property Source | Sort-Object -Property Name)) {
        Write-Host ('  {0,-30} {1,5}' -f $g.Name, $g.Count)
    }
    Write-Host ('  {0,-30} {1,5}' -f '(total)', $result.Count)
    Write-Host ('  {0,-30} {1,5}' -f 'enabled, not Microsoft', @($result | Where-Object { $_.Enabled -and -not $_.IsMicrosoft }).Count)
    Write-Host ''
    foreach ($w in $script:Warnings) { Write-Warning $w }
} else {
    foreach ($w in $script:Warnings) { Write-Warning $w }
    $result
}
