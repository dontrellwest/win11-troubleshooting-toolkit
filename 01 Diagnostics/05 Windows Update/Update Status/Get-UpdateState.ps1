<#
.SYNOPSIS
    Windows Update state: pending updates, last search/install, targeting policy, reboot flags, failures.
.DESCRIPTION
    Answers "why is this machine not patched?" in one object: what Windows Update is pointed at
    (Windows Update, WSUS or Windows Update for Business), when it last searched and last installed
    anything, which updates are pending right now, which ones have been failing, every registry flag
    that says a reboot is owed, and whether the update services are running. The pending-update list
    comes from a live online scan and is the slow part - pass -SkipSearch to leave it out.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER SkipSearch
    Skip the online scan for pending updates (the 1-3 minute part). PendingCount is left blank.
.PARAMETER Days
    Window for FailedLast30Days and the FailedUpdates table. Default 30.
.PARAMETER HistoryCount
    How many entries of update history to read back. Default 500 (about two years on a normal machine).
.PARAMETER RecentCount
    How many history entries to list in RecentHistory. Default 15.
.PARAMETER PendingTitleCap
    How many titles to fold into the PendingTitles summary string before "(+n more)". Default 10.
.EXAMPLE
    .\Get-UpdateState.ps1
.EXAMPLE
    .\Get-UpdateState.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Get-UpdateState.ps1 -SkipSearch -Display
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
    [switch]$SkipSearch,
    [int]$Days = 30,
    [int]$HistoryCount = 500,
    [int]$RecentCount = 15,
    [int]$PendingTitleCap = 10
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-UpdateState'          # <-- set per tool
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

# ---------------------------------------------------------------- tool-local helpers

# Copies every key of a section's [ordered] result into the result object, so the property order stays
# fixed even when a section fails (Invoke-Section then returns $null and nothing is copied).
function Merge-Fields {
    param($Target, $Values)
    if ($Values -is [System.Collections.IDictionary]) { foreach ($k in @($Values.Keys)) { $Target[$k] = $Values[$k] } }
}

# Every date the Windows Update Agent hands back (COM history entries, AutoUpdate.Results) is UTC but
# arrives with DateTimeKind.Unspecified. Stamping the kind before converting is what keeps a 09:47 local
# install from being reported as 16:47.
function ConvertFrom-WuaDate {
    param($Value)
    if ($Value -isnot [datetime]) { return $null }
    if ([datetime]$Value -eq [datetime]::MinValue) { return $null }
    [DateTime]::SpecifyKind([datetime]$Value, [DateTimeKind]::Utc).ToLocalTime()
}

# Registry / policy date strings ('2026-10-01T00:00:00Z' or '2026-10-01 00:00:00') -> local [datetime].
function ConvertFrom-PolicyDate {
    param([string]$Text)
    $t = ('{0}' -f $Text).Trim()
    if (-not $t) { return $null }
    $d = [datetime]::MinValue
    if (-not [datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { return $null }
    if ($d.Kind -eq [DateTimeKind]::Utc) { return $d.ToLocalTime() }
    return $d
}

# HRESULTs arrive as a negative Int32; techs and Microsoft's docs both use the unsigned hex form.
function Format-HResult {
    param($Value)
    if ($null -eq $Value) { return $null }
    '0x{0:X8}' -f ([uint32]([int64]$Value -band 0xFFFFFFFFL))
}

# One registry key read as a hashtable of values; $null when the key does not exist. Get-ItemProperty
# on a missing PATH is suppressible, but Get-ItemPropertyValue on a missing VALUE NAME throws even with
# -ErrorAction SilentlyContinue in PS 5.1, so every value read goes through this.
#
# "The key is not there" and "the key is there but this account may not read it" are different answers, and
# Windows makes them look alike: on an ACL'd key (a hardened box locks the WindowsUpdate policy keys against
# standard users) Test-Path still returns True and Get-ItemProperty -ErrorAction SilentlyContinue returns
# nothing - so a naive read yields an empty key and the caller reports "not configured" for something it
# never saw. Every denied read is therefore captured with -ErrorVariable, recorded in $script:RegReadFailed
# and re-thrown, so the calling Invoke-Section records a Warning and Get-RegReadFailures can be consulted
# before any field asserts a policy default.
$script:RegReadFailed = New-Object System.Collections.Generic.List[string]

function Get-RegValues {
    param([string]$Path)
    $exists = $false
    try { $exists = [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) }
    catch {
        if ($script:RegReadFailed -notcontains $Path) { $script:RegReadFailed.Add($Path) }
        throw ('{0} ({1})' -f $_.Exception.Message.Trim(), $Path)
    }
    if (-not $exists) { return $null }
    $readErr = $null
    $p = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue -ErrorVariable readErr
    if ($null -eq $p) {
        if (@($readErr).Count) {
            if ($script:RegReadFailed -notcontains $Path) { $script:RegReadFailed.Add($Path) }
            throw ('{0} ({1})' -f @($readErr)[0].Exception.Message.Trim(), $Path)
        }
        return @{}      # key exists and is readable, but carries no values
    }
    $h = @{}
    foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -notlike 'PS*') { $h[$prop.Name] = $prop.Value } }
    $h
}

# Which of these registry paths could not be READ (as opposed to simply not existing)? A field that would
# otherwise assert a default ("Windows Update", "not configured by policy") checks this first.
function Get-RegReadFailures {
    param([string[]]$Path)
    @($Path | Where-Object { $script:RegReadFailed -contains $_ })
}

function Get-RegValue {
    param($Values, [string]$Name)
    if ($null -eq $Values) { return $null }
    if (-not $Values.ContainsKey($Name)) { return $null }
    $Values[$Name]
}

function ConvertTo-IntOrNull { param($Value) if ($null -eq $Value -or ('{0}' -f $Value).Trim() -eq '') { $null } else { try { [int]$Value } catch { $null } } }

# 'KB5124008' out of an update title. History entries carry no KBArticleIDs collection, only a title.
function Get-KbFromText {
    param([string]$Text)
    if ($Text -match 'KB\s?(\d{6,7})') { return 'KB' + $Matches[1] }
    return ''
}

function Get-HistoryResultText {
    param($Code)
    switch (ConvertTo-IntOrNull $Code) {
        0 { 'NotStarted' } 1 { 'InProgress' } 2 { 'Succeeded' } 3 { 'SucceededWithErrors' }
        4 { 'Failed' } 5 { 'Aborted' } default { 'Unknown ({0})' -f $Code }
    }
}

function Get-HistoryOperationText {
    param($Code)
    switch (ConvertTo-IntOrNull $Code) {
        1 { 'Install' } 2 { 'Uninstall' } 3 { 'Other' } default { 'Unknown ({0})' -f $Code }
    }
}

# Plain-English gloss for the handful of Windows Update errors that account for most tickets. Anything
# not on this short list is left blank rather than guessed at - the hex code is still in the row.
function Get-WuErrorMeaning {
    param([string]$Hex)
    switch (('{0}' -f $Hex).ToUpperInvariant()) {
        '0X80240016' { 'Another install was already in progress' }
        '0X80240034' { 'Download failed' }
        '0X8024402C' { 'Cannot resolve the update server name (proxy or WSUS DNS)' }
        '0X80244022' { 'Update server returned HTTP 503 (busy or down)' }
        '0X80072EE2' { 'Network timeout reaching the update server' }
        '0X80072EFD' { 'Cannot connect to the update server' }
        '0X80070422' { 'The Windows Update service is disabled' }
        '0X80070070' { 'Not enough disk space' }
        '0X800F0922' { 'Servicing failed - often too little free space in the system-reserved partition' }
        '0X80248007' { 'Windows Update datastore missing or corrupt' }
        default      { '' }
    }
}

# Is this history title an operating-system quality update (an LCU)?
# Both naming schemes are live in the field: the classic 'Cumulative Update for Windows 11, version 25H2
# (KB5070773) (26200.6901)' and, since 2026, the shorter '2026-09 Security Update (KB5124008) (26200.9445)'.
# The trailing (build.ubr) stamp is what only an OS quality update carries; .NET rollups are excluded.
function Test-OsQualityUpdateTitle {
    param([string]$Title)
    $t = ('{0}' -f $Title)
    if (-not $t) { return $false }
    if ($t -match 'NET Framework') { return $false }
    if ($t -match 'Cumulative Update .*for Windows 1[01]') { return $true }
    if ($t -match '\(\d{5}\.\d{2,}\)') { return $true }
    return $false
}

# ---------------------------------------------------------------- collection
$isAdmin = Test-IsAdmin
$now     = [DateTime]::Now
if ($Days -lt 1)            { $Days = 30 }
if ($HistoryCount -lt 1)    { $HistoryCount = 500 }
if ($RecentCount -lt 1)     { $RecentCount = 15 }
if ($PendingTitleCap -lt 1) { $PendingTitleCap = 10 }

# Fixed property order (spec). Every field exists even when its section fails.
$o = [ordered]@{
    ComputerName             = $env:COMPUTERNAME
    CollectedAt              = $now
    OsBuild                  = $null
    OsVersion                = $null
    LastSearchSuccess        = $null
    LastInstallSuccess       = $null
    DaysSinceLastInstall     = $null
    LastInstalledUpdate      = $null
    LatestCumulativeInstalled = $null
    PendingCount             = $null
    PendingTitles            = ''
    PendingSecurityCount     = $null
    PendingRebootRequired    = $null
    FailedLast30Days         = $null
    UpdateSource             = $null
    DefaultServiceName       = $null
    WsusServer               = ''
    WsusTargetGroup          = ''
    WsusStatusServer         = ''
    DeferQualityDays         = $null
    DeferFeatureDays         = $null
    PauseQualityUntil        = $null
    PauseFeatureUntil        = $null
    ActiveHours              = ''
    AutoUpdateOption         = $null
    DualScanDisabled         = $null
    ServiceStatus            = $null
    PendingReboot            = $null
    RebootFlags              = ''
    LastWuErrorCode          = ''
    PendingUpdates           = @()
    FailedUpdates            = @()
    RecentHistory            = @()
    Warnings                 = ''
}

# --- OS build / feature release. ProductName is deliberately not used (it still says Windows 10).
Merge-Fields $o (Invoke-Section 'OS version' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $ver = ('{0}' -f $cv.DisplayVersion).Trim()
    if (-not $ver) { $ver = ('{0}' -f $cv.ReleaseId).Trim() }
    [ordered]@{
        OsBuild   = ('{0}.{1}' -f $cv.CurrentBuild, $cv.UBR)
        OsVersion = $ver
    }
})

# --- Last successful search / install, straight from the Automatic Updates agent.
Merge-Fields $o (Invoke-Section 'Last search/install (COM)' {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $r  = $au.Results
    [ordered]@{
        LastSearchSuccess  = ConvertFrom-WuaDate $r.LastSearchSuccessDate
        LastInstallSuccess = ConvertFrom-WuaDate $r.LastInstallationSuccessDate
    }
})

# --- Registry fallback for the install date. Windows 11 25H2 no longer writes this key, so its absence
# is normal and only matters when the COM value above is also missing.
if ($null -eq $o.LastInstallSuccess) {
    Merge-Fields $o (Invoke-Section 'Last install (registry fallback)' {
        $v = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'
        $t = Get-RegValue $v 'LastSuccessTime'
        # Stored as UTC 'yyyy-MM-dd HH:mm:ss' with no zone marker.
        $d = ConvertFrom-PolicyDate $t
        if ($d -and $d.Kind -ne [DateTimeKind]::Local) { $d = [DateTime]::SpecifyKind($d, [DateTimeKind]::Utc).ToLocalTime() }
        [ordered]@{ LastInstallSuccess = $d }
    })
}

# --- Update history. One COM call feeds LastInstalledUpdate, LatestCumulativeInstalled, the failure
# count, LastWuErrorCode and the RecentHistory table. Sorted newest-first defensively.
$script:History = @()
$script:HistoryTotal = $null
$script:HistoryOk = $false
Invoke-Section 'Update history' {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $total = [int]$searcher.GetTotalHistoryCount()
    $script:HistoryTotal = $total
    if ($total -le 0) { $script:HistoryOk = $true; return }   # QueryHistory(0,0) throws 0x80240007
    $take = [Math]::Min($total, $HistoryCount)
    $entries = $searcher.QueryHistory(0, $take)
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $entries.Count; $i++) {
        $e = $entries.Item($i)
        $title = ('{0}' -f $e.Title).Trim()
        $rows.Add([PSCustomObject]@{
            Date      = ConvertFrom-WuaDate $e.Date
            Title     = $title
            KB        = Get-KbFromText $title
            Result    = Get-HistoryResultText $e.ResultCode
            ResultRaw = ConvertTo-IntOrNull $e.ResultCode
            Operation = Get-HistoryOperationText $e.Operation
            HResult   = Format-HResult $e.HResult
        })
    }
    $script:History = @($rows.ToArray() | Sort-Object -Property Date -Descending)
    $script:HistoryOk = $true
    if ($total -gt $take) {
        Add-Warning ('Update history: read the newest {0} of {1} entries (raise -HistoryCount to go further back)' -f $take, $total)
    }
} | Out-Null

# --- The most recent thing that actually installed, and the most recent OS quality update.
Merge-Fields $o (Invoke-Section 'Installed update summary' {
    $ok = @($script:History | Where-Object { $_.ResultRaw -eq 2 -and $_.Date })
    $last = $ok | Select-Object -First 1
    $lcu  = $ok | Where-Object { Test-OsQualityUpdateTitle $_.Title } | Select-Object -First 1
    $fmt = {
        param($row)
        if (-not $row) { return $null }
        $t = $row.Title
        if ($row.KB -and $t -notmatch [regex]::Escape($row.KB)) { $t = '{0} [{1}]' -f $t, $row.KB }
        '{0} - installed {1:yyyy-MM-dd HH:mm}' -f $t, $row.Date
    }
    [ordered]@{
        LastInstalledUpdate       = & $fmt $last
        LatestCumulativeInstalled = & $fmt $lcu
    }
})

# --- Days since the last successful install. Prefer the agent's own timestamp; fall back to the newest
# succeeded history entry so the field is not blank on a machine that lost the agent's result blob.
Merge-Fields $o (Invoke-Section 'Days since last install' {
    $ref = $o.LastInstallSuccess
    if (-not $ref) {
        $ref = @($script:History | Where-Object { $_.ResultRaw -eq 2 -and $_.Date } | Select-Object -First 1).Date
        if ($ref) { Add-Warning 'DaysSinceLastInstall: measured from the newest succeeded history entry (the agent has no LastInstallationSuccessDate)' }
    }
    [ordered]@{ DaysSinceLastInstall = $(if ($ref) { Round1 (($now - $ref).TotalDays) } else { $null }) }
})

# --- Failure count, failure table and the most recent error code.
$cutoff = $now.AddDays(-$Days)
Merge-Fields $o (Invoke-Section 'Failure summary' {
    # A count of 0 must mean "looked, found none". When the history read itself failed the count stays
    # blank instead, so an unreadable update stack never reads as a clean one.
    if (-not $script:HistoryOk) { return [ordered]@{ FailedLast30Days = $null; LastWuErrorCode = '' } }
    $recentFails = @($script:History | Where-Object { $_.ResultRaw -eq 4 -and $_.Date -and $_.Date -ge $cutoff })
    $lastFail    = @($script:History | Where-Object { $_.ResultRaw -eq 4 } | Select-Object -First 1)
    [ordered]@{
        FailedLast30Days = [int]$recentFails.Count
        LastWuErrorCode  = $(if ($lastFail.Count) { '{0}' -f $lastFail[0].HResult } else { '' })
    }
})

$o.FailedUpdates = @(Invoke-Section 'Failed updates' {
    @($script:History |
        Where-Object { $_.ResultRaw -eq 4 -and $_.Date -and $_.Date -ge $cutoff } |
        ForEach-Object {
            [PSCustomObject]@{
                Date       = $_.Date
                Title      = $_.Title
                KB         = $_.KB
                ResultCode = $_.Result
                HResult    = $_.HResult
                Meaning    = Get-WuErrorMeaning $_.HResult
            }
        })
} -Default @())

$o.RecentHistory = @(Invoke-Section 'Recent history' {
    @($script:History | Select-Object -First $RecentCount |
        ForEach-Object {
            [PSCustomObject]@{
                Date      = $_.Date
                Title     = $_.Title
                Result    = $_.Result
                Operation = $_.Operation
            }
        })
} -Default @())

# --- Where this machine gets updates from: WSUS policy, Windows Update for Business policy, or neither.
$script:WuPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:AuPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$script:MdmPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$script:WuPolicy  = Invoke-Section 'WU policy key'  { Get-RegValues $script:WuPath }
$script:AuPolicy  = Invoke-Section 'AU policy key'  { Get-RegValues $script:AuPath }
$script:MdmPolicy = Invoke-Section 'MDM policy key' { Get-RegValues $script:MdmPath }

Merge-Fields $o (Invoke-Section 'Update source' {
    $wuServer   = ('{0}' -f (Get-RegValue $script:WuPolicy 'WUServer')).Trim()
    $statServer = ('{0}' -f (Get-RegValue $script:WuPolicy 'WUStatusServer')).Trim()
    $useWsus    = (ConvertTo-IntOrNull (Get-RegValue $script:AuPolicy 'UseWUServer')) -eq 1
    $group      = ''
    if ((ConvertTo-IntOrNull (Get-RegValue $script:WuPolicy 'TargetGroupEnabled')) -eq 1) {
        $group = ('{0}' -f (Get-RegValue $script:WuPolicy 'TargetGroup')).Trim()
    }
    $wufbValues = @('DeferQualityUpdatesPeriodInDays', 'DeferFeatureUpdatesPeriodInDays', 'BranchReadinessLevel')
    $wufbByGpo  = $false
    foreach ($n in $wufbValues) { if ($null -ne (Get-RegValue $script:WuPolicy $n)) { $wufbByGpo = $true } }
    $wufbByMdm  = ($null -ne $script:MdmPolicy) -and ($script:MdmPolicy.Keys.Count -gt 0)

    # A POSITIVE reading stands on its own: seeing WSUS or WUfB configured is true whatever else was
    # unreadable. The plain 'Windows Update' answer is the one that is only an inference from absence, so it
    # is asserted only when all three policy keys were actually read. An unreadable key leaves the headline
    # field blank + a Warning rather than telling the tech this machine is unmanaged when nobody looked.
    $blocked = Get-RegReadFailures @($script:WuPath, $script:AuPath, $script:MdmPath)
    $source = $null
    if ($useWsus -and $wuServer) { $source = 'WSUS: {0}' -f $wuServer }
    elseif ($wufbByMdm -or $wufbByGpo) { $source = 'Windows Update for Business (Intune/MDM)' }
    elseif ($blocked.Count) {
        # No ';' inside the text: Warnings is a '; '-joined string and a stray one splits this into two.
        Add-Warning ('Update source: UNKNOWN - the update policy key(s) could not be read ({0}) so targeting was never seen, which is not the same as "not configured". Re-run elevated and compare DefaultServiceName.' -f ($blocked -join ', '))
    }
    else { $source = 'Windows Update' }
    if ($useWsus -and -not $wuServer) {
        Add-Warning 'Update source: UseWUServer=1 but no WUServer value is set - the client has nowhere to scan'
    }
    [ordered]@{
        UpdateSource    = $source
        WsusServer      = $wuServer
        WsusTargetGroup = $group
        WsusStatusServer = $statServer
    }
})

# --- Which service the Automatic Updates agent is actually registered against. On a WSUS client this
# still reads 'Windows Server Update Service'; when it says 'Microsoft Update' the WSUS policy is not
# in force no matter what the registry says.
Merge-Fields $o (Invoke-Section 'Default update service' {
    $sm = New-Object -ComObject Microsoft.Update.ServiceManager
    $names = @()
    foreach ($svc in $sm.Services) { if ($svc.IsDefaultAUService) { $names += ('{0}' -f $svc.Name).Trim() } }
    [ordered]@{ DefaultServiceName = ($names -join '; ') }
})

# --- Deferrals, pauses, active hours, AU behaviour, dual scan.
Merge-Fields $o (Invoke-Section 'Deferral policy' {
    $q = ConvertTo-IntOrNull (Get-RegValue $script:WuPolicy 'DeferQualityUpdatesPeriodInDays')
    $f = ConvertTo-IntOrNull (Get-RegValue $script:WuPolicy 'DeferFeatureUpdatesPeriodInDays')
    if ($null -eq $q) { $q = ConvertTo-IntOrNull (Get-RegValue $script:MdmPolicy 'DeferQualityUpdatesPeriodInDays') }
    if ($null -eq $f) { $f = ConvertTo-IntOrNull (Get-RegValue $script:MdmPolicy 'DeferFeatureUpdatesPeriodInDays') }
    [ordered]@{ DeferQualityDays = $q; DeferFeatureDays = $f }
})

# The single user-facing "pause updates" switch writes PauseUpdatesExpiryTime and covers both rings;
# policy-driven pauses write a per-ring end time. Check the specific values first, then the shared one.
$script:UxPath    = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$script:UxAltPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\UX\Settings'
$script:UxSettings = Invoke-Section 'UX settings key' {
    # A denied read of the primary path must not cost us the fallback path, so it is caught here rather
    # than being allowed to fail the whole section.
    $v = $null
    try { $v = Get-RegValues $script:UxPath }
    catch { Add-Warning ('UX settings key: {0}' -f $_.Exception.Message.Trim()) }
    if ($null -eq $v) { $v = Get-RegValues $script:UxAltPath }
    $v
}

Merge-Fields $o (Invoke-Section 'Pause policy' {
    $shared = ConvertFrom-PolicyDate (Get-RegValue $script:UxSettings 'PauseUpdatesExpiryTime')
    $pick = {
        param([string]$Ring)
        foreach ($set in @($script:MdmPolicy, $script:WuPolicy, $script:UxSettings)) {
            foreach ($suffix in 'EndTime', 'ExpiryTime') {
                $d = ConvertFrom-PolicyDate (Get-RegValue $set ('Pause{0}UpdatesStart{1}' -f $Ring, $suffix))
                if ($d) { return $d }
                $d = ConvertFrom-PolicyDate (Get-RegValue $set ('Pause{0}Updates{1}' -f $Ring, $suffix))
                if ($d) { return $d }
            }
        }
        return $shared
    }
    [ordered]@{ PauseQualityUntil = (& $pick 'Quality'); PauseFeatureUntil = (& $pick 'Feature') }
})

Merge-Fields $o (Invoke-Section 'Active hours' {
    $s = ConvertTo-IntOrNull (Get-RegValue $script:UxSettings 'ActiveHoursStart')
    $e = ConvertTo-IntOrNull (Get-RegValue $script:UxSettings 'ActiveHoursEnd')
    [ordered]@{ ActiveHours = $(if ($null -ne $s -and $null -ne $e) { '{0}:00-{1}:00' -f $s, $e } else { '' }) }
})

Merge-Fields $o (Invoke-Section 'Automatic update option' {
    $noAuto = ConvertTo-IntOrNull (Get-RegValue $script:AuPolicy 'NoAutoUpdate')
    $opt    = ConvertTo-IntOrNull (Get-RegValue $script:AuPolicy 'AUOptions')
    $text = $null
    if ($noAuto -eq 1) { $text = 'Automatic updates turned off by policy (NoAutoUpdate=1)' }
    elseif ($null -ne $opt) {
        $text = switch ($opt) {
            2 { 'Notify before download (AUOptions=2)' }
            3 { 'Auto download, notify before install (AUOptions=3)' }
            4 { 'Auto download and schedule the install (AUOptions=4)' }
            5 { 'Local administrator chooses the setting (AUOptions=5)' }
            default { 'AUOptions={0} (unrecognised)' -f $opt }
        }
    }
    elseif ((Get-RegReadFailures @($script:AuPath)).Count) {
        # Same rule as UpdateSource: never report "not configured" for a key this account could not read.
        $text = $null
        Add-Warning ('Automatic update option: UNKNOWN - {0} could not be read, so NoAutoUpdate/AUOptions were never seen' -f $script:AuPath)
    }
    else { $text = 'Not configured by policy (Windows default)' }
    [ordered]@{ AutoUpdateOption = $text }
})

Merge-Fields $o (Invoke-Section 'Dual scan' {
    $v = ConvertTo-IntOrNull (Get-RegValue $script:WuPolicy 'DisableDualScan')
    [ordered]@{ DualScanDisabled = $(if ($null -eq $v) { $null } else { [bool]($v -eq 1) }) }
})

# --- The three services that have to be alive for updating to work at all.
Merge-Fields $o (Invoke-Section 'Service status' {
    $parts = @()
    foreach ($n in 'wuauserv', 'bits', 'DoSvc') {
        $sv = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $n) -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sv) { $parts += '{0} {1}/{2}' -f $sv.Name, $sv.State, $sv.StartMode }
        else     { $parts += '{0} (not found)' -f $n; Add-Warning ('Service status: {0} not found' -f $n) }
    }
    [ordered]@{ ServiceStatus = ($parts -join '; ') }
})

# --- Every registry location that says a reboot is owed.
Merge-Fields $o (Invoke-Section 'Reboot flags' {
    $flags = New-Object System.Collections.Generic.List[string]
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    $au  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    if (Test-Path -LiteralPath (Join-Path $cbs 'RebootPending'))       { $flags.Add('CBS RebootPending') }
    if (Test-Path -LiteralPath (Join-Path $cbs 'PackagesPending'))     { $flags.Add('CBS PackagesPending') }
    if (Test-Path -LiteralPath (Join-Path $au  'RebootRequired'))      { $flags.Add('WU RebootRequired') }
    if (Test-Path -LiteralPath (Join-Path $au  'PostRebootReporting')) { $flags.Add('WU PostRebootReporting') }

    $sm = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pfro = @((Get-RegValue $sm 'PendingFileRenameOperations') | Where-Object { $_ })
    if ($pfro.Count) { $flags.Add('PendingFileRenameOperations') }

    $active = Get-RegValue (Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName') 'ComputerName'
    $stored = Get-RegValue (Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName') 'ComputerName'
    if ($active -and $stored -and $active -ne $stored) { $flags.Add('ComputerName rename pending') }

    $nl = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon'
    $join = ('{0}' -f (Get-RegValue $nl 'JoinDomain')).Trim()
    $spn  = ('{0}' -f (Get-RegValue $nl 'AvoidSpnSet')).Trim()
    if ($join -or $spn) { $flags.Add('JoinDomain pending') }

    [ordered]@{
        PendingReboot = [bool]($flags.Count -gt 0)
        RebootFlags   = ($flags -join '; ')
    }
})

# --- Pending updates. This is the slow section: a live online scan against whatever UpdateSource says,
# 20 s to 3 min depending on the link and on how far behind the machine is. It also throws outright on a
# broken update stack, which is exactly the case this tool exists to diagnose - hence Invoke-Section.
$script:SearchRan = $false
if ($SkipSearch) {
    Add-Warning 'Pending updates: skipped (-SkipSearch); PendingCount, PendingSecurityCount and PendingRebootRequired left blank'
} else {
    $o.PendingUpdates = @(Invoke-Section 'Pending updates (online search)' {
        Write-Progress -Activity $script:ToolName -Status 'Scanning Windows Update for pending updates (can take a few minutes)...'
        Write-Verbose 'Starting online update search; this is the slow part.'
        try {
            $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
            $res = $searcher.Search('IsInstalled=0 and IsHidden=0')
            $script:SearchRan = $true
            $rows = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt $res.Updates.Count; $i++) {
                $u = $res.Updates.Item($i)
                $kb = @()
                try { for ($k = 0; $k -lt $u.KBArticleIDs.Count; $k++) { $kb += ('KB{0}' -f $u.KBArticleIDs.Item($k)) } } catch { }
                if (-not $kb.Count) { $t = Get-KbFromText $u.Title; if ($t) { $kb = @($t) } }
                $cats = @()
                try { for ($c = 0; $c -lt $u.Categories.Count; $c++) { $cats += ('{0}' -f $u.Categories.Item($c).Name) } } catch { }
                # RebootRequired alone is only populated after an install, so an InstallationBehavior of
                # AlwaysRequiresReboot (1) counts too - that is the flag that predicts a forced restart.
                $reboot = $false
                try { if ($u.RebootRequired) { $reboot = $true } } catch { }
                try { if ([int]$u.InstallationBehavior.RebootBehavior -eq 1) { $reboot = $true } } catch { }
                $sizeMb = $null
                try { $sizeMb = Round1 ([double]$u.MaxDownloadSize / 1MB) } catch { }
                $rows.Add([PSCustomObject]@{
                    Title          = ('{0}' -f $u.Title).Trim()
                    KB             = ($kb -join ', ')
                    Severity       = ('{0}' -f $u.MsrcSeverity).Trim()
                    SizeMB         = $sizeMb
                    IsDownloaded   = [bool]$u.IsDownloaded
                    RebootRequired = [bool]$reboot
                    Categories     = ($cats -join ', ')
                })
            }
            $rows.ToArray()
        } finally { Write-Progress -Activity $script:ToolName -Completed }
    } -Default @())
}

Merge-Fields $o (Invoke-Section 'Pending summary' {
    if (-not $script:SearchRan) { return [ordered]@{} }
    $pending = @($o.PendingUpdates)
    $titles = @($pending | ForEach-Object { $_.Title })
    $summary = ''
    if ($titles.Count) {
        $shown = @($titles | Select-Object -First $PendingTitleCap)
        $summary = ($shown -join '; ')
        if ($titles.Count -gt $shown.Count) { $summary = '{0}; (+{1} more)' -f $summary, ($titles.Count - $shown.Count) }
    }
    $sec = @($pending | Where-Object { $_.Severity -or ($_.Categories -match 'Security Updates') })
    [ordered]@{
        PendingCount          = [int]$pending.Count
        PendingTitles         = $summary
        PendingSecurityCount  = [int]$sec.Count
        PendingRebootRequired = [bool](@($pending | Where-Object { $_.RebootRequired }).Count -gt 0)
    }
})
if (-not $SkipSearch -and -not $script:SearchRan) {
    Add-Warning 'Pending updates: the online scan did not complete; PendingCount, PendingSecurityCount and PendingRebootRequired left blank'
}

# ---------------------------------------------------------------- output
$o.Warnings = ($script:Warnings -join '; ')          # shape A only
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
