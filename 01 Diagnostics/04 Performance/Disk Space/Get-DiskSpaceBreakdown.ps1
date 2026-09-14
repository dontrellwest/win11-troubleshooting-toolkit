<#
.SYNOPSIS
    Shows where the space on a drive went, before anything is cleaned up.
.DESCRIPTION
    Walks the drive once and reports the biggest folders, the WinSxS component store, the Windows Update
    and Delivery Optimization caches, per-user Recycle Bins, hibernation and page files, temp folders,
    stale user profiles and the largest individual files. Adds up what is safely reclaimable so you can
    decide what to run before you run it. This tool deletes nothing and changes nothing.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER Drive
    Drive to analyse. Defaults to the system drive. Accepts 'C', 'C:' or 'C:\'.
.PARAMETER Top
    How many folder rows to return in TopFolders. Default 15.
.PARAMETER StaleProfileDays
    A user profile counts as stale when it is not loaded, not a system profile, and has not been used
    for this many days. Default 90.
.PARAMETER Depth
    How many folder levels below the drive root get their own size row. Default 2.
.EXAMPLE
    .\Get-DiskSpaceBreakdown.ps1
.EXAMPLE
    .\Get-DiskSpaceBreakdown.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Get-DiskSpaceBreakdown.ps1 -Top 30 -StaleProfileDays 180 -Display
.NOTES
    Toolkit-Class:     ReadOnly            (ReadOnly | Remediation)
    Toolkit-Context:   Machine             (Machine | User)
    Toolkit-Elevation: Required            (Required | Recommended | None)
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [string]$Drive,
    [ValidateRange(1, 500)]
    [int]$Top = 15,
    [ValidateRange(1, 3650)]
    [int]$StaleProfileDays = 90,
    [ValidateRange(1, 6)]
    [int]$Depth = 2
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-DiskSpaceBreakdown'
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

$script:DsbSizes    = @{}    # lowercased full path -> [int64] bytes
$script:DsbCounts   = @{}    # lowercased full path -> [int] files
$script:DsbLevels   = @{}    # lowercased full path -> [int] level below the drive root
$script:DsbPaths    = @{}    # lowercased full path -> original-case full path
$script:DsbBlocked  = @{}    # lowercased full path -> [int] unreadable folders inside that subtree
$script:DsbSelfDenied = @{}  # lowercased full path -> $true : this folder itself could not be opened (size is not a measurement)
$script:DsbTrack    = @{}    # lowercased full path -> $true : always give this folder its own row, whatever the depth
$script:DsbBigFiles = New-Object System.Collections.Generic.List[object]
$script:DsbMaxDepth = $Depth
$script:DsbBigBytes = 500MB
$script:DsbDenied   = 0      # directories the walk could not open (usually permissions)
$script:DsbSkipLevel1 = @()  # names skipped directly under the drive root
$script:DsbRootBytes  = [int64]0
$script:DsbRootFiles  = 0
$script:DsbDismActual  = $null
$script:DsbDismReclaim = $null
$script:DsbDismCleanup = $null

function Get-DsbBucketBytes {
    param([string]$FullName)
    if (-not $FullName) { return $null }
    $k = $FullName.ToLowerInvariant()
    if ($script:DsbSizes.ContainsKey($k)) { $script:DsbSizes[$k] } else { $null }
}

# How many folders inside this subtree the walk could not open. 0 = the size below it is complete.
function Get-DsbBlockedCount {
    param([string]$FullName)
    if (-not $FullName) { return 0 }
    $k = $FullName.ToLowerInvariant()
    if ($script:DsbBlocked.ContainsKey($k)) { [int]$script:DsbBlocked[$k] } else { 0 }
}

# $true when the walk could not open this folder AT ALL. Its size is then 0 because nothing was measured,
# not because the folder is empty, so the caller reports $null instead of a fake 0.
function Test-DsbSelfDenied {
    param([string]$FullName)
    if (-not $FullName) { return $false }
    $script:DsbSelfDenied.ContainsKey($FullName.ToLowerInvariant())
}

# Single-pass recursive sizer.
# Skips directories that are reparse points (junctions, symlinks, OneDrive cloud-backed folders) so nothing is
# counted twice, and counts a file's Length only when the file itself is not a reparse point (a cloud-only
# placeholder occupies no local blocks). try/catch per directory so one unreadable folder never stops the walk.
function Measure-DsbFolder {
    param([System.IO.DirectoryInfo]$Dir, [int]$Level)
    $bytes = [int64]0
    $files = 0
    # A folder this account cannot open fails BOTH enumerations below; count the FOLDER once, not the failures.
    $failed = $false
    try {
        foreach ($fi in $Dir.EnumerateFiles()) {
            if (($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                $len = [int64]$fi.Length
                $bytes += $len
                $files++
                if ($len -ge $script:DsbBigBytes) {
                    $script:DsbBigFiles.Add([PSCustomObject]@{ Path = $fi.FullName; Bytes = $len; LastWrite = $fi.LastWriteTime })
                }
            }
        }
    } catch { $failed = $true }
    try {
        foreach ($sub in $Dir.EnumerateDirectories()) {
            if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $next = $Level + 1
            $deniedBefore = $script:DsbDenied
            $r = Measure-DsbFolder -Dir $sub -Level $next
            $bytes += $r[0]
            $files += $r[1]
            $key = $sub.FullName.ToLowerInvariant()
            if ($next -le $script:DsbMaxDepth -or $script:DsbTrack.ContainsKey($key)) {
                $script:DsbSizes[$key]   = [int64]$r[0]
                $script:DsbCounts[$key]  = [int]$r[1]
                $script:DsbLevels[$key]  = $next
                $script:DsbPaths[$key]   = $sub.FullName
                $script:DsbBlocked[$key] = [int]($script:DsbDenied - $deniedBefore)
            }
        }
    } catch { $failed = $true }
    if ($failed) {
        $script:DsbDenied++
        $script:DsbSelfDenied[$Dir.FullName.ToLowerInvariant()] = $true
    }
    ,@($bytes, $files)
}

# Sizes one folder that the main walk did not cover (or could not reach). Returns $null when it does not exist.
function Measure-DsbPath {
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not [System.IO.Directory]::Exists($Path)) { return $null }
    $di = New-Object System.IO.DirectoryInfo $Path
    if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return [int64]0 }
    $r = Measure-DsbFolder -Dir $di -Level 99
    [int64]$r[0]
}

# Bucket value if the single pass already has it, otherwise walk the folder on its own.
function Get-DsbFolderBytes {
    param([string]$Path)
    $v = Get-DsbBucketBytes -FullName $Path
    if ($null -ne $v) { return [int64]$v }
    Measure-DsbPath -Path $Path
}

# Length of a root system file (hiberfil.sys and friends). The PowerShell FileSystem provider reports these as
# non-existent on Windows 11, so go straight to System.IO.
function Get-DsbFileLength {
    param([string]$Path)
    try {
        $fi = New-Object System.IO.FileInfo $Path
        if ($fi.Exists) { [int64]$fi.Length } else { $null }
    } catch { $null }
}

function ConvertTo-DsbGB { param($Bytes) if ($null -eq $Bytes) { $null } else { Round1 ([double]$Bytes / 1GB) } }

# '7.87 GB' -> bytes.
# DISM writes numbers in the Windows DISPLAY language, which is not always the regional format this process runs
# under, so the culture cannot be trusted: on an en-US console '7,87 GB' would parse as 787 GB. Decide from the
# text instead. A lone separator with one or two digits behind it is a decimal point; anything else groups
# thousands. (DISM prints two decimal places, so '7.870' does not occur.)
function ConvertFrom-DsbSizeText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text.Trim(), '^(?<num>[0-9][0-9\s\.,\u00A0]*)\s*(?<unit>bytes|B|KB|MB|GB|TB)$', 'IgnoreCase')
    if (-not $m.Success) { return $null }
    $num = ($m.Groups['num'].Value -replace '[\s\u00A0]', '')
    $dot = $num.LastIndexOf('.'); $comma = $num.LastIndexOf(',')
    $sepAt = [math]::Max($dot, $comma)
    $isDecimal = $false
    if ($sepAt -ge 0) {
        if ($dot -ge 0 -and $comma -ge 0) { $isDecimal = $true }                       # both present: the last one is the decimal mark
        else {
            $sep = $num[$sepAt]
            $occurrences = ($num.ToCharArray() | Where-Object { $_ -eq $sep }).Count
            $tail = $num.Length - $sepAt - 1
            if ($occurrences -eq 1 -and $tail -ge 1 -and $tail -le 2) { $isDecimal = $true }
        }
    }
    if ($isDecimal) { $num = ($num.Substring(0, $sepAt) -replace '[.,]', '') + '.' + $num.Substring($sepAt + 1) }
    else            { $num = $num -replace '[.,]', '' }
    $d = [double]0
    if (-not [double]::TryParse($num, [System.Globalization.NumberStyles]::Float,
                                [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    switch ($m.Groups['unit'].Value.ToUpperInvariant()) {
        'TB'    { [int64]($d * 1TB) }
        'GB'    { [int64]($d * 1GB) }
        'MB'    { [int64]($d * 1MB) }
        'KB'    { [int64]($d * 1KB) }
        default { [int64]$d }
    }
}

# Pulls the four figures we care about out of 'Dism /Online /Cleanup-Image /AnalyzeComponentStore' output.
function ConvertFrom-DsbDismAnalyze {
    param([string[]]$Lines)
    $actual = $null; $backups = $null; $cache = $null; $recommended = $null
    foreach ($line in $Lines) {
        $i = $line.IndexOf(':')
        if ($i -lt 1) { continue }
        $label = $line.Substring(0, $i).Trim()
        $value = $line.Substring($i + 1).Trim()
        if ($label -like '*Actual Size of Component Store*') { $actual  = ConvertFrom-DsbSizeText $value }
        elseif ($label -like '*Backups and Disabled Features*') { $backups = ConvertFrom-DsbSizeText $value }
        elseif ($label -like '*Cache and Temporary Data*')      { $cache   = ConvertFrom-DsbSizeText $value }
        elseif ($label -like '*Component Store Cleanup Recommended*') {
            if ($value -match '^(?i)yes$')     { $recommended = $true }
            elseif ($value -match '^(?i)no$')  { $recommended = $false }
        }
    }
    $reclaimable = $null
    if ($null -ne $backups -or $null -ne $cache) { $reclaimable = [int64](([int64]$backups) + ([int64]$cache)) }
    [PSCustomObject]@{
        ActualBytes      = $actual
        BackupsBytes     = $backups
        CacheBytes       = $cache
        ReclaimableBytes = $reclaimable
        Recommended      = $recommended
    }
}

function Resolve-DsbSidName {
    param([string]$Sid)
    try { return (New-Object System.Security.Principal.SecurityIdentifier $Sid).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    try {
        $p = (Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{0}" -f $Sid) -ErrorAction Stop).ProfileImagePath
        if ($p) { return (Split-Path ([Environment]::ExpandEnvironmentVariables($p)) -Leaf) }
    } catch { }
    $null
}

# ---------------------------------------------------------------- collection

$started = [DateTime]::Now
$isAdmin = Test-IsAdmin
if (-not $isAdmin) {
    Add-Warning 'Not elevated: other users'' folders, C:\Windows\Temp, protected caches and the DISM component-store analysis could not be read. Sizes below are what this account can see.'
}

# --- drive ------------------------------------------------------------------
$sysDrive = $env:SystemDrive                                  # 'C:'
if ([string]::IsNullOrWhiteSpace($sysDrive)) { $sysDrive = 'C:' }
if ([string]::IsNullOrWhiteSpace($Drive)) { $Drive = $sysDrive }
$driveLetter = ($Drive.Trim().TrimEnd('\').TrimEnd(':')).ToUpperInvariant()
if ($driveLetter.Length -ne 1 -or $driveLetter -notmatch '^[A-Z]$') {
    throw ("-Drive '{0}' is not a single drive letter. Use C, C: or C:\." -f $Drive)
}
$driveId   = $driveLetter + ':'
$driveRoot = $driveId + '\'
$isSystemDrive = ($driveId -eq $sysDrive.ToUpperInvariant())
if (-not [System.IO.Directory]::Exists($driveRoot)) { throw ("Drive {0} is not available on this machine." -f $driveRoot) }

$vol = Invoke-Section 'Volume' {
    $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $driveId) -ErrorAction Stop | Select-Object -First 1
    if (-not $d) { throw ("no Win32_LogicalDisk entry for {0}" -f $driveId) }
    if ($d.DriveType -ne 3) { Add-Warning ("{0} is not a fixed local disk (DriveType {1}) - numbers may not mean what you expect." -f $driveId, $d.DriveType) }
    [PSCustomObject]@{ SizeBytes = [int64]$d.Size; FreeBytes = [int64]$d.FreeSpace; Label = $d.VolumeName }
}
$sizeBytes = if ($vol) { [int64]$vol.SizeBytes } else { $null }
$freeBytes = if ($vol) { [int64]$vol.FreeBytes } else { $null }
$usedBytes = if ($null -ne $sizeBytes -and $null -ne $freeBytes) { [int64]($sizeBytes - $freeBytes) } else { $null }

# --- well-known paths -------------------------------------------------------
$winDir      = $env:SystemRoot
if ([string]::IsNullOrWhiteSpace($winDir)) { $winDir = Join-Path $sysDrive 'Windows' }
$pWinSxS     = Join-Path $winDir 'WinSxS'
$pUpdate     = Join-Path $winDir 'SoftwareDistribution\Download'
$pDo         = Join-Path $winDir 'SoftwareDistribution\DeliveryOptimization'
$pWinTemp    = Join-Path $winDir 'Temp'
$pWinOld     = Join-Path $sysDrive '\Windows.old'
$pUsersRoot  = Join-Path $sysDrive '\Users'
$pRecycle    = Join-Path $driveRoot '$Recycle.Bin'

# --- profiles (needed before the walk so their folders get their own bucket) --
$profiles = @(Invoke-Section 'User profiles' {
    @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })
} -Default @())

$userTempPaths = @(Invoke-Section 'User temp folders' {
    $out = New-Object System.Collections.Generic.List[string]
    if ([System.IO.Directory]::Exists($pUsersRoot)) {
        foreach ($u in [System.IO.Directory]::EnumerateDirectories($pUsersRoot)) {
            $di = New-Object System.IO.DirectoryInfo $u
            if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }   # 'All Users', 'Default User' are junctions
            $t = Join-Path $u 'AppData\Local\Temp'
            if ([System.IO.Directory]::Exists($t)) { $out.Add($t) }
        }
    }
    @($out.ToArray())
} -Default @())

# --- build the track set ----------------------------------------------------
foreach ($p in @($pWinSxS, $pUpdate, $pDo, $pWinTemp, $pWinOld, (Join-Path $sysDrive '\Program Files'),
                 (Join-Path $sysDrive '\Program Files (x86)'), (Join-Path $sysDrive '\ProgramData'), $pUsersRoot, $winDir)) {
    if ($p) { $script:DsbTrack[$p.ToLowerInvariant()] = $true }
}
foreach ($p in $userTempPaths) { $script:DsbTrack[$p.ToLowerInvariant()] = $true }
foreach ($pr in $profiles) { if ($pr.LocalPath) { $script:DsbTrack[$pr.LocalPath.ToLowerInvariant()] = $true } }

# --- the single pass --------------------------------------------------------
# Skipped at the root: '$Recycle.Bin' and 'System Volume Information' (sized separately / never readable), and the
# three kernel-owned root files, which are reported on their own lines and would otherwise be double counted.
$rootSkipDirs  = @('System Volume Information', '$Recycle.Bin')
$rootSkipFiles = @('hiberfil.sys', 'pagefile.sys', 'swapfile.sys')
$scannedBytes  = [int64]0
$scannedFiles  = 0

Invoke-Section 'Folder scan' {
    $rootDir = New-Object System.IO.DirectoryInfo $driveRoot
    $rootFailed = $false          # the drive root itself: one folder, counted once even if both enumerations fail

    # files sitting directly in the drive root
    try {
        foreach ($fi in $rootDir.EnumerateFiles()) {
            if ($rootSkipFiles -contains $fi.Name) { continue }
            if (($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $len = [int64]$fi.Length
            $script:DsbRootBytes = [int64]$script:DsbRootBytes + $len
            $script:DsbRootFiles = [int]$script:DsbRootFiles + 1
            if ($len -ge $script:DsbBigBytes) {
                $script:DsbBigFiles.Add([PSCustomObject]@{ Path = $fi.FullName; Bytes = $len; LastWrite = $fi.LastWriteTime })
            }
        }
    } catch { $rootFailed = $true }

    $level1 = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($sub in $rootDir.EnumerateDirectories()) {
            if ($sub.Name -eq '$Recycle.Bin') { continue }                                     # sized separately, see RecycleBinGB
            if ($rootSkipDirs -contains $sub.Name) { $script:DsbSkipLevel1 += $sub.Name; continue }
            if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $script:DsbSkipLevel1 += ($sub.Name + ' (junction)'); continue }
            $level1.Add($sub)
        }
    } catch { $rootFailed = $true }
    if ($rootFailed) {
        $script:DsbDenied++
        $script:DsbSelfDenied[$driveRoot.ToLowerInvariant()] = $true
    }

    $n = $level1.Count
    $i = 0
    foreach ($sub in $level1) {
        $i++
        $pct = if ($n -gt 0) { [int](100 * $i / $n) } else { 100 }
        Write-Progress -Activity ('Measuring {0}' -f $driveRoot) -Status ('{0} ({1} of {2})' -f $sub.Name, $i, $n) -PercentComplete $pct
        $deniedBefore = $script:DsbDenied
        $r = Measure-DsbFolder -Dir $sub -Level 1
        $key = $sub.FullName.ToLowerInvariant()
        $script:DsbSizes[$key]   = [int64]$r[0]
        $script:DsbCounts[$key]  = [int]$r[1]
        $script:DsbLevels[$key]  = 1
        $script:DsbPaths[$key]   = $sub.FullName
        $script:DsbBlocked[$key] = [int]($script:DsbDenied - $deniedBefore)
        $script:DsbRootBytes = [int64]$script:DsbRootBytes + [int64]$r[0]
        $script:DsbRootFiles = [int]$script:DsbRootFiles + [int]$r[1]
    }
    Write-Progress -Activity ('Measuring {0}' -f $driveRoot) -Completed
} | Out-Null

$scannedBytes = [int64]$script:DsbRootBytes
$scannedFiles = [int]$script:DsbRootFiles
if ($script:DsbDenied -gt 0) {
    Add-Warning ('{0} folder(s) could not be opened and are not counted in ScannedGB.' -f $script:DsbDenied)
}
if ($script:DsbSkipLevel1.Count) {
    Add-Warning ('Not counted in ScannedGB (reparse points are followed from their real location, System Volume Information is never readable): {0}.' -f (($script:DsbSkipLevel1 | Sort-Object -Unique) -join ', '))
}

# --- special files ----------------------------------------------------------
$hiberBytes = Invoke-Section 'Hibernation file' { Get-DsbFileLength (Join-Path $driveRoot 'hiberfil.sys') }
$pageBytes  = Invoke-Section 'Page file' {
    $a = Get-DsbFileLength (Join-Path $driveRoot 'pagefile.sys')
    $b = Get-DsbFileLength (Join-Path $driveRoot 'swapfile.sys')
    if ($null -eq $a -and $null -eq $b) { $null } else { [int64](([int64]$a) + ([int64]$b)) }
}
$hiberOn = Invoke-Section 'Hibernation setting' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name HibernateEnabled -ErrorAction Stop).HibernateEnabled
    [bool]([int]$v)
}

# --- caches and temp --------------------------------------------------------
$winSxSBytes = $null; $updateBytes = $null; $doBytes = $null; $winTempBytes = $null
$userTempBytes = $null; $winOldBytes = $null
$pfBytes = $null; $pdBytes = $null; $usersBytes = $null; $windowsBytes = $null

if ($isSystemDrive) {
    $winSxSBytes  = Invoke-Section 'WinSxS'              { Get-DsbFolderBytes $pWinSxS }
    $updateBytes  = Invoke-Section 'Windows Update cache' {
        if ([System.IO.Directory]::Exists($pUpdate)) { Get-DsbFolderBytes $pUpdate } else { [int64]0 }
    }
    $doBytes      = Invoke-Section 'Delivery Optimization cache' {
        if ([System.IO.Directory]::Exists($pDo)) { Get-DsbFolderBytes $pDo }
        else {
            # Windows 11 no longer keeps a DeliveryOptimization folder under SoftwareDistribution; the DO service
            # reports its own cache size and answers without elevation.
            $snap = $null
            try { $snap = Get-DeliveryOptimizationPerfSnap -ErrorAction Stop | Select-Object -First 1 } catch { }
            if ($snap -and $null -ne $snap.CacheSizeBytes) {
                Add-Warning 'DeliveryOptimizationCacheGB came from the Delivery Optimization service (Get-DeliveryOptimizationPerfSnap), not a folder walk: this build keeps no SoftwareDistribution\DeliveryOptimization folder.'
                [int64]$snap.CacheSizeBytes
            } else {
                Add-Warning 'Delivery Optimization cache size is unknown: no cache folder and the DO service did not answer.'
                $null
            }
        }
    }
    $winTempBytes = Invoke-Section 'Windows Temp' {
        if (-not [System.IO.Directory]::Exists($pWinTemp)) { [int64]0 }
        else {
            $before = $script:DsbDenied
            $b = Get-DsbFolderBytes $pWinTemp
            if (Test-DsbSelfDenied $pWinTemp) {
                # Nothing was measured, so WindowsTempGB is empty rather than a 0 that reads as 'already clean'.
                Add-Warning ('{0} could not be opened by this account at all, so WindowsTempGB is empty, not 0 (elevation usually fixes this).' -f $pWinTemp)
                $null
            }
            elseif ((Get-DsbBlockedCount $pWinTemp) -gt 0 -or $script:DsbDenied -gt $before) {
                Add-Warning ('{0} could not be read in full by this account, so WindowsTempGB is understated (elevation usually fixes this).' -f $pWinTemp)
                $b
            }
            else { $b }
        }
    }
    $userTempBytes = Invoke-Section 'User Temp folders' {
        if (-not $userTempPaths.Count) { [int64]0 }
        else {
            $t = [int64]0
            foreach ($p in $userTempPaths) { $v = Get-DsbFolderBytes $p; if ($null -ne $v) { $t += [int64]$v } }
            [int64]$t
        }
    }
    $winOldBytes = Invoke-Section 'Windows.old' {
        if ([System.IO.Directory]::Exists($pWinOld)) { Get-DsbFolderBytes $pWinOld } else { [int64]0 }
    }
    $pfBytes      = Invoke-Section 'Program Files' {
        $a = Get-DsbBucketBytes (Join-Path $sysDrive '\Program Files')
        $b = Get-DsbBucketBytes (Join-Path $sysDrive '\Program Files (x86)')
        if ($null -eq $a -and $null -eq $b) { $null } else { [int64](([int64]$a) + ([int64]$b)) }
    }
    $pdBytes      = Invoke-Section 'ProgramData' { Get-DsbBucketBytes (Join-Path $sysDrive '\ProgramData') }
    $usersBytes   = Invoke-Section 'Users'       { Get-DsbBucketBytes $pUsersRoot }
    $windowsBytes = Invoke-Section 'Windows'     { Get-DsbBucketBytes $winDir }
} else {
    Add-Warning ("{0} is not the system drive ({1}): WinSxS, update caches, temp folders, profiles and the Windows/Program Files totals are left empty because they do not live here." -f $driveId, $sysDrive)
}

# Any headline folder the walk could only read part of gives a floor, not a total. Say which.
Invoke-Section 'Readability check' {
    if (-not $isSystemDrive) { return }
    $incomplete = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($pWinSxS, $pUpdate, $pUsersRoot, $winDir, (Join-Path $sysDrive '\ProgramData'),
                     (Join-Path $sysDrive '\Program Files'), (Join-Path $sysDrive '\Program Files (x86)'))) {
        if ((Get-DsbBlockedCount $p) -gt 0) { $incomplete.Add([string]$p) }
    }
    foreach ($p in $userTempPaths) { if ((Get-DsbBlockedCount $p) -gt 0) { $incomplete.Add([string]$p) } }
    if ($incomplete.Count) {
        Add-Warning ('Only partly readable, so these are a floor and not the real total: {0}.' -f (($incomplete.ToArray() | Sort-Object -Unique) -join ', '))
    }
} | Out-Null

# --- WinSxS actual size (DISM, elevated only) -------------------------------
$winSxSActual = $null; $winSxSReclaim = $null; $winSxSCleanup = $null
Invoke-Section 'WinSxS component store analysis' {
    if (-not $isSystemDrive) { return }
    if (-not $isAdmin) {
        Add-Warning 'WinSxS actual size / reclaimable (Dism /AnalyzeComponentStore): (needs admin). WinSxSGB below is the LOGICAL folder size and overstates the real disk cost.'
        return
    }
    $dism = Join-Path $winDir 'System32\Dism.exe'
    if (-not [System.IO.File]::Exists($dism)) { Add-Warning 'Dism.exe not found, so WinSxS actual size is unknown.'; return }
    $n = Invoke-Native -FilePath $dism -ArgumentList '/Online', '/Cleanup-Image', '/AnalyzeComponentStore'
    if ($n.ExitCode -ne 0) {
        $msg = ($n.Lines | Where-Object { $_ -match '\S' } | Select-Object -Last 1)
        Add-Warning ('Dism /AnalyzeComponentStore exited {0}: {1}' -f $n.ExitCode, $msg)
        return
    }
    $p = ConvertFrom-DsbDismAnalyze -Lines $n.Lines
    $script:DsbDismActual  = $p.ActualBytes
    $script:DsbDismReclaim = $p.ReclaimableBytes
    $script:DsbDismCleanup = $p.Recommended
    if ($null -eq $p.ActualBytes -and $null -eq $p.ReclaimableBytes) {
        Add-Warning 'Dism /AnalyzeComponentStore ran but none of the expected English labels were found (non-English Windows?), so WinSxS actual size was left empty.'
    }
} | Out-Null
$winSxSActual  = $script:DsbDismActual
$winSxSReclaim = $script:DsbDismReclaim
if ($null -ne $script:DsbDismCleanup) { $winSxSCleanup = [bool]$script:DsbDismCleanup }

# --- recycle bin ------------------------------------------------------------
$script:DsbRecycleBytes = [int64]0
$recycleRows = @(Invoke-Section 'Recycle Bin' {
    if (-not [System.IO.Directory]::Exists($pRecycle)) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    $denied = 0
    foreach ($d in [System.IO.Directory]::EnumerateDirectories($pRecycle)) {
        $sid = Split-Path $d -Leaf
        $before = $script:DsbDenied
        $b = Measure-DsbPath -Path $d
        if ($script:DsbDenied -gt $before) { $denied++ }
        $script:DsbRecycleBytes = [int64]$script:DsbRecycleBytes + [int64]$b
        # A SID folder that could not be opened at all was never measured: report $null, not a 0 that reads as empty.
        $rows.Add([PSCustomObject]@{
            Sid    = $sid
            User   = (Resolve-DsbSidName $sid)
            SizeGB = if (Test-DsbSelfDenied $d) { $null } else { (ConvertTo-DsbGB $b) }
            Bytes  = [int64]$b
        })
    }
    if ($denied -gt 0) { Add-Warning ("{0} Recycle Bin folder(s) were not readable by this account (their SizeGB is empty), so RecycleBinGB is understated." -f $denied) }
    # Sort on the raw byte count: rounding to GB first puts every sub-GB bin in an arbitrary tie group.
    @($rows.ToArray() |
        Sort-Object -Property @{Expression = 'Bytes'; Descending = $true}, @{Expression = 'Sid'; Descending = $false} |
        Select-Object -Property Sid, User, SizeGB)
} -Default @())
$recycleBytes = [int64]$script:DsbRecycleBytes

# --- stale profiles ---------------------------------------------------------
$script:DsbStaleBytes = [int64]0
$staleRows = @(Invoke-Section 'Stale profiles' {
    if (-not $isSystemDrive) { return @() }
    $cutoff = [DateTime]::Now.AddDays(-1 * $StaleProfileDays)
    $rows = New-Object System.Collections.Generic.List[object]
    $noDate = New-Object System.Collections.Generic.List[string]
    $denied = 0
    $unread = 0
    foreach ($pr in $profiles) {
        if ($pr.Loaded) { continue }
        if ($null -eq $pr.LastUseTime) {
            if ($pr.LocalPath) { $noDate.Add([string]$pr.LocalPath) }
            continue
        }
        if ($pr.LastUseTime -ge $cutoff) { continue }
        $before = $script:DsbDenied
        $b = Get-DsbFolderBytes $pr.LocalPath
        $selfDenied = Test-DsbSelfDenied $pr.LocalPath
        if ($selfDenied) { $unread++ }
        elseif ((Get-DsbBlockedCount $pr.LocalPath) -gt 0 -or $script:DsbDenied -gt $before) { $denied++ }
        $script:DsbStaleBytes = [int64]$script:DsbStaleBytes + [int64]$b
        # Same rule as the Recycle Bin rows: a folder that never opened reports $null, not a measured-looking 0.
        $rows.Add([PSCustomObject]@{
            User        = (Resolve-DsbSidName $pr.SID)
            FolderPath  = $pr.LocalPath
            LastUseTime = [datetime]$pr.LastUseTime
            SizeGB      = if ($selfDenied) { $null } else { (ConvertTo-DsbGB $b) }
            Bytes       = [int64]$b
        })
    }
    if ($noDate.Count) { Add-Warning ('Profile(s) with no LastUseTime were not judged stale: {0}.' -f (($noDate.ToArray()) -join ', ')) }
    if ($unread -gt 0) { Add-Warning ("{0} stale profile folder(s) could not be opened by this account at all, so their SizeGB is empty and StaleProfilesGB is understated." -f $unread) }
    if ($denied -gt 0) { Add-Warning ("{0} stale profile folder(s) were only partly readable by this account, so their SizeGB is understated." -f $denied) }
    @($rows.ToArray() |
        Sort-Object -Property @{Expression = 'Bytes'; Descending = $true}, @{Expression = 'FolderPath'; Descending = $false} |
        Select-Object -Property User, FolderPath, LastUseTime, SizeGB)
} -Default @())
$staleBytes = [int64]$script:DsbStaleBytes

# --- derived ----------------------------------------------------------------
$specialBytes = [int64](([int64]$hiberBytes) + ([int64]$pageBytes) + ([int64]$recycleBytes))
$unaccounted  = if ($null -ne $usedBytes) { [int64]($usedBytes - $scannedBytes - $specialBytes) } else { $null }
if ($null -ne $unaccounted -and $unaccounted -lt 0) {
    Add-Warning 'UnaccountedGB is negative, which is normal and not an error: file sizes are logical sizes, and WinSxS hard-links the same data into Windows twice while Compact OS and NTFS compression store files smaller than they measure. Treat the folder sizes as relative weights, not as blocks on the platter.'
}

$reclaimBytes = [int64](([int64]$updateBytes) + ([int64]$doBytes) + ([int64]$recycleBytes) +
                        ([int64]$winTempBytes) + ([int64]$userTempBytes) + ([int64]$winOldBytes) +
                        ([int64]$winSxSReclaim))

# --- top folders ------------------------------------------------------------
$topRows = @(Invoke-Section 'Top folders' {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($k in $script:DsbSizes.Keys) {
        if ($script:DsbLevels[$k] -gt $Depth) { continue }        # tracked deep folders are not folder-size rows
        $b = [int64]$script:DsbSizes[$k]
        $rows.Add([PSCustomObject]@{
            Path      = $script:DsbPaths[$k]
            SizeGB    = (ConvertTo-DsbGB $b)
            Size      = (Format-Bytes $b)
            Files     = [int]$script:DsbCounts[$k]
            PctOfUsed = if ($usedBytes -gt 0) { Round1 (100 * $b / $usedBytes) } else { $null }
            Bytes     = $b
        })
    }
    # Sort on raw bytes, never on the rounded SizeGB: rounding first collapses every folder under half a GB into
    # one tie group, so -Top could drop a real folder in favour of an empty one. Path breaks ties so the order is
    # the same on every run and a parent sorts above its equally sized child.
    @($rows.ToArray() |
        Sort-Object -Property @{Expression = 'Bytes'; Descending = $true}, @{Expression = 'Path'; Descending = $false} |
        Select-Object -First $Top |
        Select-Object -Property Path, SizeGB, Size, Files, PctOfUsed)
} -Default @())

$largeRows = @(Invoke-Section 'Large files' {
    @($script:DsbBigFiles.ToArray() | Sort-Object -Property Bytes -Descending | Select-Object -First 15 | ForEach-Object {
        [PSCustomObject]@{
            Path      = $_.Path
            SizeMB    = (Round1 ([double]$_.Bytes / 1MB))
            LastWrite = [datetime]$_.LastWrite
        }
    })
} -Default @())

# ---------------------------------------------------------------- output
$o = [ordered]@{}
$o.ComputerName                 = $env:COMPUTERNAME
$o.CollectedAt                  = [DateTime]::Now
$o.Drive                        = $driveId
$o.SizeGB                       = (ConvertTo-DsbGB $sizeBytes)
$o.UsedGB                       = (ConvertTo-DsbGB $usedBytes)
$o.FreeGB                       = (ConvertTo-DsbGB $freeBytes)
$o.FreePct                      = if ($sizeBytes -gt 0 -and $null -ne $freeBytes) { Round1 (100 * [double]$freeBytes / $sizeBytes) } else { $null }
$o.ScannedGB                    = (ConvertTo-DsbGB $scannedBytes)
$o.ScannedFiles                 = [int]$scannedFiles
$o.UnaccountedGB                = (ConvertTo-DsbGB $unaccounted)
$o.WinSxSGB                     = (ConvertTo-DsbGB $winSxSBytes)
$o.WinSxSActualGB               = (ConvertTo-DsbGB $winSxSActual)
$o.WinSxSReclaimableGB          = (ConvertTo-DsbGB $winSxSReclaim)
$o.WinSxSCleanupRecommended     = $winSxSCleanup
$o.UpdateCacheGB                = (ConvertTo-DsbGB $updateBytes)
$o.DeliveryOptimizationCacheGB  = (ConvertTo-DsbGB $doBytes)
$o.RecycleBinGB                 = (ConvertTo-DsbGB $recycleBytes)
$o.HiberfilGB                   = (ConvertTo-DsbGB $hiberBytes)
$o.HibernationEnabled           = $hiberOn
$o.PagefileGB                   = (ConvertTo-DsbGB $pageBytes)
$o.WindowsTempGB                = (ConvertTo-DsbGB $winTempBytes)
$o.UserTempGB                   = (ConvertTo-DsbGB $userTempBytes)
$o.WindowsOldGB                 = (ConvertTo-DsbGB $winOldBytes)
$o.StaleProfilesGB              = (ConvertTo-DsbGB $staleBytes)
$o.StaleProfileCount            = [int]$staleRows.Count
$o.ProgramFilesGB               = (ConvertTo-DsbGB $pfBytes)
$o.ProgramDataGB                = (ConvertTo-DsbGB $pdBytes)
$o.UsersGB                      = (ConvertTo-DsbGB $usersBytes)
$o.WindowsGB                    = (ConvertTo-DsbGB $windowsBytes)
$o.EstimatedReclaimGB           = (ConvertTo-DsbGB $reclaimBytes)
$o.EstimatedReclaim             = (Format-Bytes $reclaimBytes)
$o.DurationSeconds              = (Round1 ([DateTime]::Now - $started).TotalSeconds)
$o.TopFolders                   = @($topRows)
$o.LargeFiles                   = @($largeRows)
$o.RecycleBins                  = @($recycleRows)
$o.StaleProfiles                = @($staleRows)

$o.Warnings = ($script:Warnings -join '; ')
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
