<#
.SYNOPSIS
    One-screen machine fact sheet: hardware, OS, uptime, disk, identity, TPM, BitLocker, battery.
.DESCRIPTION
    Collects the facts a tech otherwise gathers from five consoles (System Information, Settings >
    System > About, dsregcmd, TPM/BitLocker, Disk Management) into one object: make/model/serial,
    BIOS, CPU/RAM, OS build and install dates, uptime and Fast Startup, pending reboot, system-drive
    space, domain/Entra/MDM state, console and last-logon user, IPv4, TPM, Secure Boot, BitLocker,
    activation and battery health. Everything degrades to a Warning when run without admin.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.EXAMPLE
    .\Get-MachineFactSheet.ps1
.EXAMPLE
    .\Get-MachineFactSheet.ps1 -Display -ReportPath C:\Temp\Toolkit
.NOTES
    Toolkit-Class:     ReadOnly
    Toolkit-Context:   Machine
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-MachineFactSheet'          # <-- set per tool
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

# Copies every key of a section's [ordered] result into the fact sheet, so the property order stays
# fixed even when a section fails (Invoke-Section then returns $null and nothing is copied).
function Merge-Fields {
    param($Target, $Values)
    if ($Values -is [System.Collections.IDictionary]) { foreach ($k in @($Values.Keys)) { $Target[$k] = $Values[$k] } }
}

# SMBIOS text fields are frequently filled with placeholders instead of being left empty.
$script:SmbiosPlaceholders = @(
    'No Asset Tag', 'No Asset Information', 'Asset Tag', 'Default string', 'System Version',
    'To Be Filled By O.E.M.', 'To be filled by O.E.M.', 'Not Specified', 'Not Available',
    'None', 'N/A', 'NA', 'Unknown', '0'
)
function Test-SmbiosPlaceholder {
    param([string]$Value)
    $v = ('{0}' -f $Value).Trim()
    if (-not $v) { return $true }
    foreach ($p in $script:SmbiosPlaceholders) { if ($v -eq $p) { return $true } }
    return $false
}

# First 'Label : value' line of dsregcmd /status output. Anchored so 'MdmUrl' never matches
# 'WorkplaceMdmUrl' and 'DeviceId' never matches 'DeviceManagementSrvId'.
function Get-DsregValue {
    param([string[]]$Lines, [string]$Label)
    $rx = '^\s*' + [regex]::Escape($Label) + '\s*:\s*(.*)$'
    foreach ($l in $Lines) { if ($l -match $rx) { return $Matches[1].Trim() } }
    return $null
}

# 'YES'/'NO' -> [bool]; anything else (label missing or renamed) -> $null.
function ConvertTo-YesNoBool { param([string]$Text) switch -Regex ($Text) { '^YES$' { $true } '^NO$' { $false } default { $null } } }

# Registry DWORD unix seconds arrive as Int32 (negative after 2038) -> local [datetime].
function ConvertFrom-UnixSeconds { param($Seconds) $n = [int64]$Seconds; if ($n -lt 0) { $n += 4294967296L }; [DateTimeOffset]::FromUnixTimeSeconds($n).LocalDateTime }

# ---------------------------------------------------------------- collection
$isAdmin     = Test-IsAdmin
$systemDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }

# Fixed property order (spec). Every field exists even when its section fails.
$o = [ordered]@{
    ComputerName           = $env:COMPUTERNAME
    CollectedAt            = [DateTime]::Now
    Manufacturer           = $null
    Model                  = $null
    SerialNumber           = $null
    AssetTag               = $null
    ChassisType            = $null
    BiosVersion            = $null
    BiosDate               = $null
    Cpu                    = $null
    CpuCores               = $null
    CpuLogical             = $null
    TotalRamGB             = $null
    AvailableRamGB         = $null
    OsName                 = $null
    OsVersion              = $null
    OsBuild                = $null
    OsArchitecture         = $null
    OsInstallDate          = $null
    OriginalInstallDate    = $null
    LastBoot               = $null
    UptimeHours            = $null
    Uptime                 = $null
    FastStartupEnabled     = $null
    PendingReboot          = $null
    SystemDriveFreeGB      = $null
    SystemDriveFreePct     = $null
    SystemDriveSizeGB      = $null
    FreeSpace              = $null
    Domain                 = $null
    DomainJoined           = $null
    EntraJoined            = $null
    EntraDeviceId          = $null
    MdmEnrolled            = $null
    ConsoleUser            = $null
    LastLogonUser          = $null
    IPv4Addresses          = $null
    TpmPresent             = $null
    TpmReady               = $null
    TpmVersion             = $null
    SecureBoot             = $null
    FirmwareType           = $null
    BitLockerStatus        = $null
    BitLockerRecoveryKeyId = $null
    WindowsActivated       = $null
    BatteryPresent         = $null
    BatteryHealthPct       = $null
    Elevated               = [bool]$isAdmin
    Warnings               = ''
}

# --- Computer system: make, model, RAM, domain.
# Lenovo (and some others) put the ordering code in Win32_ComputerSystem.Model ('21QX000MUS') and the
# name a human recognises in Win32_ComputerSystemProduct.Version ('ThinkPad T14s Gen 6'). Show both.
Merge-Fields $o (Invoke-Section 'Computer system' {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $model = ('{0}' -f $cs.Model).Trim()
    try {
        $friendly = ('{0}' -f (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).Version).Trim()
        if ($friendly -and -not (Test-SmbiosPlaceholder $friendly) -and
            $model -and $model -notlike ('*{0}*' -f $friendly) -and $friendly -notlike ('*{0}*' -f $model)) {
            $model = '{0} ({1})' -f $model, $friendly
        }
    } catch { }
    [ordered]@{
        Manufacturer = ('{0}' -f $cs.Manufacturer).Trim()
        Model        = $model
        TotalRamGB   = Round1 ($cs.TotalPhysicalMemory / 1GB)
        Domain       = ('{0}' -f $cs.Domain).Trim()
        DomainJoined = [bool]$cs.PartOfDomain
    }
})

# --- BIOS: serial (fallback to ComputerSystemProduct), version, date.
# SMBIOS stores a bare date; Windows surfaces it as midnight UTC, which renders as the PREVIOUS day in
# any negative-offset time zone. Convert back to the stored UTC date so it matches the BIOS setup screen.
Merge-Fields $o (Invoke-Section 'BIOS' {
    $b = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $serial = ('{0}' -f $b.SerialNumber).Trim()
    if (Test-SmbiosPlaceholder $serial) {
        $serial = ''
        try { $alt = ('{0}' -f (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).IdentifyingNumber).Trim()
              if (-not (Test-SmbiosPlaceholder $alt)) { $serial = $alt } } catch { }
    }
    $rel = $null
    if ($b.ReleaseDate) {
        $rd = [datetime]$b.ReleaseDate
        $utc = $rd.ToUniversalTime()
        $rel = $(if ($utc.TimeOfDay -eq [TimeSpan]::Zero) { $utc.Date } else { $rd.Date })
    }
    [ordered]@{
        SerialNumber = $serial
        BiosVersion  = ('{0}' -f $b.SMBIOSBIOSVersion).Trim()
        BiosDate     = $rel
    }
})

# --- Enclosure: asset tag (placeholders blanked) and chassis type decoded
Merge-Fields $o (Invoke-Section 'Enclosure' {
    $se  = Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop | Select-Object -First 1
    $tag = ('{0}' -f $se.SMBIOSAssetTag).Trim()
    if (Test-SmbiosPlaceholder $tag) { $tag = '' }
    $ct = [int](@($se.ChassisTypes) | Select-Object -First 1)
    $chassis = switch ($ct) {
        { $_ -in 3, 4, 6, 7 }   { 'Desktop' }
        { $_ -in 8, 9, 10, 14 } { 'Laptop' }
        30                      { 'Tablet' }
        31                      { 'Convertible' }
        32                      { 'Detachable' }
        35                      { 'Mini PC' }
        36                      { 'Stick' }
        default                 { 'Other ({0})' -f $ct }
    }
    [ordered]@{ AssetTag = $tag; ChassisType = $chassis }
})

# --- CPU: name of the first socket, core/thread totals across sockets
Merge-Fields $o (Invoke-Section 'CPU' {
    $cpus = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    if (-not $cpus.Count) { throw 'Win32_Processor returned nothing' }
    $cores = 0; $logical = 0
    foreach ($c in $cpus) { $cores += [int]$c.NumberOfCores; $logical += [int]$c.NumberOfLogicalProcessors }
    [ordered]@{
        Cpu        = (('{0}' -f $cpus[0].Name) -replace '\s+', ' ').Trim()
        CpuCores   = [int]$cores
        CpuLogical = [int]$logical
    }
})

# --- OS (CIM): name, architecture, install date, boot time, uptime, free RAM
$script:osInstallDate = $null
Merge-Fields $o (Invoke-Section 'Operating system' {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $lastBoot = [datetime]$os.LastBootUpTime
    $span = [DateTime]::Now - $lastBoot
    $script:osInstallDate = $(if ($os.InstallDate) { [datetime]$os.InstallDate } else { $null })
    [ordered]@{
        OsName         = ('{0}' -f $os.Caption).Trim()
        OsArchitecture = ('{0}' -f $os.OSArchitecture).Trim()
        OsInstallDate  = $script:osInstallDate
        LastBoot       = $lastBoot
        UptimeHours    = Round1 $span.TotalHours
        Uptime         = Format-Duration $span
        AvailableRamGB = Round1 (([int64]$os.FreePhysicalMemory * 1KB) / 1GB)
    }
})

# --- OS (registry): DisplayVersion (25H2) and CurrentBuild.UBR.
# ProductName is deliberately NOT used: it still reads 'Windows 10 Enterprise' on Windows 11.
Merge-Fields $o (Invoke-Section 'OS registry' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $ver = ('{0}' -f $cv.DisplayVersion).Trim()
    if (-not $ver) { $ver = ('{0}' -f $cv.ReleaseId).Trim() }
    [ordered]@{
        OsVersion = $ver
        OsBuild   = ('{0}.{1}' -f $cv.CurrentBuild, $cv.UBR)
    }
})

# --- Original install date: the oldest of the current install and every 'Source OS (Updated on ...)'
# key a feature update left behind. Win32_OperatingSystem.InstallDate is reset by feature updates,
# so on an upgraded machine it is the upgrade date, not the day the machine was first built.
Merge-Fields $o (Invoke-Section 'Original install date' {
    $dates = New-Object System.Collections.Generic.List[datetime]
    if ($script:osInstallDate) { $dates.Add($script:osInstallDate) }
    $cur = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).InstallDate
    if ($null -ne $cur -and [int64]$cur -ne 0) { $dates.Add((ConvertFrom-UnixSeconds $cur)) }
    foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\Setup' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Source OS*' })) {
        $d = $null
        try { $d = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop).InstallDate } catch { }
        if ($null -ne $d -and [int64]$d -ne 0) { $dates.Add((ConvertFrom-UnixSeconds $d)) }
    }
    [ordered]@{ OriginalInstallDate = $(if ($dates.Count) { ($dates | Sort-Object | Select-Object -First 1) } else { $null }) }
})

# --- Fast Startup (HiberbootEnabled): with it on, 'Shut down' hibernates the kernel instead of
# rebooting, so uptime keeps growing across shutdowns and a pending reboot never clears.
Merge-Fields $o (Invoke-Section 'Fast Startup' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled
    [ordered]@{ FastStartupEnabled = [bool]($null -ne $v -and [int]$v -eq 1) }
})

# --- Pending reboot: CBS, Windows Update, pending file renames, computer rename
Merge-Fields $o (Invoke-Section 'Pending reboot' {
    $pending = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro -and @($pfro | Where-Object { $_ }).Count) { $pending = $true }
    $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction Stop).ComputerName
    $stored = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction Stop).ComputerName
    if ($active -and $stored -and $active -ne $stored) { $pending = $true }
    [ordered]@{ PendingReboot = [bool]$pending }
})

# --- System drive space
Merge-Fields $o (Invoke-Section 'System drive' {
    $ld = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive) -ErrorAction Stop | Select-Object -First 1
    if (-not $ld) { throw ('{0} not found in Win32_LogicalDisk' -f $systemDrive) }
    $size = [int64]$ld.Size; $free = [int64]$ld.FreeSpace
    $pct  = $(if ($size -gt 0) { Round1 ($free / $size * 100) } else { $null })
    [ordered]@{
        SystemDriveFreeGB  = Round1 ($free / 1GB)
        SystemDriveFreePct = $pct
        SystemDriveSizeGB  = Round1 ($size / 1GB)
        FreeSpace          = $(if ($null -ne $pct) { '{0} free of {1} ({2}%)' -f (Format-Bytes $free), (Format-Bytes $size), [int][math]::Round([double]$pct) }
                              else { '{0} free' -f (Format-Bytes $free) })
    }
})

# --- Entra / MDM state from dsregcmd /status (the device-level lines are the same for any account)
Merge-Fields $o (Invoke-Section 'Entra (dsregcmd)' {
    $r = Invoke-Native -FilePath 'dsregcmd.exe' -ArgumentList '/status'
    if ($r.ExitCode -ne 0) { throw ('dsregcmd /status exit code {0}' -f $r.ExitCode) }
    $joined = ConvertTo-YesNoBool (Get-DsregValue $r.Lines 'AzureAdJoined')
    if ($null -eq $joined) { Add-Warning 'Entra (dsregcmd): AzureAdJoined line not found; EntraJoined left blank' }
    $deviceId   = Get-DsregValue $r.Lines 'DeviceId'
    $mdmUrl     = Get-DsregValue $r.Lines 'MdmUrl'
    $mdmSection = @($r.Lines | Where-Object { $_ -match '^\s*\|\s*MDM\b' }).Count -gt 0
    [ordered]@{
        EntraJoined   = $joined
        EntraDeviceId = $(if ($deviceId) { $deviceId } else { '' })
        MdmEnrolled   = [bool](($mdmUrl -and $mdmUrl.Trim()) -or $mdmSection)
    }
})

# --- Console user (the person at the desk, not the account this script runs as) and the name the
# sign-in screen will offer next.
Merge-Fields $o (Invoke-Section 'Console user' {
    $cu = Get-ConsoleUser
    if ($cu.Source -eq 'Process') { Add-Warning 'Console user: nobody is signed in at the console (no interactive session found)' }
    elseif ($cu.OtherDesktops)    { Add-Warning ('Console user: other live desktops on this machine: {0}' -f $cu.OtherDesktops) }
    [ordered]@{ ConsoleUser = $(if ($cu.Source -eq 'Process') { '' } else { $cu.Name }) }
})
Merge-Fields $o (Invoke-Section 'Last logon user' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction Stop).LastLoggedOnUser
    [ordered]@{ LastLogonUser = ('{0}' -f $v).Trim() }
})

# --- IPv4 on up adapters, non-APIPA, non-loopback (.NET: ~40 ms; Get-NetIPAddress costs ~3 s)
Merge-Fields $o (Invoke-Section 'IPv4 addresses' {
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($ni.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        if ($ni.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }
        foreach ($ua in $ni.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $s = $ua.Address.ToString()
            if ($s -like '169.254.*' -or $s -like '127.*') { continue }
            if (-not $ips.Contains($s)) { $ips.Add($s) }
        }
    }
    [ordered]@{ IPv4Addresses = ($ips -join '; ') }
})

# --- TPM. Both sources need admin: unelevated Get-Tpm returns the refusal as a STRING (it does not
# throw) and Win32_Tpm denies access, so do not even ask when we are not elevated.
if ($isAdmin) {
    Merge-Fields $o (Invoke-Section 'TPM' {
        $t = Get-Tpm -ErrorAction Stop
        if ($t -is [string]) { throw $t }
        $spec = ''
        try {
            $w = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
            if ($w -and $w.SpecVersion) { $spec = ('{0}' -f $w.SpecVersion).Split(',')[0].Trim() }
        } catch { Add-Warning ('TPM version (Win32_Tpm): {0}' -f $_.Exception.Message.Trim()) }
        [ordered]@{
            TpmPresent = [bool]$t.TpmPresent
            TpmReady   = [bool]$t.TpmReady
            TpmVersion = $spec
        }
    })
    # Elevated but the query still failed: say so, so a blank is never read as "no TPM". Covers both
    # the whole section failing ($null) and Win32_Tpm alone failing or returning no SpecVersion ('').
    if (-not $o.TpmVersion) { $o.TpmVersion = '(unavailable)' }
} else {
    $o.TpmVersion = '(needs admin)'
    Add-Warning 'TPM: (needs admin)'
}

# --- Secure Boot / firmware. Standard users CAN read the SecureBoot State key; the key only exists on
# UEFI firmware, so its absence (with no other UEFI signal) means a legacy BIOS.
Merge-Fields $o (Invoke-Section 'Secure Boot' {
    $fw = ('{0}' -f $env:firmware_type).Trim()
    $sb = $null
    $statePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $uefiHint  = ($fw -eq 'UEFI') -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot')
    if (Test-Path $statePath) {
        $v = (Get-ItemProperty $statePath -ErrorAction Stop).UEFISecureBootEnabled
        $sb = [bool]($null -ne $v -and [int]$v -eq 1)
        if (-not $fw) { $fw = 'UEFI' }
    } elseif ($uefiHint) {
        if (-not $fw) { $fw = 'UEFI' }
        Add-Warning 'Secure Boot: UEFI firmware but the SecureBoot State key is missing; SecureBoot left blank'
    } else {
        $sb = $false
        if (-not $fw) { $fw = 'Legacy' }
    }
    [ordered]@{ SecureBoot = $sb; FirmwareType = $fw }
})

# --- BitLocker on the system drive. Elevated gives protection + encryption state + recovery key IDs;
# unelevated the Explorer shell property still reports the protection state.
if ($isAdmin) {
    Merge-Fields $o (Invoke-Section 'BitLocker' {
        $bv = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop | Select-Object -First 1
        if (-not $bv) { throw ('no BitLocker volume object for {0}' -f $systemDrive) }
        $ids = @($bv.KeyProtector | Where-Object { ('{0}' -f $_.KeyProtectorType) -eq 'RecoveryPassword' } |
                 ForEach-Object { ('{0}' -f $_.KeyProtectorId).Trim() } | Where-Object { $_ })
        [ordered]@{
            BitLockerStatus        = ('{0} / {1} ({2}%)' -f $bv.ProtectionStatus, $bv.VolumeStatus, [int]$bv.EncryptionPercentage)
            BitLockerRecoveryKeyId = ($ids -join '; ')
        }
    })
    # An empty string here is a real finding (BitLocker on, no recovery password protector). A failed
    # query must not look like that, so mark it instead of leaving it blank.
    if ($null -eq $o.BitLockerRecoveryKeyId) { $o.BitLockerRecoveryKeyId = '(unavailable)' }
}
if (-not $isAdmin -or $null -eq $o.BitLockerStatus) {
    Merge-Fields $o (Invoke-Section 'BitLocker (shell)' {
        $shell = New-Object -ComObject Shell.Application
        $raw   = $shell.NameSpace($systemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $code  = $(if ($null -eq $raw -or ('{0}' -f $raw) -eq '') { 0 } else { [int]$raw })
        $status = switch ($code) { 1 { 'On' } 2 { 'Off' } 3 { 'Encrypting' } 4 { 'Decrypting' } 5 { 'Suspended' } 6 { 'Locked' } default { 'Unknown' } }
        [ordered]@{ BitLockerStatus = $status }
    })
    if (-not $isAdmin) {
        $o.BitLockerRecoveryKeyId = '(needs admin)'
        Add-Warning 'BitLocker recovery key ID: (needs admin)'
    }
}

# --- Windows activation. The WQL filter matters: an unfiltered SoftwareLicensingProduct enumeration
# walks every installed licence and takes ~30 s.
Merge-Fields $o (Invoke-Section 'Windows activation' {
    $lic = @(Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop)
    [ordered]@{ WindowsActivated = [bool](@($lic | Where-Object { [int]$_.LicenseStatus -eq 1 }).Count -gt 0) }
})

# --- Battery: presence, and health = full-charge capacity / design capacity.
# BatteryFullChargedCapacity reads fine as a standard user; BatteryStaticData (the design capacity)
# throws 'Generic failure' unelevated, so fall back to powercfg's XML battery report, written to this
# tool's own $env:TEMP file and deleted before exit.
Merge-Fields $o (Invoke-Section 'Battery' {
    $bat = @(Get-CimInstance Win32_Battery -ErrorAction Stop)
    $present = $bat.Count -gt 0
    $health = $null
    if ($present) {
        $full = $null; $design = $null
        try {
            $fc = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction Stop)
            if ($fc.Count) { $full = 0; foreach ($f in $fc) { $full += [int64]$f.FullChargedCapacity } }
            $sd = @(Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction Stop)
            if ($sd.Count) { $design = 0; foreach ($s in $sd) { $design += [int64]$s.DesignedCapacity } }
        } catch { $design = $null }
        if (-not ($full -and $design)) {
            $tmp = Join-Path $env:TEMP ('{0}-battery-{1}.xml' -f $script:ToolName, [guid]::NewGuid().ToString('N'))
            try {
                $r = Invoke-Native -FilePath 'powercfg.exe' -ArgumentList '/batteryreport', '/xml', '/output', $tmp
                if ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath $tmp)) {
                    [xml]$x = [System.IO.File]::ReadAllText($tmp)
                    $f2 = 0; $d2 = 0
                    foreach ($b in @($x.BatteryReport.Batteries.Battery)) {
                        $fv = ('{0}' -f $b.FullChargeCapacity).Trim(); $dv = ('{0}' -f $b.DesignCapacity).Trim()
                        if ($fv -match '^\d+$' -and $dv -match '^\d+$') { $f2 += [int64]$fv; $d2 += [int64]$dv }
                    }
                    if ($f2 -gt 0 -and $d2 -gt 0) { $full = $f2; $design = $d2 }
                } else { Add-Warning ('Battery health: powercfg /batteryreport exit code {0}' -f $r.ExitCode) }
            } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
        }
        if ($full -and $design -and $design -gt 0) { $health = Round1 ($full / $design * 100) }
        else { Add-Warning 'Battery health: capacity data not readable (BatteryHealthPct left blank)' }
    }
    [ordered]@{ BatteryPresent = [bool]$present; BatteryHealthPct = $health }
})

# ---------------------------------------------------------------- output
$o.Warnings = ($script:Warnings -join '; ')          # shape A only
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
