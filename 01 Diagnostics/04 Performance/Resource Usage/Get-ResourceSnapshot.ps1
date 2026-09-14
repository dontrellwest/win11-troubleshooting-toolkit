<#
.SYNOPSIS
    Samples CPU, memory, disk IO and handle counts over a window and names the top processes.
.DESCRIPTION
    Repeatedly reads the Windows performance counters (CIM, no Get-Counter) for a window of
    -DurationSeconds, every -IntervalSeconds. Reports machine-wide averages and peaks plus the
    processes that were worst for CPU, working set, disk IO and handle count over that window.
    Sampling over a window (not one instant) is what makes an intermittent hog visible.
.PARAMETER Display
    Print a readable report to the screen instead of returning objects.
.PARAMETER ReportPath
    Folder to also save the readable report to (only used with -Display). Created if missing.
.PARAMETER DurationSeconds
    Length of the sampling window. Default 60.
.PARAMETER IntervalSeconds
    Seconds between samples. Default 5.
.PARAMETER Top
    How many processes each of the four rankings contributes to TopProcesses. Default 10.
.EXAMPLE
    .\Get-ResourceSnapshot.ps1
.EXAMPLE
    .\Get-ResourceSnapshot.ps1 -Display -ReportPath C:\Temp\Toolkit
.EXAMPLE
    .\Get-ResourceSnapshot.ps1 -DurationSeconds 300 -IntervalSeconds 10 -Display
.NOTES
    Toolkit-Class:     ReadOnly            (ReadOnly | Remediation)
    Toolkit-Context:   Machine             (Machine | User)
    Toolkit-Elevation: None                (Required | Recommended | None)
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [string]$ReportPath,
    [ValidateRange(2, 3600)][int]$DurationSeconds = 60,
    [ValidateRange(1, 600)][int]$IntervalSeconds = 5,
    [ValidateRange(1, 200)][int]$Top = 10
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-ResourceSnapshot'
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
# Perf-counter instance names carry a positional ordinal for duplicate images ('chrome#7'). The ordinal is
# not part of the process name and can be reassigned when a process exits, so strip it; IDProcess is the key.
function Get-BaseProcessName { param([string]$Name) if ($null -eq $Name) { $null } else { ($Name -replace '#\d+$', '') } }

# One counter class, isolated. A dead or disabled counter provider must blank only its own fields, never
# discard the whole sample, so every class is queried on its own and its first error is recorded by name.
# Returns the instances (an empty array when the class errored or exposed no instances - the caller tells the
# two apart by looking in $ErrorLog).
function Get-PerfInstances {
    param([string]$ClassName, [string]$Filter, $ErrorLog)
    try {
        if ($Filter) { @(Get-CimInstance -ClassName $ClassName -Filter $Filter -ErrorAction Stop) }
        else         { @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop) }
    } catch {
        if (-not $ErrorLog.Contains($ClassName)) { $ErrorLog[$ClassName] = $_.Exception.Message.Trim() }
        @()
    }
}

$o = [ordered]@{}
$o.ComputerName = $env:COMPUTERNAME
$o.CollectedAt  = [DateTime]::Now

$isAdmin = Test-IsAdmin

# --- machine constants -------------------------------------------------------------------------------
$cs = Invoke-Section 'Computer system' { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
$logicalCpus = 0
if ($cs -and $cs.NumberOfLogicalProcessors) { $logicalCpus = [int]$cs.NumberOfLogicalProcessors }
if ($logicalCpus -lt 1) {
    $logicalCpus = 0
    if ($env:NUMBER_OF_PROCESSORS -match '^\d+$') { $logicalCpus = [int]$env:NUMBER_OF_PROCESSORS }
    if ($logicalCpus -lt 1) { $logicalCpus = 1 }
    Add-Warning ('Logical CPU count unreadable from Win32_ComputerSystem; using {0}. Per-process CPU percentages may be wrong.' -f $logicalCpus)
}
$memTotalGB = $null
if ($cs -and $cs.TotalPhysicalMemory) { $memTotalGB = Round1 ([double]$cs.TotalPhysicalMemory / 1GB) }

# --- sampling ----------------------------------------------------------------------------------------
$procAgg      = New-Object 'System.Collections.Generic.Dictionary[int,object]'
$sysSamples   = New-Object System.Collections.Generic.List[object]
$procCounts   = New-Object System.Collections.Generic.List[int]
$sampleCount  = 0      # samples in which at least one counter class answered
$procSamples  = 0      # samples in which the per-process class answered
$failedSamples = 0     # samples in which every counter class failed
$firstSampleError = $null
$queriesPerSample = 5
$classErrors = [ordered]@{}    # counter class -> first error text seen, so one dead provider is named
$sawProc = $false; $sawCpu = $false; $sawMem = $false; $sawDsk = $false; $sawNet = $false
$plannedSamples = [math]::Max(1, [int][math]::Floor($DurationSeconds / $IntervalSeconds))
if ($plannedSamples -lt 2) {
    Add-Warning ('IntervalSeconds ({0}) is not smaller than DurationSeconds ({1}), so only one sample is taken and this is an instant reading, not a window.' -f $IntervalSeconds, $DurationSeconds)
}
$windowWatch  = [Diagnostics.Stopwatch]::StartNew()

for ($i = 1; $i -le $plannedSamples; $i++) {
    $remaining = [int]([math]::Max(0, ($plannedSamples - $i + 1) * $IntervalSeconds))
    Write-Progress -Activity ('{0}: sampling {1}s window' -f $script:ToolName, $DurationSeconds) `
                   -Status ('Sample {0} of {1}' -f $i, $plannedSamples) `
                   -PercentComplete ([int](100.0 * ($i - 1) / $plannedSamples)) `
                   -SecondsRemaining $remaining
    $sampleWatch = [Diagnostics.Stopwatch]::StartNew()
    $sampleErr = [ordered]@{}
    $rows = @(Get-PerfInstances 'Win32_PerfFormattedData_PerfProc_Process' $null $sampleErr |
              Where-Object { $_.Name -ne '_Total' -and $_.Name -ne 'Idle' -and [int]$_.IDProcess -gt 0 })
    $procOk = -not $sampleErr.Contains('Win32_PerfFormattedData_PerfProc_Process')
    $cpuT = @(Get-PerfInstances 'Win32_PerfFormattedData_PerfOS_Processor' "Name='_Total'" $sampleErr) | Select-Object -First 1
    $mem  = @(Get-PerfInstances 'Win32_PerfFormattedData_PerfOS_Memory' $null $sampleErr) | Select-Object -First 1
    $dsk  = @(Get-PerfInstances 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' "Name='_Total'" $sampleErr) | Select-Object -First 1
    $net  = @(Get-PerfInstances 'Win32_PerfFormattedData_Tcpip_NetworkInterface' $null $sampleErr)
    foreach ($k in @($sampleErr.Keys)) { if (-not $classErrors.Contains($k)) { $classErrors[$k] = $sampleErr[$k] } }
    if ($rows.Count) { $sawProc = $true }
    if ($cpuT)       { $sawCpu  = $true }
    if ($mem)        { $sawMem  = $true }
    if ($dsk)        { $sawDsk  = $true }
    if ($net.Count)  { $sawNet  = $true }

    foreach ($r in $rows) {
        $key  = [int]$r.IDProcess
        $cpu  = [double]$r.PercentProcessorTime
        $wsp  = [double]$r.WorkingSetPrivate
        $io   = [double]$r.IODataBytesPersec
        $hnd  = [int]$r.HandleCount
        $thr  = [int]$r.ThreadCount
        if ($procAgg.ContainsKey($key)) {
            $a = $procAgg[$key]
            $a.Name = Get-BaseProcessName $r.Name       # last name wins; ordinals are stripped anyway
            $a.CpuSum += $cpu; if ($cpu -gt $a.CpuMax) { $a.CpuMax = $cpu }
            $a.MemSum += $wsp; if ($wsp -gt $a.MemMax) { $a.MemMax = $wsp }
            $a.IoSum  += $io;  if ($io  -gt $a.IoMax)  { $a.IoMax  = $io }
            if ($hnd -gt $a.HandlesMax) { $a.HandlesMax = $hnd }
            if ($thr -gt $a.ThreadsMax) { $a.ThreadsMax = $thr }
            $a.Samples++
        } else {
            $procAgg[$key] = [PSCustomObject]@{
                Pid = $key; Name = (Get-BaseProcessName $r.Name)
                CpuSum = $cpu; CpuMax = $cpu
                MemSum = $wsp; MemMax = $wsp
                IoSum  = $io;  IoMax  = $io
                HandlesMax = $hnd; ThreadsMax = $thr; Samples = 1
            }
        }
    }
    if ($procOk) { $procSamples++; $procCounts.Add([int]$rows.Count) }

    if ($sampleErr.Count -ge $queriesPerSample) {
        # every class failed in this sample: nothing to record
        $failedSamples++
        if (-not $firstSampleError) { $firstSampleError = '{0}: {1}' -f @($sampleErr.Keys)[0], @($sampleErr.Values)[0] }
    } else {
        # no network instances at all is NOT zero traffic: leave it $null so Get-Stat drops it
        $netBytes = $null
        if ($net.Count) {
            $netBytes = 0.0
            foreach ($n in $net) { if ($null -ne $n.BytesTotalPersec) { $netBytes += [double]$n.BytesTotalPersec } }
        }
        $sysSamples.Add([PSCustomObject]@{
            Cpu        = $(if ($cpuT) { [double]$cpuT.PercentProcessorTime } else { $null })
            AvailMB    = $(if ($mem)  { [double]$mem.AvailableMBytes } else { $null })
            PagesSec   = $(if ($mem)  { [double]$mem.PagesPersec } else { $null })
            DiskQueue  = $(if ($dsk)  { [double]$dsk.AvgDiskQueueLength } else { $null })
            DiskIdle   = $(if ($dsk)  { [double]$dsk.PercentIdleTime } else { $null })
            DiskBytes  = $(if ($dsk)  { [double]$dsk.DiskBytesPersec } else { $null })
            NetBytes   = $netBytes
        })
        $sampleCount++
    }
    if ($i -lt $plannedSamples) {
        $sleepMs = ($IntervalSeconds * 1000) - $sampleWatch.ElapsedMilliseconds
        if ($sleepMs -gt 0) { Start-Sleep -Milliseconds $sleepMs }
    }
}
Write-Progress -Activity ('{0}: sampling {1}s window' -f $script:ToolName, $DurationSeconds) -Completed
$windowWatch.Stop()
$actualWindow = $windowWatch.Elapsed.TotalSeconds

if ($failedSamples -gt 0) {
    Add-Warning ('Sampling: {0} of {1} samples failed completely ({2}).' -f $failedSamples, $plannedSamples, $firstSampleError)
}
if ($sampleCount -eq 0) {
    Add-Warning 'Sampling: no samples were collected; every metric below is empty. Check that the performance counters are healthy (lodctr /q).'
}

# One counter class going dark blanks only its own fields. Name every such class so that no field below is
# blank without an explanation, and so that a blank is never mistaken for a measured zero.
$counterClasses = @(
    [PSCustomObject]@{ Class = 'Win32_PerfFormattedData_PerfProc_Process';       Seen = $sawProc; Fields = 'ProcessCount, TopCpu/TopMemory/TopIo/TopHandles and TopProcesses' }
    [PSCustomObject]@{ Class = 'Win32_PerfFormattedData_PerfOS_Processor';       Seen = $sawCpu;  Fields = 'CpuAvgPct and CpuMaxPct' }
    [PSCustomObject]@{ Class = 'Win32_PerfFormattedData_PerfOS_Memory';          Seen = $sawMem;  Fields = 'MemAvailableAvgGB, MemAvailableMinGB, MemUsedPct and PagesPerSecAvg' }
    [PSCustomObject]@{ Class = 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk';  Seen = $sawDsk;  Fields = 'DiskQueueAvg, DiskQueueMax, DiskIdlePctAvg, DiskMBpsAvg and DiskMBpsMax' }
    [PSCustomObject]@{ Class = 'Win32_PerfFormattedData_Tcpip_NetworkInterface'; Seen = $sawNet;  Fields = 'NetMbpsAvg and NetMbpsMax' }
)
foreach ($c in $counterClasses) {
    if ($classErrors.Contains($c.Class)) {
        Add-Warning ('{0} could not be read ({1}); {2} are blank, not zero.' -f $c.Class, $classErrors[$c.Class], $c.Fields)
    } elseif ($sampleCount -gt 0 -and -not $c.Seen) {
        Add-Warning ('{0} returned no instances; {1} are blank, not zero.' -f $c.Class, $c.Fields)
    }
}
if ($sampleCount -gt 0 -and $actualWindow -gt ($DurationSeconds * 1.2)) {
    Add-Warning ('Sampling: the window took {0}s instead of the requested {1}s (the machine was too busy to keep the interval).' -f [int]$actualWindow, $DurationSeconds)
}

# --- machine-wide aggregates -------------------------------------------------------------------------
function Get-Stat {
    param([System.Collections.Generic.List[object]]$Samples, [string]$Property, [string]$Mode)
    $vals = @($Samples | ForEach-Object { $_.$Property } | Where-Object { $null -ne $_ })
    if (-not $vals.Count) { return $null }
    switch ($Mode) {
        'Avg' { ($vals | Measure-Object -Average).Average }
        'Max' { ($vals | Measure-Object -Maximum).Maximum }
        'Min' { ($vals | Measure-Object -Minimum).Minimum }
    }
}

$o.DurationSeconds  = [int]$DurationSeconds
$o.IntervalSeconds  = [int]$IntervalSeconds
$o.SampleCount      = [int]$sampleCount
$o.LogicalCpus      = [int]$logicalCpus

$o.CpuAvgPct = Round1 (Invoke-Section 'CPU average' { Get-Stat $sysSamples 'Cpu' 'Avg' })
$o.CpuMaxPct = Round1 (Invoke-Section 'CPU peak'    { Get-Stat $sysSamples 'Cpu' 'Max' })

$o.MemTotalGB = $memTotalGB
$availAvgMB = Invoke-Section 'Memory average' { Get-Stat $sysSamples 'AvailMB' 'Avg' }
$availMinMB = Invoke-Section 'Memory low'     { Get-Stat $sysSamples 'AvailMB' 'Min' }
$o.MemAvailableAvgGB = $(if ($null -ne $availAvgMB) { Round1 ($availAvgMB / 1024) } else { $null })
$o.MemAvailableMinGB = $(if ($null -ne $availMinMB) { Round1 ($availMinMB / 1024) } else { $null })
$o.MemUsedPct = $(if ($null -ne $availAvgMB -and $memTotalGB) { Round1 ((1 - (($availAvgMB / 1024) / $memTotalGB)) * 100) } else { $null })
$o.PagesPerSecAvg = Round1 (Invoke-Section 'Pages/sec' { Get-Stat $sysSamples 'PagesSec' 'Avg' })

$o.DiskQueueAvg   = Round1 (Invoke-Section 'Disk queue avg'  { Get-Stat $sysSamples 'DiskQueue' 'Avg' })
$o.DiskQueueMax   = Round1 (Invoke-Section 'Disk queue peak' { Get-Stat $sysSamples 'DiskQueue' 'Max' })
$o.DiskIdlePctAvg = Round1 (Invoke-Section 'Disk idle'       { Get-Stat $sysSamples 'DiskIdle'  'Avg' })
$dskAvg = Invoke-Section 'Disk throughput avg'  { Get-Stat $sysSamples 'DiskBytes' 'Avg' }
$dskMax = Invoke-Section 'Disk throughput peak' { Get-Stat $sysSamples 'DiskBytes' 'Max' }
$o.DiskMBpsAvg = $(if ($null -ne $dskAvg) { Round1 ($dskAvg / 1MB) } else { $null })
$o.DiskMBpsMax = $(if ($null -ne $dskMax) { Round1 ($dskMax / 1MB) } else { $null })

$netAvg = Invoke-Section 'Network avg'  { Get-Stat $sysSamples 'NetBytes' 'Avg' }
$netMax = Invoke-Section 'Network peak' { Get-Stat $sysSamples 'NetBytes' 'Max' }
$o.NetMbpsAvg = $(if ($null -ne $netAvg) { Round1 ($netAvg * 8 / 1000000) } else { $null })
$o.NetMbpsMax = $(if ($null -ne $netMax) { Round1 ($netMax * 8 / 1000000) } else { $null })

$o.ProcessCount = $(if ($procCounts.Count) { [int](($procCounts | Measure-Object -Maximum).Maximum) } else { $null })

# --- per-process roll-up -----------------------------------------------------------------------------
$procs = @(Invoke-Section 'Per-process roll-up' {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($a in $procAgg.Values) {
        $list.Add([PSCustomObject]@{
            Name       = $a.Name
            Pid        = [int]$a.Pid
            CpuAvgPct  = Round1 (($a.CpuSum / $a.Samples) / $logicalCpus)
            CpuMaxPct  = Round1 ($a.CpuMax / $logicalCpus)
            MemAvgMB   = Round1 (($a.MemSum / $a.Samples) / 1MB)
            MemMaxMB   = Round1 ($a.MemMax / 1MB)
            IoAvgMBps  = Round1 (($a.IoSum / $a.Samples) / 1MB)
            IoMaxMBps  = Round1 ($a.IoMax / 1MB)
            HandlesMax = [int]$a.HandlesMax
            ThreadsMax = [int]$a.ThreadsMax
            Samples    = [int]$a.Samples
        })
    }
    $list.ToArray()
} -Default @())

# Each ranking keeps only processes that actually registered on that counter, so an idle machine does not
# pad the table with ten processes at 0.0 MB/s. This can only shorten a ranking, never hide a busier process.
$byCpu = @($procs | Where-Object { $_.CpuAvgPct -gt 0 -or $_.CpuMaxPct -gt 0 } | Sort-Object -Property CpuAvgPct, CpuMaxPct -Descending | Select-Object -First $Top)
$byMem = @($procs | Where-Object { $_.MemMaxMB  -gt 0 } | Sort-Object -Property MemMaxMB  -Descending | Select-Object -First $Top)
$byIo  = @($procs | Where-Object { $_.IoAvgMBps -gt 0 -or $_.IoMaxMBps -gt 0 } | Sort-Object -Property IoAvgMBps, IoMaxMBps -Descending | Select-Object -First $Top)
$byHnd = @($procs | Where-Object { $_.HandlesMax -gt 0 } | Sort-Object -Property HandlesMax -Descending | Select-Object -First $Top)

# summary strings: top 3 of each ranking
$fmtTop = {
    param($rows, [scriptblock]$Render)
    $s = (@($rows | Select-Object -First 3 | ForEach-Object { & $Render $_ }) -join '; ')
    if ($s) { $s } else { '(none)' }
}
$o.TopCpu     = & $fmtTop $byCpu { param($p) '{0} ({1}%/{2}%)'   -f $p.Name, $p.CpuAvgPct, $p.CpuMaxPct }
$o.TopMemory  = & $fmtTop $byMem { param($p) '{0} ({1}/{2} MB)'  -f $p.Name, $p.MemAvgMB,  $p.MemMaxMB }
$o.TopIo      = & $fmtTop $byIo  { param($p) '{0} ({1}/{2} MB/s)'-f $p.Name, $p.IoAvgMBps, $p.IoMaxMBps }
$o.TopHandles = & $fmtTop $byHnd { param($p) '{0} ({1})'         -f $p.Name, $p.HandlesMax }

# --- verdict -----------------------------------------------------------------------------------------
$o.Verdict = Invoke-Section 'Verdict' {
    if ($sampleCount -eq 0) { return $null }
    # A test whose counter is blank did not run. Never let that read as an all-clear.
    $missing = New-Object System.Collections.Generic.List[string]
    if ($null -eq $o.CpuAvgPct) { $missing.Add('CPU') }
    if ($null -eq $o.MemAvailableMinGB -and $null -eq $o.MemUsedPct) { $missing.Add('memory') }
    if ($null -eq $o.DiskQueueAvg) { $missing.Add('disk queue') }
    if ($missing.Count) {
        Add-Warning ('Verdict: the {0} counter(s) were not readable, so that part of the check did not run.' -f ($missing -join ', '))
    }
    $hits = New-Object System.Collections.Generic.List[string]
    if ($null -ne $o.CpuAvgPct -and $o.CpuAvgPct -gt 80) { $hits.Add('CPU bound') }
    if (($null -ne $o.MemAvailableMinGB -and $o.MemAvailableMinGB -lt 1) -or
        ($null -ne $o.MemUsedPct -and $o.MemUsedPct -gt 90)) { $hits.Add('Memory pressure') }
    if ($null -ne $o.DiskQueueAvg -and $o.DiskQueueAvg -gt 2) { $hits.Add('Disk bound') }
    if ($hits.Count) {
        if ($missing.Count) { '{0} ({1} not measured)' -f ($hits -join '; '), ($missing -join ', ') }
        else                { $hits -join '; ' }
    }
    elseif ($missing.Count) { 'Incomplete: {0} not measured; no bottleneck in what was measured' -f ($missing -join ', ') }
    else { 'No sustained bottleneck in window' }
}

# --- top processes detail ----------------------------------------------------------------------------
$o.TopProcesses = @(Invoke-Section 'Top processes' {
    $tags = New-Object 'System.Collections.Generic.Dictionary[int,object]'
    $addTag = {
        param($rows, [string]$Tag)
        foreach ($r in $rows) {
            if (-not $tags.ContainsKey($r.Pid)) { $tags[$r.Pid] = New-Object System.Collections.Generic.List[string] }
            $tags[$r.Pid].Add($Tag)
        }
    }
    $null = & $addTag $byCpu 'CPU'
    $null = & $addTag $byMem 'Memory'
    $null = & $addTag $byIo  'IO'
    $null = & $addTag $byHnd 'Handles'
    if (-not $tags.Count) { return @() }

    # owner / path / company: best effort, one lookup per PID, only for the processes we are about to report
    $owners = @{}
    $live = @{}
    $wmi = Invoke-Section 'Process owners' {
        $h = @{}
        foreach ($w in @(Get-CimInstance Win32_Process -ErrorAction Stop)) { $h[[int]$w.ProcessId] = $w }
        $h
    } -Default @{}
    $gp = Invoke-Section 'Process images' {
        $h = @{}
        foreach ($g in @(Get-Process -ErrorAction SilentlyContinue)) { $h[[int]$g.Id] = $g }
        $h
    } -Default @{}

    $ownerDenied = 0; $imageBlank = 0; $gone = 0
    foreach ($key in @($tags.Keys)) {
        $user = $null
        if ($wmi.ContainsKey($key)) {
            try {
                $res = Invoke-CimMethod -InputObject $wmi[$key] -MethodName GetOwner -ErrorAction Stop
                if ($res.ReturnValue -eq 0 -and $res.User) { $user = ('{0}\{1}' -f $res.Domain, $res.User) }
                elseif ($res.ReturnValue -eq 2) {
                    # 2 = access denied: another account's process, readable only when elevated
                    $ownerDenied++
                    if (-not $isAdmin) { $user = '(needs admin)' }
                }
                else { $gone++ }   # any other code means the process went away mid-lookup
            } catch { $gone++ }
        } else { $gone++ }
        $path = $null; $company = $null
        if ($gp.ContainsKey($key)) {
            try { $path    = $gp[$key].Path } catch { }
            try { $company = $gp[$key].Company } catch { }
        }
        # protected images come back as an empty string, not an error; keep the field genuinely blank
        if ([string]::IsNullOrWhiteSpace($path))    { $path    = $null }
        if ([string]::IsNullOrWhiteSpace($company)) { $company = $null }
        if (-not $path) { $imageBlank++ }
        $owners[$key] = [PSCustomObject]@{ User = $user; Path = $path; Company = $company }
    }
    if ($ownerDenied -gt 0 -and -not $isAdmin) {
        Add-Warning ('User: not readable for {0} of {1} reported processes (other accounts'' processes need admin).' -f $ownerDenied, $tags.Count)
    } elseif ($ownerDenied -gt 0) {
        Add-Warning ('User: not readable for {0} of {1} reported processes.' -f $ownerDenied, $tags.Count)
    }
    if ($imageBlank -gt 0) {
        Add-Warning ('Path/Company: blank for {0} of {1} reported processes (protected or other accounts'' processes need admin).' -f $imageBlank, $tags.Count)
    }
    if ($gone -gt 0) {
        Add-Warning ('{0} of the reported processes had already exited when the window ended; their User/Path/Company are blank.' -f $gone)
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $procs) {
        if (-not $tags.ContainsKey($p.Pid)) { continue }
        $extra = $owners[$p.Pid]
        $rows.Add([PSCustomObject]@{
            Name       = $p.Name
            Pid        = [int]$p.Pid
            User       = $(if ($extra) { $extra.User } else { $null })
            CpuAvgPct  = $p.CpuAvgPct
            CpuMaxPct  = $p.CpuMaxPct
            MemMaxMB   = $p.MemMaxMB
            IoAvgMBps  = $p.IoAvgMBps
            IoMaxMBps  = $p.IoMaxMBps
            HandlesMax = $p.HandlesMax
            ThreadsMax = $p.ThreadsMax
            Samples    = $p.Samples
            TopIn      = (($tags[$p.Pid] | Select-Object -Unique) -join ';')
            Company    = $(if ($extra) { $extra.Company } else { $null })
            Path       = $(if ($extra) { $extra.Path } else { $null })
        })
    }
    @($rows.ToArray() | Sort-Object -Property CpuAvgPct, MemMaxMB -Descending)
} -Default @())

if ($sampleCount -gt 0 -and $sampleCount -lt $plannedSamples) {
    Add-Warning ('Only {0} of {1} planned samples were usable; averages are over those {0}.' -f $sampleCount, $plannedSamples)
}
if ($procSamples -gt 0 -and $procSamples -lt $sampleCount) {
    Add-Warning ('The per-process counters answered in only {0} of {1} samples; the process figures are over those {0}.' -f $procSamples, $sampleCount)
}
$shortLived = @($o.TopProcesses | Where-Object { $_.Samples -lt $procSamples })
if ($shortLived.Count -gt 0) {
    Add-Warning ('{0} reported process(es) were not present for the whole window; their averages cover only the samples in which they existed (see Samples).' -f $shortLived.Count)
}

$o.Warnings = ($script:Warnings -join '; ')
$result = [PSCustomObject]$o
if ($Display) { $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath }
else          { $result }
