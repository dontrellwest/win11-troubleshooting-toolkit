<#
================================================================
 Get-PerformanceOverview.ps1
================================================================
 PURPOSE
 Read-only triage set for "my computer is slow" tickets with no
 specific error attached. Checks CPU, memory, disk, and startup
 load in one pass so you can rule out a fault fast and tell
 whether you are looking at a real problem or a machine
 performing normally at the limit of its hardware.

 SAFETY
 Query-only. Get / Test / Measure verbs only. Nothing is set,
 removed, stopped, or written to except the optional transcript
 log this script creates on the local disk.

 USAGE
 Right-click > Run with PowerShell, or from an admin prompt:
     powershell -ExecutionPolicy Bypass -File .\Get-PerformanceOverview.ps1

 Admin is recommended. Without it the PhysicalDisk performance
 counters return access denied; everything else still runs.

 Log is written to C:\Temp\PerformanceOverview_<COMPUTERNAME>_<date>.txt
 unless -NoLog is passed.

 WHAT TO LOOK FOR
   Available MBytes under ~500      memory pressure
   Avg. Disk Queue Length above 2   storage bottleneck
   MediaType = HDD                  compare load before blaming storage
   Uptime in weeks                  restart before deeper work
   FreeGB under ~10                 low disk affecting paging
   One process holding high CPU     that process is the ticket

 Dontrell West, centrexIT
================================================================
#>

[CmdletBinding()]
param(
    [switch]$NoLog,
    [string]$LogPath = "C:\Temp"
)

$ErrorActionPreference = 'Continue'

# ---- Logging -------------------------------------------------
if (-not $NoLog) {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    $logFile = Join-Path $LogPath "PerformanceOverview_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyy-MM-dd_HHmm').txt"
    Start-Transcript -Path $logFile -Force | Out-Null
}

function Section($Title) {
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 62) -ForegroundColor DarkGray
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Section "MACHINE"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

[PSCustomObject]@{
    Computer   = $env:COMPUTERNAME
    Model      = "$($cs.Manufacturer) $($cs.Model)"
    OS         = "$($os.Caption) build $($os.BuildNumber)"
    CPU        = $cpu.Name.Trim()
    Cores      = "$($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) logical"
    TotalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    LastBoot   = $os.LastBootUpTime
    UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
    RunningAs  = if ($isAdmin) { "Administrator" } else { "STANDARD USER - counters will be limited" }
} | Format-List

if (-not $isAdmin) {
    Write-Host "  Not elevated. PhysicalDisk counters will fail." -ForegroundColor Yellow
}

Section "TOP 10 PROCESSES BY CPU TIME"
Get-Process | Sort-Object CPU -Descending |
    Select-Object -First 10 Name, Id,
        @{n='CPUSeconds'; e={ [math]::Round($_.CPU, 1) }},
        @{n='MemMB';      e={ [math]::Round($_.WS / 1MB) }} |
    Format-Table -AutoSize

Section "TOP 10 PROCESSES BY MEMORY"
Get-Process | Sort-Object WS -Descending |
    Select-Object -First 10 Name, Id,
        @{n='MemMB'; e={ [math]::Round($_.WS / 1MB) }} |
    Format-Table -AutoSize

Section "LIVE PERFORMANCE COUNTERS (3 samples)"
$counters = @(
    '\Processor(_Total)\% Processor Time'
    '\Memory\Available MBytes'
    '\Memory\Pages/sec'
    '\PhysicalDisk(_Total)\Avg. Disk Queue Length'
    '\PhysicalDisk(_Total)\% Idle Time'
)
try {
    (Get-Counter -Counter $counters -SampleInterval 2 -MaxSamples 3 -ErrorAction Stop).CounterSamples |
        Group-Object Path |
        ForEach-Object {
            [PSCustomObject]@{
                Counter = ($_.Name -split '\\')[-1]
                Average = [math]::Round(($_.Group | Measure-Object CookedValue -Average).Average, 2)
                Max     = [math]::Round(($_.Group | Measure-Object CookedValue -Maximum).Maximum, 2)
            }
        } | Format-Table -AutoSize
} catch {
    Write-Host "  Counter collection failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Section "STORAGE"
Get-PhysicalDisk -ErrorAction SilentlyContinue |
    Select-Object FriendlyName, MediaType, BusType,
        @{n='SizeGB'; e={ [math]::Round($_.Size / 1GB) }},
        HealthStatus, OperationalStatus |
    Format-Table -AutoSize

Get-Volume | Where-Object DriveLetter |
    Select-Object DriveLetter, FileSystemLabel, HealthStatus,
        @{n='FreeGB';  e={ [math]::Round($_.SizeRemaining / 1GB, 1) }},
        @{n='TotalGB'; e={ [math]::Round($_.Size / 1GB, 1) }},
        @{n='Free%';   e={ if ($_.Size) { [math]::Round(($_.SizeRemaining / $_.Size) * 100) } }} |
    Format-Table -AutoSize

Section "PAGE FILE"
Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
    Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage |
    Format-Table -AutoSize

Section "STARTUP ITEMS"
Get-CimInstance Win32_StartupCommand |
    Select-Object Name, User, Location, Command |
    Format-Table -AutoSize -Wrap

Section "PENDING REBOOT"
$pending = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
) | Where-Object { Test-Path $_ }

if ($pending) {
    Write-Host "  REBOOT PENDING:" -ForegroundColor Yellow
    $pending | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  No pending reboot flags found."
}

Section "BOOT AND SHUTDOWN PERFORMANCE EVENTS"
try {
    Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' `
        -MaxEvents 15 -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName,
            @{n='Detail'; e={ ($_.Message -split "`n")[0] }} |
        Format-Table -AutoSize -Wrap
} catch {
    Write-Host "  Log unavailable or empty. Disabled on some builds - log is off, machine is not clean." -ForegroundColor Yellow
}

Section "RECENT SYSTEM ERRORS (last 48h, top 15)"
try {
    Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Level     = 1, 2
        StartTime = (Get-Date).AddHours(-48)
    } -MaxEvents 15 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName,
            @{n='Message'; e={ ($_.Message -split "`n")[0] }} |
        Format-Table -AutoSize -Wrap
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Host "  No critical or error events in the last 48 hours."
    } else {
        Write-Host "  System log could not be read: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Section "DONE"
Write-Host "  Compare these readings with the workload while the problem occurs." -ForegroundColor Green
Write-Host "  A normal snapshot does not rule out intermittent performance problems." -ForegroundColor Green
Write-Host ""
Write-Host "  Deeper options if needed:"
Write-Host "    perfmon /report                                  60s report, names the bottleneck"
Write-Host "    powercfg /energy /output C:\Temp\energy.html      driver-level power issues"
Write-Host "    resmon                                            live per-process disk and network"
Write-Host ""

if (-not $NoLog) {
    Stop-Transcript | Out-Null
    Write-Host "  Log saved: $logFile" -ForegroundColor Cyan
}
