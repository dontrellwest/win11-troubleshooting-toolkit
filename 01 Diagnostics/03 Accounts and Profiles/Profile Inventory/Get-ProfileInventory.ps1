<#
================================================================
 Profile Inventory
 READ-ONLY. Enumerates profiles, resolves SIDs, measures local
 data. Writes a CSV and a transcript. Deletes nothing.

 Changes from the bare Section 12.3 Phase 1 block:
   - Elevation check, hard stop if not admin
   - Transcript logging so failures are captured to disk
   - Explicit echo of the resolved output path before writing
   - Existence verification of the CSV after writing
   - Preserve-list flagging (localuser, Public, plus this site's permanent accounts)
   - Try/catch around the export so a write failure is visible

 It still deletes nothing. Every added line is diagnostic.
================================================================
#>

$ErrorActionPreference = 'Continue'

# ---------- Elevation check ----------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "NOT RUNNING AS ADMINISTRATOR. Stopping." -ForegroundColor Red
    Write-Host "Relaunch via Get-ProfileInventory.cmd and approve the UAC prompt."
    Read-Host "Press Enter to close"
    exit 1
}

# ---------- Resolve output location ----------
$runDate = Get-Date -Format 'yyyy-MM-dd'
$outDir  = "C:\ProfileAudit\$runDate"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Profile Inventory - READ ONLY" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Computer     : $env:COMPUTERNAME"
Write-Host " Running as   : $env:USERNAME (elevated)"
Write-Host " Machine date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host " Output dir   : $outDir" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

try {
    New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null
    Write-Host "Output directory ready." -ForegroundColor Green
} catch {
    Write-Host "FAILED to create output directory: $outDir" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

# ---------- Start transcript ----------
$transcript = Join-Path $outDir "InventoryTranscript_$($env:COMPUTERNAME)_$(Get-Date -Format 'HHmmss').log"
try { Start-Transcript -Path $transcript -Force | Out-Null } catch {}

# ---------- Preserve list ----------
# Accounts that must never appear as deletion candidates.
# localuser is IT-provisioned at build time. Permanent.
$preserve = @('localuser','Public')   # add this site's permanent accounts here

# ---------- Inventory ----------
$report = @()

Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {

    $p = $_

    $resolved = "Unresolved SID (account status unknown)"
    try {
        $resolved = ([System.Security.Principal.SecurityIdentifier]$p.SID).Translate(
                     [System.Security.Principal.NTAccount]).Value
    } catch {}

    $leaf = Split-Path $p.LocalPath -Leaf
    $isPreserved = $false
    foreach ($name in $preserve) {
        if ($leaf -eq $name -or $resolved -like "*\$name") { $isPreserved = $true }
    }

    $localDataMB = 0
    if (Test-Path $p.LocalPath) {
        foreach ($f in 'Desktop','Documents','Downloads','Pictures','Favorites') {
            $fp = Join-Path $p.LocalPath $f
            if (Test-Path $fp) {
                $sz = (Get-ChildItem $fp -Recurse -File -ErrorAction SilentlyContinue |
                       Measure-Object Length -Sum).Sum
                if ($sz) { $localDataMB += [math]::Round($sz/1MB,1) }
            }
        }
    }

    $report += [PSCustomObject]@{
        Computer     = $env:COMPUTERNAME
        ResolvedUser = $resolved
        FolderName   = $leaf
        PRESERVE     = $isPreserved
        SID          = $p.SID
        LocalPath    = $p.LocalPath
        FolderExists = (Test-Path $p.LocalPath)
        LastUseTime  = $p.LastUseTime
        LocalDataMB  = $localDataMB
        Loaded       = $p.Loaded
    }
}

Write-Host ""
Write-Host "Profiles enumerated: $($report.Count)" -ForegroundColor Green
Write-Host "Flagged PRESERVE   : $(($report | Where-Object PRESERVE).Count)" -ForegroundColor Green
Write-Host ""

$report | Sort-Object PRESERVE, LocalDataMB -Descending |
    Format-Table ResolvedUser, FolderName, PRESERVE, LocalDataMB, Loaded, LastUseTime -AutoSize

# ---------- Export ----------
$csvPath = Join-Path $outDir "ProfileInventory_$($env:COMPUTERNAME).csv"

try {
    $report | Export-Csv $csvPath -NoTypeInformation -ErrorAction Stop
    if (Test-Path $csvPath) {
        Write-Host ""
        Write-Host "CSV WRITTEN AND VERIFIED:" -ForegroundColor Green
        Write-Host "  $csvPath" -ForegroundColor Yellow
        Write-Host "  Size: $((Get-Item $csvPath).Length) bytes"
    } else {
        Write-Host "Export reported success but file not found at $csvPath" -ForegroundColor Red
    }
} catch {
    Write-Host "CSV EXPORT FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

Write-Host ""
Write-Host "Contents of C:\ProfileAudit:" -ForegroundColor Cyan
Get-ChildItem "C:\ProfileAudit" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize

try { Stop-Transcript | Out-Null } catch {}

Write-Host ""
Write-Host "Transcript: $transcript" -ForegroundColor Yellow
Write-Host "No profiles were modified or deleted." -ForegroundColor Green
Write-Host ""
if (-not $env:TOOLKIT_NOPAUSE) { Read-Host "Press Enter to close" }
