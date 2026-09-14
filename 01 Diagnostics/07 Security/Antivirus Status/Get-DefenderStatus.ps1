<#
.SYNOPSIS
    Report Defender protection, signatures, configured exclusions and detections.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Get-DefenderStatus.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [ValidateRange(1,365)][int]$Days=30)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-DefenderStatus'
$script:Warnings  = New-Object System.Collections.Generic.List[string]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, $Default = $null)
    try { & $Script } catch { Add-Warning ("{0}: {1}" -f $Name, $_.Exception.Message.Trim()); $Default }
}

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

function ConvertFrom-FileTimePair { param($High, $Low) [DateTime]::FromFileTime(([int64]$High -shl 32) -bor ([int64]$Low -band 0xFFFFFFFFL)) }
function ConvertFrom-FileTimeBytes { param([byte[]]$Bytes) [DateTime]::FromFileTime([BitConverter]::ToInt64($Bytes, 0)) }

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

function Get-ConsoleUser {
    param([string]$OverrideName)
    $name = $null; $sid = $null; $source = $null; $sessionId = $null; $logonId = $null
    $desktops = @()
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
        Name          = $name
        Sid           = $sid
        Hive          = $hive
        ProfilePath   = $profilePath
        SessionId     = $sessionId
        LogonId       = $logonId
        Source        = $source
        OtherDesktops = (($desktops | Where-Object { $_.Name -ne $name } | ForEach-Object { '{0} (session {1})' -f $_.Name, $_.SessionId }) -join ', ')
        IsMe          = ($sid -eq $me.User.Value)
        IsSystem      = ($me.User.Value -eq 'S-1-5-18')
        RunningAs     = $me.Name
    }
}

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



function Get-RegistryValues {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) { Get-ItemProperty -LiteralPath $Path -ErrorAction Stop }
    } catch { Add-Warning ("Registry {0}: {1}" -f $Path, $_.Exception.Message) }
}
function Copy-Fields {
    param($Target, $Source, [string[]]$Names)
    if ($null -ne $Source) { foreach ($n in $Names) { if ($null -ne $Source.$n) { $Target[$n] = $Source.$n } } }
}
function Get-WindowEvents {
    param([string]$LogName, [int[]]$Id, [int]$Days = 30, [int]$MaxEvents = 1000)
    $filter = @{LogName=$LogName; StartTime=[DateTime]::Now.AddDays(-$Days)}
    if ($Id) { $filter.Id = $Id }
    try { Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
function Get-OptionalDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $date = [datetime]$Value; if ($date.Year -gt 1900) { $date } } catch { }
}
function Get-AgeDays {
    param($Value)
    $date = Get-OptionalDate $Value
    if ($null -ne $date) { [int][math]::Floor(([DateTime]::Now - $date).TotalDays) }
}
function Convert-PolicyValue {
    param($Value, [hashtable]$Map)
    if ($null -eq $Value) { return $null }
    $key = [int]$Value
    if ($Map.ContainsKey($key)) { $Map[$key] } else { "Unknown ($Value)" }
}

$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;AMRunningMode=$null;AMServiceEnabled=$null;AntivirusEnabled=$null;RealTimeProtectionEnabled=$null;BehaviorMonitorEnabled=$null;IoavProtectionEnabled=$null;OnAccessProtectionEnabled=$null;NISEnabled=$null;IsTamperProtected=$null;AntivirusSignatureVersion=$null;AntivirusSignatureLastUpdated=$null;AntivirusSignatureAgeDays=$null;DefinitionsStale=$null;AMEngineVersion=$null;AMProductVersion=$null;QuickScanLastRun=$null;QuickScanAgeDays=$null;FullScanLastRun=$null;FullScanAgeDays=$null;QuickScanOverdue=$null;CloudProtection=$null;SampleSubmission=$null;CloudBlockLevel=$null;PUAProtection=$null;ControlledFolderAccess=$null;NetworkProtection=$null;AsrRulesConfigured=$null;AsrRulesBlockMode=$null;ScanSchedule=$null;SignatureUpdateIntervalHours=$null;ExclusionCount=$null;ExclusionsReadable=$false;ThirdPartyAV=$null;ThirdPartyAVEnabled=$null;ThirdPartyAVUpToDate=$null;DetectionsInWindow=$null;LastDetection=$null;LastDetectionThreat=$null;ActiveThreats=$null;DefenderEventErrors=$null;Exclusions=@();Detections=@();AsrRules=@();AntivirusProducts=@();Warnings=''}
$status=Invoke-Section 'Defender status' {Get-MpComputerStatus -ErrorAction Stop}
Copy-Fields $o $status @('AMRunningMode','AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IoavProtectionEnabled','OnAccessProtectionEnabled','NISEnabled','IsTamperProtected','AntivirusSignatureVersion','AMEngineVersion','AMProductVersion')
if($status){
    $o.AntivirusSignatureLastUpdated=Get-OptionalDate $status.AntivirusSignatureLastUpdated
    $o.AntivirusSignatureAgeDays=Get-AgeDays $o.AntivirusSignatureLastUpdated
    if($null -ne $o.AntivirusSignatureAgeDays){$o.DefinitionsStale=($o.AntivirusSignatureAgeDays -gt 3)}
    $o.QuickScanLastRun=Get-OptionalDate $status.QuickScanEndTime
    $o.FullScanLastRun=Get-OptionalDate $status.FullScanEndTime
    $o.QuickScanAgeDays=Get-AgeDays $o.QuickScanLastRun
    $o.FullScanAgeDays=Get-AgeDays $o.FullScanLastRun
    if($null -ne $o.QuickScanAgeDays){$o.QuickScanOverdue=($o.QuickScanAgeDays -gt 7)}
}
$pref=Invoke-Section 'Defender preferences' {Get-MpPreference -ErrorAction Stop}
if($pref){
    $o.CloudProtection=Convert-PolicyValue $pref.MAPSReporting @{0='Off';1='Basic';2='Advanced'}
    $o.SampleSubmission=Convert-PolicyValue $pref.SubmitSamplesConsent @{0='Prompt';1='Safe samples';2='Never';3='All samples'}
    $o.CloudBlockLevel=Convert-PolicyValue $pref.CloudBlockLevel @{0='Default';1='Moderate';2='High';4='High plus';6='Zero tolerance'}
    $o.PUAProtection=Convert-PolicyValue $pref.PUAProtection @{0='Off';1='On';2='Audit'}
    $o.ControlledFolderAccess=Convert-PolicyValue $pref.EnableControlledFolderAccess @{0='Off';1='On';2='Audit';3='Block disk modification';4='Audit disk modification'}
    $o.NetworkProtection=Convert-PolicyValue $pref.EnableNetworkProtection @{0='Off';1='On';2='Audit'}
    $day=Convert-PolicyValue $pref.ScanScheduleDay @{0='Every day';1='Sunday';2='Monday';3='Tuesday';4='Wednesday';5='Thursday';6='Friday';7='Saturday';8='Never'}
    $o.ScanSchedule="$day; scheduled scan $($pref.ScanScheduleTime); quick scan $($pref.ScanScheduleQuickScanTime)"
    $o.SignatureUpdateIntervalHours=$pref.SignatureUpdateInterval
    $ids=@($pref.AttackSurfaceReductionRules_Ids | Where-Object {$_})
    $actions=@($pref.AttackSurfaceReductionRules_Actions)
    $o.AsrRules=@(Invoke-Section 'ASR rules' {
        for($i=0;$i -lt $ids.Count;$i++){
            $action=$null;if($i -lt $actions.Count){$action=$actions[$i]}
            [pscustomobject]@{Id=[string]$ids[$i];Action=(Convert-PolicyValue $action @{0='Disabled';1='Block';2='Audit';6='Warn'});Name='See rule GUID'}
        }
    } -Default @())
    $o.AsrRulesConfigured=[int]$ids.Count
    $o.AsrRulesBlockMode=[int]@($o.AsrRules | Where-Object Action -eq 'Block').Count
    if(Test-IsAdmin){
        $o.Exclusions=@(Invoke-Section 'Exclusions' {
            foreach($pair in @(@('Path','ExclusionPath'),@('Extension','ExclusionExtension'),@('Process','ExclusionProcess'),@('IP','ExclusionIpAddress'))){
                foreach($value in @($pref.($pair[1]) | Where-Object {$_})){
                    if([string]$value -match 'N/A:|administrator|not permitted'){throw 'Exclusions are hidden by access restrictions'}
                    [pscustomobject]@{Type=$pair[0];Value=[string]$value}
                }
            }
            $o.ExclusionsReadable=$true
        } -Default @())
        if($o.ExclusionsReadable){$o.ExclusionCount=[int]$o.Exclusions.Count}
    }else{Add-Warning 'Defender exclusions: needs admin; count is unknown.'}
}
$o.AntivirusProducts=@(Invoke-Section 'Registered antivirus products' {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{Name=[string]$_.displayName;ProductState=[int]$_.productState}
    }
} -Default @())
$o.ThirdPartyAV=(@($o.AntivirusProducts | Where-Object {$_.Name -notmatch '^(Microsoft|Windows) Defender$'} | ForEach-Object Name) -join '; ')
if($o.ThirdPartyAV){Add-Warning 'Third-party AV registration is not proof of active protection. Vendor productState is retained raw; enabled and up-to-date are unknown.'}
$threats=@(Invoke-Section 'Threat inventory' {Get-MpThreat -ErrorAction Stop} -Default @())
if(Get-Command Get-MpThreat -ErrorAction SilentlyContinue){$o.ActiveThreats=Invoke-Section 'Active threats' {[int]@(Get-MpThreat -ErrorAction Stop | Where-Object IsActive).Count}}
$threatMap=@{};foreach($threat in $threats){$threatMap[[string]$threat.ThreatID]=$threat}
$o.Detections=@(Invoke-Section 'Threat detections' {
    $found=@(Get-MpThreatDetection -ErrorAction Stop | Where-Object {$_.InitialDetectionTime -ge [datetime]::Now.AddDays(-$Days)})
    $o.DetectionsInWindow=[int]$found.Count
    foreach($d in $found){
        $th=$threatMap[[string]$d.ThreatID]
        [pscustomobject]@{Time=(Get-OptionalDate $d.InitialDetectionTime);Threat=$(if($th){[string]$th.ThreatName}else{"Threat ID $($d.ThreatID)"});Severity=$(if($th){[int]$th.SeverityID}else{$null});Category=$(if($th){[int]$th.CategoryID}else{$null});Action=("Cleaning action {0}; success {1}" -f $d.CleaningActionID,$d.ActionSuccess);Path=(@($d.Resources) -join '; ');User=[string]$d.DomainUser;Source=[string]$d.DetectionSourceTypeID;ProcessName=[string]$d.ProcessName}
    }
} -Default @())
if($null -eq $o.DetectionsInWindow){
    $o.Detections=@(Invoke-Section 'Detection event fallback' {
        $events=@(Get-WindowEvents 'Microsoft-Windows-Windows Defender/Operational' @(1116,1006) $Days 1000)
        if($events.Count -eq 1000){Add-Warning 'Detection event fallback capped at 1000 events.'}
        foreach($e in $events){[pscustomobject]@{Time=$e.TimeCreated;Threat=([string]$e.Message -split '\r?\n')[0];Severity=$null;Category=$null;Action='See event log';Path='';User='';Source='Event log';ProcessName=''}}
    } -Default @())
    Add-Warning 'Detection fallback counts log events rather than unique threats; total detection count remains unknown.'
}
$last=$o.Detections | Sort-Object Time -Descending | Select-Object -First 1
if($last){$o.LastDetection=$last.Time;$o.LastDetectionThreat=$last.Threat}
$o.DefenderEventErrors=Invoke-Section 'Defender error events' {
    $events=@(Get-WindowEvents 'Microsoft-Windows-Windows Defender/Operational' @(2001,2003,2004,5001,5008,5010,5012) $Days 1000)
    if($events.Count -eq 1000){Add-Warning 'Defender event count capped at 1000.'}
    [int]$events.Count
}
$o.Warnings=$script:Warnings -join '; '
$result=[pscustomobject]$o
if($Display){$result | Show-Result -Title $script:ToolName -ReportPath $ReportPath}else{$result}
