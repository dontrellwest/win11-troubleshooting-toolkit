<#
.SYNOPSIS
    Inventory installed apps from registry entries and optional Store packages.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Get-SoftwareInventory.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [switch]$IncludeSystemComponents, [switch]$IncludeUpdates, [switch]$IncludeStoreApps)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-SoftwareInventory'
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

$collected=[datetime]::Now
$rows=New-Object System.Collections.Generic.List[object]
function Convert-InstallDate {
    param($Value)
    if(-not $Value){return $null}
    $parsed=[datetime]::MinValue
    foreach($fmt in 'yyyyMMdd','yyyy-MM-dd','MM/dd/yyyy'){
        if([datetime]::TryParseExact([string]$Value,$fmt,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)){return $parsed}
    }
}
function Read-UninstallRoot {
    param([string]$Path,[string]$Scope,[string]$Architecture)
    if(-not (Test-Path -LiteralPath $Path)){return}
    foreach($key in @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)){
        $v=Get-RegistryValues $key.PSPath
        if(-not $v.DisplayName){continue}
        $system=($v.SystemComponent -eq 1)
        $update=[bool]($v.ParentKeyName -or $v.ReleaseType -match 'Update|Hotfix' -or $v.DisplayName -match '^(Update for|Security Update for|Hotfix for)')
        if(($system -and -not $IncludeSystemComponents) -or ($update -and -not $IncludeUpdates)){continue}
        $size=$null;if($null -ne $v.EstimatedSize){$size=Round1 ([double]$v.EstimatedSize/1024)}
        [pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$collected;Name=[string]$v.DisplayName;Version=[string]$v.DisplayVersion;Publisher=[string]$v.Publisher;InstallDate=(Convert-InstallDate $v.InstallDate);Scope=$Scope;Architecture=$Architecture;InstallLocation=[string]$v.InstallLocation;UninstallString=[string]$v.UninstallString;QuietUninstallString=[string]$v.QuietUninstallString;EstimatedSizeMB=$size;IsSystemComponent=[bool]$system;IsUpdate=[bool]$update;KeyPath=$key.Name;Source='Registry';Detail=''}
    }
}
$roots=@(@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','Machine','x64'),@('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','Machine (32-bit)','x86'))
foreach($root in $roots){foreach($r in @(Invoke-Section $root[0] {Read-UninstallRoot $root[0] $root[1] $root[2]} -Default @())){$rows.Add($r)}}
$hives=@(Invoke-Section 'Loaded user hives' {Get-ChildItem Registry::HKEY_USERS -ErrorAction Stop | Where-Object {$_.PSChildName -match '^S-1-(5-21|12-1)-[0-9-]+$'}} -Default @())
foreach($h in $hives){
    $sid=$h.PSChildName;$user=$sid
    try{$user=([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value}catch{}
    foreach($r in @(Invoke-Section "Apps for $user" {Read-UninstallRoot ($h.PSPath+'\Software\Microsoft\Windows\CurrentVersion\Uninstall') ("User: "+$user) 'Unknown'} -Default @())){$rows.Add($r)}
}
Add-Warning 'Per-user apps are limited to loaded registry hives; logged-off user hives are not loaded by this tool.'
if($IncludeStoreApps){
    $appx=@(Invoke-Section 'Store packages' {
        if(Test-IsAdmin){Get-AppxPackage -AllUsers -ErrorAction Stop}else{Add-Warning 'Store packages: only the running account is visible without admin.';Get-AppxPackage -ErrorAction Stop}
    } -Default @())
    foreach($a in $appx){
        $publisher=[string]$a.Publisher;if($publisher -match '(?:^|,\s*)CN=([^,]+)'){$publisher=$Matches[1]}
        $rows.Add([pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$collected;Name=[string]$a.Name;Version=[string]$a.Version;Publisher=$publisher;InstallDate=$null;Scope='Store';Architecture=[string]$a.Architecture;InstallLocation=[string]$a.InstallLocation;UninstallString='';QuietUninstallString='';EstimatedSizeMB=$null;IsSystemComponent=[bool]$a.IsFramework;IsUpdate=$false;KeyPath='';Source='Appx';Detail=''})
    }
}
$office=Get-RegistryValues 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
if($office.VersionToReport -and -not @($rows | Where-Object {$_.Version -eq $office.VersionToReport -and $_.Name -match 'Microsoft 365|Microsoft Office'}).Count){
    $channel=[string]$office.UpdateChannel;if(-not $channel){$channel=[string]$office.CDNBaseUrl}
    $rows.Add([pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$collected;Name=('Microsoft 365 Apps (Click-to-Run) '+$office.Platform);Version=[string]$office.VersionToReport;Publisher='Microsoft';InstallDate=$null;Scope='Machine';Architecture=[string]$office.Platform;InstallLocation=[string]$office.InstallationPath;UninstallString='';QuietUninstallString='';EstimatedSizeMB=$null;IsSystemComponent=$false;IsUpdate=$false;KeyPath='HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration';Source='Registry';Detail=('Update channel: '+$channel)})
}
$result=@($rows | Sort-Object Name,Scope,Version)
foreach($warning in $script:Warnings){Write-Warning $warning}
if($Display){$result | Show-Result -Title $script:ToolName -ReportPath $ReportPath}else{$result}
