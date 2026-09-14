<#
.SYNOPSIS
    Compare profile registry records with profile folders without changing them.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Get-ProfileState.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [ValidateRange(1,3650)][int]$StaleDays=90, [switch]$SkipSizes)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-ProfileState'
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

$now=[datetime]::Now
$admin=Test-IsAdmin
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$cim=@(Invoke-Section 'Profile records' {Get-CimInstance Win32_UserProfile -ErrorAction Stop} -Default @())
$bySid=@{};foreach($c in $cim){$bySid[$c.SID]=$c}
$profileRoot='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$rootValues=Get-RegistryValues $profileRoot
$usersRoot=Join-Path $env:SystemDrive 'Users'
if($rootValues.ProfilesDirectory){$usersRoot=[Environment]::ExpandEnvironmentVariables($rootValues.ProfilesDirectory)}
$entries=New-Object System.Collections.Generic.List[object]
$knownPaths=@{}
foreach($key in @(Invoke-Section 'Profile registry' {Get-ChildItem -LiteralPath $profileRoot -ErrorAction Stop} -Default @())){
    $v=Get-RegistryValues $key.PSPath
    $sid=$key.PSChildName -replace '\.bak$',''
    $path=$null
    if($v.ProfileImagePath){$path=[Environment]::ExpandEnvironmentVariables($v.ProfileImagePath);$knownPaths[$path.TrimEnd('\')]=$true}
    $entries.Add([pscustomobject]@{Sid=$sid;Path=$path;Bak=$key.PSChildName.EndsWith('.bak');Registry=$true;Values=$v})
}
foreach($folder in @(Invoke-Section 'Profile directories' {Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction Stop} -Default @())){
    if(-not $knownPaths.ContainsKey($folder.FullName.TrimEnd('\'))){
        $entries.Add([pscustomobject]@{Sid=$null;Path=$folder.FullName;Bak=$false;Registry=$false;Values=$null})
    }
}
function Measure-Profile {
    param([string]$Path)
    if((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Profile root is a reparse point; size scan skipped.'}
    $stack=New-Object System.Collections.Generic.Stack[string];$stack.Push($Path)
    $watch=[Diagnostics.Stopwatch]::StartNew();[double]$bytes=0;[double]$cloud=0;$folders=@{};$partial=$false;$files=0
    while($stack.Count){
        if($watch.Elapsed.TotalSeconds -gt 60 -or $files -ge 200000){$partial=$true;break}
        $dir=$stack.Pop()
        try{$items=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)}catch{$partial=$true;continue}
        foreach($item in $items){
            if($item.PSIsContainer){
                if(([int64]$item.Attributes -band 0x400) -ne 0){$partial=$true}else{$stack.Push($item.FullName)}
                continue
            }
            $files++
            if($files -gt 200000){$partial=$true;break}
            if(([int64]$item.Attributes -band 0x400) -ne 0){
                if($item.FullName -match '\\OneDrive[^\\]*\\'){$cloud+=$item.Length}
                continue
            }
            $bytes+=$item.Length
            $relative=$item.FullName.Substring($Path.TrimEnd('\').Length+1)
            $top=($relative -split '\\')[0]
            if($relative.Contains('\')){if(-not $folders.ContainsKey($top)){$folders[$top]=[double]0};$folders[$top]+=$item.Length}
        }
    }
    $largest=$folders.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    if($partial){Add-Warning ("Profile size is partial: "+$Path+' (permissions, reparse folders, or 60-second/200000-file cap).')}
    [pscustomobject]@{SizeGB=(Round1 ($bytes/1GB));CloudOnlyGB=(Round1 ($cloud/1GB));LargestFolder=$(if($largest){'{0} ({1})' -f $largest.Key,(Format-Bytes $largest.Value)}else{''});SizeComplete=(-not $partial)}
}
$rows=New-Object System.Collections.Generic.List[object]
foreach($entry in $entries){
    $c=$null;if($entry.Sid){$c=$bySid[$entry.Sid]}
    $name='(unresolved SID)'
    if($entry.Sid){try{$name=([Security.Principal.SecurityIdentifier]$entry.Sid).Translate([Security.Principal.NTAccount]).Value}catch{}}
    $folderName='';$exists=$null;$lastWrite=$null;$size=$null
    if($entry.Path){
        $folderName=Split-Path $entry.Path -Leaf
        $exists=Invoke-Section ('Folder '+$entry.Path) {Test-Path -LiteralPath $entry.Path -PathType Container -ErrorAction Stop}
        if($exists){
            $nt=Join-Path $entry.Path 'NTUSER.DAT'
            $lastWrite=Invoke-Section ('NTUSER '+$entry.Path) {if(Test-Path -LiteralPath $nt -ErrorAction Stop){(Get-Item -LiteralPath $nt -Force -ErrorAction Stop).LastWriteTime}}
        }
    }
    $special=[bool](($c -and $c.Special) -or $entry.Sid -in 'S-1-5-18','S-1-5-19','S-1-5-20' -or $folderName -in 'Default','Default User','All Users','Public','defaultuser0')
    $loaded=$null;$lastUse=$null;$state=$null
    if($c){
        $loaded=[bool]$c.Loaded;$lastUse=Get-OptionalDate $c.LastUseTime;$states=@()
        foreach($pair in @(@(1,'Temporary'),@(2,'Roaming'),@(4,'Mandatory'),@(8,'Corrupted'))){if(([int]$c.Status -band $pair[0]) -ne 0){$states+=$pair[1]}}
        $state=$states -join ', ';if(-not $state){$state='Normal'}
    }
    $temp=($folderName -match '^TEMP(\.|$)' -or ($c -and ([int]$c.Status -band 1) -ne 0))
    $issue=@()
    if(-not $entry.Path){$issue+='ProfileImagePath missing'}
    elseif($exists -eq $false){$issue+='folder missing'}
    if($entry.Bak){$issue+='orphaned .bak'}
    if($temp){$issue+='temp profile'}
    if(-not $entry.Registry -and -not $special){$issue+='stray folder (no registry entry)'}
    $stale=$null
    if($special -or $loaded -eq $true){$stale=$false}
    elseif($loaded -eq $false -and $lastUse -and $lastWrite){$stale=($lastUse -lt $now.AddDays(-$StaleDays) -and $lastWrite -lt $now.AddDays(-$StaleDays))}
    if(-not $SkipSizes -and -not $special -and $exists){
        if($admin -or $entry.Sid -eq $me){$size=Invoke-Section ('Size '+$entry.Path) {Measure-Profile $entry.Path}}
        else{Add-Warning ('Profile size needs admin: '+$entry.Path)}
    }
    $rows.Add([pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$now;Sid=$entry.Sid;User=$name;FolderPath=$entry.Path;FolderName=$folderName;InRegistry=[bool]$entry.Registry;FolderExists=$exists;IsBak=[bool]$entry.Bak;IsTemp=[bool]$temp;IsSuffixed=[bool]($folderName -match '\.(\d{3}|[^.]+)$');Special=$special;Loaded=$loaded;State=$state;LastUseTime=$lastUse;NtUserLastWrite=$lastWrite;RefCount=$entry.Values.RefCount;SizeGB=$size.SizeGB;CloudOnlyGB=$size.CloudOnlyGB;LargestFolder=$size.LargestFolder;SizeComplete=$size.SizeComplete;DataIssue=($issue -join '; ');Stale=$stale})
}
Add-Warning 'Profile dates can be changed by background tasks. Stale is a review flag, not approval to delete a profile.'
$result=$rows.ToArray()
foreach($w in $script:Warnings){Write-Warning $w}
if($Display){
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath
    Write-Host ("Profiles: {0}; issues: {1}; stale: {2}" -f $result.Count,@($result | Where-Object DataIssue).Count,@($result | Where-Object {$_.Stale -eq $true}).Count)
    Write-Host ("Measured logical GB: {0}" -f (Round1 (($result | Measure-Object SizeGB -Sum).Sum)))
}else{$result}
