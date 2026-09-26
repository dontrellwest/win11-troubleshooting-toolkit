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
    .\Check-User-Profiles.ps1 -Display
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
$script:ToolName  = 'Check-User-Profiles'
$script:Warnings  = New-Object System.Collections.Generic.List[string]
$script:Findings  = New-Object System.Collections.Generic.List[object]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

# '1 crash' / '3 crashes': a count with the singular or plural noun, for summary text.
function Format-Count { param([int]$Count, [string]$One, [string]$Many) if ($Count -eq 1) { '1 ' + $One } else { '{0} {1}' -f $Count, $Many } }

# Plain-language summary line for -Display. Level: Problem | Warning | NotChecked | Info | OK. Next: what to do about it.
function Add-Finding {
    param([ValidateSet('Problem', 'Warning', 'NotChecked', 'Info', 'OK')][string]$Level, [string]$Text, [string]$Next)
    $script:Findings.Add([PSCustomObject]@{ Level = $Level; Text = $Text; Next = $Next })
}

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

# Readable report for -Display. With -About/-Findings/-NextSteps/-Result a plain-language SUMMARY comes first
# (result line, then findings ranked by severity, each with its next step) and the RESULT is repeated at the end.
# DETAILS: scalars as a list, array properties as tables (never silently dropping columns).
function Show-Result {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Title, [string]$ReportPath,
          [string]$About, [object[]]$Findings, [string[]]$NextSteps, [string]$Result)
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
        # Word-wraps summary text at 78 columns: the first line starts with $Lead, later lines align under it.
        $wrap = {
            param([string]$Text, [string]$Lead)
            $pad = ' ' * $Lead.Length; $line = $Lead; $has = $false
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($word in @(('{0}' -f $Text).Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)') -split '\s+' | Where-Object { $_ })) {
                if ($has -and ($line.Length + 1 + $word.Length) -gt 78) { $out.Add($line); $line = $pad; $has = $false }
                if ($has) { $line += ' ' + $word } else { $line += $word; $has = $true }
            }
            if ($has) { $out.Add($line) }
            $out.ToArray()
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine(('  {0}   {1}   {2}' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')))
        [void]$sb.AppendLine(('=' * 78))
        $found = @($Findings | Where-Object { $null -ne $_ })
        $summary = [bool]($About -or $found.Count -or $NextSteps -or $Result)
        if ($summary) {
            if ($About) { foreach ($l in (& $wrap $About '  ')) { [void]$sb.AppendLine($l) }; [void]$sb.AppendLine('') }
            $rank  = @{ Problem = 0; Warning = 1; NotChecked = 2; Info = 3; OK = 4 }
            $label = @{ Problem = 'PROBLEM'; Warning = 'WARNING'; NotChecked = 'NOT CHECKED'; Info = 'INFO'; OK = 'OK' }
            $n = @{}; foreach ($k in @($rank.Keys)) { $n[$k] = @($found | Where-Object { [string]$_.Level -eq $k }).Count }
            $counts = @()
            if ($n.Problem)    { $counts += $(if ($n.Problem -eq 1) { '1 problem' } else { '{0} problems' -f $n.Problem }) }
            if ($n.Warning)    { $counts += $(if ($n.Warning -eq 1) { '1 warning' } else { '{0} warnings' -f $n.Warning }) }
            if ($n.NotChecked) { $counts += $(if ($n.NotChecked -eq 1) { '1 item not checked' } else { '{0} items not checked' -f $n.NotChecked }) }
            if (-not $Result) {
                if ($n.Problem)        { $Result = 'ACTION NEEDED - {0}.' -f ($counts -join ', ') }
                elseif ($n.Warning)    { $Result = 'REVIEW - {0}. No problems found.' -f ($counts -join ', ') }
                elseif ($n.NotChecked) { $Result = 'INCOMPLETE - {0}. Nothing else needs attention.' -f ($counts -join ', ') }
                else                   { $Result = 'NO PROBLEMS FOUND by this check.' }
            }
            [void]$sb.AppendLine('SUMMARY'); [void]$sb.AppendLine('-------')
            foreach ($l in (& $wrap $Result '  RESULT: ')) { [void]$sb.AppendLine($l) }
            $ranked = New-Object System.Collections.Generic.List[object]
            for ($k = 0; $k -lt $found.Count; $k++) {
                $lv = [string]$found[$k].Level; $r = 3; if ($rank.ContainsKey($lv)) { $r = $rank[$lv] }
                $ranked.Add([PSCustomObject]@{ Rank = $r; Index = $k; Finding = $found[$k] })
            }
            if ($ranked.Count) { [void]$sb.AppendLine('') }
            foreach ($e in @($ranked | Sort-Object Rank, Index)) {
                $lv = [string]$e.Finding.Level; $tag = $lv.ToUpper(); if ($label.ContainsKey($lv)) { $tag = $label[$lv] }
                foreach ($l in (& $wrap $e.Finding.Text ('  ' + $tag.PadRight(13)))) { [void]$sb.AppendLine($l) }
                if ($e.Finding.Next) { foreach ($l in (& $wrap $e.Finding.Next ((' ' * 15) + 'Next: '))) { [void]$sb.AppendLine($l) } }
            }
            if ($NextSteps) {
                [void]$sb.AppendLine(''); [void]$sb.AppendLine('NEXT STEPS'); [void]$sb.AppendLine('----------')
                foreach ($s in $NextSteps) { if ($s) { foreach ($l in (& $wrap $s '  - ')) { [void]$sb.AppendLine($l) } } }
            }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('DETAILS'); [void]$sb.AppendLine('-------')
        }
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
        if ($summary) {
            [void]$sb.AppendLine(('-' * 78))
            foreach ($l in (& $wrap ($Result + ' The summary and next steps are at the top of this report.') '  RESULT: ')) { [void]$sb.AppendLine($l) }
        }
        # Registered, trademark and copyright signs (from device and product names) and invisible direction marks, as ASCII.
        $text = $sb.ToString().Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)').Replace([string][char]0x200E, '').Replace([string][char]0x200F, '')
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
# A registry read that failed must not look like a damaged entry or a leftover folder.
$before=$script:Warnings.Count
$regKeys=@(Invoke-Section 'Profile registry' {Get-ChildItem -LiteralPath $profileRoot -ErrorAction Stop} -Default @())
$registryRead=($script:Warnings.Count -eq $before)
foreach($key in $regKeys){
    $before=$script:Warnings.Count
    $v=Get-RegistryValues $key.PSPath
    $sid=$key.PSChildName -replace '\.bak$',''
    $path=$null
    if($v.ProfileImagePath){$path=[Environment]::ExpandEnvironmentVariables($v.ProfileImagePath);$knownPaths[$path.TrimEnd('\')]=$true}
    $entries.Add([pscustomobject]@{Sid=$sid;Path=$path;Bak=$key.PSChildName.EndsWith('.bak');Registry=$true;Values=$v;ReadFailed=($script:Warnings.Count -gt $before)})
}
# Windows' own profile list (read by the WMI service) stands in for registry entries this account could not read,
# so a live user's folder is never taken for a leftover one.
if(-not $registryRead){foreach($c in $cim){if($c.SID -and $c.LocalPath){$entries.Add([pscustomobject]@{Sid=[string]$c.SID;Path=[string]$c.LocalPath;Bak=$false;Registry=$true;Values=$null;ReadFailed=$false})}}}
foreach($c in $cim){if($c.LocalPath){$knownPaths[([string]$c.LocalPath).TrimEnd('\')]=$true}}
$registryComplete=($registryRead -and -not @($entries | Where-Object {$_.ReadFailed}).Count)
foreach($folder in @(Invoke-Section 'Profile directories' {Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction Stop} -Default @())){
    if(-not $knownPaths.ContainsKey($folder.FullName.TrimEnd('\'))){
        $entries.Add([pscustomobject]@{Sid=$null;Path=$folder.FullName;Bak=$false;Registry=$false;Values=$null;ReadFailed=$false})
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
    if(-not $entry.Path){$issue+=$(if($entry.ReadFailed){'registry entry unreadable'}else{'ProfileImagePath missing'})}
    elseif($exists -eq $false){$issue+='folder missing'}
    if($entry.Bak){$issue+='orphaned .bak'}
    if($temp){$issue+='temp profile'}
    if(-not $entry.Registry -and -not $special -and $registryComplete){$issue+='stray folder (no registry entry)'}
    $stale=$null
    if($special -or $loaded -eq $true){$stale=$false}
    elseif($loaded -eq $false -and $lastUse -and $lastWrite){$stale=($lastUse -lt $now.AddDays(-$StaleDays) -and $lastWrite -lt $now.AddDays(-$StaleDays))}
    if(-not $SkipSizes -and -not $special -and $exists){
        if($admin -or $entry.Sid -eq $me){$size=Invoke-Section ('Size '+$entry.Path) {Measure-Profile $entry.Path}}
        else{Add-Warning ('Profile size needs admin: '+$entry.Path)}
    }
    $rows.Add([pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$now;Sid=$entry.Sid;User=$name;FolderPath=$entry.Path;FolderName=$folderName;InRegistry=[bool]$entry.Registry;FolderExists=$exists;IsBak=[bool]$entry.Bak;IsTemp=[bool]$temp;IsSuffixed=[bool]($folderName -match '\.(\d{3}|[^.]+)$');Special=$special;Loaded=$loaded;State=$state;LastUseTime=$lastUse;NtUserLastWrite=$lastWrite;RefCount=$entry.Values.RefCount;SizeGB=$size.SizeGB;CloudOnlyGB=$size.CloudOnlyGB;LargestFolder=$size.LargestFolder;SizeComplete=$size.SizeComplete;DataIssue=($issue -join '; ');OldDates=$stale})
}
Add-Warning 'Profile dates can be changed by background tasks and do not show when a user last signed in. OldDates is a review flag, not approval to delete a profile.'
$result=$rows.ToArray()
# With -Display the warnings appear in SUMMARY instead of as loose lines above the report.
if(-not $Display){foreach($w in $script:Warnings){Write-Warning $w}}

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = ('Checks every user profile on this PC: registry entries against folders, temporary and .bak profiles, missing or leftover folders, profile sizes, and profile dates older than {0} days. Nothing is changed or deleted.' -f $StaleDays)
$script:SummaryNext = @(
    'User gets a temporary profile or "We can''t sign in to your account": run this check again while it is happening. A PROBLEM line then names the .bak or temporary entry; back up the user''s data, then follow the site''s profile repair procedure.',
    'Old profile dates are a review list, not approval to delete: they do not show when the user last signed in. Run Accounts - Check Profile Last Sign-In and confirm with the site before any cleanup.',
    'Disk space: Performance - Check Disk Space shows how much each profile uses among other folders.'
)
function Add-SummaryFindings {
    param($Rows)
    $Rows = @($Rows)
    $users = @($Rows | Where-Object { -not $_.Special })
    foreach ($r in $users) {
        $who = '{0} ({1})' -f $r.User, $(if ($r.FolderPath) { $r.FolderPath } else { $r.Sid })
        if ($r.DataIssue -match 'temp profile') { Add-Finding Problem ('{0} is using a temporary profile: changes are lost at sign-out.' -f $who) 'The real profile failed to load. Look for a .bak entry for this user and check the Application log for User Profile Service events 1511 and 1515.' }
        if ($r.DataIssue -match 'orphaned \.bak') { Add-Finding Problem ('{0} has a .bak profile registry entry, the usual cause of temporary profiles.' -f $who) 'Follow the site''s profile repair procedure. Back up the user''s data before changing anything.' }
        if ($r.State -match 'Corrupted') { Add-Finding Problem ('{0} is marked Corrupted by Windows.' -f $who) 'Back up the user''s data, then follow the site''s profile repair procedure.' }
        if ($r.DataIssue -match 'folder missing') { Add-Finding Warning ('{0}: the registry entry points to a folder that does not exist.' -f $who) 'Windows will create a new empty profile at the next sign-in. Find where the user''s data is before changing anything.' }
        if ($r.DataIssue -match 'stray folder') { Add-Finding Warning ('{0}: folder with no profile registry entry (left over from a removed or failed profile).' -f $who) 'It may still hold user data. Review it with the site before removing anything.' }
        if ($r.DataIssue -match 'ProfileImagePath missing') { Add-Finding Warning ('{0}: the profile registry entry has no folder path.' -f $who) 'This entry is damaged; follow the site''s profile repair procedure.' }
        if ($r.FolderName -match '\.\d{3}$') { Add-Finding Warning ('{0}: numbered folder name, so Windows created a new profile because an older one could not be used.' -f $who) 'The user''s older files may be in the folder without the number; check before the user reports missing files.' }
    }
    # Anything that could not be read is NOT CHECKED, so a failed read never ends in a clean result.
    $unread = 0
    $again = 'Run Accounts - Check User Profiles again with administrator rights. Until then, do not act on a profile that is missing from this report.'
    foreach ($w in $script:Warnings) {
        if ($w -like 'Profile size needs admin:*' -or $w -like 'Profile size is partial:*' -or $w -like 'Profile dates can be changed*') { continue }
        if ($w -match '^(Folder|NTUSER) (.+?): (.+)$') {
            # Windows' own service profiles are unreadable without admin and never hold user data.
            if ($Matches[2] -notmatch '\\(system32\\config\\systemprofile|ServiceProfiles\\)') { $unread++; Add-Finding NotChecked ('Profile folder {0} could not be read: {1}' -f $Matches[2], $Matches[3]) 'Run Accounts - Check User Profiles again and approve the admin prompt.' }
            continue
        }
        if ($w -match '^Size (.+?): (.+)$') { Add-Finding NotChecked ('The size of {0} could not be measured: {1}' -f $Matches[1], $Matches[2]) 'The size is left blank; check the folder in File Explorer if it matters.'; continue }
        $unread++
        if ($w -match '^Profile records: (.+)$') { Add-Finding NotChecked ('Windows'' profile list (Win32_UserProfile) could not be read, so loaded, temporary and corrupted states are unknown. Error: {0}' -f $Matches[1]) $again }
        elseif ($w -match '^Profile registry: (.+)$') { Add-Finding NotChecked ('The profile registry (ProfileList) could not be read, so the .bak and leftover-folder checks were skipped. Error: {0}' -f $Matches[1]) $again }
        elseif ($w -match '^Profile directories: (.+)$') { Add-Finding NotChecked ('The profiles folder could not be listed, so leftover folders were not checked. Error: {0}' -f $Matches[1]) $again }
        elseif ($w -match '^Registry (.+?): (.+)$') { Add-Finding NotChecked ('A profile registry entry could not be read, so the leftover-folder check was skipped: {0}. Error: {1}' -f ($Matches[1] -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''), $Matches[2]) $again }
        else { Add-Finding NotChecked ('Not read: {0}' -f $w) $again }
    }
    if (-not $users.Count) { $unread++; Add-Finding NotChecked 'No user profiles were found, so there was nothing to check.' $again }
    $issueRows = @($users | Where-Object { $_.DataIssue -or $_.State -match 'Corrupted' })
    if ($users.Count -and -not $issueRows.Count -and -not $unread) { Add-Finding OK ('{0} checked: no temporary, .bak, missing or leftover profiles.' -f (Format-Count $users.Count 'user profile' 'user profiles')) }
    $stale = @($users | Where-Object { $_.OldDates -eq $true })
    if ($stale.Count) { Add-Finding Info ('{0} with Windows profile dates older than {1} days (review only; this is not when the user last signed in): {2}.' -f (Format-Count $stale.Count 'profile' 'profiles'), $StaleDays, ((@($stale | ForEach-Object { $_.User })) -join '; ')) 'These dates change with background tasks and do not show whether the user still signs in. Run Accounts - Check Profile Last Sign-In and confirm with the site.' }
    $sized = @($users | Where-Object { $null -ne $_.SizeGB } | Sort-Object SizeGB -Descending)
    if ($sized.Count) { Add-Finding Info ('{0}: {1}.' -f $(if ($sized.Count -eq 1) { 'Largest profile' } else { 'Largest profiles' }), ((@($sized | Select-Object -First 3 | ForEach-Object { '{0}, {1} GB{2}' -f $_.User, $_.SizeGB, $(if ($_.LargestFolder) { ' (largest folder: ' + ([string]$_.LargestFolder -replace '^(.+) \((.+)\)$', '$1, $2') + ')' } else { '' }) })) -join '; ')) }
    $noSize = @($script:Warnings | Where-Object { $_ -like 'Profile size needs admin:*' })
    if ($noSize.Count) { Add-Finding NotChecked ('Sizes of {0} need administrator rights.' -f (Format-Count $noSize.Count 'other profile' 'other profiles')) 'Run Accounts - Check User Profiles.cmd again and approve the admin prompt.' }
    if (@($script:Warnings | Where-Object { $_ -like 'Profile size is partial:*' }).Count) { Add-Finding Info 'Some sizes are partial (unreadable folders or the 60-second limit), so they are a minimum.' }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    # The columns the guide asks technicians to judge, as one table; the object output keeps every column (SID too).
    # Folders with no SID at all (Public, Default, leftovers) are labelled as folders, not as unknown accounts.
    $result | Select-Object @{ n = 'User'; e = { if (-not $_.Sid -and $_.Special) { '(shared folder, not a user)' } elseif (-not $_.Sid) { $(if ($registryComplete) { '(folder only, no account)' } else { '(folder only; registry not fully read)' }) } else { $_.User } } }, FolderPath, InRegistry, FolderExists, Loaded, State, LastUseTime, SizeGB, SizeComplete, DataIssue, OldDates |
        Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
