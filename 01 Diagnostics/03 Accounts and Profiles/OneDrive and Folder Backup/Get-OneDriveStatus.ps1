<#
.SYNOPSIS
    Report the target user's OneDrive client, folder redirection and file metadata.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Get-OneDriveStatus.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: User
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [string]$TargetUser, [switch]$SkipFileCounts, [ValidateRange(1,1000000)][int]$MaxFiles=200000)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-OneDriveStatus'
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

$console=Get-ConsoleUser -OverrideName $TargetUser
if($console.OtherDesktops -and -not $TargetUser){Add-Warning ("Other desktops: "+$console.OtherDesktops)}
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;TargetUser=$console.Name;RunningAs=$console.RunningAs;TargetSource=$console.Source;Installed=$null;InstallScope=$null;Version=$null;Running=$null;AccountEmail=$null;AccountName=$null;TenantId=$null;SyncRoot=$null;SyncRootExists=$null;KfmDesktop=$null;KfmDocuments=$null;KfmPictures=$null;KfmState=$null;KfmPolicy=$null;KfmPolicyTenantMatches=$null;SilentAccountConfig=$null;FilesOnDemandEnabled=$null;CloudOnlyFiles=$null;LocalFiles=$null;AlwaysAvailableFiles=$null;CloudOnlyGB=$null;LocalGB=$null;CountsComplete=$null;SyncErrorsHint=$null;LastDiagnosticsWrite=$null;SyncProgressState=$null;PersonalAccountSignedIn=$null;Warnings=''}
$paths=@()
foreach($base in @($env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) | Where-Object {$_}){$paths+=,@((Join-Path $base 'Microsoft OneDrive\OneDrive.exe'),'Per-machine')}
if($console.ProfilePath){$paths+=,@((Join-Path $console.ProfilePath 'AppData\Local\Microsoft\OneDrive\OneDrive.exe'),'Per-user')}
foreach($p in $paths){if(Test-Path -LiteralPath $p[0]){$o.Installed=$true;$o.InstallScope=$p[1];$o.Version=(Get-Item -LiteralPath $p[0]).VersionInfo.FileVersion;break}}
if($null -eq $o.Installed -and $console.ProfilePath){$o.Installed=$false}
if(-not $console.ProfilePath){Add-Warning 'Target profile unavailable; per-user installation and sync files were not read.'}
if($console.Hive){
    $account=Get-RegistryValues ($console.Hive+'\Software\Microsoft\OneDrive\Accounts\Business1')
    if($account){$o.AccountEmail=$account.UserEmail;$o.AccountName=$account.DisplayName;$o.TenantId=$account.ConfiguredTenantId;$o.SyncRoot=$account.UserFolder}
    else{Add-Warning 'Business1 account not found or unreadable; only the first business account is reported.'}
    if($o.SyncRoot){$o.SyncRootExists=Invoke-Section 'Sync root' {Test-Path -LiteralPath $o.SyncRoot -ErrorAction Stop}}
    $o.PersonalAccountSignedIn=Invoke-Section 'Personal account' {Test-Path -LiteralPath ($console.Hive+'\Software\Microsoft\OneDrive\Accounts\Personal') -ErrorAction Stop}
    if($o.SyncRoot -and $console.ProfilePath){
        $shell=Get-RegistryValues ($console.Hive+'\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
        if($shell){
            foreach($pair in @(@('KfmDesktop','Desktop'),@('KfmDocuments','Personal'),@('KfmPictures','My Pictures'))){
                $value=[string]$shell.($pair[1])
                if($value){
                    $value=[regex]::Replace($value,'(?i)%USERPROFILE%',{param($m) $console.ProfilePath})
                    if($value -match '%[^%]+%'){Add-Warning ("Unexpanded target folder: "+$value);continue}
                    $root=[IO.Path]::GetFullPath($o.SyncRoot).TrimEnd('\')
                    $folder=[IO.Path]::GetFullPath($value).TrimEnd('\')
                    $o[$pair[0]]=$folder.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)
                }
            }
            $flags=@($o.KfmDesktop,$o.KfmDocuments,$o.KfmPictures)
            if(@($flags | Where-Object {$null -eq $_}).Count){$o.KfmState='Unknown'}
            elseif(@($flags | Where-Object {$_}).Count -eq 3){$o.KfmState='All redirected'}
            elseif(@($flags | Where-Object {$_}).Count -eq 0){$o.KfmState='None'}
            else{$o.KfmState='Partial'}
        }
    }
}else{Add-Warning 'Target hive unavailable; account, folder redirection and personal-account state were not read.'}
$o.Running=Invoke-Section 'OneDrive processes' {
    $matched=0;$unknown=0
    foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='OneDrive.exe'" -ErrorAction Stop)){
        try{$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop;if($owner.ReturnValue -ne 0){$unknown++;continue};if(('{0}\{1}' -f $owner.Domain,$owner.User) -eq $console.Name){$matched++}}catch{$unknown++}
    }
    if($matched){return $true};if($unknown){throw 'Process owners unreadable; Running is unknown'};$false
}
$policy=Get-RegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
if($policy){
    $parts=@()
    if($policy.KFMSilentOptIn){$parts+='Silent opt-in configured';if($o.TenantId){$o.KfmPolicyTenantMatches=([string]$policy.KFMSilentOptIn -eq [string]$o.TenantId)}}
    if($policy.KFMOptInWithWizard){$parts+='Wizard'};if($policy.KFMBlockOptOut -eq 1){$parts+='Opt-out blocked'}
    $o.KfmPolicy=$parts -join '; '
    if($null -ne $policy.SilentAccountConfig){$o.SilentAccountConfig=($policy.SilentAccountConfig -eq 1)}
    if($null -ne $policy.FilesOnDemandEnabled){$o.FilesOnDemandEnabled=($policy.FilesOnDemandEnabled -eq 1)}
}else{$o.KfmPolicy='Not configured or not readable'}
if($SkipFileCounts){Add-Warning 'File counts skipped; counts and sizes are unknown.'}
elseif($o.SyncRootExists){
    $scan=Invoke-Section 'File metadata counts' {
        $stack=New-Object System.Collections.Generic.Stack[string];$stack.Push($o.SyncRoot)
        $cloud=0;$local=0;$pinned=0;[double]$cloudBytes=0;[double]$localBytes=0;$files=0;$skipped=0;$complete=$true
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while($stack.Count){
            if($files -ge $MaxFiles -or $watch.Elapsed.TotalSeconds -ge 30){$complete=$false;break}
            $dir=$stack.Pop()
            try{$children=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)}catch{$skipped++;$complete=$false;continue}
            foreach($file in $children){
                if($file.PSIsContainer){if(([int64]$file.Attributes -band 0x400) -ne 0){$skipped++;$complete=$false}else{$stack.Push($file.FullName)};continue}
                if($files -ge $MaxFiles){$complete=$false;break}
                $files++;$attr=[int64]$file.Attributes
                if(($attr -band 0x400000) -ne 0 -or ($attr -band 0x1000) -ne 0){$cloud++;$cloudBytes+=$file.Length}
                elseif(($attr -band 0x80000) -ne 0){$pinned++;$localBytes+=$file.Length}
                else{$local++;$localBytes+=$file.Length}
            }
        }
        if(-not $complete){Add-Warning ("Counts partial: {0} skipped folders; cap {1} files / 30 seconds. Reparse subfolders are not followed." -f $skipped,$MaxFiles)}
        [pscustomobject]@{CloudOnlyFiles=$cloud;LocalFiles=$local;AlwaysAvailableFiles=$pinned;CloudOnlyGB=(Round1 ($cloudBytes/1GB));LocalGB=(Round1 ($localBytes/1GB));CountsComplete=$complete}
    }
    Copy-Fields $o $scan @('CloudOnlyFiles','LocalFiles','AlwaysAvailableFiles','CloudOnlyGB','LocalGB','CountsComplete')
    if($scan -and $scan.CloudOnlyFiles -gt 0 -and $null -eq $o.FilesOnDemandEnabled){$o.FilesOnDemandEnabled=$true}
}
if($console.ProfilePath){
    $log=Join-Path $console.ProfilePath 'AppData\Local\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log'
    if(Test-Path -LiteralPath $log){
        $diag=Invoke-Section 'Sync diagnostics' {
            $info=Get-Item -LiteralPath $log -ErrorAction Stop;$tail=@(Get-Content -LiteralPath $log -Tail 200 -ErrorAction Stop)
            $state=$tail | Select-String -Pattern 'SyncProgressState' | Select-Object -Last 1
            [pscustomobject]@{LastDiagnosticsWrite=$info.LastWriteTime;SyncProgressState=[string]$state;SyncErrorsHint=('{0} error mentions in last 200 lines; not a failure count' -f @($tail | Select-String -Pattern '(?i)error').Count)}
        }
        Copy-Fields $o $diag @('LastDiagnosticsWrite','SyncProgressState','SyncErrorsHint')
    }
}
Add-Warning 'Account keys and process presence do not establish sync health. Confirm the current OneDrive tray status.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o
if($Display){$result | Show-Result -Title $script:ToolName -ReportPath $ReportPath}else{$result}
