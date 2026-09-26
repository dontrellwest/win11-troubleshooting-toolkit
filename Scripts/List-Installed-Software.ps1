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
    .\List-Installed-Software.ps1 -Display
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
$script:ToolName  = 'List-Installed-Software'
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
# Hive names are listed without opening each hive: service-account hives deny non-admins, and that must not
# cost the signed-in user's own programs. Each user's programs are read (or reported unreadable) separately.
$hives=@(Invoke-Section 'Loaded user hives' {[Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object {$_ -match '^S-1-(5-21|12-1)-[0-9-]+$'}} -Default @())
foreach($sid in $hives){
    $user=$sid
    try{$user=([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value}catch{}
    foreach($r in @(Invoke-Section "Apps for $user" {Read-UninstallRoot ('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall') ("User: "+$user) 'Unknown'} -Default @())){$rows.Add($r)}
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
# With -Display the warnings appear in SUMMARY instead of as loose lines above the report.
if(-not $Display){foreach($warning in $script:Warnings){Write-Warning $warning}}

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Inventory of installed programs with version, publisher, install date and scope (all users or one user), read from the registry. Nothing is installed or removed.'
$script:SummaryNext = @(
    'One program misbehaving: repair it from Settings > Apps > Installed apps (Modify, or Advanced options > Repair), or reinstall it.',
    'Problem started recently: run Windows - Check Recent Changes to see what changed and when.',
    'Store apps, updates and system components are hidden by default. From PowerShell in the Scripts folder, add -IncludeStoreApps, -IncludeUpdates or -IncludeSystemComponents, for example: .\List-Installed-Software.ps1 -IncludeStoreApps -Display'
)
function Add-SummaryFindings {
    param($Rows)
    $Rows = @($Rows)
    $machine = @($Rows | Where-Object { $_.Scope -like 'Machine*' }).Count
    $perUser = @($Rows | Where-Object { $_.Scope -like 'User:*' } | Group-Object Scope | ForEach-Object { '{0} for {1}' -f $_.Count, ($_.Name -replace '^User:\s*', '') })
    $store = @($Rows | Where-Object { $_.Scope -eq 'Store' }).Count
    Add-Finding Info ('{0}: {1} for all users{2}{3}.' -f (Format-Count $Rows.Count 'program listed' 'programs listed'), $machine, $(if ($perUser.Count) { ', ' + ($perUser -join ', ') } else { ', none installed for a single user' }), $(if ($store) { ', {0} Store packages' -f $store } else { '' }))
    $recent = @($Rows | Where-Object { $_.InstallDate -is [datetime] -and $_.InstallDate -ge [DateTime]::Today.AddDays(-14) } | Sort-Object InstallDate -Descending)
    if ($recent.Count) { Add-Finding Info ('Installed or updated in the last 14 days: {0}{1}' -f ((@($recent | Select-Object -First 6 | ForEach-Object { '{0} ({1:yyyy-MM-dd})' -f $_.Name, $_.InstallDate })) -join '; '), $(if ($recent.Count -gt 6) { '; and {0} more.' -f ($recent.Count - 6) } else { '.' })) 'If the problem started after one of these, repair, update or remove it.' }
    $dupes = @($Rows | Where-Object { $_.Scope -ne 'Store' } | Group-Object Name | Where-Object { $_.Count -gt 1 -and @($_.Group | Select-Object -ExpandProperty Version -Unique).Count -gt 1 })
    if ($dupes.Count) { Add-Finding Warning ('Listed more than once with different versions: {0}.' -f ((@($dupes | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, ((@($_.Group | Select-Object -ExpandProperty Version -Unique)) -join ', ') })) -join '; ')) 'A leftover older version can break updates. Check Settings > Apps and remove the older one if the vendor supports that.' }
    $m365 = @($Rows | Where-Object { $_.Name -match '^Microsoft 365|^Microsoft Office' } | Select-Object -First 1)
    if ($m365.Count) { Add-Finding Info ('{0}: version {1}{2}.' -f $m365[0].Name, $m365[0].Version, $(if ($m365[0].Detail) { '; ' + $m365[0].Detail } else { '' })) }
    $remote = @($Rows | Where-Object { $_.Name -match 'TeamViewer|AnyDesk|ScreenConnect|ConnectWise Control|Splashtop|LogMeIn|RustDesk|Chrome Remote Desktop|UltraVNC|TightVNC|RealVNC|VNC Server|GoTo Resolve|Zoho Assist|RemotePC|NoMachine|Supremo|Atera|BeyondTrust' } | Select-Object -ExpandProperty Name -Unique)
    if ($remote.Count) { Add-Finding Info ('Remote access software: {0}.' -f ($remote -join '; ')) 'Confirm each one is approved for this site; unapproved remote tools are a security risk.' }
    foreach ($w in $script:Warnings) {
        if ($w -like 'Per-user apps are limited*') { Add-Finding Info 'Per-user programs are listed only for users whose registry is loaded (usually those signed in now).' }
        elseif ($w -like 'Loaded user hives:*') { Add-Finding NotChecked 'The signed-in users could not be listed, so programs installed for a single user are missing.' 'Run Windows - List Installed Software.cmd again and approve the admin prompt.' }
        elseif ($w -match '^Apps for (.+?):') { Add-Finding NotChecked ('Programs installed only for {0} could not be read without admin rights.' -f $Matches[1]) 'Run Windows - List Installed Software.cmd again and approve the admin prompt.' }
        else { Add-Finding NotChecked $w 'Some programs may be missing from the list; the rest is still valid.' }
    }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    # The columns the guide asks technicians to compare; the object output keeps every column.
    $result | Select-Object Name, Version, Publisher, @{ n = 'InstallDate'; e = { if ($_.InstallDate -is [datetime]) { $_.InstallDate.ToString('yyyy-MM-dd') } } }, Scope, EstimatedSizeMB |
        Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
