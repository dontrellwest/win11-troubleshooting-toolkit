<#
.SYNOPSIS
    Inventory local administrators, local accounts and LAPS policy signals.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\List-Local-Admins.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [string[]]$KnownLocalAccounts=@('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','defaultuser0','localuser'), [string[]]$ExpectedAdmins)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'List-Local-Admins'
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

$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;AdminCount=$null;Admins=$null;UnexpectedAdmins=$null;OrphanedAdminSids=$null;BuiltInAdminName=$null;BuiltInAdminEnabled=$null;BuiltInAdminPasswordLastSet=$null;BuiltInAdminPasswordAgeDays=$null;GuestEnabled=$null;LocalAccountCount=$null;UnexpectedLocalAccounts=$null;LocalAccountsNeverExpire=$null;WindowsLaps=$null;LapsPolicySource=$null;LapsManagedAccount=$null;LapsPasswordAgeDays=$null;LapsLastRotation=$null;LapsExpiry=$null;LapsLastError=$null;LegacyLaps=$null;LegacyLapsEnabled=$null;LapsHealthy=$null;AdminMembers=@();LocalAccounts=@();Warnings=''}
$users=@(Invoke-Section 'Local users' {Get-LocalUser -ErrorAction Stop} -Default @())
$userMap=@{};foreach($u in $users){$userMap[[string]$u.SID]=$u}
$builtin=$users | Where-Object {$_.SID.Value -match '-500$'} | Select-Object -First 1
$guest=$users | Where-Object {$_.SID.Value -match '-501$'} | Select-Object -First 1
if($builtin){$o.BuiltInAdminName=$builtin.Name;$o.BuiltInAdminEnabled=[bool]$builtin.Enabled;$o.BuiltInAdminPasswordLastSet=Get-OptionalDate $builtin.PasswordLastSet;$o.BuiltInAdminPasswordAgeDays=Get-AgeDays $builtin.PasswordLastSet}
if($guest){$o.GuestEnabled=[bool]$guest.Enabled}
# Microsoft documents whole-key precedence: CSP, Group Policy, local config.
$roots=@('HKLM:\SOFTWARE\Microsoft\Policies\LAPS','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config')
$policy=$null;$policyErrorCount=$script:Warnings.Count
foreach($root in $roots){
    $p=Get-RegistryValues $root
    if($p){
        $settingNames=@($p.PSObject.Properties.Name | Where-Object {$_ -notmatch '^PS'})
        if($settingNames.Count){$policy=$p;$o.LapsPolicySource=$root;break}
    }
}
if($policy){
    $backup=0;if($null -ne $policy.BackupDirectory){$backup=[int]$policy.BackupDirectory}
    $o.WindowsLaps=Convert-PolicyValue $backup @{0='Not configured';1='Configured (Entra)';2='Configured (AD)'}
    $o.LapsManagedAccount=$policy.AdministratorAccountName
    if(-not $o.LapsManagedAccount){$o.LapsManagedAccount=$o.BuiltInAdminName}
    $o.LapsPasswordAgeDays=30;if($null -ne $policy.PasswordAgeDays){$o.LapsPasswordAgeDays=[int]$policy.PasswordAgeDays}
    if($policy.AutomaticAccountManagementEnabled -eq 1){
        $o.LapsManagedAccount=$null
        Add-Warning 'LAPS automatic account management is enabled; the managed account must be confirmed from LAPS events.'
    }
}elseif($script:Warnings.Count -eq $policyErrorCount){$o.WindowsLaps='Not configured'}
$legacy=Get-RegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
$o.LegacyLaps=[bool]((Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'LAPS\CSE\AdmPwd.dll')) -or $null -ne $legacy)
if($null -ne $legacy.AdmPwdEnabled){$o.LegacyLapsEnabled=($legacy.AdmPwdEnabled -eq 1)}
$memberData=@(Invoke-Section 'Administrators group' {
    try{
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{Name=[string]$_.Name;Sid=[string]$_.SID;ObjectClass=[string]$_.ObjectClass;PrincipalSource=[string]$_.PrincipalSource}
        }
    }catch{
        Add-Warning 'LocalGroupMember failed; using the localized ADSI group fallback.'
        $groupName=([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group=[ADSI]("WinNT://./{0},group" -f $groupName)
        foreach($member in $group.Invoke('Members')){
            $type=$member.GetType()
            $sidBytes=$type.InvokeMember('objectSid','GetProperty',$null,$member,$null)
            $sid=(New-Object Security.Principal.SecurityIdentifier($sidBytes,0)).Value
            $name=$sid;try{$name=([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value}catch{}
            [pscustomobject]@{Name=$name;Sid=$sid;ObjectClass=[string]$type.InvokeMember('Class','GetProperty',$null,$member,$null);PrincipalSource='Unknown'}
        }
    }
} -Default @())
$o.AdminMembers=@(Invoke-Section 'Administrator details' {
    foreach($m in $memberData){
        $resolved=$m.Name;$orphan=$false
        try{$resolved=([Security.Principal.SecurityIdentifier]$m.Sid).Translate([Security.Principal.NTAccount]).Value}catch{$orphan=$true}
        $localUser=$userMap[$m.Sid]
        $expected=$false
        if($ExpectedAdmins){$expected=($resolved -in $ExpectedAdmins -or $m.Sid -in $ExpectedAdmins)}
        else{
            $expected=($builtin -and $m.Sid -eq [string]$builtin.SID) -or ($m.ObjectClass -eq 'Group' -and $m.Sid -match '^S-1-5-21-.*-512$') -or ($localUser -and $o.LapsManagedAccount -and $localUser.Name -eq $o.LapsManagedAccount)
        }
        [pscustomobject]@{Name=$resolved;Sid=$m.Sid;ObjectClass=$m.ObjectClass;PrincipalSource=$m.PrincipalSource;Enabled=$(if($localUser){[bool]$localUser.Enabled}else{$null});Orphaned=[bool]$orphan;Expected=[bool]$expected}
    }
} -Default @())
if($memberData.Count){
    $o.AdminCount=[int]$o.AdminMembers.Count;$o.Admins=@($o.AdminMembers | ForEach-Object Name) -join '; '
    $o.UnexpectedAdmins=@($o.AdminMembers | Where-Object {-not $_.Expected} | ForEach-Object Name) -join '; '
    $o.OrphanedAdminSids=[int]@($o.AdminMembers | Where-Object Orphaned).Count
}
$o.LocalAccounts=@(Invoke-Section 'Account details' {
    foreach($u in $users){
        $known=$u.Name -in $KnownLocalAccounts -or $u.SID.Value -match '-(500|501|503|504)$'
        [pscustomobject]@{Name=$u.Name;Sid=[string]$u.SID;Enabled=[bool]$u.Enabled;PasswordLastSet=(Get-OptionalDate $u.PasswordLastSet);PasswordAgeDays=(Get-AgeDays $u.PasswordLastSet);PasswordNeverExpires=($null -eq $u.PasswordExpires);PasswordRequired=[bool]$u.PasswordRequired;LastLogon=(Get-OptionalDate $u.LastLogon);Description=[string]$u.Description;Known=[bool]$known;IsAdmin=([string]$u.SID -in @($o.AdminMembers | ForEach-Object Sid))}
    }
} -Default @())
if($users.Count){
    $o.LocalAccountCount=[int]$users.Count
    $o.UnexpectedLocalAccounts=@($o.LocalAccounts | Where-Object {-not $_.Known} | ForEach-Object Name) -join '; '
    $o.LocalAccountsNeverExpire=[int]@($o.LocalAccounts | Where-Object {$_.Enabled -and $_.PasswordNeverExpires -and $_.Name -ne $o.LapsManagedAccount}).Count
}
$lapsEvents=@(Invoke-Section 'LAPS events' {Get-WindowEvents 'Microsoft-Windows-LAPS/Operational' @() 30 1000} -Default @())
$backupEvent=$lapsEvents | Where-Object {$_.Id -in 10018,10029} | Sort-Object TimeCreated -Descending | Select-Object -First 1
if($backupEvent){$o.LapsLastRotation=$backupEvent.TimeCreated;Add-Warning 'LapsLastRotation is the latest successful backup event, not independent proof of a password change.'}
$errorEvent=$lapsEvents | Where-Object {$_.Level -in 1,2} | Sort-Object TimeCreated -Descending | Select-Object -First 1
if($errorEvent){$o.LapsLastError="$($errorEvent.Id): "+([string]$errorEvent.Message -split '\r?\n')[0]}
if($o.WindowsLaps -like 'Configured*' -and $o.LapsLastRotation -and $o.LapsPasswordAgeDays){$o.LapsHealthy=(([datetime]::Now-$o.LapsLastRotation).TotalDays -le 2*$o.LapsPasswordAgeDays)}
Add-Warning 'Unresolved SIDs can reflect an unreachable domain, not a deleted account. No members or accounts are changed.'
Add-Warning 'LAPS expiry and directory backup contents are not verified locally; confirm them on a managed machine. No passwords are read.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Who has administrator rights on this PC, the built-in Administrator and Guest accounts, local accounts, and whether the local admin password is managed by LAPS. Nothing is changed.'
$script:SummaryNext = @(
    'Confirm every unexpected administrator with the site. Remove admin rights only through the site''s approved process, never as a quick fix.',
    'To flag only surprises, list the expected admins. From PowerShell in the Scripts folder: .\List-Local-Admins.ps1 -ExpectedAdmins ''PC\name'',''DOMAIN\group'' -Display',
    'No LAPS on a business PC means the local admin password may be the same on many PCs; raise it with whoever manages security for the site.'
)
function Add-SummaryFindings {
    param($R)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    # Each administrator with what it is: built-in, disabled, a group, a Microsoft account, the signed-in user.
    $describe = {
        param($m)
        $tags = @()
        if ([string]$m.Sid -match '-500$') { $tags += 'built-in' }
        if ($m.Enabled -eq $false) { $tags += 'disabled' }
        if ([string]$m.ObjectClass -eq 'Group') { $tags += 'group' }
        if ([string]$m.PrincipalSource -eq 'MicrosoftAccount') { $tags += 'Microsoft account' }
        if ([string]$m.Name -ieq $me) { $tags += 'signed-in user' }
        '{0}{1}' -f $m.Name, $(if ($tags.Count) { ' (' + ($tags -join ', ') + ')' } else { '' })
    }
    $members = @($R.AdminMembers | Where-Object { $_ })
    if ($members.Count) { Add-Finding Info ('{0}: {1}.' -f (Format-Count $members.Count 'administrator' 'administrators'), ((@($members | ForEach-Object { & $describe $_ })) -join '; ')) }
    elseif ($null -ne $R.AdminCount) { Add-Finding Info ('{0}: {1}.' -f (Format-Count $R.AdminCount 'administrator' 'administrators'), $R.Admins) }
    if ($R.UnexpectedAdmins) {
        $flagged = @($members | Where-Object { -not $_.Expected })
        $names = $(if ($flagged.Count) { (@($flagged | ForEach-Object { & $describe $_ })) -join '; ' } else { $R.UnexpectedAdmins })
        $one = ($flagged.Count -eq 1)
        if ($ExpectedAdmins) { Add-Finding Warning ('Not on the expected list you gave: {0}.' -f $names) $(if ($one) { 'Confirm with the site that this account should be an administrator.' } else { 'Confirm with the site that each of these should be an administrator.' }) }
        else { Add-Finding Warning ('{0} an administrator: {1}. No expected list was given, so every admin except the built-in account, Domain Admins and the LAPS account is flagged.' -f $(if ($one) { 'This account is' } else { 'These accounts are' }), $names) $(if ($one) { 'Confirm with the site that this account should be an administrator.' } else { 'Confirm with the site that each of these should be an administrator.' }) }
    }
    elseif ($null -ne $R.AdminCount) { Add-Finding OK 'Every administrator is on the expected list.' }
    if ($R.OrphanedAdminSids -gt 0) { Add-Finding Warning ('{0} could not be resolved to a name (deleted account, or the domain could not be reached).' -f (Format-Count $R.OrphanedAdminSids 'administrator entry' 'administrator entries')) 'Check again while connected to the domain before removing anything.' }
    if ($R.GuestEnabled) { Add-Finding Problem 'The Guest account is enabled.' 'Disable it unless the site has a documented reason for it.' }
    if ($R.BuiltInAdminEnabled) { Add-Finding Warning ('The built-in Administrator account ({0}) is enabled{1}.' -f $R.BuiltInAdminName, $(if ($null -ne $R.BuiltInAdminPasswordAgeDays) { ', password {0} days old' -f $R.BuiltInAdminPasswordAgeDays } else { '' })) $(if ($R.LapsManagedAccount) { 'LAPS manages it; confirm the password rotates.' } else { 'Disable it or put it under LAPS, per the site''s policy.' }) }
    if ($R.WindowsLaps -like 'Configured*') {
        if ($R.LapsHealthy -eq $false) { Add-Finding Warning ('LAPS is configured ({0}) but the password has not rotated on schedule; last backup {1}.' -f $R.WindowsLaps, $R.LapsLastRotation) $(if ($R.LapsLastError) { 'Latest LAPS error: ' + $R.LapsLastError } else { 'Check the LAPS event log (Microsoft > Windows > LAPS > Operational).' }) }
        else { Add-Finding OK ('The local admin password is managed by Windows LAPS ({0}).' -f $R.WindowsLaps) }
    } elseif ($R.LegacyLapsEnabled) { Add-Finding Info 'The local admin password is managed by legacy Microsoft LAPS.' }
    elseif ($R.WindowsLaps -eq 'Not configured' -and -not $R.LegacyLaps) { Add-Finding Info 'Windows LAPS (automatic rotation of the local admin password) is not set up.' 'On business PCs, confirm the site''s local admin password policy.' }
    if ($R.UnexpectedLocalAccounts) { Add-Finding Info ('Local user accounts besides Windows'' own built-in ones: {0}.' -f $R.UnexpectedLocalAccounts) 'Confirm they belong to people or software the site expects.' }
    foreach ($w in $script:Warnings) {
        if ($w -match '^(Unresolved SIDs can reflect|LAPS expiry and directory backup|LapsLastRotation is the latest|LocalGroupMember failed)') { continue }
        Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.'
    }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
