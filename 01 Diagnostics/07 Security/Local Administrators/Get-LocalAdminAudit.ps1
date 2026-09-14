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
    .\Get-LocalAdminAudit.ps1 -Display
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
$script:ToolName  = 'Get-LocalAdminAudit'
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
if($Display){$result | Show-Result -Title $script:ToolName -ReportPath $ReportPath}else{$result}
