<#
.SYNOPSIS
    Review local profiles using recorded interactive sign-ins, not file dates.
.DESCRIPTION
    Read-only. Matches Security events to local profile SIDs. Separates sign-in,
    unlock/reconnect and ambiguous interactive activity. Missing history is
    unknown, never permission to delete. Does not change audit policy.
.EXAMPLE
    .\Check-Profile-Last-Sign-In.ps1 -Display
.EXAMPLE
    .\Check-Profile-Last-Sign-In.ps1 -StaleMonths 6 -ReportPath C:\Temp\Toolkit
.NOTES
    Toolkit-Class: Diagnostic
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Windows PowerShell 5.1. Standalone; not a Fleet runner input.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [ValidateRange(1,120)][int]$StaleMonths=6,
    [ValidateRange(100,1000000)][int]$MaxEvents=100000,
    [ValidateNotNullOrEmpty()][string]$ReportPath='C:\Temp\Toolkit'
)
$ErrorActionPreference='Stop'

function Get-PSAAge {
    param($Date,[datetime]$Now)
    if ($null -eq $Date) {return 'Unknown'}
    $dateValue=[datetime]$Date
    if ($dateValue -gt $Now) {return 'Future date - check clock'}
    $days=[math]::Floor(($Now-$dateValue).TotalDays)
    if ($days -eq 0) {return 'Today'}
    $months=($Now.Year-$dateValue.Year)*12+$Now.Month-$dateValue.Month
    if ($dateValue.AddMonths($months) -gt $Now) {$months--}
    if ($months -ge 12) {
        $years=[math]::Floor($months/12);$extra=$months%12
        $label=('{0} year{1}' -f $years,$(if($years -ne 1){'s'}))
        if ($extra) {$label+=(' {0} month{1}' -f $extra,$(if($extra -ne 1){'s'}))}
        return ($label+' ago')
    }
    if ($months -ge 1) {return ('{0} month{1} ago' -f $months,$(if($months -ne 1){'s'}))}
    '{0} day{1} ago' -f $days,$(if($days -ne 1){'s'})
}

function Get-PSAReportFolder {
    param([string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem') {throw 'ReportPath must be a filesystem folder.'}
    $walk=$full
    while ($walk) {
        if (Test-Path -LiteralPath $walk) {
            $item=Get-Item -LiteralPath $walk -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw ('Report path contains a link or junction: '+$walk)}
        }
        $parent=[IO.Path]::GetDirectoryName($walk)
        if ($parent -eq $walk) {break};$walk=$parent
    }
    $null=[IO.Directory]::CreateDirectory($full);$full
}

function Get-PSAAuditPolicy {
    # Native numeric flags avoid parsing localized auditpol output. Query only.
    if (-not ('Toolkit.ProfileSignInAudit' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Toolkit {
 public static class ProfileSignInAudit {
  [StructLayout(LayoutKind.Sequential)] public struct Info { public Guid Subcategory; public uint Flags; public Guid Category; }
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)]
  static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr buffer);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
  public static uint Read(string id) {
   IntPtr p; if (!AuditQuerySystemPolicy(new Guid[]{new Guid(id)},1,out p))
    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   try { return ((Info)Marshal.PtrToStructure(p,typeof(Info))).Flags; }
   finally { AuditFree(p); }
  }
 }
}
'@ -ErrorAction Stop
    }
    [pscustomobject]@{
        LogonSuccess=(([Toolkit.ProfileSignInAudit]::Read('0CCE9215-69AE-11D9-BED3-505054503030') -band 1) -ne 0)
        OtherLogonSuccess=(([Toolkit.ProfileSignInAudit]::Read('0CCE921C-69AE-11D9-BED3-505054503030') -band 1) -ne 0)
    }
}

function ConvertFrom-PSAEvent {
    param($Event)
    $xml=[xml]$Event.ToXml();$fields=@{}
    foreach ($d in $xml.Event.EventData.Data) {if ($d.Name) {$fields[[string]$d.Name]=[string]$d.'#text'}}
    $id=[int]$Event.Id
    $expected=if ($id -in 1100,1101,1102,1104) {'Microsoft-Windows-Eventlog'} else {'Microsoft-Windows-Security-Auditing'}
    if ([string]$xml.Event.System.Provider.Name -ne $expected) {throw "Unexpected provider for event $id"}
    if (-not $Event.TimeCreated) {throw 'Event has no timestamp.'}
    $type=0
    if ($id -eq 4624 -and -not [int]::TryParse($fields.LogonType,[ref]$type)) {throw 'Logon event has no valid LogonType.'}
    $sid=[string]$fields.TargetUserSid
    if ($id -in 4624,4801 -and $sid -notmatch '^S-1-\d+(-\d+)+$') {throw 'Logon/unlock event has no target SID.'}
    [pscustomobject]@{
        Id=$id;Time=[datetime]$Event.TimeCreated;RecordId=[long]$Event.RecordId
        Sid=$sid;Type=$type;Process=([string]$fields.LogonProcessName).Trim()
        User=[string]$fields.TargetUserName;Domain=[string]$fields.TargetDomainName
        ReconnectUser=[string]$fields.AccountName;ReconnectDomain=[string]$fields.AccountDomain
    }
}

function Get-PSASecurity {
    param([int]$Limit,[datetime]$Now)
    $r=[pscustomobject]@{Readable=$false;Complete=$false;Oldest=$null;Newest=$null;Events=@();Error='';Malformed=0;Truncated=$false}
    try {
        $old=Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        $new=Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        $r.Readable=$true;$r.Oldest=$old.TimeCreated;$r.Newest=$new.TimeCreated
        $bound=[long]$new.RecordId
        # Filter in the event service, including log integrity/policy markers.
        $xpath="*[System[EventRecordID <= $bound] and ((System[EventID=4624] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11' or Data[@Name='LogonType']='12' or Data[@Name='LogonType']='13']) or System[EventID=4801 or EventID=4778 or EventID=1100 or EventID=1101 or EventID=1102 or EventID=1104 or EventID=4719 or EventID=4616])]"
        $events=New-Object Collections.Generic.List[object]
        $seen=0
        try {
            Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents ($Limit+1) -ErrorAction Stop | ForEach-Object {
                $seen++
                if ($seen -le $Limit) {
                    try {
                        $parsed=ConvertFrom-PSAEvent $_
                        if ($parsed.Time -gt $Now.AddMinutes(5)) {throw 'Future event timestamp; check the system clock.'}
                        $events.Add($parsed)
                    } catch {$r.Malformed++}
                }
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {throw}
        }
        $r.Truncated=($seen -gt $Limit);$r.Events=$events.ToArray()
        $r.Complete=(-not $r.Truncated -and $r.Malformed -eq 0)
        # Detect rollover during enumeration; the initial oldest record must remain.
        $after=Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        if ([long]$after.RecordId -ne [long]$old.RecordId) {$r.Complete=$false;$r.Error='Security log changed/rolled over during this query. Rerun.'}
    } catch {$r.Error=$_.Exception.Message;$r.Complete=$false;$r.Events=@()}
    $r
}

function Get-PSAInputs {
    param([int]$Limit,[datetime]$Now)
    # Read historical logs first, then check current state. A new/loaded profile
    # observed after log collection must be protected even if its event is absent.
    $security=Get-PSASecurity -Limit $Limit -Now $Now
    $supporting=@(
        Get-PSASupportingLog -LogName 'System' -Provider 'Microsoft-Windows-Winlogon' -Ids @(7001,7002) -Limit $Limit -Now $Now
        Get-PSASupportingLog -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -Provider 'Microsoft-Windows-TerminalServices-LocalSessionManager' -Ids @(21,22,23,24,25) -Limit $Limit -Now $Now
    )
    $profiles=@(Get-CimInstance Win32_UserProfile -OperationTimeoutSec 20 -ErrorAction Stop)
    $sessionSids=New-Object Collections.Generic.List[string]
    $sessionsComplete=$true;$sessionError=''
    try {
        $sessions=@(Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10 OR LogonType=11 OR LogonType=12' -OperationTimeoutSec 20 -ErrorAction Stop)
        foreach ($session in $sessions) {
            $accounts=@(Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ResultClassName Win32_Account -OperationTimeoutSec 15 -ErrorAction Stop)
            foreach ($account in $accounts) {if ($account.SID) {$sessionSids.Add([string]$account.SID)}}
        }
    } catch {$sessionsComplete=$false;$sessionError=$_.Exception.Message}
    $names=@{}
    foreach ($p in $profiles) {
        try {$names[[string]$p.SID]=([Security.Principal.SecurityIdentifier]$p.SID).Translate([Security.Principal.NTAccount]).Value}
        catch {$names[[string]$p.SID]='(unresolved SID)'}
    }
    $audit=$null;$auditError=''
    try {$audit=Get-PSAAuditPolicy} catch {$auditError=$_.Exception.Message}
    [pscustomobject]@{
        Profiles=$profiles;Names=$names;SessionSids=$sessionSids.ToArray();SessionsComplete=$sessionsComplete;SessionError=$sessionError
        CurrentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Audit=$audit;AuditError=$auditError;Security=$security;SupportingLogs=$supporting
    }
}

function ConvertFrom-PSASupportingEvent {
    param($Event,[string]$Provider,[string]$LogName)
    $xml=[xml]$Event.ToXml();$fields=@{}
    if ([string]$xml.Event.System.Provider.Name -ne $Provider) {throw 'Unexpected supporting event provider.'}
    foreach ($d in $xml.Event.EventData.Data) {if($d.Name){$fields[[string]$d.Name]=[string]$d.'#text'}}
    $sid='';$user='';$kind=''
    if ($Provider -eq 'Microsoft-Windows-Winlogon') {
        $sid=[string]$fields.UserSid
        if ($sid -notmatch '^S-1-\d+(-\d+)+$') {throw 'Winlogon notification has no user SID.'}
        $kind=if($Event.Id -eq 7001){'Sign-in notification'}else{'Sign-out notification'}
    } else {
        $user=[string]$xml.Event.UserData.EventXML.User
        if(-not $user){$user=[string]$fields.User}
        if(-not $user){throw 'Session event has no account name.'}
        $kinds=@{21='Session sign-in';22='Shell started';23='Session signed out';24='Session disconnected';25='Session reconnected'}
        $kind=$kinds[[int]$Event.Id]
    }
    if(-not $Event.TimeCreated -or -not $kind){throw 'Invalid supporting event.'}
    [pscustomobject]@{Id=[int]$Event.Id;Time=[datetime]$Event.TimeCreated;RecordId=[long]$Event.RecordId;Sid=$sid;Account=$user;Kind=$kind;LogName=$LogName;Provider=$Provider}
}

function Get-PSASupportingLog {
    param([string]$LogName,[string]$Provider,[int[]]$Ids,[int]$Limit,[datetime]$Now)
    $r=[pscustomobject]@{LogName=$LogName;Readable=$false;Complete=$false;Oldest=$null;Newest=$null;Events=@();Error='';Malformed=0;Truncated=$false}
    try {
        $old=Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop
        $new=Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        $r.Readable=$true;$r.Oldest=$old.TimeCreated;$r.Newest=$new.TimeCreated
        $idFilter=($Ids | ForEach-Object {'EventID='+$_}) -join ' or '
        $xpath="*[System[Provider[@Name='$Provider'] and ($idFilter) and EventRecordID <= $($new.RecordId)]]"
        $events=New-Object Collections.Generic.List[object];$seen=0
        try {
            Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents ($Limit+1) -ErrorAction Stop | ForEach-Object {
                $seen++
                if($seen -le $Limit){
                    try {$e=ConvertFrom-PSASupportingEvent -Event $_ -Provider $Provider -LogName $LogName;if($e.Time -gt $Now.AddMinutes(5)){throw 'Future event timestamp.'};$events.Add($e)}
                    catch {$r.Malformed++}
                }
            }
        } catch {if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
        $r.Truncated=($seen -gt $Limit);$r.Events=$events.ToArray();$r.Complete=(-not $r.Truncated -and $r.Malformed -eq 0)
        $after=Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop
        if([long]$after.RecordId -ne [long]$old.RecordId){$r.Complete=$false;$r.Error='Log changed/rolled over during this query. Rerun.'}
    } catch {$r.Complete=$false;$r.Error=$_.Exception.Message;$r.Events=@()}
    $r
}

function Get-PSAEvidence {
    param($Inputs)
    $nameMap=@{};$profileSids=@($Inputs.Profiles | ForEach-Object {[string]$_.SID})
    foreach($sid in $profileSids){
        $name=$Inputs.Names[$sid]
        if($name -and $name -ne '(unresolved SID)'){
            if(-not $nameMap.ContainsKey($name)){$nameMap[$name]=@()};$nameMap[$name]+=$sid
        }
    }
    foreach($e in $Inputs.Security.Events){
        if($e.Sid -in $profileSids -and $e.User -and $e.Domain){
            $name=$e.Domain+'\'+$e.User
            if(-not $nameMap.ContainsKey($name)){$nameMap[$name]=@()}
            if($e.Sid -notin $nameMap[$name]){$nameMap[$name]+=$e.Sid}
        }
    }
    foreach($e in $Inputs.Security.Events){
        $matches=@();$match='SID';$kind='';$name=$e.Domain+'\'+$e.User
        if($e.Id -eq 4778){$name=$e.ReconnectDomain+'\'+$e.ReconnectUser;$matches=@($nameMap[$name] | Where-Object {$_});$match='Account name only';$kind='Session reconnected'}
        elseif($e.Sid -in $profileSids){
            $matches=@($e.Sid)
            if($e.Id -eq 4801 -or ($e.Id -eq 4624 -and $e.Type -in 7,13)){$kind='Unlocked'}
            elseif($e.Id -eq 4624 -and $e.Type -in 2,10,11,12){$kind=if($e.Process -eq 'User32'){'Desktop sign-in'}else{'Other interactive logon'}}
        }
        if($kind){foreach($sid in $matches){[pscustomobject]@{SID=$sid;Time=$e.Time;LogName='Security';EventId=$e.Id;RecordId=$e.RecordId;Kind=$kind;Match=$match;Account=$name;LogonType=$e.Type;LogonProcess=$e.Process}}}
    }
    foreach($log in $Inputs.SupportingLogs){foreach($e in $log.Events){
        $matches=@();$match='SID'
        if($e.Sid -in $profileSids){$matches=@($e.Sid)}
        elseif($e.Account){$matches=@($nameMap[$e.Account] | Where-Object {$_});$match='Account name only'}
        foreach($sid in $matches){[pscustomobject]@{SID=$sid;Time=$e.Time;LogName=$e.LogName;EventId=$e.Id;RecordId=$e.RecordId;Kind=$e.Kind;Match=$match;Account=$e.Account;LogonType=$null;LogonProcess=''}}
    }}
}

function Get-PSARows {
    param($Inputs,[datetime]$Now,[int]$Months)
    $cutoff=$Now.AddMonths(-$Months);$sec=$Inputs.Security
    $gaps=@($sec.Events | Where-Object {$_.Id -in 1100,1101,1102,1104,4719,4616 -and $_.Time -ge $cutoff})
    $evidence=@(Get-PSAEvidence $Inputs)
    $bySid=@{};$reconnects=@{}
    foreach ($e in $sec.Events) {
        if ($e.Id -eq 4778) {
            $key=$e.ReconnectDomain+'\'+$e.ReconnectUser
            if (-not $reconnects.ContainsKey($key) -or $e.Time -gt $reconnects[$key].Time) {$reconnects[$key]=$e}
        } elseif ($e.Sid) {
            if (-not $bySid.ContainsKey($e.Sid)) {$bySid[$e.Sid]=New-Object Collections.Generic.List[object]}
            $bySid[$e.Sid].Add($e)
        }
    }
    foreach ($p in $Inputs.Profiles | Sort-Object LocalPath) {
        $sid=[string]$p.SID;$name=$Inputs.Names[$sid];$events=@($bySid[$sid] | Where-Object {$null -ne $_})
        $profileEvidence=@($evidence | Where-Object SID -eq $sid)
        # User32 is the Windows desktop logon process. Other type-2 contexts can
        # be RUNAS/programmatic logons: retain separately, never call them a sign-in.
        $signIn=$events | Where-Object {$_.Id -eq 4624 -and $_.Type -in 2,10,11,12 -and $_.Process -eq 'User32'} | Sort-Object Time -Descending | Select-Object -First 1
        $securitySignIn=$signIn
        $winlogon=$profileEvidence | Where-Object {$_.EventId -eq 7001 -and $_.Match -eq 'SID'} | Sort-Object Time -Descending | Select-Object -First 1
        $signInSource='Security 4624 (User32)'
        if($winlogon -and (-not $signIn -or $winlogon.Time -gt $signIn.Time)){$signIn=$winlogon;$signInSource='System / Winlogon 7001 (SID)'}
        if(-not $signIn){$signInSource=''}
        $other=$events | Where-Object {$_.Id -eq 4624 -and $_.Type -in 2,10,11,12 -and $_.Process -ne 'User32'} | Sort-Object Time -Descending | Select-Object -First 1
        $unlock=$events | Where-Object {$_.Id -eq 4801 -or ($_.Id -eq 4624 -and $_.Type -in 7,13)} | Sort-Object Time -Descending | Select-Object -First 1
        # 4778 lacks a SID. Name matching is supplemental protection only; it
        # never supplies LastRecordedSignIn. Renames/reused names limit it.
        $reconnect=$null
        if ($name -and $name -ne '(unresolved SID)') {$reconnect=$reconnects[$name]}
        $lastUse=$profileEvidence | Sort-Object Time -Descending | Select-Object -First 1
        $lastSession=$profileEvidence | Where-Object {$_.LogName -like '*LocalSessionManager*'} | Sort-Object Time -Descending | Select-Object -First 1
        $current=($sid -eq $Inputs.CurrentSid -or $sid -in $Inputs.SessionSids)
        $special=($p.Special -eq $true -or $sid -match '^S-1-5-(18|19|20)$')
        $blockers=New-Object Collections.Generic.List[string]
        if (-not $sec.Readable) {$blockers.Add('Security log unavailable')}
        if (-not $sec.Complete) {$blockers.Add('event query incomplete')}
        if (-not $sec.Oldest -or $sec.Oldest -gt $cutoff) {$blockers.Add('retained log does not cover the review threshold')}
        if (-not $Inputs.Audit -or -not $Inputs.Audit.LogonSuccess -or -not $Inputs.Audit.OtherLogonSuccess) {$blockers.Add('current logon/unlock auditing not confirmed enabled')}
        if ($gaps.Count) {$blockers.Add('log/policy/clock change marker within threshold')}
        if (-not $Inputs.SessionsComplete) {$blockers.Add('current-session check incomplete')}
        if ($null -eq $p.Loaded) {$blockers.Add('profile loaded state unknown')}
        if(-not $name -or $name -eq '(unresolved SID)'){$blockers.Add('account name unresolved; session-name evidence cannot be fully matched')}
        foreach($log in $Inputs.SupportingLogs){
            if(-not $log.Complete){$blockers.Add('supporting log unavailable/incomplete: '+$log.LogName)}
            elseif(-not $log.Oldest -or $log.Oldest -gt $cutoff){$blockers.Add('supporting log history shorter than threshold: '+$log.LogName)}
        }
        $assessment='Unknown - insufficient history';$reason='No recorded desktop sign-in for this SID. Missing records do not mean never used.'
        if ($special) {$assessment='Protected - system profile';$reason='Special/system profile; exclude from stale-user review.'}
        elseif ($p.Loaded -eq $true -or $current) {$assessment='Protected - loaded or signed in';$reason='Profile loaded or an interactive logon session exists. It may be disconnected or used by a process.'}
        elseif ($lastUse -and $lastUse.Time -ge $cutoff) {
            $assessment='Recent evidence - keep'
            $reason=if($signIn -and $signIn.Time -ge $cutoff){'Recorded desktop sign-in within the review threshold.'}else{'Recent unlock, reconnect, session or other interactive evidence; do not treat an old sign-in as stale.'}
        }
        elseif ($signIn) {
            if ($blockers.Count) {$reason='Old sign-in found, but later use cannot be ruled out: '+($blockers -join '; ')+'.'}
            else {$assessment='Older sign-in - review';$reason='Recorded sign-in and other observed interactive evidence are older than the threshold. Historical audit continuity is unproven; review before deletion.'}
        }
        $types=@{2='Console / interactive';10='Remote Desktop';11='Cached interactive';12='Cached Remote Desktop'}
        [pscustomobject][ordered]@{
            ComputerName=$env:COMPUTERNAME;CollectedAt=$Now;User=$name;SID=$sid;ProfilePath=[string]$p.LocalPath
            Assessment=$assessment;Reason=$reason;Loaded=$p.Loaded;InteractiveSession=$current;Special=$special
            LastRecordedSignIn=$(if($signIn){$signIn.Time}else{$null})
            SignInAge=(Get-PSAAge $(if($signIn){$signIn.Time}else{$null}) $Now)
            DaysSinceSignIn=$(if($signIn){[int][math]::Floor(($Now-$signIn.Time).TotalDays)}else{$null})
            SignInType=$(if($signInSource -like 'System*'){'Winlogon sign-in notification'}elseif($signIn){$types[[int]$signIn.Type]}else{''})
            SignInSource=$signInSource
            SignInRecordId=$(if($signIn){$signIn.RecordId}else{$null})
            LastSecuritySignIn=$(if($securitySignIn){$securitySignIn.Time}else{$null})
            LastWinlogonSignIn=$(if($winlogon){$winlogon.Time}else{$null})
            LastRecordedUnlock=$(if($unlock){$unlock.Time}else{$null})
            LastRecordedReconnectByName=$(if($reconnect){$reconnect.Time}else{$null})
            LastOtherInteractiveLogon=$(if($other){$other.Time}else{$null})
            LastSessionEventByName=$(if($lastSession){$lastSession.Time}else{$null})
            LastSessionEventKind=$(if($lastSession){$lastSession.Kind}else{''})
            LastInteractiveEvidence=$(if($lastUse){$lastUse.Time}else{$null})
            EvidenceAge=(Get-PSAAge $(if($lastUse){$lastUse.Time}else{$null}) $Now)
            EvidenceCount=$profileEvidence.Count
            EvidenceSources=(($profileEvidence | Select-Object -ExpandProperty LogName -Unique) -join '; ')
            ReviewCutoff=$cutoff;StaleMonths=$Months;HistoryLimits=($blockers -join '; ')
            SecurityLogOldest=$sec.Oldest;SecurityQueryComplete=$sec.Complete
        }
    }
}

$now=Get-Date
$folder=Get-PSAReportFolder $ReportPath
$stem=Join-Path $folder ('ProfileSignInAge_{0}_{1}_{2}' -f $env:COMPUTERNAME,$now.ToString('yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
$encoding=New-Object Text.UTF8Encoding($false)
$report=[pscustomobject][ordered]@{
    ComputerName=$env:COMPUTERNAME;CollectedAt=$now;Status='NotCompleted';StaleMonths=$StaleMonths;ReviewCutoff=$now.AddMonths(-$StaleMonths)
    Meaning='Last recorded desktop sign-in on this PC, not file activity. Never automatic approval to delete.'
    SecurityLogOldest=$null;SecurityLogNewest=$null;SecurityQueryComplete=$false;SecurityEventsRead=0;EventLimit=$MaxEvents
    MalformedEvents=0;Truncated=$false;LogonAuditSuccessNow=$null;UnlockAuditSuccessNow=$null
    HistoricalAuditContinuity='Not proven';CurrentSessionCheckComplete=$false
    SupportingLogs=@();Warnings=@();Profiles=@();Error='';TextPath=$stem+'.txt';CsvPath=$stem+'.csv';JsonPath=$stem+'.json';EvidenceCsvPath=$stem+'.events.csv'
}
[IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 6),$encoding)
$failure=$null;$rows=@()
try {
    if ($Display) {Write-Host 'Reading profile records and retained Security events. This may take a minute.'}
    $inputs=Get-PSAInputs -Limit $MaxEvents -Now $now
    $sec=$inputs.Security
    $report.SecurityLogOldest=$sec.Oldest;$report.SecurityLogNewest=$sec.Newest
    $report.SecurityQueryComplete=$sec.Complete;$report.SecurityEventsRead=@($sec.Events).Count
    $report.MalformedEvents=$sec.Malformed;$report.Truncated=$sec.Truncated
    $report.CurrentSessionCheckComplete=$inputs.SessionsComplete
    $report.SupportingLogs=@($inputs.SupportingLogs | Select-Object LogName,Readable,Complete,Oldest,Newest,Error,Malformed,Truncated,@{n='EventsRead';e={@($_.Events).Count}})
    if ($inputs.Audit) {$report.LogonAuditSuccessNow=$inputs.Audit.LogonSuccess;$report.UnlockAuditSuccessNow=$inputs.Audit.OtherLogonSuccess}
    $warnings=New-Object Collections.Generic.List[string]
    foreach ($message in @($sec.Error,$inputs.AuditError,$inputs.SessionError)) {if($message){$warnings.Add([string]$message)}}
    if ($sec.Truncated) {$warnings.Add('Event limit reached. Unknown histories stay unknown; use -MaxEvents to raise the limit.')}
    if ($sec.Malformed) {$warnings.Add('Some event records could not be interpreted. Old evidence is not a complete history.')}
    foreach($log in $inputs.SupportingLogs){
        if(-not $log.Complete){$warnings.Add('Supporting log incomplete: '+$log.LogName+'; '+$log.Error)}
    }
    $warnings.Add('Only retained local log history is available. Current policy does not prove auditing was always enabled; per-user exclusions may apply.')
    $warnings.Add('User32 interactive records indicate desktop sign-in, not proof of a human at the keyboard. Automatic sign-in can also produce them.')
    $warnings.Add('4778 reconnects are matched by current account name only. Other interactive logons are retained separately, not reported as desktop sign-ins.')
    $warnings.Add('Session-manager evidence is matched by current or recorded account names only. Name reuse can protect an extra profile; absence cannot prove inactivity.')
    $warnings.Add('This is a point-in-time report. Rerun immediately before any removal decision; user sessions can change after collection.')
    $report.Warnings=$warnings.ToArray()
    $rows=@(Get-PSARows -Inputs $inputs -Now $now -Months $StaleMonths)
    $report.Profiles=$rows
    $evidence=@(Get-PSAEvidence $inputs)
    if($evidence.Count){$evidence | Sort-Object Time -Descending | Select-Object @{n='ComputerName';e={$env:COMPUTERNAME}},SID,@{n='TimeUtc';e={$_.Time.ToUniversalTime().ToString('o')}},LogName,EventId,RecordId,Kind,Match,Account,LogonType,LogonProcess | Export-Csv -LiteralPath $report.EvidenceCsvPath -NoTypeInformation -Encoding UTF8}
    else{[IO.File]::WriteAllText($report.EvidenceCsvPath,'"ComputerName","SID","TimeUtc","LogName","EventId","RecordId","Kind","Match","Account","LogonType","LogonProcess"'+"`r`n",$encoding)}
    if ($rows.Count) {
        $rows | ForEach-Object {
            $flat=[ordered]@{}
            foreach($property in $_.PSObject.Properties){$flat[$property.Name]=if($property.Value -is [datetime]){$property.Value.ToString('o')}else{$property.Value}}
            [pscustomobject]$flat
        } | Export-Csv -LiteralPath $report.CsvPath -NoTypeInformation -Encoding UTF8
    }
    else {[IO.File]::WriteAllText($report.CsvPath,'"ComputerName","User","SID","ProfilePath","Assessment","LastRecordedSignIn","SignInAge"'+"`r`n",$encoding)}
    $supportComplete=(@($inputs.SupportingLogs | Where-Object {-not $_.Complete}).Count -eq 0)
    $report.Status=if($sec.Complete -and $inputs.SessionsComplete -and $inputs.Audit -and $supportComplete){'Completed'}else{'Partial'}
} catch {$failure=$_;$report.Status='Failed';$report.Error=$_.Exception.Message;$report.Profiles=@();$rows=@()}
$text=New-Object Text.StringBuilder
# Word-wraps summary text at 78 columns; later lines align under the text after $Lead.
$wrap={param([string]$Body,[string]$Lead) $pad=' '*$Lead.Length;$line=$Lead;$has=$false
    foreach($word in @(('{0}' -f $Body) -split '\s+' | Where-Object {$_})){
        if($has -and ($line.Length+1+$word.Length) -gt 78){[void]$text.AppendLine($line);$line=$pad;$has=$false}
        if($has){$line+=' '+$word}else{$line+=$word;$has=$true}}
    if($has){[void]$text.AppendLine($line)}}
[void]$text.AppendLine('='*78)
[void]$text.AppendLine(('  Check-Profile-Last-Sign-In   {0}   {1:yyyy-MM-dd HH:mm}' -f $env:COMPUTERNAME,$now))
[void]$text.AppendLine('='*78)
& $wrap ('When each user last signed in to this PC, from the Windows event logs, with a {0}-month review threshold. Read-only: no profile is changed or deleted.' -f $StaleMonths) '  '
[void]$text.AppendLine('')
[void]$text.AppendLine('SUMMARY')
[void]$text.AppendLine('-------')
# Every line below only restates each profile's Assessment; the summary adds no verdict of its own.
$older=@($rows | Where-Object {[string]$_.Assessment -like 'Older sign-in*'})
$unknown=@($rows | Where-Object {[string]$_.Assessment -like 'Unknown*'})
$recent=@($rows | Where-Object {[string]$_.Assessment -like 'Recent evidence*'})
$protected=@($rows | Where-Object {[string]$_.Assessment -like 'Protected*'})
$elevatedRun=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$lastText={param($r) if(-not $r.LastRecordedSignIn){'no recorded sign-in'}elseif([string]$r.SignInAge -eq 'Today'){'last sign-in {0:yyyy-MM-dd HH:mm}, less than a day ago' -f $r.LastRecordedSignIn}else{'last sign-in {0:yyyy-MM-dd}, {1}' -f $r.LastRecordedSignIn,$r.SignInAge}}
$lead=switch ($report.Status) {
    'Completed' {if($older.Count){'REVIEW - {0} with an older sign-in to check with the site. Review only, never approval to delete.' -f $(if($older.Count -eq 1){'1 profile'}else{'{0} profiles' -f $older.Count})}else{'NO OLDER SIGN-INS FOUND - every profile is protected, recently used or unknown (treat unknown as in use).'}}
    'Partial' {'INCOMPLETE - some history could not be read{0}. {1}' -f $(if(-not $elevatedRun){' (the Security log needs admin rights)'}else{''}),$(if($older.Count){'Older sign-ins listed below are review only.'}else{'No profile is a review candidate.'})}
    default {'STOPPED - no result: '+$report.Error}
}
& $wrap $lead '  RESULT: '
[void]$text.AppendLine('')
if ($failure) {& $wrap $report.Error '  PROBLEM      ';& $wrap 'Read the error, then run Accounts - Check Profile Last Sign-In.cmd again and approve the admin prompt.' ((' '*15)+'Next: ')}
if ($report.Status -eq 'Partial' -and -not $elevatedRun) {& $wrap ('The Security log and audit settings were not read without administrator rights.{0}' -f $(if($unknown.Count){' Profiles with no other evidence stay Unknown.'}else{''})) '  NOT CHECKED  ';& $wrap 'Run Accounts - Check Profile Last Sign-In.cmd and approve the admin prompt.' ((' '*15)+'Next: ')}
elseif ($report.Status -eq 'Partial') {& $wrap 'Part of the history could not be read; see HISTORY LIMIT and NOTE lines in DETAILS.' '  NOT CHECKED  ';& $wrap 'Profiles without enough evidence stay Unknown. Treat them as in use.' ((' '*15)+'Next: ')}
if ($unknown.Count) {& $wrap ('Unknown - treat as in use: '+((@($unknown | ForEach-Object {$_.User})) -join '; ')+'. The retained logs cannot show when they last signed in.') '  NOT CHECKED  '}
if ($older.Count) {& $wrap ('Older sign-in - review only, never approval to delete: '+((@($older | ForEach-Object {'{0} ({1})' -f $_.User,(& $lastText $_)})) -join '; ')+'.') '  INFO         ';& $wrap 'Confirm with the site that each person has left, back up their data, and run this check again right before any removal.' ((' '*15)+'Next: ')}
if ($recent.Count) {& $wrap ('Recent sign-in evidence - keep: '+((@($recent | ForEach-Object {'{0} ({1})' -f $_.User,(& $lastText $_)})) -join '; ')+'.') '  OK           '}
if ($protected.Count) {
    $inUse=@($protected | Where-Object {[string]$_.Assessment -notlike '*system profile*'})
    $system=@($protected | Where-Object {[string]$_.Assessment -like '*system profile*'})
    $parts=@();if($inUse.Count){$parts+=((@($inUse | ForEach-Object {'{0} is signed in or loaded now ({1})' -f $_.User,(& $lastText $_)})) -join '; ')};if($system.Count){$parts+=$(if($system.Count -eq 1){'1 Windows system profile'}else{'{0} Windows system profiles' -f $system.Count})}
    & $wrap ('Protected: '+($parts -join '; ')+'.') '  OK           '
}
[void]$text.AppendLine('')
[void]$text.AppendLine('NEXT STEPS')
[void]$text.AppendLine('----------')
& $wrap '"Older sign-in - review" is a list to check, never approval to delete. Confirm with the site that each person has left, back up their data, and run this check again right before any removal.' '  - '
& $wrap 'Unknown means the retained logs cannot show when that user last signed in. Treat those profiles as in use.' '  - '
& $wrap 'Profile sizes and leftover folders: Accounts - Check User Profiles.' '  - '
[void]$text.AppendLine('')
[void]$text.AppendLine('DETAILS')
[void]$text.AppendLine('-------')
[void]$text.AppendLine(('Checked: {0:yyyy-MM-dd HH:mm:ss zzz} | Status: {1}' -f $now,$report.Status))
[void]$text.AppendLine(('Review threshold: {0} calendar months; cutoff {1:yyyy-MM-dd HH:mm:ss}' -f $StaleMonths,$report.ReviewCutoff))
[void]$text.AppendLine($report.Meaning)
[void]$text.AppendLine('Completed means collection finished, not that the full review period is proven inactive.')
if ($report.SecurityLogOldest -or $report.SecurityLogNewest) {[void]$text.AppendLine(('Retained Security log: {0} through {1}' -f $report.SecurityLogOldest,$report.SecurityLogNewest))}
else {[void]$text.AppendLine('Retained Security log: not readable in this run.')}
$auditText={param($v) if([string]::IsNullOrEmpty([string]$v)){'unknown'}else{[string]$v}}
[void]$text.AppendLine(('Event query complete: {0}; records read: {1}; logon/unlock auditing now: {2}/{3}' -f $report.SecurityQueryComplete,$report.SecurityEventsRead,(& $auditText $report.LogonAuditSuccessNow),(& $auditText $report.UnlockAuditSuccessNow)))
foreach($log in $report.SupportingLogs){[void]$text.AppendLine(('Supporting log: {0} | {1} through {2} | complete: {3}; records: {4}' -f $log.LogName,$log.Oldest,$log.Newest,$log.Complete,$log.EventsRead))}
$coverageLimits=@($rows | Where-Object {-not $_.Special} | Select-Object -ExpandProperty HistoryLimits -Unique | Where-Object {$_})
foreach($limit in $coverageLimits){[void]$text.AppendLine('HISTORY LIMIT: '+$limit)}
foreach ($w in $report.Warnings) {[void]$text.AppendLine('NOTE: '+$w)}
if ($failure) {[void]$text.AppendLine('FAILED: '+$report.Error)}
elseif (-not $rows.Count) {[void]$text.AppendLine('No registered profiles returned. Unregistered folders are outside this report.')}
foreach ($row in $rows) {
    [void]$text.AppendLine('')
    [void]$text.AppendLine($row.User+' | '+$row.ProfilePath)
    [void]$text.AppendLine('  '+$row.Assessment)
    $dateText=if($row.LastRecordedSignIn){$row.LastRecordedSignIn.ToString('yyyy-MM-dd HH:mm:ss zzz')}else{'Unknown (no qualifying retained event)'}
    [void]$text.AppendLine('  Last recorded sign-in: '+$dateText+' | '+$row.SignInAge)
    if ($row.SignInType) {[void]$text.AppendLine('  Source: '+$row.SignInSource+' | record '+$row.SignInRecordId+' | '+$row.SignInType)}
    if ($row.LastRecordedUnlock) {[void]$text.AppendLine('  Last unlock: '+$row.LastRecordedUnlock.ToString('yyyy-MM-dd HH:mm:ss zzz'))}
    if ($row.LastRecordedReconnectByName) {[void]$text.AppendLine('  Last reconnect (name match): '+$row.LastRecordedReconnectByName.ToString('yyyy-MM-dd HH:mm:ss zzz'))}
    if ($row.LastOtherInteractiveLogon) {[void]$text.AppendLine('  Other interactive logon (not verified desktop sign-in): '+$row.LastOtherInteractiveLogon.ToString('yyyy-MM-dd HH:mm:ss zzz'))}
    if ($row.LastSessionEventByName) {[void]$text.AppendLine('  Session event (name match): '+$row.LastSessionEventByName.ToString('yyyy-MM-dd HH:mm:ss zzz')+' | '+$row.LastSessionEventKind)}
    [void]$text.AppendLine(('  Supporting records: {0}; sources: {1}' -f $row.EvidenceCount,$row.EvidenceSources))
    [void]$text.AppendLine('  '+$row.Reason)
    [void]$text.AppendLine('  SID: '+$row.SID)
}
if (-not $failure) {[void]$text.AppendLine("`r`nCSV: "+$report.CsvPath);[void]$text.AppendLine('Event evidence CSV: '+$report.EvidenceCsvPath)}
[void]$text.AppendLine('-'*78)
& $wrap ($lead+' The summary and next steps are at the top of this report.') '  RESULT: '
[IO.File]::WriteAllText($report.TextPath,$text.ToString(),$encoding)
[IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 6),$encoding)
if ($Display) {Write-Host $text.ToString();Write-Host ('Report: '+$report.TextPath)}
else {Write-Verbose ('Report: '+$report.TextPath)}
if ($failure) {throw ('{0} Report: {1}' -f $report.Error,$report.TextPath)}
# With -Display the RESULT line already says INCOMPLETE; the warning is for pipeline use.
if ($report.Status -eq 'Partial' -and -not $Display) {Write-Warning ('Report incomplete. Read its coverage notes: '+$report.TextPath)}
if (-not $Display) {$rows}
