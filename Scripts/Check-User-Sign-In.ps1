<#
.SYNOPSIS
    Report domain logon, Kerberos, time and user sign-in signals.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Check-User-Sign-In.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: User
    Toolkit-Elevation: Recommended
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [string]$TargetUser)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-User-Sign-In'
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

$console=Get-ConsoleUser -OverrideName $TargetUser
$admin=Test-IsAdmin
$cs=Invoke-Section 'Domain membership' {Get-CimInstance Win32_ComputerSystem -ErrorAction Stop}
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;TargetUser=$console.Name;TargetUserSid=$console.Sid;RunningAs=$console.RunningAs;TargetSource=$console.Source;Elevated=$admin;LogonServer=$null;DomainController=$null;DcSite=$null;DcFlags=$null;SecureChannelOk=$null;SecureChannelDc=$null;TimeSource=$null;TimeSkewSeconds=$null;TimeSkewOk=$null;CachedLogonsAllowed=$null;PasswordLastSet=$null;PasswordExpires=$null;PasswordNeverExpires=$null;AccountLockedOut=$null;AccountDisabled=$null;TgtPresent=$null;TgtServer=$null;TgtRenewUntil=$null;TicketCount=$null;KerberosSource='unavailable';EntraJoined=$null;EntraPrt=$null;EntraPrtUpdated=$null;GroupCount=$null;GroupSource=$null;Tickets=@();Groups=@();Warnings=''}
if($console.OtherDesktops -and -not $TargetUser){Add-Warning ('Other desktops: '+$console.OtherDesktops)}
if($console.IsMe){$o.LogonServer=$env:LOGONSERVER}
elseif($console.Hive){$v=Get-RegistryValues ($console.Hive+'\Volatile Environment');$o.LogonServer=$v.LOGONSERVER}
function Read-Label {
 param([string[]]$Lines,[string]$Label)
 foreach($line in $Lines){if($line -match ('^\s*'+[regex]::Escape($Label)+'\s*:\s*(.*?)\s*$')){return $Matches[1]}}
}
function Convert-TicketDate {param($Value) if($Value){$parsed=[datetime]::MinValue;if([datetime]::TryParse(($Value -replace '\s*\(local\)\s*$',''),[ref]$parsed)){return $parsed}}}
$o.TimeSource=Invoke-Section 'Time source' {$r=Invoke-Native w32tm.exe @('/query','/source');if($r.ExitCode){throw ($r.Lines -join ' ')};$r.Lines -join ' '}
$winlogon=Get-RegistryValues 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if("$($winlogon.CachedLogonsCount)" -match '^\d+$'){$o.CachedLogonsAllowed=[int]$winlogon.CachedLogonsCount}
if($cs -and $cs.PartOfDomain){
 $dcInfo=Invoke-Section 'Domain controller' { $r=Invoke-Native nltest.exe @('/dsgetdc:'+$cs.Domain);if($r.ExitCode){throw ($r.Lines -join ' ')};$r }
 if($dcInfo){
  $dc=Read-Label $dcInfo.Lines 'DC';if($dc){$o.DomainController=$dc.TrimStart('\')}
  $o.DcSite=Read-Label $dcInfo.Lines 'Dc Site Name';$o.DcFlags=Read-Label $dcInfo.Lines 'Flags'
  if(-not $o.DomainController){Add-Warning 'DC locator labels were not recognized; domain probes skipped.'}
 }
 if($admin){$o.SecureChannelOk=Invoke-Section 'Secure channel' {
  if($o.DomainController){Test-ComputerSecureChannel -Server $o.DomainController -ErrorAction Stop}
  else{Test-ComputerSecureChannel -ErrorAction Stop}
 };if($null -ne $o.SecureChannelOk){$o.SecureChannelDc=$o.DomainController}}
 else{Add-Warning 'Secure-channel test needs admin; no repair is attempted.'}
 if($o.DomainController -and (Test-TcpPort $o.DomainController 389)){
  $offsets=@(Invoke-Section 'Time offset' {
   $r=Invoke-Native w32tm.exe @('/stripchart',('/computer:'+$o.DomainController),'/samples:3','/dataonly')
   if($r.ExitCode){throw ($r.Lines -join ' ')}
   foreach($line in $r.Lines){if($line -match '([+-]\d+[.,]\d+)s\s*$'){[double]::Parse($Matches[1].Replace(',','.'),[Globalization.CultureInfo]::InvariantCulture)}}
  } -Default @())
  if($offsets.Count){$sorted=@($offsets | Sort-Object);$o.TimeSkewSeconds=[math]::Round($sorted[[int][math]::Floor($sorted.Count/2)],3);$o.TimeSkewOk=([math]::Abs($o.TimeSkewSeconds) -lt 300)}
  $ad=Invoke-Section 'AD account state' {
   if(-not $console.Sid){throw 'Target SID unavailable'}
   $root=[ADSI]("LDAP://"+$o.DomainController+'/RootDSE')
   $dn=[string]$root.defaultNamingContext
   if(-not $dn){throw 'Default naming context unavailable'}
   $entry=New-Object DirectoryServices.DirectoryEntry("LDAP://"+$o.DomainController+'/'+$dn)
   $search=New-Object DirectoryServices.DirectorySearcher($entry)
   try{
    $search.ClientTimeout=[timespan]::FromSeconds(8);$search.ServerTimeLimit=[timespan]::FromSeconds(8)
    $sid=[Security.Principal.SecurityIdentifier]$console.Sid;$bytes=New-Object byte[] $sid.BinaryLength;$sid.GetBinaryForm($bytes,0)
    $filterSid=(@($bytes | ForEach-Object {'\{0:X2}' -f $_}) -join '')
    $search.Filter='(objectSid='+$filterSid+')'
    foreach($prop in 'pwdLastSet','msDS-UserPasswordExpiryTimeComputed','userAccountControl','msDS-User-Account-Control-Computed','tokenGroups'){[void]$search.PropertiesToLoad.Add($prop)}
    $found=$search.FindOne();if(-not $found){throw 'Target user not found in AD'}
    ,($found.Properties)
   }finally{$search.Dispose();$entry.Dispose();$root.Dispose()}
  }
  if($ad){
   if($ad['pwdlastset'].Count -and [int64]$ad['pwdlastset'][0] -gt 0){$o.PasswordLastSet=[datetime]::FromFileTime([int64]$ad['pwdlastset'][0])}
   if($ad['useraccountcontrol'].Count){$uac=[int]$ad['useraccountcontrol'][0];$o.AccountDisabled=(($uac -band 2) -ne 0);$o.PasswordNeverExpires=(($uac -band 0x10000) -ne 0)}
   if($ad['msds-user-account-control-computed'].Count){$o.AccountLockedOut=(([int]$ad['msds-user-account-control-computed'][0] -band 16) -ne 0)}
   if($ad['msds-userpasswordexpirytimecomputed'].Count){$expiry=[int64]$ad['msds-userpasswordexpirytimecomputed'][0];if($expiry -gt 0 -and $expiry -lt [int64]::MaxValue){$o.PasswordExpires=Invoke-Section 'Password expiry' {[datetime]::FromFileTime($expiry)}}}
   if(-not $console.IsMe){
    $o.Groups=@(Invoke-Section 'AD token groups' {foreach($b in $ad['tokengroups']){$sid=New-Object Security.Principal.SecurityIdentifier($b,0);[pscustomobject]@{Name=$sid.Value;Sid=$sid.Value;Type='AD';Attributes='Effective AD tokenGroups; not a live Windows token'}}} -Default @())
    $o.GroupCount=$o.Groups.Count;$o.GroupSource='AD tokenGroups (effective)'
   }
  }
 }else{Add-Warning 'Domain LDAP endpoint unavailable; AD account and time-offset fields remain unknown.'}
}else{Add-Warning 'Not domain joined, or membership unreadable; domain logon checks are unavailable.'}
if($console.IsMe){
 $groupRead=Invoke-Section 'Own token groups' {
  $r=Invoke-Native whoami.exe @('/groups','/fo','csv','/nh');if($r.ExitCode){throw ($r.Lines -join ' ')}
  $data=@($r.Lines | Where-Object {$_ -match '^\s*"'} | ConvertFrom-Csv -Header Name,Type,Sid,Attributes)
  [pscustomobject]@{Rows=@(foreach($g in $data){[pscustomobject]@{Name=$g.Name;Sid=$g.Sid;Type=$g.Type;Attributes=$g.Attributes}})}
 }
 if($groupRead){$o.Groups=@($groupRead.Rows);$o.GroupCount=$o.Groups.Count;$o.GroupSource='whoami (token)'}
}
$kargs=@();$kSource=$null
if($console.IsMe){$kSource='klist (own session)'}
elseif($admin -and $null -ne $console.LogonId){$kargs=@('-li',('0x{0:X}' -f [int64]$console.LogonId));$kSource='klist -li (target session)'}
if($kSource){
 $ticketData=Invoke-Section 'Kerberos tickets' { $r=Invoke-Native klist.exe $kargs;if($r.ExitCode){throw ($r.Lines -join ' ')};$r }
 if($ticketData){
  $text=$ticketData.Lines -join [Environment]::NewLine
  if($text -match '(?i)Cached Tickets:\s*\((\d+)\)'){
   $o.TicketCount=[int]$Matches[1];$o.KerberosSource=$kSource
   $o.Tickets=@(Invoke-Section 'Ticket fields' {
    foreach($block in [regex]::Split($text,'(?m)^\s*#\d+>\s*') | Select-Object -Skip 1){
     $lines=$block -split '\r?\n'
     [pscustomobject]@{Client=(Read-Label $lines 'Client');Server=(Read-Label $lines 'Server');EncryptionType=(Read-Label $lines 'KerbTicket Encryption Type');Start=(Convert-TicketDate (Read-Label $lines 'Start Time'));End=(Convert-TicketDate (Read-Label $lines 'End Time'));RenewUntil=(Convert-TicketDate (Read-Label $lines 'Renew Time'));Flags=(Read-Label $lines 'Ticket Flags')}
    }
   } -Default @())
   $tgt=$o.Tickets | Where-Object {$_.Server -match '^krbtgt/'} | Select-Object -First 1
   $o.TgtPresent=[bool]$tgt;if($tgt){$o.TgtServer=$tgt.Server;$o.TgtRenewUntil=$tgt.RenewUntil}
   if($o.TicketCount -ne $o.Tickets.Count){Add-Warning 'Ticket parser count differs from klist; inspect klist directly.';$o.TgtPresent=$null}
  }else{Add-Warning 'klist labels not recognized; Kerberos fields remain unknown.'}
 }
}else{Add-Warning 'Target-session Kerberos tickets unavailable; no fallback to the technician session.'}
$ds=Invoke-Section 'Entra status' {$r=Invoke-Native dsregcmd.exe @('/status');if($r.ExitCode){throw ($r.Lines -join ' ')};$r}
if($ds){
 $joined=Read-Label $ds.Lines 'AzureAdJoined';if($joined -in 'YES','NO'){$o.EntraJoined=($joined -eq 'YES')}
 if($console.IsMe){$prt=Read-Label $ds.Lines 'AzureAdPrt';if($prt -in 'YES','NO'){$o.EntraPrt=($prt -eq 'YES')};$o.EntraPrtUpdated=Convert-TicketDate (Read-Label $ds.Lines 'AzureAdPrtUpdateTime')}
 else{Add-Warning 'PRT status belongs to the running account and is omitted for another target user.'}
}
Add-Warning 'Domain/Entra success paths need field validation. Missing tickets, PRT or secure-channel results alone do not prescribe a repair.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Sign-in health for the signed-in user: domain controller, computer trust (secure channel), clock difference, account lockout and password expiry, Kerberos tickets and the Microsoft Entra sign-in token.'
$script:SummaryNext = @(
    'Match the user''s exact error: "trust relationship failed" = repair the trust from an admin PowerShell (Test-ComputerSecureChannel -Repair -Credential (Get-Credential)); time or clock errors = resync the clock from an admin prompt (w32tm /resync /force); locked out or password expired = unlock or reset the account in Active Directory.',
    'Group Policy or drive mappings not applying: run Accounts - Check Group Policy.',
    'A missing Kerberos ticket or Entra token alone does not prove a fault: lock and unlock the PC (Windows+L) while connected to the office network or VPN, then check again.'
)
function Add-SummaryFindings {
    param($R)
    $admin = 'Run Accounts - Check User Sign-In.cmd again and approve the admin prompt.'
    # A logon server named after this PC means the PC itself checked the password: a local or Microsoft account.
    $localSignIn = [string]$R.LogonServer -and ([string]$R.LogonServer).TrimStart('\') -ieq $env:COMPUTERNAME
    if ($localSignIn) {
        $kind = 'a local or Microsoft account'
        try { $source = [string](Get-LocalUser -Name (([string]$R.TargetUser -split '\\')[-1]) -ErrorAction Stop).PrincipalSource; if ($source -eq 'MicrosoftAccount') { $kind = 'a Microsoft account' } elseif ($source -eq 'Local') { $kind = 'a local account' } } catch { }
        Add-Finding Info ('Checked for {0}, who signed in with {1}: this PC checked the password itself (no domain controller).' -f $R.TargetUser, $kind)
    } else { Add-Finding Info ('Checked for {0}{1}.' -f $R.TargetUser, $(if ($R.LogonServer) { ', signed in through domain controller {0}' -f ([string]$R.LogonServer).TrimStart('\') } else { '' })) }
    if (-not $R.DomainController -and $R.EntraJoined -eq $false) {
        # Domain advice does not apply to a workgroup PC; replace it with what does.
        $script:SummaryNext = @(
            'Microsoft account password problem: reset it at account.microsoft.com (Security) from any device, then sign in once while this PC is online.',
            'Local account password problem: sign in with another administrator account and use Control Panel > User Accounts > Manage another account > Change the password.',
            'Sign-in is slow or a temporary profile appears: run Accounts - Check User Profiles.'
        )
    }
    if ($R.AccountDisabled) { Add-Finding Problem 'The user''s account is disabled in Active Directory.' 'Confirm with the site whether it should be enabled, then enable it in Active Directory.' }
    if ($R.AccountLockedOut) { Add-Finding Problem 'The user''s account is locked out in Active Directory.' 'Unlock it in Active Directory. If it locks again, look for old saved passwords on phones, mapped drives and Credential Manager (Network - Check Mapped Drives).' }
    if ($R.PasswordExpires -is [datetime]) {
        $days = [math]::Floor(($R.PasswordExpires - [DateTime]::Now).TotalDays)
        if ($days -lt 0) { Add-Finding Problem ('The password expired on {0:yyyy-MM-dd}.' -f $R.PasswordExpires) 'The user must change it (Ctrl+Alt+Del > Change a password) while connected to the office network or VPN.' }
        elseif ($days -le 7) { Add-Finding Warning ('The password expires in {0} ({1:yyyy-MM-dd}).' -f (Format-Count $days 'day' 'days'), $R.PasswordExpires) 'Have the user change it now while connected to the office network or VPN, then update saved passwords on phones.' }
    }
    if ($R.DomainController) { Add-Finding Info ('Domain controller: {0}{1}.' -f $R.DomainController, $(if ($R.DcSite) { ' (site {0})' -f $R.DcSite } else { '' })) }
    if ($R.SecureChannelOk -eq $false) { Add-Finding Problem 'The computer failed the domain trust (secure channel) test.' 'First confirm the domain controller is reachable (Network - Check Connection). If users see "trust relationship failed", repair it from an admin PowerShell with a domain admin account: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)' }
    elseif ($R.SecureChannelOk) { Add-Finding OK 'The computer''s trust with the domain (secure channel) works.' }
    if ($R.TimeSkewOk -eq $false) { Add-Finding Problem ('The PC clock differs from the domain by {0} seconds; Kerberos sign-in fails beyond 5 minutes.' -f $R.TimeSkewSeconds) 'Resync the clock from an admin command prompt: w32tm /resync /force (if the Windows Time service is stopped, run net start w32time first).' }
    elseif ($R.TimeSkewOk) { Add-Finding OK ('The PC clock matches the domain (within {0} seconds).' -f [math]::Abs($R.TimeSkewSeconds)) }
    if ($R.DomainController -and $R.TgtPresent -eq $false) { Add-Finding Warning 'This user has no Kerberos ticket from the domain, so they may be signed in with cached credentials.' 'Connect to the office network or VPN, then lock and unlock the PC (Windows+L) and check again.' }
    if ($R.EntraJoined) {
        if ($R.EntraPrt -eq $false) { Add-Finding Warning 'The PC is Entra-joined but has no Entra sign-in token (PRT) for this user, so Microsoft 365 may keep asking for a password.' 'Lock and unlock the PC while online. If it is still missing, read the dsregcmd /status output for errors.' }
        elseif ($R.EntraPrt) { Add-Finding OK ('The Entra sign-in token (PRT) is present{0}.' -f $(if ($R.EntraPrtUpdated) { ', updated {0}' -f $R.EntraPrtUpdated } else { '' })) }
    }
    if (-not $R.DomainController -and $R.EntraJoined -eq $false) { Add-Finding Info 'This PC is not joined to a domain or Entra ID, so domain sign-in checks do not apply.' }
    if ($R.CachedLogonsAllowed -eq 0) { Add-Finding Warning 'Cached sign-in is turned off (0), so domain users cannot sign in when no domain controller is reachable.' 'Expected on some secured sites; otherwise check the Interactive logon policy.' }
    foreach ($w in $script:Warnings) {
        if ($w -match '^(Domain/Entra success paths|Not domain joined)') { continue }
        if ($w -like 'Secure-channel test needs admin*') { Add-Finding NotChecked 'The domain trust (secure channel) test needs administrator rights.' $admin }
        elseif ($w -like 'Time source:*Access is denied*') { Add-Finding NotChecked 'The Windows time source could not be read without administrator rights.' $admin }
        elseif ($w -like 'Other desktops:*') { Add-Finding Info ('Other people are also signed in: {0}' -f ($w -replace '^Other desktops:\s*', '')) }
        else { Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.' }
    }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
