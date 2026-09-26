<#
.SYNOPSIS
    Summarize Group Policy results for the computer and interactive user.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Check-Group-Policy.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath, [string]$TargetUser)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Check-Group-Policy'
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
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;TargetUser=$console.Name;RunningAs=$console.RunningAs;TargetSource=$console.Source;Elevated=$admin;ResultFormat='Unavailable';NativeSummary=$null;ComputerLastApplied=$null;UserLastApplied=$null;ComputerSlowLink=$null;UserSlowLink=$null;Site=$null;Domain=$null;ComputerAppliedCount=$null;ComputerDeniedCount=$null;UserAppliedCount=$null;UserDeniedCount=$null;ComputerGroups=$null;UserGroups=$null;AppliedGPOs=@();DeniedGPOs=@();LastGpErrors=@();Warnings=''}
$applied=New-Object System.Collections.Generic.List[object];$denied=New-Object System.Collections.Generic.List[object]
function Get-GpChild {param($Node,[string]$Name) if($Node){$child=$Node.SelectSingleNode("./*[local-name()='$Name']");if($child){$child.InnerText}}}
function Get-GpBoolean {param($Value) if("$Value" -match '^(true|1)$'){return $true};if("$Value" -match '^(false|0)$'){return $false};return $null}
function Read-GpDocument {
 param([xml]$Xml)
 foreach($scope in 'Computer','User'){
  $node=$Xml.SelectSingleNode("//*[local-name()='$($scope)Results']")
  if(-not $node){continue}
  $o[$scope+'SlowLink']=Get-GpBoolean (Get-GpChild $node 'SlowLink')
  if(-not $o.Domain){$o.Domain=Get-GpChild $node 'Domain'};if(-not $o.Site){$o.Site=Get-GpChild $node 'Site'}
  $o[$scope+'Groups']=@($node.SelectNodes("./*[local-name()='SecurityGroup']") | ForEach-Object {Get-GpChild $_ 'Name'}) -join '; '
  $o[$scope+'AppliedCount']=0;$o[$scope+'DeniedCount']=0
  foreach($gpo in @($node.SelectNodes("./*[local-name()='GPO']"))){
   $name=Get-GpChild $gpo 'Name';$enabled=Get-GpBoolean (Get-GpChild $gpo 'Enabled');$valid=Get-GpBoolean (Get-GpChild $gpo 'IsValid')
   $filter=Get-GpBoolean (Get-GpChild $gpo 'FilterAllowed');$accessDenied=Get-GpBoolean (Get-GpChild $gpo 'AccessDenied')
   $link=$gpo.SelectSingleNode("./*[local-name()='Link']");$linkPath=Get-GpChild $link 'SOMPath'
   $version=Get-GpChild $gpo 'VersionDirectory';$sysvol=Get-GpChild $gpo 'VersionSysvol'
   $order=$null;$orderText=Get-GpChild $link 'LinkOrder';if($orderText -match '^\d+$'){$order=[int]$orderText}
   if($version -and $sysvol -and $version -ne $sysvol){Add-Warning ("GPO version mismatch: "+$scope+' / '+$name)}
   if($enabled -eq $true -and $valid -eq $true -and $filter -eq $true -and $accessDenied -eq $false){
    $extensions=@($gpo.SelectNodes(".//*[local-name()='ExtensionName']") | ForEach-Object InnerText) -join '; '
    $applied.Add([pscustomobject]@{Scope=$scope;Name=$name;LinkPath=$linkPath;LinkOrder=$order;Version=$version;Extensions=$extensions});$o[$scope+'AppliedCount']++
   }else{
    $reason='Result incomplete; inspect original RSoP'
    if($enabled -eq $false){$reason='Link disabled'}elseif($valid -eq $false){$reason='GPO empty/invalid'}elseif($accessDenied -eq $true){$reason='Security filtering (access denied)'}
    elseif($filter -eq $false){$reason='Filtered';$filterName=Get-GpChild $gpo 'FilterName';if($filterName){$reason='WMI filter: '+$filterName}}
    $denied.Add([pscustomobject]@{Scope=$scope;Name=$name;Reason=$reason;LinkPath=$linkPath});$o[$scope+'DeniedCount']++
   }
  }
 }
}
$tmp=Join-Path $env:TEMP ('Toolkit-gpresult-'+[guid]::NewGuid().ToString('N')+'.xml')
try{
 $arguments=@('/x',$tmp,'/f')
 if(-not $admin){$arguments+=@('/scope','user');Add-Warning 'Computer RSoP needs admin; only user scope requested.';if(-not $console.IsMe){throw 'Cannot query another user unelevated.'}}
 if($console.Name -and -not $console.IsMe){$arguments+=@('/user',$console.Name)}
 $help=Invoke-Native gpresult.exe @('/?')
 $xmlSupported=(($help.Lines -join [Environment]::NewLine) -match '(?im)(?:^|[\s\[])/X(?=[\s\]])')
 if($xmlSupported){
  $native=Invoke-Native gpresult.exe $arguments
  if($native.ExitCode -ne 0){throw ("gpresult failed ({0}): {1}" -f $native.ExitCode,($native.Lines -join ' '))}
  $settings=New-Object System.Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
  $reader=[Xml.XmlReader]::Create($tmp,$settings)
  try{$xml=New-Object System.Xml.XmlDocument;$xml.XmlResolver=$null;$xml.Load($reader);Read-GpDocument $xml;$o.ResultFormat='XML'}finally{$reader.Dispose()}
 }else{
  $fallback=@('/R')
  if(-not $admin){$fallback+=@('/scope','user')}
  if($console.Name -and -not $console.IsMe){$fallback+=@('/user',$console.Name)}
  $native=Invoke-Native gpresult.exe $fallback
  $o.NativeSummary=$native.Lines -join [Environment]::NewLine
  if($native.ExitCode -ne 0){throw ("gpresult /R failed ({0}): {1}" -f $native.ExitCode,($native.Lines -join ' '))}
  $o.ResultFormat='Text (/R)'
  Add-Warning 'This gpresult build lacks XML (/X). NativeSummary contains its text report; structured GPO counts remain unknown.'
 }
}catch{Add-Warning $_.Exception.Message}finally{if(Test-Path -LiteralPath $tmp){[IO.File]::Delete($tmp)}}
$o.AppliedGPOs=$applied.ToArray();$o.DeniedGPOs=$denied.ToArray()
foreach($scope in 'Computer','User'){
 $stateName='Machine';if($scope -eq 'User'){$stateName=$console.Sid;if(-not $stateName){continue}}
 $state=Get-RegistryValues ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\'+$stateName+'\Extension-List\{00000000-0000-0000-0000-000000000000}')
 if($null -ne $state.EndTimeHi -and $null -ne $state.EndTimeLo){$o[$scope+'LastApplied']=Invoke-Section ($scope+' apply time') {ConvertFrom-FileTimePair $state.EndTimeHi $state.EndTimeLo}}
}
$o.LastGpErrors=@(Invoke-Section 'Group Policy errors' {
 foreach($log in 'System','Microsoft-Windows-GroupPolicy/Operational'){
  foreach($e in @(Get-WindowEvents $log @(1058,1030,1053,1055,1129) 7 100)){[pscustomobject]@{Time=$e.TimeCreated;Id=[int]$e.Id;Message=([string]$e.Message -split '\r?\n')[0]}}
 }
} -Default @())
Add-Warning 'Domain RSoP filtering results need field validation; unknown flags are not treated as applied.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Group Policy for this PC and the signed-in user: which policies (GPOs) applied or were filtered out, when policy last applied, and Group Policy errors from the last 7 days.'
$script:SummaryNext = @(
    'A setting, drive or printer from policy is missing: run gpupdate /force (Windows key + R works), then sign out and in (user policy) or restart (computer policy).',
    'Errors reaching SYSVOL or the domain controller: run Network - Check Connection; off-site users need the VPN.',
    'An expected GPO is listed as filtered out: send this report to whoever manages Group Policy for the site. The reason shown (security filtering or a WMI filter) tells them what to change.'
)
function Add-SummaryFindings {
    param($R)
    $now = [DateTime]::Now
    $errors = @($R.LastGpErrors)
    $noComputerRsop = [bool]@($script:Warnings | Where-Object { $_ -like 'Computer RSoP needs admin*' }).Count
    if (-not $R.Domain -and -not @($R.AppliedGPOs).Count) {
        # Domain advice does not apply without domain policies; say what to do instead.
        $script:SummaryNext = @(
            'No domain policies apply here. If the user expects company settings (drives, printers, security settings), this PC is not joined to the company domain or Intune: escalate to whoever manages the site''s PCs.',
            'Settings made on this PC (Local Group Policy Editor or programs) still apply without a domain.'
        )
    }
    if ($errors.Count) {
        $latest = @($errors | Sort-Object Time -Descending)[0]
        Add-Finding Problem ('{0} in the last 7 days; the latest ({1:yyyy-MM-dd HH:mm}, event {2}): {3}' -f (Format-Count $errors.Count 'Group Policy error' 'Group Policy errors'), $latest.Time, $latest.Id, $latest.Message) 'Events 1058/1030 mean SYSVOL or the domain controller could not be reached; 1129 means no network at startup. Check the network, then run gpupdate /force.'
    } else { Add-Finding OK 'No Group Policy errors in the last 7 days.' }
    foreach ($scope in 'Computer', 'User') {
        $at = $R.($scope + 'LastApplied')
        if ($at -is [datetime]) {
            if ($R.Domain -and ($now - $at).TotalDays -gt 7) { Add-Finding Warning ('{0} policy last applied {1:yyyy-MM-dd HH:mm}, over a week ago.' -f $scope, $at) 'Run gpupdate /force and check that the domain controller is reachable.' }
            else { Add-Finding Info ('{0} policy last applied {1:yyyy-MM-dd HH:mm}{2}.' -f $scope, $at, $(if ($scope -eq 'Computer' -and $noComputerRsop) { ' (time only; the details need administrator rights)' } else { '' })) }
        }
        if ($R.($scope + 'SlowLink')) { Add-Finding Warning ('{0} policy detected a slow network link, so some policies (software install, folder redirection, scripts) may be skipped.' -f $scope) 'Check the connection to the domain controller; on VPN this can be expected.' }
    }
    $applied = @($R.AppliedGPOs)
    if ($applied.Count) { Add-Finding Info ('{0}: {1}' -f (Format-Count $applied.Count 'policy (GPO) applied' 'policies (GPOs) applied'), ((@($applied | Select-Object -First 8 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Scope })) -join '; ') + $(if ($applied.Count -gt 8) { '; ...' } else { '' })) }
    $denied = @($R.DeniedGPOs | Where-Object { $_.Name -ne 'Local Group Policy' })
    if ($denied.Count) { Add-Finding Info ('{0}: {1}' -f (Format-Count $denied.Count 'policy was filtered out' 'policies were filtered out'), ((@($denied | Select-Object -First 6 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Reason })) -join '; ')) 'If one of these should apply, send this report to whoever manages Group Policy.' }
    if (-not $R.Domain -and -not $applied.Count) { Add-Finding Info 'No domain policies found: this PC appears to use local policy only (workgroup, Entra-only or not yet joined).' }
    foreach ($w in $script:Warnings) {
        if ($w -like 'Domain RSoP filtering results*') { continue }
        if ($w -like 'Computer RSoP needs admin*') { Add-Finding NotChecked 'Computer policy results need administrator rights; only user policy was read.' 'Run Accounts - Check Group Policy.cmd again and approve the admin prompt.' }
        elseif ($w -like 'This gpresult build lacks XML*') { Add-Finding Info 'This Windows edition cannot export policy results in detail; the full gpresult text is in DETAILS, under NativeSummary.' }
        elseif ($w -like 'GPO version mismatch*') { Add-Finding Warning ($w + ': the copies in Active Directory and SYSVOL differ.') 'Tell the domain administrator: SYSVOL replication may be failing.' }
        else { Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.' }
    }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
