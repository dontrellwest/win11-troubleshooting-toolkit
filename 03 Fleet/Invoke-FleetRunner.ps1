<#
.SYNOPSIS
    Run approved read-only scripts over WinRM and export per-computer results.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Invoke-FleetRunner.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Display, [string]$ReportPath, [Parameter(Mandatory)][string[]]$Script, [string[]]$ComputerName, [string]$ComputerListPath, [string]$SearchBase, [string]$OperatingSystemFilter='*Windows 1*', [hashtable]$ScriptArgs=@{}, [string]$OutputFolder='C:\Temp\Toolkit\Fleet', [ValidateRange(1,64)][int]$ThrottleLimit=16, [ValidateRange(1,3600)][int]$TimeoutSeconds=300, [pscredential]$Credential, [switch]$SkipPing)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Invoke-FleetRunner'
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

function Read-FleetScript {
 param([string]$Path)
 $resolved=(Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
 if([IO.Path]::GetExtension($resolved) -ne '.ps1'){throw 'Only .ps1 tools are accepted'}
 $code=Get-Content -LiteralPath $resolved -Raw -ErrorAction Stop
 $head=(@($code -split '\r?\n' | Select-Object -First 80) -join [Environment]::NewLine)
 $class=[regex]::Matches($head,'(?m)^[ \t]*Toolkit-Class:[ \t]*([^\r\n]+)')
 if($class.Count -ne 1 -or $class[0].Groups[1].Value.Trim() -notmatch '^ReadOnly(?:\s+\([^)]*\))?$'){throw ("Refusing "+$resolved+': exactly one Toolkit-Class: ReadOnly header is required')}
 if([IO.Path]::GetFileNameWithoutExtension($resolved) -eq 'Invoke-FleetRunner'){throw 'The fleet runner cannot run itself'}
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($code,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ("Script syntax errors: "+($errors.Message -join '; '))}
 [pscustomobject]@{Name=[IO.Path]::GetFileNameWithoutExtension($resolved);Path=$resolved;Code=$code;UserContext=($head -match 'Toolkit-Context:\s*User')}
}
function Export-FleetRows {
 param([object[]]$Rows,[string]$Path)
 if(-not $Rows.Count){return}
 $columns=New-Object System.Collections.Generic.List[string]
 foreach($row in $Rows){foreach($p in $row.PSObject.Properties){if(-not $columns.Contains($p.Name)){$columns.Add($p.Name)}}}
 $Rows | Select-Object -Property $columns.ToArray() | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}
function Split-FleetObject {
 param($InputObject,[string]$Computer,[System.Collections.Generic.List[object]]$Main,[hashtable]$Details)
 $scalar=[ordered]@{Computer=$Computer}
 foreach($p in $InputObject.PSObject.Properties){
  if($p.Name -in 'PSComputerName','RunspaceId','PSShowComputerName','Computer'){continue}
  if($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string] -and $p.Value -isnot [System.Collections.IDictionary]){
   $safe=$p.Name
   if($safe -notmatch '^[A-Za-z_][A-Za-z0-9_]*$'){throw ("Unsupported detail property name: "+$safe+". Use simple column names to prevent CSV filename collisions.")}
   if(-not $Details.ContainsKey($safe)){$Details[$safe]=New-Object System.Collections.Generic.List[object]}
   foreach($item in $p.Value){
    $row=[ordered]@{Computer=$Computer}
    if($item -is [string] -or $item -is [valuetype] -or $null -eq $item){$row.Value=$item}
    else{foreach($q in $item.PSObject.Properties){if($q.Name -eq 'Computer'){continue};$row[$q.Name]=$q.Value}}
    $Details[$safe].Add([pscustomobject]$row)
   }
  }else{$scalar[$p.Name]=$p.Value}
 }
 $Main.Add([pscustomobject]$scalar)
}
if($ScriptArgs.ContainsKey('Display') -or $ScriptArgs.ContainsKey('ReportPath') -or $ScriptArgs.ContainsKey('LogPath')){throw 'Fleet ScriptArgs must not request remote display or file reports'}
$tools=@($Script | ForEach-Object {Read-FleetScript $_})
if(@($tools.Name | Sort-Object -Unique).Count -ne $tools.Count){throw 'Script names must be unique in a fleet run'}
$targets=@($ComputerName)
if($ComputerListPath){$targets+=@(Get-Content -LiteralPath $ComputerListPath -ErrorAction Stop | ForEach-Object {($_ -split '#',2)[0].Trim()})}
if($SearchBase){
 $entry=New-Object DirectoryServices.DirectoryEntry("LDAP://"+$SearchBase)
 $search=New-Object DirectoryServices.DirectorySearcher($entry)
 try{
  $search.Filter='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
  $search.PageSize=500;$search.SizeLimit=10000;$search.ClientTimeout=[timespan]::FromSeconds(15);$search.ServerTimeLimit=[timespan]::FromSeconds(15)
  [void]$search.PropertiesToLoad.Add('dnshostname');[void]$search.PropertiesToLoad.Add('operatingsystem')
  $found=$search.FindAll()
  try{foreach($c in $found){if([string]$c.Properties['operatingsystem'][0] -like $OperatingSystemFilter){$targets+=[string]$c.Properties['dnshostname'][0]}}}finally{$found.Dispose()}
 }finally{$search.Dispose();$entry.Dispose()}
}
$targets=@($targets | Where-Object {$_} | ForEach-Object {$_.Trim()} | Where-Object {$_} | Sort-Object -Unique)
if(-not $targets.Count){throw 'Supply ComputerName, ComputerListPath, or SearchBase with at least one target'}
foreach($hostName in $targets){if($hostName -notmatch '^[a-zA-Z0-9_.:-]+$'){throw "Invalid computer name: $hostName"}}
$reachable=@{};foreach($hostName in $targets){$reachable[$hostName]=($SkipPing -or (Test-TcpPort $hostName 5985))}
$OutputFolder=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
$wrapper={param($Code,$Arguments) $ErrorActionPreference='Stop';$body=[scriptblock]::Create($Code); & $body @Arguments}
foreach($tool in $tools){
 $script:Warnings.Clear()
 if($tool.UserContext){Add-Warning 'User fields describe each target console user; session-only fields may be unavailable over WinRM.'}
 $watch=[Diagnostics.Stopwatch]::StartNew()
 $status=New-Object System.Collections.Generic.List[object];$main=New-Object System.Collections.Generic.List[object];$details=@{}
 $runFolder=Join-Path $OutputFolder ([datetime]::Now.ToString('yyyyMMdd-HHmmss-fff')+'_'+$tool.Name)
 $go=$PSCmdlet.ShouldProcess(($targets -join ', '),('Run '+$tool.Name+' over WinRM and export results to '+$runFolder))
 if($go){
  [IO.Directory]::CreateDirectory($runFolder) | Out-Null
  $queue=New-Object System.Collections.Generic.Queue[string]
  foreach($hostName in $targets){
   if($reachable[$hostName]){$queue.Enqueue($hostName)}
   else{$status.Add([pscustomobject]@{Computer=$hostName;Status='No WinRM';Objects=0;Seconds=0;Error='TCP 5985 did not answer';Warnings=''})}
  }
  $active=New-Object System.Collections.Generic.List[object]
  try{
   while($queue.Count -or $active.Count){
    while($queue.Count -and $active.Count -lt $ThrottleLimit){
     $hostName=$queue.Dequeue()
     try{
      $sessionOption=New-PSSessionOption -OpenTimeout ([math]::Min(20000,$TimeoutSeconds*1000)) -OperationTimeout ($TimeoutSeconds*1000)
      $args=@{ComputerName=$hostName;ScriptBlock=$wrapper;ArgumentList=@($tool.Code,$ScriptArgs);AsJob=$true;SessionOption=$sessionOption;ErrorAction='Stop'}
      if($Credential){$args.Credential=$Credential}
      $job=Invoke-Command @args
      $active.Add([pscustomobject]@{Computer=$hostName;Job=$job;Started=[datetime]::Now})
     }catch{$status.Add([pscustomobject]@{Computer=$hostName;Status='Error';Objects=0;Seconds=0;Error=$_.Exception.Message;Warnings=''})}
    }
    foreach($work in @($active.ToArray())){
     $seconds=([datetime]::Now-$work.Started).TotalSeconds
     $timeout=$seconds -ge $TimeoutSeconds -and $work.Job.State -in 'Running','NotStarted'
     if($work.Job.State -in 'Running','NotStarted' -and -not $timeout){continue}
     if($timeout){Stop-Job -Job $work.Job -ErrorAction SilentlyContinue}
     $jobErrors=@();$jobWarnings=@()
     $data=@(Receive-Job -Job $work.Job -ErrorAction SilentlyContinue -ErrorVariable +jobErrors -WarningVariable +jobWarnings 3>$null)
     $state='Success';$errorText=@($jobErrors | ForEach-Object ToString)
     if($work.Job.State -eq 'Failed' -and -not $errorText.Count){
      $errorText=@($work.Job.ChildJobs | ForEach-Object {if($_.JobStateInfo.Reason){$_.JobStateInfo.Reason.Message}})
     }
     if($timeout){$state='Timeout'}elseif($work.Job.State -ne 'Completed' -or $jobErrors.Count){$state='Error'}
     if(($errorText -join ' ') -match '(?i)access.*denied|unauthorized'){$state='Access denied'}
     foreach($item in $data){Split-FleetObject $item $work.Computer $main $details}
     $status.Add([pscustomobject]@{Computer=$work.Computer;Status=$state;Objects=[int]$data.Count;Seconds=(Round1 $seconds);Error=($errorText -join '; ');Warnings=(@($jobWarnings | ForEach-Object ToString) -join '; ')})
     Remove-Job -Job $work.Job -Force -ErrorAction SilentlyContinue
     [void]$active.Remove($work)
    }
    if($active.Count){Start-Sleep -Milliseconds 100}
   }
  }finally{foreach($work in $active){Stop-Job -Job $work.Job -ErrorAction SilentlyContinue;Remove-Job -Job $work.Job -Force -ErrorAction SilentlyContinue}}
  Export-FleetRows $main.ToArray() (Join-Path $runFolder ($tool.Name+'.csv'))
  foreach($key in $details.Keys){Export-FleetRows $details[$key].ToArray() (Join-Path $runFolder ($tool.Name+'_'+$key+'.csv'))}
  Export-FleetRows $status.ToArray() (Join-Path $runFolder '_Status.csv')
  [IO.File]::WriteAllText((Join-Path $runFolder '_Run.txt'),("Script: {0}{1}Targets: {2}{1}Collected: {3:o}{1}Running as: {4}{1}" -f $tool.Path,[Environment]::NewLine,($targets -join ', '),[datetime]::Now,[Security.Principal.WindowsIdentity]::GetCurrent().Name),[Text.Encoding]::UTF8)
 }else{Add-Warning 'Preview only: no remote scripts were run and no output files were written.'}
 $mainCsv=$null;$subCsvs=''
 if($go){$candidate=Join-Path $runFolder ($tool.Name+'.csv');if(Test-Path -LiteralPath $candidate){$mainCsv=$candidate};$subCsvs=@(Get-ChildItem -LiteralPath $runFolder -Filter ($tool.Name+'_*.csv') | ForEach-Object FullName) -join '; '}
 $result=[pscustomobject]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;Tool=$tool.Name;Targets=$targets.Count;Reachable=@($targets | Where-Object {$reachable[$_]}).Count;Succeeded=@($status | Where-Object Status -eq 'Success').Count;Failed=@($status | Where-Object Status -ne 'Success').Count;TimedOut=@($status | Where-Object Status -eq 'Timeout').Count;OutputFolder=$(if($go){$runFolder}else{$null});MainCsv=$mainCsv;SubCsvs=$subCsvs;DurationSeconds=(Round1 $watch.Elapsed.TotalSeconds);Status=$status.ToArray();Warnings=($script:Warnings -join '; ')}
 if($Display){$result | Show-Result -Title $script:ToolName}else{$result}
}

