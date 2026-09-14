<#
.SYNOPSIS
    Run DISM and SFC with progress logs and a bounded CBS repair extract.
.EXAMPLE
    .\Repair-WindowsSystemFiles.ps1 -WhatIf -Display
.NOTES
    Toolkit-Class: Remediation
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Windows PowerShell 5.1. Read README.txt before use.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[string]$LogPath='C:\Temp\Toolkit',[string]$Source,[switch]$SkipDism,[switch]$SkipSfc,[switch]$DismScanOnly)
$ErrorActionPreference='Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Repair-WindowsSystemFiles'
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



function New-RepairLog {
    param([string]$Folder,[string]$Fallback,[string]$Prefix,[bool]$Preview)
    $suffix=if($Preview){'_WHATIF.log'}else{'.log'}
    $name='{0}_{1}_{2}_{3}{4}' -f $Prefix,$env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8)),$suffix
    foreach($candidate in @($Folder,$Fallback) | Where-Object {$_} | Select-Object -Unique){
        try {
            $dir=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($candidate)
            $null=[IO.Directory]::CreateDirectory($dir)
            $path=Join-Path $dir $name
            [IO.File]::WriteAllText($path,("Started: {0:o}; WhatIf: {1}{2}" -f (Get-Date),$Preview,[Environment]::NewLine),[Text.Encoding]::UTF8)
            if($candidate -ne $Folder){Add-Warning "Log folder unavailable; using $dir."}
            return $path
        } catch {if($candidate -eq $Fallback){throw}}
    }
    throw "Cannot create a log in $Folder. Supply a writable -LogPath."
}
function Write-RepairLog {
    param([string]$Text)
    [IO.File]::AppendAllText($script:RepairLog,((Get-Date -Format o)+' '+$Text+[Environment]::NewLine),[Text.Encoding]::UTF8)
}
function Assert-LocalRepairPath {
    param([string]$Path,[string]$RequiredParent)
    if([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('::') -or $Path.Substring(2).Contains(':')){
        throw "Refusing a non-local or ambiguous path: $Path"
    }
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root=[IO.Path]::GetPathRoot($full).TrimEnd('\')
    if($full -eq $root){throw "Refusing drive root: $full"}
    foreach($blocked in @($env:windir,(Join-Path $env:windir 'System32'),$env:ProgramFiles,$env:USERPROFILE,(Join-Path $env:SystemDrive 'Users'))){
        if($blocked -and $full -eq $blocked.TrimEnd('\')){throw "Refusing protected root: $full"}
    }
    if($RequiredParent){
        $parent=[IO.Path]::GetFullPath($RequiredParent).TrimEnd('\')
        if(-not $full.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase)){throw "Path escapes its required parent: $full"}
    }
    $probe=$full
    while($probe -and $probe -ne $root){
        if(Test-Path -LiteralPath $probe){
            $item=Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Refusing reparse point: $probe"}
        }
        $probe=[IO.Path]::GetDirectoryName($probe)
    }
    return $full
}

function Get-PendingRepairReboot {
    [bool]((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'))
}
function Read-CbsRepairs {
    param([string]$Path,[datetime]$Since)
    $lines=New-Object System.Collections.Generic.List[string];$fixed=@{};$unfixed=@{}
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $reader=$null;$partial=$false
    try {
        if($stream.Length -gt 50MB){$null=$stream.Seek(-50MB,[IO.SeekOrigin]::End);$partial=$true}
        $reader=New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true)
        if($partial){$null=$reader.ReadLine()}
        while(-not $reader.EndOfStream){
            $line=$reader.ReadLine()
            if($line -notmatch '^(?<Time>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*\[SR\]\s*(?<Detail>.*)$'){continue}
            $time=[datetime]::MinValue
            if(-not [datetime]::TryParseExact($Matches.Time,'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$time) -or $time -lt $Since){continue}
            $detail=$Matches.Detail;$lines.Add($line)
            $target=$null
            if($detail -match '(?i)Cannot repair member file'){$target=$unfixed}
            elseif($detail -match '(?i)Repairing corrupted file|Repaired file|Repairing file'){$target=$fixed}
            if($null -ne $target){
                $pathText=$null
                if($detail -match '(?<Path>[A-Za-z]:\\.*?)(?: from store| with |$)'){$pathText=$Matches.Path.Trim()}
                $target[$detail]=[pscustomobject]@{Path=$pathText;Detail=$detail}
            }
        }
    } finally {if($reader){$reader.Dispose()}else{$stream.Dispose()}}
    [pscustomobject]@{Lines=$lines.ToArray();Repaired=@($fixed.Values);NotRepaired=@($unfixed.Values);Partial=$partial}
}
function Get-SfcVerdict {
    param([string]$Text)
    if($Text -match '(?i)did not find any integrity violations'){return 'No violations'}
    if($Text -match '(?i)successfully repaired them'){return 'Repaired'}
    if($Text -match '(?i)unable to fix some'){return 'Could not repair all'}
    if($Text -match '(?i)could not perform the requested operation'){return 'Could not run'}
    'Unclassified; read the log (output may be localized)'
}
function Invoke-RepairNative {
    param([string]$Exe,[string[]]$Arguments,[switch]$Unicode)
    $savedPreference=$ErrorActionPreference;$savedEncoding=[Console]::OutputEncoding
    $captured=New-Object System.Collections.Generic.List[string]
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $ErrorActionPreference='Continue'
        if($Unicode){[Console]::OutputEncoding=[Text.Encoding]::Unicode}
        & $Exe @Arguments 2>&1 | ForEach-Object {
            $line=("$_" -replace "\x00",'');$captured.Add($line);Write-Host $line;Write-RepairLog $line
        }
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$savedPreference;[Console]::OutputEncoding=$savedEncoding}
    [pscustomobject]@{ExitCode=$code;Text=($captured -join [Environment]::NewLine);Minutes=(Round1 $watch.Elapsed.TotalMinutes)}
}
if(-not (Test-IsAdmin)){throw 'Administrator rights are required. Run the CMD launcher as administrator.'}
if($SkipDism -and $SkipSfc){throw 'Both checks are skipped. Select at least one.'}
if(@(Get-Process -Name dism,sfc,TiWorker -ErrorAction SilentlyContinue).Count){throw 'DISM, SFC or Windows servicing is already running. Wait for it to finish.'}
if($Source -and ($Source.Contains('"') -or $Source -match '[\r\n]')){throw 'Invalid source argument.'}
$start=Get-Date;$preview=[bool]$WhatIfPreference
$script:RepairLog=New-RepairLog $LogPath '' 'WindowsSystemFiles' $preview
$mode=if($DismScanOnly){'ScanHealth'}else{'RestoreHealth'}
$plan="DISM $mode (skip=$SkipDism), SFC /scannow (skip=$SkipSfc). Allow 10-40 minutes. Log: $script:RepairLog"
Write-RepairLog $plan
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=$start;WhatIf=$preview;Performed=$false;DismRan=$false;DismExitCode=$null;DismResult='Not run';DismCorruptionFound=$null;DismRepaired=$null;DismSourceUsed=$Source;DismMinutes=$null;SfcRan=$false;SfcExitCode=$null;SfcResult='Not run';SfcMinutes=$null;FilesRepairedCount=0;FilesNotRepairedCount=0;RebootPending=(Get-PendingRepairReboot);RebootRecommended=$false;TotalMinutes=0.0;LogPath=$script:RepairLog;CbsExtractPath=$null;NextStep='Preview or declined; no repair performed';FilesRepaired=@();FilesNotRepaired=@();Warnings=''}
if($o.RebootPending){Add-Warning 'Windows already reports a pending reboot.'}
try{$go=$PSCmdlet.ShouldProcess($env:COMPUTERNAME,$plan)}catch{throw 'Refusing: this host cannot show the confirmation prompt. Run interactively or pass -WhatIf.'}
if($go){
    $o.Performed=$true
    if(-not $SkipDism){
        $argsDism=@('/Online','/Cleanup-Image',('/'+$mode))
        if($Source){$argsDism+=('/Source:'+$Source);$argsDism+='/LimitAccess'}
        $r=Invoke-RepairNative (Join-Path $env:windir 'System32\dism.exe') $argsDism
        $o.DismRan=$true;$o.DismExitCode=$r.ExitCode;$o.DismMinutes=$r.Minutes
        if($r.ExitCode -in 0,3010){$o.DismResult='Completed; read the log for corruption details'}else{$o.DismResult='Failed; inspect exit code and log'}
        if($r.Text -match '(?i)No component store corruption detected'){$o.DismCorruptionFound=$false;$o.DismRepaired=$false}
        elseif($r.Text -match '(?i)component store is repairable'){$o.DismCorruptionFound=$true}
        if(-not $DismScanOnly -and $r.ExitCode -in 0,3010 -and $r.Text -match '(?i)restore operation completed successfully'){$o.DismResult='Restore operation completed successfully'}
        # A successful restore alone does not prove that corruption was found or repaired.
        if($r.Text -match '(?i)source files could not be found|0x800f081f'){$o.DismResult='Source files unavailable'}
    }
    if(-not $SkipSfc){
        $r=Invoke-RepairNative (Join-Path $env:windir 'System32\sfc.exe') @('/scannow') -Unicode
        $o.SfcRan=$true;$o.SfcExitCode=$r.ExitCode;$o.SfcMinutes=$r.Minutes;$o.SfcResult=Get-SfcVerdict $r.Text
        $cbs=Invoke-Section 'CBS extract' {Read-CbsRepairs (Join-Path $env:windir 'Logs\CBS\CBS.log') $start.AddSeconds(-1)}
        if($cbs){
            $o.FilesRepaired=$cbs.Repaired;$o.FilesNotRepaired=$cbs.NotRepaired
            $o.FilesRepairedCount=$cbs.Repaired.Count;$o.FilesNotRepairedCount=$cbs.NotRepaired.Count
            $o.CbsExtractPath=[IO.Path]::ChangeExtension($script:RepairLog,'CBS-SR.txt')
            [IO.File]::WriteAllLines($o.CbsExtractPath,[string[]]$cbs.Lines,[Text.Encoding]::UTF8)
            if($cbs.Partial){Add-Warning 'CBS extract is limited to the last 50 MB; earlier entries may be missing.'}
            Add-Warning 'CBS rows are repair messages from this time window, not proof of final file integrity. Later rows may supersede earlier failures.'
        }
    }
    $o.RebootPending=Get-PendingRepairReboot
    $o.RebootRecommended=($o.RebootPending -or $o.DismExitCode -eq 3010 -or $o.SfcResult -in 'Repaired','Could not run')
    $o.NextStep='Review the logs and confirm the original problem is resolved'
    if($o.DismResult -eq 'Source files unavailable'){$o.NextStep='Mount matching Windows media and retry with -Source'}
    elseif($o.SfcResult -eq 'Could not run'){$o.NextStep='Reboot and retry; if it persists, investigate offline SFC from recovery'}
    elseif($o.SfcResult -eq 'Could not repair all'){$o.NextStep='Review CBS failures and DISM status before another repair attempt'}
    elseif($o.RebootRecommended){$o.NextStep='Reboot when convenient, then run again to confirm the result'}
    elseif($o.DismExitCode -notin $null,0,3010 -or $o.SfcExitCode -notin $null,0){$o.NextStep='Investigate the failed command in the log'}
}
$o.TotalMinutes=Round1 ((Get-Date)-$start).TotalMinutes
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o
Write-RepairLog ($result | ConvertTo-Json -Depth 5)
if($Display){$result | Show-Result -Title $script:ToolName}else{$result}
