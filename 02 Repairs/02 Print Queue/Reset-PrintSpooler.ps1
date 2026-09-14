<#
.SYNOPSIS
    Clear inventoried SPL/SHD print jobs and restart the Print Spooler.
.EXAMPLE
    .\Reset-PrintSpooler.ps1 -WhatIf -Display
.NOTES
    Toolkit-Class: Remediation
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Windows PowerShell 5.1. Read README.txt before use.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[string]$LogPath='C:\Temp\Toolkit')
$ErrorActionPreference='Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Reset-PrintSpooler'
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

function Get-SafeSpoolFolder {
    param([string]$ConfiguredPath)
    if(-not $ConfiguredPath){$ConfiguredPath=Join-Path $env:windir 'System32\spool\PRINTERS'}
    $expanded=[Environment]::ExpandEnvironmentVariables($ConfiguredPath)
    if($expanded.Contains('%')){throw 'Spool path contains an unresolved environment variable.'}
    $full=Assert-LocalRepairPath $expanded
    # Also forbid broad custom directories: a dedicated folder is required.
    if((Split-Path $full -Leaf) -in 'Windows','System32','spool','Users','Temp','Desktop','Documents','Downloads','AppData','Local','Microsoft','Program Files','ProgramData'){throw "Refusing a broad spool directory: $full"}
    if(-not (Test-Path -LiteralPath $full -PathType Container)){throw "Spool directory is unavailable: $full"}
    $full
}
function Get-SpoolJobs {
    param([string]$Folder)
    @(Get-ChildItem -LiteralPath $Folder -File -Force -ErrorAction Stop | Where-Object {
        $_.Extension -in '.SPL','.SHD' -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
    })
}
if(-not (Test-IsAdmin)){throw 'Administrator rights are required. Run the CMD launcher as administrator.'}
$service=Get-Service Spooler -ErrorAction Stop
if(@($service.DependentServices | Where-Object Status -eq 'Running').Count){throw 'Another running service depends on Spooler. Review dependent services before resetting it.'}
$config=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -ErrorAction Stop
$folder=Get-SafeSpoolFolder $config.DefaultSpoolDirectory
$files=@(Get-SpoolJobs $folder)
$oldestFile=$null;if($files.Count){$oldestFile=($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime}
$before=$service.Status.ToString();$preview=[bool]$WhatIfPreference
$script:RepairLog=New-RepairLog $LogPath '' 'PrintSpoolerReset' $preview
$mb=Round1 (($files | Measure-Object Length -Sum).Sum/1MB)
$plan="Stop Spooler, remove $($files.Count) SPL/SHD files ($mb MB) from $folder, and start Spooler."
Write-RepairLog $plan
foreach($f in $files){Write-RepairLog ('Planned file: '+$f.FullName)}
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;WhatIf=$preview;Performed=$false;SpoolFolder=$folder;FilesBefore=$files.Count;MBBefore=$mb;OldestFileBefore=$oldestFile;FilesDeleted=0;FilesFailed='';SpoolerStatusBefore=$before;SpoolerStatusAfter=$before;StopSeconds=$null;StartSeconds=$null;PrinterCount=$null;DefaultPrinter=$null;LogPath=$script:RepairLog;NextStep='Preview or declined; no jobs removed';Printers=@();Drivers=@();Ports=@();Warnings=''}
try{$go=$PSCmdlet.ShouldProcess($env:COMPUTERNAME,$plan)}catch{throw 'Refusing: this host cannot show the confirmation prompt. Run interactively or pass -WhatIf.'}
$failed=New-Object System.Collections.Generic.List[string]
if($go){
    $o.Performed=$true
    try {
        $watch=[Diagnostics.Stopwatch]::StartNew()
        if($service.Status -ne 'Stopped'){Stop-Service Spooler -Confirm:$false -ErrorAction Stop}
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[timespan]::FromSeconds(30))
        $o.StopSeconds=Round1 $watch.Elapsed.TotalSeconds
        $null=Get-SafeSpoolFolder $folder
        foreach($f in $files){
            try {
                $safe=Assert-LocalRepairPath $f.FullName $folder
                if([IO.Path]::GetDirectoryName($safe) -ne $folder -or [IO.Path]::GetExtension($safe) -notin '.SPL','.SHD'){throw 'File no longer matches the approved inventory'}
                if(Test-Path -LiteralPath $safe -PathType Leaf){Remove-Item -LiteralPath $safe -Force -Confirm:$false -ErrorAction Stop;$o.FilesDeleted++;Write-RepairLog ('Deleted: '+$safe)}
            } catch {$failed.Add($f.Name+': '+$_.Exception.Message);Write-RepairLog ('Failed: '+$f.FullName+' '+$_.Exception.Message)}
        }
    } catch {Add-Warning ('Spooler reset: '+$_.Exception.Message);Write-RepairLog $_.Exception.Message}
    finally {
        try {
            $watch=[Diagnostics.Stopwatch]::StartNew()
            Start-Service Spooler -Confirm:$false -ErrorAction Stop
            $service=Get-Service Spooler;$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[timespan]::FromSeconds(30))
            $o.StartSeconds=Round1 $watch.Elapsed.TotalSeconds
        } catch {Add-Warning ('Could not start Spooler: '+$_.Exception.Message)}
        $o.SpoolerStatusAfter=(Get-Service Spooler -ErrorAction SilentlyContinue).Status.ToString()
    }
    $o.NextStep='Print a test page. Remaining or new jobs may still need attention'
    if($o.SpoolerStatusAfter -ne 'Running'){$o.NextStep='Spooler did not start. Read the log and investigate the service or printer driver'}
}
$o.FilesFailed=$failed -join '; '
$console=& { $WhatIfPreference=$false; Get-ConsoleUser }
$o.Ports=@(Invoke-Section 'Printer ports' {Get-PrinterPort -ErrorAction Stop | Select-Object Name,PrinterHostAddress,PortNumber} -Default @())
$o.Drivers=@(Invoke-Section 'Printer drivers' {Get-PrinterDriver -ErrorAction Stop | Select-Object Name,Manufacturer,DriverVersion,MajorVersion} -Default @())
$o.Printers=@(Invoke-Section 'Printers' {
    Get-Printer -ErrorAction Stop | ForEach-Object {
        $portName=$_.PortName;$port=$o.Ports | Where-Object Name -eq $portName | Select-Object -First 1
        [pscustomobject]@{Name=$_.Name;DriverName=$_.DriverName;PortName=$portName;PortAddress=$port.PrinterHostAddress;Type=[string]$_.Type;Shared=[bool]$_.Shared;Status=[string]$_.PrinterStatus;Source='Not determined';IsDefault=$null}
    }
} -Default @())
$o.PrinterCount=$o.Printers.Count
if($console.IsMe){
    $default=Invoke-Section 'Default printer' {Get-CimInstance Win32_Printer -Filter 'Default=True' -ErrorAction Stop | Select-Object -First 1}
    if($default){$o.DefaultPrinter=$default.Name;foreach($p in $o.Printers){$p.IsDefault=($p.Name -eq $default.Name)}}
}else{Add-Warning 'Default printer for another user is unavailable; no fallback to the technician default.'}
Add-Warning 'Only inventoried SPL/SHD files are removed. Printer deployment source is not inferred; use Get-PrinterInventory for policy details.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o;Write-RepairLog ($result | ConvertTo-Json -Depth 5)
if($Display){$result | Show-Result -Title $script:ToolName}else{$result}
