<#
.SYNOPSIS
    Rename classic Outlook OST caches for one verified user and restart Outlook.
.EXAMPLE
    .\Rebuild-OutlookOST.ps1 -WhatIf -Display
.NOTES
    Toolkit-Class: Remediation
    Toolkit-Context: User
    Toolkit-Elevation: None
    Windows PowerShell 5.1. Read README.txt before use.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[string]$LogPath='C:\Temp\Toolkit',[string]$TargetUser)
$ErrorActionPreference='Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Rebuild-OutlookOST'
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

function Resolve-RepairTarget {
    param($User)
    $WhatIfPreference=$false # Only read-only target lookup occurs in this function.
    if(-not $User -or $User.IsSystem){throw 'Run this tool in the signed-in user session, not as SYSTEM.'}
    if($User.Source -eq 'Process' -or -not $User.Name -or -not $User.Sid){throw 'No verified interactive user. Sign in and run the launcher there.'}
    if(-not $User.ProfilePath -or -not (Test-Path -LiteralPath $User.ProfilePath -PathType Container)){throw 'The target user profile is unavailable.'}
    # A profile itself may equal USERPROFILE; only descendants are deletion targets.
    $profile=[IO.Path]::GetFullPath($User.ProfilePath).TrimEnd('\')
    $null=Assert-LocalRepairPath (Join-Path $profile 'AppData\Local') $profile
    $currentSession=[Diagnostics.Process]::GetCurrentProcess().SessionId
    if($User.IsMe -and $null -eq $User.SessionId -and $currentSession -gt 0){$User.SessionId=$currentSession}
    if($null -eq $User.SessionId -or $User.SessionId -le 0){throw 'No verified desktop session. Run the launcher in the affected session.'}
    if($User.IsMe -and $User.SessionId -ne $currentSession){throw 'The selected desktop is another session. Run the launcher in that session.'}
    if(-not $User.IsMe){
        if(-not (Test-IsAdmin)){throw 'Another user is selected. Run as administrator or run in that user session.'}
        $sessions=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | ForEach-Object {
            $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
            if(('{0}\{1}' -f $owner.Domain,$owner.User) -eq $User.Name){[int]$_.SessionId}
        } | Select-Object -Unique)
        if($sessions.Count -ne 1 -or $sessions[0] -ne $User.SessionId){throw 'Cannot safely select one desktop for this user. Run in the affected session.'}
    }
    $User
}
function Get-TargetProcesses {
    param([string]$Name,$User)
    $WhatIfPreference=$false # GetOwner reads process ownership; it does not change a process.
    @(Get-CimInstance Win32_Process -Filter ("Name='{0}' AND SessionId={1}" -f $Name,[int]$User.SessionId) -ErrorAction Stop | Where-Object {
        $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
        $owner.ReturnValue -eq 0 -and ('{0}\{1}' -f $owner.Domain,$owner.User) -eq $User.Name
    })
}
function Start-TargetApplication {
    param([string]$Exe,[string]$ProcessName,$User)
    if(-not $Exe -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)){throw "Application executable is unavailable: $Exe"}
    $task=$null
    try {
        if($User.IsMe){
            Start-Process -FilePath $Exe -ErrorAction Stop | Out-Null
            $method='Start-Process'
        } else {
            $task='Toolkit-'+$script:ToolName+'-'+[guid]::NewGuid().ToString('N')
            $action=New-ScheduledTaskAction -Execute $Exe
            $principal=New-ScheduledTaskPrincipal -UserId $User.Name -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
            Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $task -ErrorAction Stop
            $method='Scheduled task as user'
        }
        $until=(Get-Date).AddSeconds(15)
        do {
            if(@(Get-TargetProcesses $ProcessName $User).Count){return $method}
            Start-Sleep -Milliseconds 500
        } while((Get-Date) -lt $until)
        throw 'No application process appeared in the selected session.'
    } finally {
        if($task){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}
    }
}

function Expand-TargetProfilePath {
    param([string]$Value,[string]$Profile)
    $map=@{USERPROFILE=$Profile;LOCALAPPDATA=(Join-Path $Profile 'AppData\Local');APPDATA=(Join-Path $Profile 'AppData\Roaming')}
    $expanded=[regex]::Replace($Value,'%([^%]+)%',{param($m) $key=$m.Groups[1].Value;if($map.ContainsKey($key)){$map[$key]}else{$m.Value}})
    if($expanded.Contains('%')){throw 'OST policy contains unsupported variables. Review the target user policy.'}
    $expanded
}
function Get-OutlookExecutable {
    foreach($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE'){
        if(Test-Path -LiteralPath $key){
            $reg=Get-Item -LiteralPath $key -ErrorAction Stop
            $value=[string]$reg.GetValue('');$value=$value.Trim('"')
            if($value -and (Test-Path -LiteralPath $value -PathType Leaf) -and [IO.Path]::GetFileName($value) -ieq 'OUTLOOK.EXE'){return $value}
        }
    }
    throw 'Classic Outlook executable was not found in App Paths. Open Outlook manually afterward.'
}
$user=Resolve-RepairTarget (& { $WhatIfPreference=$false; Get-ConsoleUser -OverrideName $TargetUser })
$local=Assert-LocalRepairPath (Join-Path $user.ProfilePath 'AppData\Local') $user.ProfilePath
$folder=Join-Path $local 'Microsoft\Outlook'
if(-not $user.Hive){throw 'Target registry hive is unavailable; cannot check ForceOSTPath safely.'}
foreach($key in @(($user.Hive+'\Software\Policies\Microsoft\Office\16.0\Outlook'),($user.Hive+'\Software\Microsoft\Office\16.0\Outlook'))){
    if(Test-Path -LiteralPath $key){
        $config=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        if($config.ForceOSTPath){$folder=Expand-TargetProfilePath ([string]$config.ForceOSTPath) $user.ProfilePath;break}
    }
}
$folder=Assert-LocalRepairPath $folder
if(-not (Test-Path -LiteralPath $folder -PathType Container)){throw "Nothing to do: OST folder does not exist: $folder"}
$files=@(Get-ChildItem -LiteralPath $folder -File -Force -Filter '*.ost' -ErrorAction Stop | Where-Object {$_.Extension -ieq '.ost'})
if(-not $files.Count){throw "Nothing to do: no OST files in $folder. New Outlook and PST files are not supported."}
foreach($file in $files){$null=Assert-LocalRepairPath $file.FullName $folder;if($file.Length -gt 20GB){Add-Warning ($file.Name+' exceeds 20 GB; resynchronization may take a long time.')}}
$ostFreshNote='';$newestOst=$files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if($newestOst){$ostAgeMin=[int]((Get-Date)-$newestOst.LastWriteTime).TotalMinutes;if($ostAgeMin -le 10){$ostFreshNote=" WARNING: $($newestOst.Name) was written $ostAgeMin minute(s) ago, so sync appears active. Rule out a display problem (View > Reset View, Get-OutlookSyncState) first.";Add-Warning ("OST written {0} minute(s) ago; sync appears active. Rule out a display problem before rebuilding." -f $ostAgeMin)}}
$old=@(Get-ChildItem -LiteralPath $folder -File -Force -Filter '*.ost.old-*' -ErrorAction Stop)
$procs=@(Get-TargetProcesses 'OUTLOOK.EXE' $user);$exe=Invoke-Section 'Outlook executable' {Get-OutlookExecutable}
$mb=Round1 (($files | Measure-Object Length -Sum).Sum/1MB)
$preview=[bool]$WhatIfPreference;$stamp=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$script:RepairLog=New-RepairLog $LogPath (Join-Path $local 'Temp') 'OutlookOSTRebuild' $preview
$plan="Close classic Outlook in session $($user.SessionId), rename $($files.Count) OST files ($mb MB) in $folder to .ost.old-$stamp, then open Outlook. Confirm mail is synced to the server first."+$ostFreshNote
Write-RepairLog $plan
foreach($file in $files){Write-RepairLog ('Planned rename: '+$file.FullName+' -> '+$file.Name+'.old-'+$stamp)}
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;WhatIf=$preview;Performed=$false;TargetUser=$user.Name;TargetSessionId=[int]$user.SessionId;RunningAs=$user.RunningAs;OstFolder=$folder;OstFilesFound=$files.Count;OstMB=$mb;OutlookWasRunning=[bool]$procs.Count;OutlookClosedGracefully=$null;OstRenamed=0;RenamedFiles='';RenameFailed='';OutlookStarted=$false;StartMethod='Not attempted';OldFilesLeftBehindMB=(Round1 (($old | Measure-Object Length -Sum).Sum/1MB));LogPath=$script:RepairLog;NextStep='Preview or declined; no OST files renamed';Warnings=''}
try{$go=$PSCmdlet.ShouldProcess(("$($user.Name), session $($user.SessionId), $folder"),$plan)}catch{throw 'Refusing: this host cannot show the confirmation prompt. Run interactively or pass -WhatIf.'}
$renamed=New-Object System.Collections.Generic.List[string];$failed=New-Object System.Collections.Generic.List[string]
if($go){
    $o.Performed=$true
    try{
        foreach($p in @(Get-TargetProcesses 'OUTLOOK.EXE' $user)){
            try{$proc=Get-Process -Id $p.ProcessId -ErrorAction Stop;$null=$proc.CloseMainWindow()}catch{Add-Warning ('Graceful Outlook close: '+$_.Exception.Message)}
        }
        $until=(Get-Date).AddSeconds(20)
        while(@(Get-TargetProcesses 'OUTLOOK.EXE' $user).Count -and (Get-Date) -lt $until){Start-Sleep -Milliseconds 500}
        $remaining=@(Get-TargetProcesses 'OUTLOOK.EXE' $user)
        $o.OutlookClosedGracefully=($remaining.Count -eq 0)
        foreach($p in $remaining){Stop-Process -Id $p.ProcessId -Force -Confirm:$false -ErrorAction Stop}
        if(@(Get-TargetProcesses 'OUTLOOK.EXE' $user).Count){throw 'Outlook is still running. No files will be renamed.'}
        foreach($f in $files){
            try{
                $safe=Assert-LocalRepairPath $f.FullName $folder
                if([IO.Path]::GetExtension($safe) -ine '.ost' -or [IO.Path]::GetDirectoryName($safe) -ine $folder){throw 'File no longer matches the OST inventory'}
                $newName=$f.Name+'.old-'+$stamp
                if(Test-Path -LiteralPath (Join-Path $folder $newName)){throw 'Backup name already exists'}
                Rename-Item -LiteralPath $safe -NewName $newName -Confirm:$false -ErrorAction Stop
                $o.OstRenamed++;$renamed.Add($newName);Write-RepairLog ('Renamed: '+$safe+' -> '+$newName)
            }catch{$failed.Add($f.Name+': '+$_.Exception.Message)}
        }
    }catch{Add-Warning ('OST rebuild: '+$_.Exception.Message)}
    finally{
        try{
            if(@(Get-TargetProcesses 'OUTLOOK.EXE' $user).Count){$o.StartMethod='Already running';$o.OutlookStarted=$true}
            elseif($exe){$o.StartMethod=Start-TargetApplication $exe 'OUTLOOK.EXE' $user;$o.OutlookStarted=$true}
            else{$o.StartMethod='Open Outlook manually'}
        }catch{Add-Warning ('Outlook restart: '+$_.Exception.Message);$o.StartMethod='Open Outlook manually'}
    }
    $o.NextStep='Allow Outlook to resync and verify mail before considering old cache cleanup'
    if($failed.Count -or $o.OstRenamed -ne $files.Count){$o.NextStep='Some OST files were not renamed. Read the log; close Outlook or reboot before retrying'}
    elseif(-not $o.OutlookStarted){$o.NextStep='Open classic Outlook in the affected session and allow it to resync'}
}
$o.RenamedFiles=$renamed -join '; ';$o.RenameFailed=$failed -join '; '
Add-Warning 'OST backups are retained but may not be directly importable. Unsynced local items can be difficult to recover; verify server sync before rebuilding.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o;Write-RepairLog ($result | ConvertTo-Json -Depth 4)
if($Display){$result | Show-Result -Title $script:ToolName}else{$result}
