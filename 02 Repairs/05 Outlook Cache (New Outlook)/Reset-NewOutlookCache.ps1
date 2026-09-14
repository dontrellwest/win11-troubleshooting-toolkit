<#
.SYNOPSIS
    Move new Outlook's local data folders aside for one verified user and reopen the app.
.EXAMPLE
    .\Reset-NewOutlookCache.ps1 -WhatIf -Display
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
$script:ToolName  = 'Reset-NewOutlookCache'
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
        $owner=$null;try{$owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop}catch{return $false} # a process that exited mid-enumeration is not a target
        $owner -and $owner.ReturnValue -eq 0 -and ('{0}\{1}' -f $owner.Domain,$owner.User) -eq $User.Name
    })
}
function Start-NewOutlook {
    param($User)
    # Store apps start through the shell by application ID, not by an executable path.
    $launch='shell:AppsFolder\'+$script:AppId
    $task=$null
    try {
        if($User.IsMe){
            Start-Process -FilePath 'explorer.exe' -ArgumentList $launch -ErrorAction Stop | Out-Null
            $method='Start-Process'
        } else {
            $task='Toolkit-'+$script:ToolName+'-'+[guid]::NewGuid().ToString('N')
            $action=New-ScheduledTaskAction -Execute 'explorer.exe' -Argument $launch
            $principal=New-ScheduledTaskPrincipal -UserId $User.Name -LogonType Interactive -RunLevel Limited
            $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
            Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
            Start-ScheduledTask -TaskName $task -ErrorAction Stop
            $method='Scheduled task as user'
        }
        $until=(Get-Date).AddSeconds(20)
        do {
            if(@(Get-TargetProcesses 'olk.exe' $User).Count){return $method}
            Start-Sleep -Milliseconds 500
        } while((Get-Date) -lt $until)
        throw 'No new Outlook process appeared in the selected session.'
    } finally {
        if($task){Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}
    }
}
$script:PackageFamily='Microsoft.OutlookForWindows_8wekyb3d8bbwe'
$script:AppId=$script:PackageFamily+'!Microsoft.OutlookforWindows'
$script:DataFolderNames=@('LocalCache','LocalState','RoamingState','TempState','Settings')
$user=Resolve-RepairTarget (& { $WhatIfPreference=$false; Get-ConsoleUser -OverrideName $TargetUser })
$local=Assert-LocalRepairPath (Join-Path $user.ProfilePath 'AppData\Local') $user.ProfilePath
$root=Assert-LocalRepairPath (Join-Path $local ('Packages\'+$script:PackageFamily)) $local
$olk=Assert-LocalRepairPath (Join-Path $local 'Microsoft\Olk') $local   # offline store, attachments, settings; classic Outlook's Microsoft\Outlook is never touched
$folders=@(if(Test-Path -LiteralPath $root -PathType Container){foreach($n in $script:DataFolderNames){$p=Join-Path $root $n;if(Test-Path -LiteralPath $p -PathType Container){Get-Item -LiteralPath $p -Force -ErrorAction Stop}}};if(Test-Path -LiteralPath $olk -PathType Container){Get-Item -LiteralPath $olk -Force -ErrorAction Stop})
if(-not $folders.Count){throw "Nothing to do: new Outlook has no data folders for this user under $olk or $root."}
foreach($f in $folders){if($f.FullName -ieq $olk){$null=Assert-LocalRepairPath $f.FullName $local}else{$null=Assert-LocalRepairPath $f.FullName $root}}
[double]$bytes=0;foreach($f in $folders){$bytes+=(@(Get-ChildItem -LiteralPath $f.FullName -Recurse -File -Force -ErrorAction SilentlyContinue) | Measure-Object Length -Sum).Sum}
$mb=Round1 ($bytes/1MB)
$old=@(@(if(Test-Path -LiteralPath $root -PathType Container){Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop})+@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($olk)) -Directory -Force -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'Olk.old-*'}) | Where-Object {$_.Name -like '*.old-*'})
[double]$oldBytes=0;foreach($d in $old){$oldBytes+=(@(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Force -ErrorAction SilentlyContinue) | Measure-Object Length -Sum).Sum}
$procs=@(Get-TargetProcesses 'olk.exe' $user)
$freshNote='';$newest=$null
foreach($f in $folders){$n=@(Get-ChildItem -LiteralPath $f.FullName -Recurse -File -Force -ErrorAction SilentlyContinue) | Sort-Object LastWriteTime -Descending | Select-Object -First 1;if($n -and (-not $newest -or $n.LastWriteTime -gt $newest.LastWriteTime)){$newest=$n}}
if($newest){$ageMin=[int]((Get-Date)-$newest.LastWriteTime).TotalMinutes;if($ageMin -le 10){$freshNote=" WARNING: local data was written $ageMin minute(s) ago, so the app appears active. Rule out a filter, sort or Focused/Other setting (Get-NewOutlookSyncState) first.";Add-Warning ("Local data written {0} minute(s) ago; the app appears active. Rule out a display setting before resetting." -f $ageMin)}}
$preview=[bool]$WhatIfPreference;$stamp=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$script:RepairLog=New-RepairLog $LogPath (Join-Path $local 'Temp') 'NewOutlookCacheReset' $preview
$plan="Close new Outlook in session $($user.SessionId), move $($folders.Count) data folders ($mb MB: Microsoft\Olk and the Store package data) to <name>.old-$stamp, then open new Outlook. It signs in again through Windows; unsent drafts and offline-only items may be lost."+$freshNote
Write-RepairLog $plan
foreach($f in $folders){Write-RepairLog ('Planned move: '+$f.FullName+' -> '+$f.Name+'.old-'+$stamp)}
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;WhatIf=$preview;Performed=$false;TargetUser=$user.Name;TargetSessionId=[int]$user.SessionId;RunningAs=$user.RunningAs;DataRoot=$root;OlkFolder=$olk;FoldersFound=$folders.Count;DataMB=$mb;NewOutlookWasRunning=[bool]$procs.Count;NewOutlookClosedGracefully=$null;FoldersMoved=0;MovedFolders='';MoveFailed='';NewOutlookStarted=$false;StartMethod='Not attempted';OldBackupsMB=(Round1 ($oldBytes/1MB));LogPath=$script:RepairLog;NextStep='Preview or declined; no folders moved';Warnings=''}
try{$go=$PSCmdlet.ShouldProcess(("$($user.Name), session $($user.SessionId), $root"),$plan)}catch{throw 'Refusing: this host cannot show the confirmation prompt. Run interactively or pass -WhatIf.'}
$moved=New-Object System.Collections.Generic.List[string];$failed=New-Object System.Collections.Generic.List[string]
if($go){
    $o.Performed=$true
    try{
        foreach($p in @(Get-TargetProcesses 'olk.exe' $user)){
            try{$proc=Get-Process -Id $p.ProcessId -ErrorAction Stop;$null=$proc.CloseMainWindow()}catch{Add-Warning ('Graceful close: '+$_.Exception.Message)}
        }
        $until=(Get-Date).AddSeconds(20)
        while(@(Get-TargetProcesses 'olk.exe' $user).Count -and (Get-Date) -lt $until){Start-Sleep -Milliseconds 500}
        $remaining=@(Get-TargetProcesses 'olk.exe' $user)
        $o.NewOutlookClosedGracefully=($remaining.Count -eq 0)
        foreach($p in $remaining){Stop-Process -Id $p.ProcessId -Force -Confirm:$false -ErrorAction Stop}
        if(@(Get-TargetProcesses 'olk.exe' $user).Count){throw 'New Outlook is still running. No folders will be moved.'}
        Start-Sleep -Seconds 2
        foreach($f in $folders){
            try{
                $isOlk=($f.FullName -ieq $olk);$safe=Assert-LocalRepairPath $f.FullName $(if($isOlk){$local}else{$root})
                if(-not $isOlk -and ([IO.Path]::GetDirectoryName($safe) -ine $root -or $script:DataFolderNames -notcontains [IO.Path]::GetFileName($safe))){throw 'Folder no longer matches the inventory'}
                $newName=$f.Name+'.old-'+$stamp
                if(Test-Path -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($safe)) $newName)){throw 'Backup name already exists'}
                Rename-Item -LiteralPath $safe -NewName $newName -Confirm:$false -ErrorAction Stop
                $o.FoldersMoved++;$moved.Add($newName);Write-RepairLog ('Moved: '+$safe+' -> '+$newName)
            }catch{$failed.Add($f.Name+': '+$_.Exception.Message)}
        }
    }catch{$failed.Add('Reset aborted: '+$_.Exception.Message);Add-Warning ('Cache reset: '+$_.Exception.Message)}
    finally{
        try{
            if(@(Get-TargetProcesses 'olk.exe' $user).Count){$o.StartMethod='Already running';$o.NewOutlookStarted=$true}
            else{$o.StartMethod=Start-NewOutlook $user;$o.NewOutlookStarted=$true}
        }catch{Add-Warning ('New Outlook restart: '+$_.Exception.Message);$o.StartMethod='Open new Outlook manually'}
    }
    $o.NextStep='Sign in if asked, let the app finish loading, and verify mail before removing old backups'
    if($failed.Count -or $o.FoldersMoved -ne $folders.Count){$o.NextStep='Some folders were not moved. Read the log; close new Outlook or reboot before retrying'}
    elseif(-not $o.NewOutlookStarted){$o.NextStep='Open new Outlook in the affected session and sign in if asked'}
}
$o.MovedFolders=$moved -join '; ';$o.MoveFailed=$failed -join '; '
Add-Warning 'Backups are kept as <name>.old-<stamp> beside the originals and can be removed once the app works. Offline-only items are not recoverable from them without support tools.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o;Write-RepairLog ($result | ConvertTo-Json -Depth 4)
if($Display){$result | Show-Result -Title $script:ToolName}else{$result}
