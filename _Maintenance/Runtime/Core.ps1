# Shared Windows PowerShell 5.1 runtime. Only Invoke-ToolkitTool is exported.
function Add-TkResult {
    param([string]$Kind,[string]$Target,[string]$Status,[string]$Detail)
    $script:Rows.Add([pscustomobject][ordered]@{
        ComputerName=$env:COMPUTERNAME; CollectedAt=[datetime]::Now
        Tool=$script:ToolId; Kind=$Kind; Target=$Target; Status=$Status; Detail=$Detail
    })
}
function Test-TkAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-TkAdmin { if (-not (Test-TkAdmin)) { throw 'Run this machine repair from an administrator PowerShell or its CMD launcher.' } }
function Assert-TkUser {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -in 'S-1-5-18','S-1-5-19','S-1-5-20') { throw 'Run in the affected user desktop session, not a service account.' }
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    $desktops=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Where-Object SessionId -eq $session)
    $match=$false
    foreach($p in ($desktops | Sort-Object CreationDate)){
        try{$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop}catch{continue}
        if($owner.ReturnValue -eq 0 -and $owner.Sid -eq $identity.User.Value){$match=$true;break}
    }
    if(-not $match){throw 'No matching Explorer desktop for this account/session. Run as the affected signed-in user.'}
}
function ConvertTo-TkArgument {
    param([AllowEmptyString()][string]$Value)
    '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'
}
function Invoke-TkNative {
    param([string]$File,[string[]]$Arguments=@(),[int]$TimeoutSeconds=60,[switch]$AllowFailure)
    $command=Get-Command $File -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$command.Source; $info.Arguments=($Arguments | ForEach-Object {ConvertTo-TkArgument $_}) -join ' '
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardInput=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process; $process.StartInfo=$info
    try {
        [void]$process.Start(); $process.StandardInput.Close(); $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($TimeoutSeconds*1000)){try{$process.Kill()}catch{}; throw "$File timed out after $TimeoutSeconds seconds. Check its state before retrying."}
        if(-not $out.Wait(5000) -or -not $err.Wait(5000)){throw "$File exited but its output pipe remained open. A child process may still be active; check before retrying."}
        $text=($out.Result+"`r`n"+$err.Result).Trim(); $code=$process.ExitCode
        if($code -ne 0 -and -not $AllowFailure){throw "$File exited $code : $text"}
        [pscustomobject]@{ExitCode=$code;Text=$text}
    } finally {$process.Dispose()}
}
function Test-TkTcp {
    param([string]$HostName,[int]$Port=443,[int]$TimeoutMs=2000)
    $client=New-Object Net.Sockets.TcpClient
    try {$task=$client.ConnectAsync($HostName,$Port); if(-not $task.Wait($TimeoutMs)){return $false}; return $client.Connected} catch {return $false} finally {$client.Dispose()}
}
function Get-TkFullPath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){throw 'A nonempty filesystem path is required.'}
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}
function Assert-TkPath {
    param([string]$Path,[string]$Root,[switch]$AllowRoot)
    $full=[IO.Path]::GetFullPath((Get-TkFullPath $Path)).TrimEnd('\')
    $base=[IO.Path]::GetFullPath((Get-TkFullPath $Root)).TrimEnd('\')
    if(($full -ieq $base -and -not $AllowRoot) -or ($full -ine $base -and -not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase))){throw "Path is outside the allowed folder: $full"}
    # Check every existing ancestor, including above Root. Never follow a junction.
    $walk=$full
    while($walk){
        if(Test-Path -LiteralPath $walk){$item=Get-Item -LiteralPath $walk -Force -ErrorAction Stop; if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Link/junction paths are not allowed: $walk"}}
        $parent=[IO.Path]::GetDirectoryName($walk); if($parent -eq $walk){break}; $walk=$parent
    }
    $full
}
function Write-TkJson {
    param([string]$Path,$Value)
    $json=ConvertTo-Json -InputObject $Value -Depth 12
    [IO.File]::WriteAllText($Path,$json+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false)))
}
function Get-TkOutputFolder {
    $folder=Get-TkFullPath $script:Options.ReportPath
    $null=Assert-TkPath $folder $folder -AllowRoot
    if(-not (Test-Path -LiteralPath $folder)){[void][IO.Directory]::CreateDirectory($folder)}
    $folder
}
function Save-TkEvidence {
    param([string]$Name,$Value)
    $folder=Get-TkOutputFolder
    $path=Join-Path $folder ($script:RunId+'-'+$Name+'.json')
    Write-TkJson $path $Value
    if($script:Options.CasePath){
        # Evidence belongs with the case as well, so an export after -CasePath is complete.
        try {$case=Get-TkCase $script:Options.CasePath;if($case.Folder -ine $folder){Copy-Item -LiteralPath $path -Destination (Join-Path $case.Folder (Split-Path $path -Leaf)) -Force -ErrorAction Stop}}
        catch {Add-TkResult 'Evidence' $Name 'NotCopiedToCase' $_.Exception.Message}
    }
    $path
}
function Approve-TkAction {
    param([string]$Target,[string]$Action)
    # Durable intent record must succeed before any mutation is approved.
    $null=Save-TkEvidence 'intent' ([ordered]@{Tool=$script:ToolId;Target=$Target;Action=$Action;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;At=[datetime]::Now;Preview=[bool]$script:Options.WhatIf})
    $ok=$script:Caller.ShouldProcess($Target,$Action)
    if(-not $ok){Add-TkResult 'Action' $Target 'NotRun' 'Preview or confirmation declined. No repair performed.'}
    $ok
}
function Get-TkChoice {
    param([string]$Name,[string]$Prompt,[string[]]$Allowed)
    $value=[string]$script:Options[$Name]
    if(-not $value -and $script:Options.Interactive){
        if($Allowed){Write-Host ($Allowed -join ' / ')}
        $value=Read-Host $Prompt
    }
    if(-not $value){throw "Specify -$Name. $Prompt"}
    if($Allowed -and $value -notin $Allowed){throw "Invalid $Name. Choose: $($Allowed -join ', ')"}
    $value
}
function Get-TkPendingRestart {
    $reasons=New-Object Collections.Generic.List[string]
    foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){if(Test-Path -LiteralPath $key){$reasons.Add($key)}}
    $sm=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
    if($sm.PendingFileRenameOperations){$reasons.Add('PendingFileRenameOperations')}
    $reasons.ToArray()
}
function Get-TkReadiness {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    Add-TkResult 'Readiness' 'Account' 'Information' ($id.Name+'; SID='+$id.User.Value+'; Admin='+(Test-TkAdmin)+'; Session='+[Diagnostics.Process]::GetCurrentProcess().SessionId)
    try {$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; Add-TkResult 'Readiness' 'Desktop user' 'Information' ([string]$cs.UserName)}catch{Add-TkResult 'Readiness' 'Desktop user' 'Unavailable' $_.Exception.Message}
    try {$pending=@(Get-TkPendingRestart); $status='Clear'; if($pending.Count){$status='RestartPending'}; Add-TkResult 'Readiness' 'Restart' $status ($pending -join '; ')}catch{Add-TkResult 'Readiness' 'Restart' 'Unavailable' $_.Exception.Message}
    try {$drive=Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $env:SystemDrive) -ErrorAction Stop; Add-TkResult 'Readiness' 'System free space GB' 'Information' ([math]::Round($drive.FreeSpace/1GB,2).ToString([cultureinfo]::InvariantCulture))}catch{Add-TkResult 'Readiness' 'System free space GB' 'Unavailable' $_.Exception.Message}
    $active=@(Get-Process dism,sfc,TiWorker,TrustedInstaller,msiexec -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
    Add-TkResult 'Readiness' 'Servicing processes' 'Information' ($active -join ', ')
}
function Get-TkEvents {
    param([string]$Log='Application',[int]$Hours=24,[string[]]$Providers,[int[]]$Ids,[int]$Maximum=40)
    $filter=@{LogName=$Log;StartTime=(Get-Date).AddHours(-$Hours)}
    if($Providers){$filter.ProviderName=$Providers}; if($Ids){$filter.Id=$Ids}
    try {Get-WinEvent -FilterHashtable $filter -MaxEvents $Maximum -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Time=$_.TimeCreated;Id=$_.Id;Provider=$_.ProviderName;Level=$_.LevelDisplayName;Message=$_.Message}}}
    catch {if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
}
function Get-TkOwnedProcesses {
    param([string[]]$Names)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
    foreach($name in $Names){
        foreach($p in @(Get-CimInstance Win32_Process -Filter ("Name='{0}'" -f $name) -ErrorAction Stop | Where-Object SessionId -eq $session)){
            try{$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop}
            catch{
                $fresh=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $p.ProcessId) -ErrorAction Stop
                if(-not $fresh -or $fresh.CreationDate -ne $p.CreationDate){continue}
                throw
            }
            if($owner.ReturnValue -ne 0 -or -not $owner.Sid){throw ('Cannot establish owner of process '+$p.ProcessId+'. No process will be stopped.')}
            if($owner.Sid -eq $sid){$p}
        }
    }
}
function Stop-TkOwnedProcesses {
    param([string[]]$Names)
    foreach($p in @(Get-TkOwnedProcesses $Names)){
        # Re-query ownership immediately before targeting the PID.
        $fresh=Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $p.ProcessId) -ErrorAction Stop
        if($fresh -and $fresh.CreationDate -eq $p.CreationDate){
            try{$owner=Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid -ErrorAction Stop; if($owner.Sid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Process owner changed.'}; Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop}
            catch{if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){throw}}
        }
    }
}
function Move-TkCache {
    param([string]$Path,[string]$Root)
    $path=Assert-TkPath $Path $Root
    if(-not (Test-Path -LiteralPath $path)){return $null}
    $backup=$path+'.ToolkitBackup-'+$script:RunId
    $null=Assert-TkPath $backup $Root
    Move-Item -LiteralPath $path -Destination $backup -ErrorAction Stop
    Add-TkResult 'Backup' $path 'Saved' $backup
    $backup
}
function Add-TkHumanCheck {
    param([string]$Detail)
    Add-TkResult 'Verification' 'Original problem' 'NeedsUserCheck' $Detail
}
