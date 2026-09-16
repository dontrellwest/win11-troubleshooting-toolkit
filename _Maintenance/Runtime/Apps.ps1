function Get-TkApps {
    try {
        foreach($p in @(Get-AppxPackage -ErrorAction Stop | Where-Object {-not $_.IsFramework -and -not $_.IsResourcePackage})){
            [pscustomobject]@{Name=$p.Name;Version=[string]$p.Version;Publisher=$p.Publisher;Kind='Packaged';Id=$p.PackageFullName;Family=$p.PackageFamilyName;Location=$p.InstallLocation;Status=[string]$p.Status;Msi=$false;RegistryPath=$null}
        }
    }catch{Add-TkResult 'Inventory' 'Packaged apps for current account' 'Unavailable' $_.Exception.Message}
    foreach($root in @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){
        if(-not (Test-Path -LiteralPath $root)){continue}
        foreach($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)){
            $p=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if($p.DisplayName -and -not $p.SystemComponent){[pscustomobject]@{Name=$p.DisplayName;Version=$p.DisplayVersion;Publisher=$p.Publisher;Kind='Desktop';Id=$key.PSChildName;Family='';Location=$p.InstallLocation;Status='Registered';Msi=($p.WindowsInstaller -eq 1);RegistryPath=$key.PSPath}}
        }
    }
}
function Set-TkSelectedApp {
    param($App)
    $script:Options.Target=$App.Id
    if($App.Kind -eq 'Packaged'){$script:Options.Target=$App.Family}
    $App
}
function Select-TkApp {
    $target=[string]$script:Options.Target
    $apps=@(Get-TkApps)
    if($target){$apps=@($apps | Where-Object {$_.Name -ieq $target -or $_.Id -ieq $target -or $_.Family -ieq $target})}
    if($apps.Count -eq 1){return (Set-TkSelectedApp $apps[0])}
    if($script:Options.Interactive){
        if(-not $target){$query=Read-Host 'Part of the app name';$apps=@($apps | Where-Object {$_.Name.IndexOf($query,[StringComparison]::OrdinalIgnoreCase) -ge 0})}
        if(-not $apps.Count){throw 'No matching installed app for this account.'}
        for($i=0;$i -lt $apps.Count;$i++){Write-Host ("{0}. {1} {2} [{3}] {4}" -f ($i+1),$apps[$i].Name,$apps[$i].Version,$apps[$i].Kind,$apps[$i].Id)}
        $number=0;if(-not [int]::TryParse((Read-Host 'Select one number'),[ref]$number) -or $number -lt 1 -or $number -gt $apps.Count){throw 'No valid selection.'}
        return (Set-TkSelectedApp $apps[$number-1])
    }
    if(-not $target){throw 'Specify -Target with an exact app name or package ID, or use the interactive CMD.'}
    throw "Found $($apps.Count) matches. Use a unique package ID or the interactive selection."
}
function Get-TkAppCheck {
    $app=Select-TkApp
    Add-TkResult 'App' $app.Name $app.Status ('Type='+$app.Kind+'; Version='+$app.Version+'; Publisher='+$app.Publisher+'; ID='+$app.Id)
    $methods='Settings (if the publisher provides repair)'
    if($app.Kind -eq 'Packaged'){$methods='Settings Repair if available; Reset removes local app data'}
    elseif($app.Msi -and $app.Id -match '^\{[0-9A-Fa-f-]{36}\}$'){$methods+='; Windows Installer repair'}
    if($app.Kind -eq 'Desktop' -and (Get-Command winget.exe -ErrorAction SilentlyContinue)){$methods+='; WinGet repair if the WinGet source supports this program (may run the publisher installer)'}
    Add-TkResult 'Repair options' $app.Name 'Information' $methods
    try {
        $events=@(Get-TkEvents -Log Application -Hours 24 -Ids 1000,1001,1002 -Maximum 100 | Where-Object {$_.Message -and $_.Message.IndexOf($app.Name,[StringComparison]::OrdinalIgnoreCase) -ge 0})
        foreach($e in $events){Add-TkResult 'Related event' ($e.Time.ToString('o')+' '+$e.Id) 'Observed' $e.Message}
        if(-not $events.Count){Add-TkResult 'Related events' $app.Name 'NoNameMatches' 'No matching app-name text in the newest 100 crash/hang events from 24 hours. This does not prove app health.'}
    }catch{Add-TkResult 'Related events' $app.Name 'Unavailable' $_.Exception.Message}
}
function Open-TkAppSettings {
    param($App)
    $uri='ms-settings:appsfeatures'
    if($App.Kind -eq 'Packaged'){$uri='ms-settings:appsfeatures-app?PFN='+[uri]::EscapeDataString($App.Family)}
    Start-Process -FilePath $uri -ErrorAction Stop | Out-Null
    Add-TkResult 'Settings' $App.Name 'ManualStepRequired' 'Choose Advanced options > Repair if available. This tool has opened the page; it has not performed the repair.'
}
function Repair-TkApp {
    Assert-TkUser
    $app=Select-TkApp
    $method=Get-TkChoice 'Method' 'Select repair method' @('Settings','Winget','Installer')
    $null=Save-TkEvidence 'app-before' $app
    if($method -eq 'Installer' -and (-not $app.Msi -or $app.Id -notmatch '^\{[0-9A-Fa-f-]{36}\}$')){throw 'This app does not expose a valid Windows Installer product registration. Use Settings.'}
    if($method -eq 'Winget'){
        if($app.Kind -ne 'Desktop'){throw 'WinGet repair applies to desktop programs. For a packaged app use Settings, or Reset Selected App Data.'}
        $help=Invoke-TkNative winget.exe @('repair','--help') -AllowFailure
        if($help.ExitCode -ne 0){throw 'This WinGet version does not support repair. Choose Settings.'}
    }
    $plan=switch($method){Settings {'Open the Windows Settings page for this app; you click Repair yourself'} Winget {'WinGet repair: may download and run the publisher installer interactively (30-minute limit); close the app and save work first'} Installer {'Windows Installer repair (msiexec /f) of this product; close the app and save work first'}}
    if(-not (Approve-TkAction ($app.Name+' '+$app.Version+' '+$app.Id) $plan)){return}
    switch($method){
        Settings {Open-TkAppSettings $app}
        Winget {
            $r=Invoke-TkNative winget.exe @('repair','--name',$app.Name,'--exact','--interactive','--disable-interactivity') -TimeoutSeconds 1800 -AllowFailure
            $null=Save-TkEvidence 'winget-result' $r
            if($r.ExitCode -ne 0){throw "WinGet returned $($r.ExitCode). Repair may be unsupported; review the saved output before choosing Settings. $($r.Text)"}
            Add-TkResult 'Action' $app.Name 'Completed' 'WinGet returned success. Confirm the app works.'
        }
        Installer {
            $log=Join-Path (Get-TkOutputFolder) ($script:RunId+'-installer.log')
            $r=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\msiexec.exe') @('/fomus',$app.Id,'/passive','/norestart','/l*v',$log) -TimeoutSeconds 1800 -AllowFailure
            if($r.ExitCode -notin 0,3010){throw "Installer repair returned $($r.ExitCode). See $log"}
            $status='Completed';if($r.ExitCode -eq 3010){$status='RestartRequired'}
            Add-TkResult 'Action' $app.Name $status $log
        }
    }
    Add-TkHumanCheck 'Open the selected app and repeat the task that failed. Use Verify App Works to record the outcome.'
}
function Backup-TkPackageData {
    param($App)
    # Best-effort copy of user data before Reset-AppxPackage deletes it. Caches are not copied.
    $packageRoot=Join-Path $env:LOCALAPPDATA ('Packages\'+$App.Family)
    if(-not $App.Family -or -not (Test-Path -LiteralPath $packageRoot -PathType Container)){Add-TkResult 'Backup' $App.Name 'NotFound' 'No package data folder exists for this account; nothing to copy.';return}
    $null=Assert-TkPath $packageRoot $env:LOCALAPPDATA
    $sources=@(foreach($n in 'LocalState','RoamingState','Settings'){$p=Join-Path $packageRoot $n;if(Test-Path -LiteralPath $p -PathType Container){$p}})
    if(-not $sources.Count){Add-TkResult 'Backup' $App.Name 'NotFound' 'No LocalState, RoamingState or Settings folder to copy.';return}
    $bytes=0;foreach($s in $sources){$bytes+=[int64](Get-ChildItem -LiteralPath $s -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum}
    if($bytes -gt 1GB){Add-TkResult 'Backup' $App.Name 'Skipped' ('App data is '+[math]::Round($bytes/1GB,2)+' GB; copy it manually first if it matters.');return}
    $backup=Assert-TkPath ($packageRoot+'.ToolkitBackup-'+$script:RunId) $env:LOCALAPPDATA
    $failed=0
    foreach($s in $sources){
        $r=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\robocopy.exe') @($s,(Join-Path $backup (Split-Path $s -Leaf)),'/E','/R:0','/W:0','/XJ','/NFL','/NDL','/NJH','/NJS','/NP') -TimeoutSeconds 600 -AllowFailure
        if($r.ExitCode -ge 8){$failed++;Add-TkResult 'Backup' (Split-Path $s -Leaf) 'Incomplete' ('robocopy exit '+$r.ExitCode+'; some files were in use or unreadable.')}
    }
    $status='Saved';if($failed){$status='Partial'}
    Add-TkResult 'Backup' $App.Name $status ($backup+' ('+[math]::Round($bytes/1MB,1)+' MB requested). Copy the folders back with the app closed to restore; delete the backup when no longer needed.')
}
function Reset-TkApp {
    Assert-TkUser
    $app=Select-TkApp
    if($app.Kind -ne 'Packaged'){throw 'Automatic reset supports packaged apps only. Use the desktop app publisher instructions.'}
    if(-not (Get-Command Reset-AppxPackage -ErrorAction SilentlyContinue)){throw 'Reset-AppxPackage is unavailable on this Windows build.'}
    $null=Save-TkEvidence 'app-before' $app
    Add-TkResult 'Data impact' $app.Name 'DeletesLocalAppData' 'Reset closes the app if it is running and removes local app data, preferences and sign-in state. LocalState, RoamingState and Settings are copied aside first when they total under 1 GB; there is no automatic undo.'
    if(-not (Approve-TkAction ($app.Name+' for '+[Security.Principal.WindowsIdentity]::GetCurrent().Name) 'RESET this exact package: close it if running and DELETE its local app data (LocalState, RoamingState and Settings are copied aside first when under 1 GB); confirm Repair was tried first')){return}
    Backup-TkPackageData $app
    Reset-AppxPackage -Package $app.Id -ErrorAction Stop
    # Registration can briefly disappear after Reset-AppxPackage returns.
    $after=$null
    for($attempt=0;$attempt -lt 60;$attempt++){
        try{$after=Get-AppxPackage -Name $app.Name -ErrorAction Stop | Where-Object PackageFamilyName -eq $app.Family | Select-Object -First 1}catch{$after=$null}
        if($after -and [string]$after.Status -in 'Ok','0'){break}
        Start-Sleep -Milliseconds 500
    }
    $status='VerificationPending'
    if($after -and [string]$after.Status -in 'Ok','0'){$status='PackageVerified'}
    Add-TkResult 'Action' $app.Name $status 'Reset command returned. Checked package registration for up to 30 seconds; application behavior still requires a user test.'
    Add-TkHumanCheck 'Open the app, sign in if needed and verify the original task and expected data.'
}
function Verify-TkApp {
    Get-TkAppCheck
    $outcome=Get-TkChoice 'Outcome' 'After opening the app and repeating the failed task, choose the result' @('NotChecked','Works','StillFails','PartlyWorks')
    Add-TkResult 'User verification' 'Selected app' $outcome 'Recorded by the technician. Installation status and lack of crash events alone do not establish success.'
}
function Get-TkTeams {
    $packages=@(Get-AppxPackage -Name MSTeams -ErrorAction Stop)
    if(-not $packages.Count){Add-TkResult 'Teams' 'Current account' 'NotInstalled' 'New Teams package is not registered for the running account.'}
    foreach($p in $packages){Add-TkResult 'Teams package' $p.PackageFamilyName ([string]$p.Status) ([string]$p.Version)}
    $processes=@(Get-TkOwnedProcesses @('ms-teams.exe'))
    Add-TkResult 'Teams process' 'Current account/session' 'Information' ('Count='+$processes.Count)
    foreach($hostName in 'teams.microsoft.com','login.microsoftonline.com'){$status='Unreachable';if(Test-TkTcp $hostName 443){$status='Reachable'};Add-TkResult 'TCP 443' $hostName $status 'Transport check only; does not validate login, calls, proxy authentication or tenant service health.'}
}
function Repair-TkTeams {
    Assert-TkUser
    $action=Get-TkChoice 'Action' 'Select Restart first; ClearCache only if needed' @('Restart','ClearCache')
    $packages=@(Get-AppxPackage -Name MSTeams -ErrorAction Stop)
    if($packages.Count -ne 1){throw 'One New Teams package must be registered for this account.'}
    $p=$packages[0];$root=Join-Path $env:LOCALAPPDATA ('Packages\'+$p.PackageFamilyName)
    $cache=Join-Path $root 'LocalCache\Microsoft\MSTeams'
    if($action -eq 'ClearCache'){$null=Assert-TkPath $cache $env:LOCALAPPDATA}
    $launch=@(Get-StartApps -ErrorAction Stop | Where-Object {$_.AppID.StartsWith($p.PackageFamilyName+'!',[StringComparison]::OrdinalIgnoreCase)})
    if($launch.Count -ne 1){throw 'Cannot identify one Teams launch entry. Open Teams manually and retry.'}
    Get-TkTeams
    $plan='Close Teams for this account (interrupts active calls) and start it again';if($action -eq 'ClearCache'){$plan='Close Teams for this account (interrupts active calls), move '+$cache+' to a .ToolkitBackup folder, then start Teams again'}
    if(-not (Approve-TkAction 'New Teams in this account/session' $plan)){return}
    Stop-TkOwnedProcesses @('ms-teams.exe')
    for($wait=0;$wait -lt 12 -and @(Get-TkOwnedProcesses @('ms-teams.exe')).Count;$wait++){Start-Sleep -Milliseconds 500}
    if(@(Get-TkOwnedProcesses @('ms-teams.exe')).Count){throw 'Teams restarted or did not close. Cache was not moved.'}
    $moveError=$null
    if($action -eq 'ClearCache'){try{$null=Move-TkCache $cache $root}catch{$moveError=$_.Exception.Message}}
    Start-Process explorer.exe -ArgumentList ('"shell:AppsFolder\'+$launch[0].AppID+'"') -ErrorAction Stop | Out-Null
    if($moveError){Add-TkResult 'Cache' $cache 'NotMoved' $moveError;throw ('Cache was not moved: '+$moveError+' Teams was started again without clearing it.')}
    Add-TkResult 'Action' 'New Teams' 'LaunchRequested' 'Teams may take longer while rebuilding its cache. Cache backup, if present, is listed above.'
    Add-TkHumanCheck 'Confirm Teams opens, signs in, sends a message and completes a test call.'
}
function Repair-TkOneDrive {
    Assert-TkUser
    if(Test-TkAdmin){throw 'Run OneDrive actions from a normal, non-administrator window; OneDrive does not run elevated.'}
    $action=Get-TkChoice 'Action' 'Select Restart first; Reset only for a confirmed sync issue' @('Restart','Reset')
    $paths=@((Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'),(Join-Path $env:ProgramFiles 'Microsoft OneDrive\OneDrive.exe'))
    if(${env:ProgramFiles(x86)}){$paths+=Join-Path ${env:ProgramFiles(x86)} 'Microsoft OneDrive\OneDrive.exe'}
    $exe=$paths | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf} | Select-Object -First 1
    if(-not $exe){throw 'OneDrive.exe was not found in a supported installation location.'}
    $sig=Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
    if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'OneDrive executable did not pass the Microsoft signature check.'}
    $null=Save-TkEvidence 'onedrive-before' @(Get-TkOwnedProcesses @('OneDrive.exe') | Select-Object Name,ProcessId,ExecutablePath)
    if(-not (Approve-TkAction 'OneDrive for the current user' "$action sync client; Reset rebuilds sync settings and triggers a full sync")){return}
    $arg='/shutdown';if($action -eq 'Reset'){$arg='/reset'}
    $p=Start-Process -FilePath $exe -ArgumentList $arg -PassThru -ErrorAction Stop
    if(-not $p.WaitForExit(60000)){throw 'OneDrive shutdown/reset is still running. Check its state before starting another action.'}
    if($p.ExitCode -ne 0){throw "OneDrive returned $($p.ExitCode)."}
    for($wait=0;$wait -lt 40 -and @(Get-TkOwnedProcesses @('OneDrive.exe')).Count;$wait++){Start-Sleep -Milliseconds 500}
    if(@(Get-TkOwnedProcesses @('OneDrive.exe')).Count){Add-TkResult 'Notice' 'OneDrive' 'StillRunning' 'The previous OneDrive process had not exited after 20 seconds; the running instance may ignore the relaunch.'}
    Start-Process -FilePath $exe -ErrorAction Stop | Out-Null
    Add-TkResult 'Action' 'OneDrive' 'LaunchRequested' 'Recheck account and selected sync folders. Reset can require selecting folders again.'
    Add-TkHumanCheck 'Check the OneDrive tray status and verify a test file both locally and on the OneDrive website. Do not remove cloud or local files to force sync.'
}
function Repair-TkOutlook {
    Assert-TkUser
    $action=Get-TkChoice 'Action' 'Choose the smaller Outlook troubleshooting step' @('SafeMode','ListAddins','DisableAddin','RestoreAddin')
    if($action -eq 'ListAddins'){
        foreach($root in @('HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\WOW6432Node\Microsoft\Office\Outlook\Addins')){
            if(Test-Path -LiteralPath $root){foreach($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)){$p=Get-ItemProperty -LiteralPath $key.PSPath;Add-TkResult 'Outlook add-in' $key.PSChildName 'Information' ('LoadBehavior='+$p.LoadBehavior+'; '+$root)}}
        };return
    }
    if(@(Get-TkOwnedProcesses @('OUTLOOK.EXE')).Count){throw 'Save work and close Classic Outlook before this step.'}
    if($action -eq 'SafeMode'){
        $exe=$null
        foreach($key in @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE')){if(Test-Path -LiteralPath $key){$exe=(Get-Item -LiteralPath $key).GetValue('');if($exe){break}}}
        if(-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)){throw 'Classic Outlook installation not found.'}
        $sig=Get-AuthenticodeSignature -LiteralPath $exe;if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'Outlook did not pass the Microsoft signature check.'}
        if(-not (Approve-TkAction 'Classic Outlook' 'Start in safe mode to test without add-ins')){return}
        Start-Process -FilePath $exe -ArgumentList '/safe' -ErrorAction Stop | Out-Null
        Add-TkHumanCheck 'Repeat the failing task. If it works, close Outlook and isolate one add-in; then retest normal mode.'
        return
    }
    if($action -eq 'DisableAddin'){
        $id=Get-TkChoice 'AddinId' 'Exact current-user add-in ID from ListAddins' @()
        if($id -match '[\\/]' -or $id -in '.','..'){throw 'Use an exact add-in ID, not a path.'}
        foreach($hive in 'HKCU:','HKLM:'){
            $policy=$hive+'\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Resiliency\AddinList'
            if(Test-Path -LiteralPath $policy){$managed=Get-Item -LiteralPath $policy -ErrorAction Stop;if($null -ne $managed.GetValue($id,$null)){throw 'This add-in is managed by organizational policy. Ask its owner to change it.'}}
        }
        $key='HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins\'+$id
        $p=Get-ItemProperty -LiteralPath $key -Name LoadBehavior -ErrorAction Stop
        $backup=Save-TkEvidence 'outlook-addin' ([ordered]@{Schema=1;UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;AddinId=$id;LoadBehavior=[int]$p.LoadBehavior})
        $machineRoots=@('HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\WOW6432Node\Microsoft\Office\Outlook\Addins')
        $machine=@($machineRoots | Where-Object {Test-Path -LiteralPath ($_+'\'+$id)})
        $plan='Disable this current-user Outlook add-in; its previous setting is saved'
        if($machine.Count){Add-TkResult 'Notice' $id 'AlsoRegisteredPerMachine' ('Also registered under '+($machine -join '; ')+'. Outlook may still load it; a per-machine registration needs its owner.');$plan+='. It is also registered per-machine, so Outlook may still load it'}
        if(-not (Approve-TkAction $id $plan)){return}
        Set-ItemProperty -LiteralPath $key -Name LoadBehavior -Value 0 -Type DWord -ErrorAction Stop
        Add-TkResult 'Add-in' $id 'Disabled' ('Restore with -Action RestoreAddin -BackupPath "'+$backup+'"')
    }else{
        $path=Get-TkChoice 'BackupPath' 'Path to the saved outlook-addin JSON' @()
        $b=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if($b.Schema -ne 1 -or $b.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or -not $b.AddinId -or $b.AddinId -match '[\\/]' -or $b.AddinId -in '.','..' -or $b.LoadBehavior -isnot [ValueType]){throw 'Invalid backup or user mismatch.'}
        $key='HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins\'+$b.AddinId
        if(-not (Test-Path -LiteralPath $key)){throw 'This add-in is no longer installed for the current user.'}
        if(-not (Approve-TkAction $b.AddinId 'Restore saved Outlook LoadBehavior')){return}
        Set-ItemProperty -LiteralPath $key -Name LoadBehavior -Value ([int]$b.LoadBehavior) -Type DWord -ErrorAction Stop
        Add-TkResult 'Add-in' $b.AddinId 'Restored' ([string]$b.LoadBehavior)
    }
    Add-TkHumanCheck 'Open Outlook normally and repeat the failing task. Machine-installed or policy-controlled add-ins must be managed through their owner.'
}
