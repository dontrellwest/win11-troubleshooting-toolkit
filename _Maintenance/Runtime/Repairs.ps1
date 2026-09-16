function Get-TkPrintSnapshot {
    $service=Get-Service Spooler -ErrorAction Stop
    Add-TkResult 'Service' 'Spooler' ([string]$service.Status) ''
    foreach($printer in @(Get-Printer -ErrorAction Stop | Sort-Object Name)){
        Add-TkResult 'Printer' $printer.Name ([string]$printer.PrinterStatus) ('Driver='+$printer.DriverName+'; Port='+$printer.PortName)
        foreach($job in @(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop | Sort-Object ID)){
            Add-TkResult 'Print job' ($printer.Name+' #'+$job.ID) ([string]$job.JobStatus) ('Document='+$job.DocumentName+'; User='+$job.UserName+'; Submitted='+$job.SubmittedTime)
        }
    }
}
function Select-TkPrinter {
    $name=[string]$script:Options.PrinterName
    $printers=@(Get-Printer -ErrorAction Stop)
    if(-not $name -and $script:Options.Interactive){$printers | Select-Object Name,DriverName,PortName | Format-Table -AutoSize | Out-Host;$name=Read-Host 'Exact printer name'}
    $matches=@($printers | Where-Object Name -eq $name)
    if($matches.Count -ne 1){throw 'Specify -PrinterName with one exact installed printer name.'}
    $matches[0]
}
function Cancel-TkPrintJob {
    $printer=Select-TkPrinter
    $jobs=@(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop)
    if(-not $jobs.Count){Add-TkResult 'Queue' $printer.Name 'Empty' 'No jobs to cancel.';return}
    $id=[int]$script:Options.JobId
    if($id -le 0 -and $script:Options.Interactive){$jobs | Select-Object ID,DocumentName,UserName,JobStatus | Format-Table -AutoSize | Out-Host;$inputId=Read-Host 'Exact job ID to cancel';if(-not [int]::TryParse($inputId,[ref]$id)){throw 'Job ID must be numeric.'}}
    $job=@($jobs | Where-Object ID -eq $id)
    if($job.Count -ne 1){throw 'Select one existing job ID; all-job cancellation is not supported here.'}
    $null=Save-TkEvidence 'print-job-before' ($job[0] | Select-Object ID,PrinterName,DocumentName,UserName,SubmittedTime,JobStatus)
    if(-not (Approve-TkAction ($printer.Name+' job '+$id+' '+$job[0].DocumentName) 'Cancel only this print job')){return}
    $fresh=@(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop | Where-Object ID -eq $id)
    if($fresh.Count -ne 1 -or $fresh[0].DocumentName -ne $job[0].DocumentName -or $fresh[0].SubmittedTime -ne $job[0].SubmittedTime -or $fresh[0].UserName -ne $job[0].UserName){throw 'The selected job changed or already left the queue. No cancellation was sent.'}
    Remove-PrintJob -PrinterName $printer.Name -ID $id -ErrorAction Stop
    $remaining=@(Get-PrintJob -PrinterName $printer.Name -ErrorAction Stop | Where-Object ID -eq $id)
    $status='Removed';if($remaining.Count){$status='StillQueued'}
    Add-TkResult 'Print job' ($printer.Name+' #'+$id) $status 'Other jobs were not targeted. A job already sent to printer hardware may still print.'
    Add-TkHumanCheck 'Check the printer display and queue, then retry the original print job.'
}
function Test-TkPrinterPage {
    $printer=Select-TkPrinter
    if(-not (Approve-TkAction $printer.Name 'Submit one Windows printer test page; uses paper and ink')){return}
    $cim=@(Get-CimInstance Win32_Printer -ErrorAction Stop | Where-Object Name -eq $printer.Name)
    if($cim.Count -ne 1){throw 'Cannot identify the exact printer through Windows printing management.'}
    $result=Invoke-CimMethod -InputObject $cim[0] -MethodName PrintTestPage -ErrorAction Stop
    if($result.ReturnValue -ne 0){throw "Windows rejected the test-page request: $($result.ReturnValue)"}
    Add-TkResult 'Test page' $printer.Name 'Submitted' 'Windows accepted the request; this does not prove paper came out.'
    $outcome=[string]$script:Options.Outcome
    $note='Physical output must be checked by a person.'
    if(-not $outcome -and $script:Options.Interactive){
        # The page is already submitted; an empty or unrecognized answer must not turn the run into a failure.
        $answer=([string](Read-Host 'Observe the printer, then type Printed, DidNotPrint or PoorQuality (Enter = NotChecked)')).Trim()
        if($answer -in 'NotChecked','Printed','DidNotPrint','PoorQuality'){$outcome=$answer}elseif($answer){$note='Unrecognized answer "'+$answer+'" recorded as NotChecked. '+$note}
    }
    if(-not $outcome){$outcome='NotChecked'}
    Add-TkResult 'User verification' $printer.Name $outcome $note
}
function Repair-TkWindowsUpdate {
    Assert-TkAdmin
    $action=Get-TkChoice 'Action' 'Choose StartServices or ResetDownloadCache after reviewing the update diagnostic' @('StartServices','ResetDownloadCache')
    Get-TkReadiness
    $services=@(Get-Service -Name wuauserv,bits -ErrorAction Stop)
    $serviceConfig=@(Get-CimInstance Win32_Service -Filter "Name='wuauserv' OR Name='BITS'" -ErrorAction Stop)
    foreach($s in $serviceConfig){if($s.StartMode -eq 'Disabled'){throw ($s.Name+' is disabled. Resolve policy or service configuration with its owner first.')}}
    $null=Save-TkEvidence 'update-services-before' @($serviceConfig | Select-Object Name,State,StartMode)
    if(@(Get-TkPendingRestart).Count){throw 'Restart is pending. Save work, restart manually, then run the update diagnostic again.'}
    if(@(Get-Process dism,sfc,TiWorker -ErrorAction SilentlyContinue).Count){throw 'Windows servicing (DISM, SFC or TiWorker) is active. Allow it to finish before this repair.'}
    $installers=@(Get-Process MoUsoCoreWorker,msiexec -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique)
    if($installers.Count){Add-TkResult 'Notice' 'Update or installer processes' 'Present' (($installers -join ', ')+' is running; these often idle in the background. Confirm no installation is in progress before continuing.')}
    $download=Join-Path $env:SystemRoot 'SoftwareDistribution\Download'
    $null=Assert-TkPath $download $env:SystemRoot
    $null=Save-TkEvidence 'update-events-before' @(Get-TkEvents -Log 'Microsoft-Windows-WindowsUpdateClient/Operational' -Hours 48 -Maximum 40)
    $plan='Start the Windows Update and BITS services if they are stopped; no files change';if($action -eq 'ResetDownloadCache'){$plan='Stop Windows Update and BITS, rename SoftwareDistribution\Download to Download.ToolkitBackup-'+$script:RunId+', then start the services again'}
    if(-not (Approve-TkAction 'Windows Update and BITS' $plan)){return}
    if($action -eq 'StartServices'){
        foreach($service in $services){if($service.Status -ne 'Running'){Start-Service -Name $service.Name -ErrorAction Stop}}
    }else{
        $stopped=New-Object Collections.Generic.List[string];$moved=$false
        try {
            foreach($service in $services){if($service.Status -eq 'Running'){Stop-Service -Name $service.Name -ErrorAction Stop;$stopped.Add($service.Name);(Get-Service $service.Name).WaitForStatus('Stopped',[timespan]::FromSeconds(30))}}
            foreach($service in $services){if((Get-Service $service.Name).Status -ne 'Stopped'){throw 'An update service restarted. Cache was not moved.'}}
            $null=Move-TkCache $download (Join-Path $env:SystemRoot 'SoftwareDistribution')
            $moved=$true
        }finally{
            $failures=@();foreach($name in $stopped){try{Start-Service -Name $name -ErrorAction Stop}catch{$failures+=$name+': '+$_.Exception.Message}}
            if($failures.Count){Add-TkResult 'Service restore' 'Windows Update and BITS' 'Failed' ('Start these manually: '+($failures -join '; '));if($moved){throw ('Could not restore running services: '+($failures -join '; '))}}
        }
    }
    foreach($service in @(Get-Service -Name wuauserv,bits)){Add-TkResult 'Service after' $service.Name ([string]$service.Status) 'Startup type and policy were not changed. Trigger-start services may stop when idle.'}
    Add-TkHumanCheck 'Run Check Windows Updates without -SkipSearch, then retry the failed update. Download cache backup can be removed later after success; installed updates and DataStore were not removed.'
}
function Repair-TkTime {
    Assert-TkAdmin
    $before=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\w32tm.exe') @('/query','/status') -AllowFailure
    Add-TkResult 'Time before' 'Configured Windows time service' 'Observed' $before.Text
    $service=Get-Service w32time -ErrorAction Stop
    if($service.Status -ne 'Running'){throw 'Windows Time is not running. Check time-service configuration or policy before resync.'}
    if(-not (Approve-TkAction 'Configured Windows time source' 'Resynchronize time; keep the existing time-source configuration')){return}
    $result=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\w32tm.exe') @('/resync','/rediscover') -TimeoutSeconds 60
    Add-TkResult 'Action' 'Time resync' 'Completed' $result.Text
    $after=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\w32tm.exe') @('/query','/status')
    Add-TkResult 'Time after' 'Configured Windows time service' 'Observed' $after.Text
    Add-TkHumanCheck 'Rerun the sign-in check and retry authentication. Check the reported source and last successful synchronization.'
}
function Repair-TkPolicy {
    $target=Get-TkChoice 'Scope' 'Select User or Computer policy' @('User','Computer')
    if($target -eq 'User'){Assert-TkUser}else{Assert-TkAdmin}
    if(-not (Approve-TkAction ($target+' Group Policy') 'Refresh policy; may apply settings configured by the organization')){return}
    $result=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\gpupdate.exe') @(('/target:'+$target.ToLowerInvariant()),'/force','/wait:60') -TimeoutSeconds 90 -AllowFailure
    $status='Completed';if($result.ExitCode -ne 0){$status='NeedsReview'}
    Add-TkResult 'Policy refresh' $target $status ('Exit='+$result.ExitCode+'; '+$result.Text)
    Add-TkHumanCheck 'Rerun Check Group Policy. If Windows requests a sign-out or restart, save work and do that manually.'
}
function Repair-TkTrust {
    Assert-TkAdmin
    $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if(-not $cs.PartOfDomain -or $cs.DomainRole -ge 4){throw 'This repair is only for an Active Directory domain member, not an Entra-only PC or domain controller.'}
    $server=Get-TkChoice 'Server' 'FQDN of a known domain controller for this domain' @()
    if($server -match '[\s/\\]' -or -not $server.EndsWith('.'+$cs.Domain,[StringComparison]::OrdinalIgnoreCase)){throw 'Use a domain-controller DNS name in the joined AD domain.'}
    foreach($port in 389,445,135){if(-not (Test-TkTcp $server $port)){throw "Domain controller TCP $port is unreachable. Resolve VPN, DNS and connectivity first."}}
    $before=Test-ComputerSecureChannel -Server $server -ErrorAction Stop
    Add-TkResult 'Secure channel' $cs.Domain 'Observed' ([string]$before)
    if($before){Add-TkResult 'Action' $cs.Domain 'NotNeeded' 'The secure channel test passed.';return}
    $time=Invoke-TkNative (Join-Path $env:SystemRoot 'System32\w32tm.exe') @('/query','/status') -AllowFailure
    Add-TkResult 'Time prerequisite' $server 'ReviewRequired' $time.Text
    if(-not (Approve-TkAction ($env:COMPUTERNAME+' in '+$cs.Domain+' via '+$server) 'Repair the failed machine secure channel; confirm DNS and time were checked')){return}
    $credential=$script:Options.Credential
    if(-not $credential -and $script:Options.Interactive){$credential=Get-Credential -Message 'Authorized domain account for machine trust repair'}
    if(-not $credential){throw 'Supply -Credential with an authorized domain account. No password is logged.'}
    $result=Test-ComputerSecureChannel -Repair -Server $server -Credential $credential -ErrorAction Stop
    $verified=Test-ComputerSecureChannel -Server $server -ErrorAction Stop
    $status='Failed';if($result -and $verified){$status='Passed'}
    Add-TkResult 'Secure channel after' $cs.Domain $status ('Repair returned '+$result+'; verification returned '+$verified)
    Add-TkHumanCheck 'Retry domain authentication and Group Policy. Do not unjoin/rejoin the PC automatically.'
}
function Get-TkSafeFiles {
    param([string]$Root,[datetime]$Before,[int]$Limit=20000)
    $root=Assert-TkPath $Root $Root -AllowRoot
    if(-not (Test-Path -LiteralPath $root -PathType Container)){return}
    $queue=New-Object Collections.Generic.Queue[string];$queue.Enqueue($root);$count=0;$visited=0
    while($queue.Count){
        $dir=$queue.Dequeue();$null=Assert-TkPath $dir $root -AllowRoot
        try{$children=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)}catch{Add-TkResult 'Skipped folder' $dir 'Unavailable' $_.Exception.Message;continue}
        foreach($item in $children){
            $visited++;if($visited -gt $Limit){throw "Temporary folder contains more than $Limit entries. Narrow or clean it manually; no files have been deleted."}
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
            if($item.PSIsContainer){$queue.Enqueue($item.FullName)}elseif($item.LastWriteTime -lt $Before){$count++;[pscustomobject]@{Path=$item.FullName;Length=$item.Length;LastWriteUtc=$item.LastWriteTimeUtc}}
        }
    }
}
function Clear-TkTemporaryFiles {
    Assert-TkUser
    $scope=Get-TkChoice 'Scope' 'Choose CurrentUserTemp or WindowsTemp' @('CurrentUserTemp','WindowsTemp')
    $root=Join-Path $env:LOCALAPPDATA 'Temp'
    if($scope -eq 'WindowsTemp'){Assert-TkAdmin;$root=Join-Path $env:SystemRoot 'Temp'}
    if($script:Options.Subfolder){$root=Assert-TkPath (Join-Path $root $script:Options.Subfolder) $root}
    $root=Assert-TkPath $root $root -AllowRoot
    # Log outside cleanup roots so neither intent nor reports become candidates.
    $output=Get-TkOutputFolder
    if($output.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or $output -ieq $root){throw 'Choose a report folder outside the temporary folder being cleaned.'}
    $days=[int]$script:Options.OlderThanDays;if($days -lt 1){throw 'OlderThanDays must be at least 1 so that files written today are never candidates.'};$cutoff=(Get-Date).AddDays(-$days)
    $files=@(Get-TkSafeFiles $root $cutoff)
    $bytes=($files | Measure-Object Length -Sum).Sum
    $inventory=Save-TkEvidence 'cleanup-candidates' $files
    Add-TkResult 'Candidates' $root 'Preview' ('Files='+$files.Count+'; bytes='+$bytes+'; older than '+$days+' days; list='+$inventory)
    if(-not $files.Count){return}
    if(-not (Approve-TkAction $root ('Permanently delete only '+$files.Count+' inventoried old temporary files; skip changed or in-use files'))){return}
    $deleted=0;$removed=0L;$skipped=0
    foreach($file in $files){
        try {
            $path=Assert-TkPath $file.Path $root
            $current=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if($current.PSIsContainer -or $current.Length -ne $file.Length -or $current.LastWriteTimeUtc -ne $file.LastWriteUtc -or $current.LastWriteTime -ge $cutoff){$skipped++;continue}
            # Exclusive-open probe avoids files currently in use. Revalidate after it.
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$stream.Dispose()
            $null=Assert-TkPath $path $root
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $deleted++;$removed+=$file.Length
        }catch{$skipped++;Add-TkResult 'Skipped file' $file.Path 'NotDeleted' $_.Exception.Message}
    }
    Add-TkResult 'Cleanup' $root 'Completed' ('Deleted='+$deleted+'; file bytes removed='+$removed+'; skipped='+$skipped+'. File size is not a measurement of physical disk space recovered.')
    Add-TkHumanCheck 'Recheck free space with Check Disk Space Usage and repeat the task that was affected by low space.'
    Get-TkReadiness
}
