function Get-TkCase {
    param([string]$Path)
    $folder=Get-TkFullPath $Path
    $null=Assert-TkPath $folder $folder -AllowRoot
    $metadata=Join-Path $folder 'case.json'
    if(-not (Test-Path -LiteralPath $metadata -PathType Leaf)){throw 'Select a case folder created by Start Case and Check Readiness.'}
    $case=Get-Content -LiteralPath $metadata -Raw -ErrorAction Stop | ConvertFrom-Json
    if($case.Schema -ne 1 -or -not $case.CaseId -or $case.Computer -ine $env:COMPUTERNAME){throw 'Case format or computer does not match this PC.'}
    [pscustomobject]@{Folder=$folder;Metadata=$case}
}
function Start-TkCase {
    $issue=Get-TkChoice 'Issue' 'Describe the original problem or error' @()
    $folder=Get-TkOutputFolder
    $casePath=Join-Path $folder ('Case-'+$env:COMPUTERNAME+'-'+$script:RunId)
    $null=Assert-TkPath $casePath $folder
    [void][IO.Directory]::CreateDirectory($casePath)
    $id=[guid]::NewGuid().ToString()
    Write-TkJson (Join-Path $casePath 'case.json') ([ordered]@{Schema=1;CaseId=$id;Computer=$env:COMPUTERNAME;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Created=[datetime]::Now;Issue=$issue})
    Get-TkReadiness
    Write-TkJson (Join-Path $casePath 'readiness.json') @($script:Rows.ToArray())
    $guide=@('CASE CHECKLIST','==============','Original problem: '+$issue,'','1. Capture Before checks for the relevant area.','2. Run only the repair justified by the findings.','3. Run repairs with -CasePath set to this folder so reports and evidence are copied here.','4. If a restart is needed, save work and restart manually.','5. Reopen Capture Before or After Checks and select After.','6. Use the same area, target and affected user as Before.','7. Compare results; confirm the original task works.','8. Review the case contents before exporting them.','', 'A changed value or a running process is not proof of a fix.')
    [IO.File]::WriteAllLines((Join-Path $casePath 'NEXT-STEPS.txt'),$guide,[Text.Encoding]::ASCII)
    Add-TkResult 'Case' $id 'Created' $casePath
}
function Add-TkFlatValue {
    param([string]$Key,$Value,[int]$Depth=0)
    if($Depth -gt 8){Add-TkResult 'Snapshot' $Key 'Observed' '[Depth limit]';return}
    if($null -eq $Value){Add-TkResult 'Snapshot' $Key 'Observed' '(null)';return}
    if($Value -is [string] -or $Value -is [ValueType]){Add-TkResult 'Snapshot' $Key 'Observed' ([string]$Value);return}
    if($Value -is [Collections.IEnumerable] -and $Value -isnot [Collections.IDictionary]){$i=0;foreach($v in $Value){Add-TkFlatValue ($Key+'['+$i+']') $v ($Depth+1);$i++};if($i -eq 0){Add-TkResult 'Snapshot' $Key 'Observed' '(empty)'};return}
    foreach($p in $Value.PSObject.Properties){if($p.Name -notin 'CollectedAt','PSComputerName','RunspaceId','PSShowComputerName'){Add-TkFlatValue ($Key+'.'+$p.Name) $p.Value ($Depth+1)}}
}
function Get-TkLegacySnapshot {
    param([string]$Name,[hashtable]$Parameters=@{})
    $manifest=Get-Content -LiteralPath (Join-Path $script:ToolkitRoot '_Maintenance\Validation\tool-manifest.json') -Raw | ConvertFrom-Json
    $entry=@($manifest | Where-Object {$_.Name -eq $Name -and $_.Class -eq 'ReadOnly'})
    if($entry.Count -ne 1){throw 'Snapshot diagnostic was not found in the reviewed local manifest.'}
    $path=Assert-TkPath (Join-Path $script:ToolkitRoot ($entry[0].Folder+'\'+$entry[0].Name+'.ps1')) $script:ToolkitRoot
    $diagnosticWarnings=@()
    $items=@(& $path @Parameters -WarningVariable diagnosticWarnings)
    $n=0;foreach($item in $items){Add-TkFlatValue ($Name+'['+$n+']') $item;$n++}
    foreach($warning in $diagnosticWarnings){Add-TkResult 'Diagnostic warning' $Name 'NeedsReview' ([string]$warning)}
}
function Capture-TkCase {
    $case=Get-TkCase (Get-TkChoice 'CasePath' 'Paste the case folder path' @())
    $phase=Get-TkChoice 'Phase' 'Before or After' @('Before','After')
    $area=Get-TkChoice 'Area' 'Choose the problem area' @('General','Network','Printing','OneDrive','ClassicOutlook','NewOutlook','Updates','Storage','Devices','Teams','App','SignIn')
    $start=$script:Rows.Count
    switch($area){
        General {Get-TkReadiness}
        Network {Get-TkNetworkSnapshot}
        Printing {Get-TkPrintSnapshot}
        OneDrive {Get-TkLegacySnapshot '05-Check-OneDrive-and-Folder-Backup' @{SkipFileCounts=$true}}
        ClassicOutlook {Get-TkLegacySnapshot '01-Check-Classic-Outlook-Sync'}
        NewOutlook {Get-TkLegacySnapshot '01-Check-New-Outlook-App-and-Service'}
        Updates {Get-TkLegacySnapshot '06-Check-Windows-Updates' @{SkipSearch=$true}}
        Storage {Get-TkStorage}
        Devices {Get-TkDevices}
        Teams {Get-TkTeams}
        App {Get-TkAppCheck}
        SignIn {Get-TkLegacySnapshot '01-Check-User-Sign-In'}
    }
    $rows=@($script:Rows.ToArray() | Select-Object -Skip $start)
    $snapshot=[ordered]@{Schema=1;CaseId=$case.Metadata.CaseId;Computer=$env:COMPUTERNAME;UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Phase=$phase;Area=$area;Target=[string]$script:Options.Target;Created=[datetime]::Now;Rows=$rows}
    $file=Join-Path $case.Folder ($phase+'-'+$area+'-'+$script:RunId+'.json')
    Write-TkJson $file $snapshot
    # Keep bounded event context alongside the snapshot, without exporting full logs.
    try {Write-TkJson (Join-Path $case.Folder ($phase+'-Events-'+$script:RunId+'.json')) @(Get-TkEvents -Log System -Hours 4 -Maximum 30)}catch{Add-TkResult 'Evidence' 'System events' 'Unavailable' $_.Exception.Message}
    Add-TkResult 'Case' $area 'Captured' $file
}
function Compare-TkCase {
    $case=Get-TkCase (Get-TkChoice 'CasePath' 'Paste the case folder path' @())
    $area=Get-TkChoice 'Area' 'Choose the same area used for Before and After' @('General','Network','Printing','OneDrive','ClassicOutlook','NewOutlook','Updates','Storage','Devices','Teams','App','SignIn')
    $snapshots=@{}
    foreach($phase in 'Before','After'){
        $files=@(Get-ChildItem -LiteralPath $case.Folder -File -Filter ($phase+'-'+$area+'-*.json') | Sort-Object Name -Descending)
        if(-not $files.Count){throw "No $phase snapshot for $area."}
        $null=Assert-TkPath $files[0].FullName $case.Folder
        $snapshots[$phase]=Get-Content -LiteralPath $files[0].FullName -Raw | ConvertFrom-Json
    }
    $before=$snapshots.Before;$after=$snapshots.After
    if($before.CaseId -ne $after.CaseId -or $before.CaseId -ne $case.Metadata.CaseId -or $before.Computer -ne $after.Computer -or $before.UserSid -ne $after.UserSid -or $before.Target -ne $after.Target){throw 'Snapshots have different cases, PCs, users or targets. Capture a matching pair.'}
    if([datetime]$after.Created -lt [datetime]$before.Created){throw 'After snapshot predates Before. Capture After again.'}
    $left=@{};$right=@{}
    foreach($r in $before.Rows){$left[$r.Kind+'|'+$r.Target]=$r}
    foreach($r in $after.Rows){$right[$r.Kind+'|'+$r.Target]=$r}
    foreach($key in @(@($left.Keys)+@($right.Keys) | Sort-Object -Unique)){
        $b=$left[$key];$a=$right[$key];$status='Unchanged'
        if(-not $b){$status='Added'}elseif(-not $a){$status='MissingAfter'}elseif($b.Status -ne $a.Status -or $b.Detail -ne $a.Detail){$status='Changed'}
        Add-TkResult 'Comparison' $key $status ('Before: '+$b.Status+' '+$b.Detail+'; After: '+$a.Status+' '+$a.Detail)
    }
    $resolution=Get-TkChoice 'Resolution' 'Did the original task work?' @('NotChecked','Resolved','Unchanged','PartlyResolved')
    Add-TkResult 'User verification' $case.Metadata.Issue $resolution 'Technician-reported outcome; changed values alone do not establish a fix.'
    Write-TkJson (Join-Path $case.Folder ('Comparison-'+$script:RunId+'.json')) @($script:Rows.ToArray())
}
function Export-TkCase {
    $case=Get-TkCase (Get-TkChoice 'CasePath' 'Paste the case folder path' @())
    $files=@(Get-ChildItem -LiteralPath $case.Folder -File | Where-Object Extension -in '.txt','.json','.csv','.log')
    foreach($file in $files){$null=Assert-TkPath $file.FullName $case.Folder;Add-TkResult 'Export contents' $file.Name 'Selected' ($file.Length.ToString()+' bytes')}
    if(-not (Approve-TkAction $case.Folder 'Create a local ZIP of listed reports; they can contain user, PC, file and server names')){return}
    Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
    $destination=Join-Path (Get-TkOutputFolder) ('CaseExport-'+$script:RunId+'.zip')
    $zip=[IO.Compression.ZipFile]::Open($destination,[IO.Compression.ZipArchiveMode]::Create)
    try {foreach($file in $files){$null=Assert-TkPath $file.FullName $case.Folder;[void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$file.FullName,$file.Name)}}finally{$zip.Dispose()}
    Add-TkResult 'Export' $destination 'Created' 'Local archive only. Review before sharing; no upload was performed.'
}
