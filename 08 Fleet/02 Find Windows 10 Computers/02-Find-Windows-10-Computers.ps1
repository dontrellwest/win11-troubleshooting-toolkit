<#
.SYNOPSIS
    Find Windows 10 clients from live local/fleet checks or endpoint reports.
.DESCRIPTION
    Read-only inventory. Defaults to this PC for unattended RMM execution.
    Fleet mode uses an explicit list or AD discovery, then existing WinRM.
    Failed checks and stale imported reports remain Unknown, not upgraded.
.EXAMPLE
    .\02-Find-Windows-10-Computers.ps1 -Mode Local -OutputFormat Json
.EXAMPLE
    .\02-Find-Windows-10-Computers.ps1 -Mode Fleet -ComputerListPath .\PCs.txt -Display
.EXAMPLE
    .\02-Find-Windows-10-Computers.ps1 -Mode Fleet -FromAD -SearchBase 'OU=Workstations,DC=example,DC=com' -Display
.EXAMPLE
    .\02-Find-Windows-10-Computers.ps1 -Mode Merge -InputFolder .\EndpointReports -ExpectedListPath .\PCs.txt -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: None
    Requires Windows PowerShell 5.1. Fleet AD discovery needs RSAT AD tools.
    Does not upgrade, reboot, install modules or enable remoting.
#>
[CmdletBinding()]
param(
    [ValidateSet('Local','Fleet','Merge')][string]$Mode='Local',
    [switch]$Interactive,
    [switch]$Display,
    [ValidateSet('Objects','Json')][string]$OutputFormat='Objects',
    [string[]]$ComputerName,
    [string]$ComputerListPath,
    [switch]$FromAD,
    [string]$SearchBase,
    [string]$DirectoryServer,
    [switch]$EnabledOnly,
    [pscredential]$Credential,
    [switch]$UseSSL,
    [ValidateRange(1,32)][int]$ThrottleLimit=12,
    [ValidateRange(10,300)][int]$TimeoutSeconds=30,
    [string]$InputFolder,
    [string]$ExpectedListPath,
    [ValidateRange(1,365)][int]$MaxAgeDays=7,
    [string]$CustomerName='',
    [string]$SiteName='',
    [switch]$NoReport,
    [ValidateNotNullOrEmpty()][string]$ReportPath='C:\Temp\Toolkit\Windows10'
)
$ErrorActionPreference='Stop'

# This block is the complete endpoint probe. It never prompts or writes files.
$probe={
    $ErrorActionPreference='Stop'
    $os=Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15 -ErrorAction Stop
    if(-not $os -or -not $os.CSName){throw 'Operating-system query returned no computer identity.'}
    $domain='';$manufacturer='';$model='';$release='';$revision=$null;$installationId='';$warnings=@()
    try {$cs=Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15 -ErrorAction Stop;$domain=[string]$cs.Domain;$manufacturer=[string]$cs.Manufacturer;$model=[string]$cs.Model}
    catch {$warnings+='Computer details unavailable: '+$_.Exception.Message}
    $base=$null;$key=$null;$identityKey=$null
    try {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        if($key){$release=[string]$key.GetValue('DisplayVersion');if(-not $release){$release=[string]$key.GetValue('ReleaseId')};$revision=$key.GetValue('UBR')}
        $identityKey=$base.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
        if($identityKey){$installationId=[string]$identityKey.GetValue('MachineGuid')}
    }catch{$warnings+='Display version unavailable: '+$_.Exception.Message}
    finally{if($identityKey){$identityKey.Dispose()};if($key){$key.Dispose()};if($base){$base.Dispose()}}
    [pscustomobject]@{
        ComputerName=[string]$os.CSName;Domain=$domain;OSName=[string]$os.Caption
        OSVersion=[string]$os.Version;BuildNumber=[string]$os.BuildNumber;ProductType=$os.ProductType
        DisplayVersion=$release;UpdateBuildRevision=$revision;Architecture=[string]$os.OSArchitecture
        Manufacturer=$manufacturer;Model=$model;InstallationId=$installationId;CollectedAtUtc=[datetime]::UtcNow.ToString('o');DetailWarnings=($warnings -join '; ')
    }
}

function Get-W10Classification {
    param($Raw)
    $type=0;$build=0;$version=$null
    if(-not [int]::TryParse([string]$Raw.ProductType,[ref]$type) -or $type -notin 1,2,3){return 'Unknown'}
    if($type -in 2,3){return 'Windows Server'}
    if(-not [int]::TryParse([string]$Raw.BuildNumber,[ref]$build) -or $build -le 0 -or -not [version]::TryParse([string]$Raw.OSVersion,[ref]$version)){return 'Unknown'}
    if($version.Build -ge 0 -and $version.Build -ne $build){return 'Unknown'}
    if($version.Major -eq 10 -and $version.Minor -eq 0){
        if($build -ge 10240 -and $build -lt 22000){return 'Windows 10'}
        if($build -ge 22000){return 'Windows 11 or later'}
        return 'Unknown'
    }
    if($version.Major -ge 6){return 'Other Windows client'}
    'Unknown'
}

function New-W10Row {
    param($Raw,$Target,[string]$Source,[string]$Problem='',[string]$Customer='', [string]$Site='')
    $family='Unknown';$is10=$null
    if($Raw -and -not $Problem){$family=Get-W10Classification $Raw;if($family -ne 'Unknown'){$is10=($family -eq 'Windows 10')}else{$Problem='OS/product/build data could not be classified reliably.'}}
    [pscustomobject][ordered]@{
        ComputerName=$(if($Raw.ComputerName){[string]$Raw.ComputerName}else{[string]$Target.Name})
        RequestedComputerName=[string]$Target.Target;CustomerName=$Customer;SiteName=$Site;Domain=[string]$Raw.Domain
        IsWindows10=$is10;OSFamily=$family;Status=$(if($Problem){'Unknown'}else{'Checked'});Source=$Source
        CollectedAtUtc=$(if($Raw.CollectedAtUtc){[string]$Raw.CollectedAtUtc}else{[datetime]::UtcNow.ToString('o')})
        OSName=[string]$Raw.OSName;OSVersion=[string]$Raw.OSVersion;BuildNumber=[string]$Raw.BuildNumber
        ProductType=$Raw.ProductType;DisplayVersion=[string]$Raw.DisplayVersion;UpdateBuildRevision=$Raw.UpdateBuildRevision
        Architecture=[string]$Raw.Architecture;Manufacturer=[string]$Raw.Manufacturer;Model=[string]$Raw.Model;InstallationId=[string]$Raw.InstallationId
        DirectoryOS=[string]$Target.DirectoryOS;DirectoryEnabled=$Target.DirectoryEnabled;DirectoryDN=[string]$Target.DirectoryDN
        Error=$Problem;DetailWarnings=[string]$Raw.DetailWarnings
    }
}

function Get-W10Folder {
    param([string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if($provider.Name -ne 'FileSystem'){throw 'ReportPath must be a filesystem folder.'}
    $walk=$full
    while($walk){
        if(Test-Path -LiteralPath $walk){$item=Get-Item -LiteralPath $walk -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('Report folder contains a link or junction: '+$walk)}}
        $parent=[IO.Path]::GetDirectoryName($walk);if($parent -eq $walk){break};$walk=$parent
    }
    $null=[IO.Directory]::CreateDirectory($full);$full
}

function Read-W10Names {
    param([string[]]$Names,[string]$File)
    $all=@($Names)
    if($File){$all+=@(Get-Content -LiteralPath $File -ErrorAction Stop | ForEach-Object {($_ -split '#',2)[0].Trim()})}
    $all=@($all | Where-Object {$_} | ForEach-Object {$_.Trim()} | Where-Object {$_} | Sort-Object -Unique)
    foreach($entry in $all){if($entry -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'){throw ('Use computer names, FQDNs or IPv4 addresses, one per line. Invalid entry: '+$entry)}}
    $all
}

function Get-W10Targets {
    param([bool]$AD,[string[]]$Names,[string]$List,[string]$Base,[string]$Server,[bool]$OnlyEnabled,[pscredential]$Access)
    if($AD){
        if($Names -or $List){throw 'Choose AD discovery OR an explicit computer list.'}
        try{Import-Module ActiveDirectory -ErrorAction Stop}catch{throw 'AD discovery needs the RSAT ActiveDirectory module. Use an explicit list or run Local through N-central instead.'}
        $connection=@{};if($Server){$connection.Server=$Server};if($Access){$connection.Credential=$Access}
        $rootDse=Get-ADRootDSE @connection -ErrorAction Stop
        if(-not $rootDse.defaultNamingContext -or -not $rootDse.dnsHostName){throw 'AD did not return a domain naming context and domain controller.'}
        $connection.Server=[string]$rootDse.dnsHostName
        if(-not $Base){$Base=[string]$rootDse.defaultNamingContext}
        # Do not filter by AD operatingSystem: that attribute may be stale/missing.
        $filter='(objectCategory=computer)'
        if($OnlyEnabled){$filter='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'}
        $computers=@(Get-ADComputer -LDAPFilter $filter -SearchBase $Base -SearchScope Subtree -Properties DNSHostName,OperatingSystem,Enabled @connection -ErrorAction Stop)
        foreach($c in $computers){
            $target=if($c.DNSHostName){[string]$c.DNSHostName}else{[string]$c.Name}
            $null=Read-W10Names @($target)
            if(-not $target){throw 'AD computer has no usable name; discovery is incomplete.'}
            [pscustomobject]@{Name=[string]$c.Name;Target=$target;DirectoryOS=[string]$c.OperatingSystem;DirectoryEnabled=$c.Enabled;DirectoryDN=[string]$c.DistinguishedName}
        }
    }else{
        foreach($target in @(Read-W10Names $Names $List)){[pscustomobject]@{Name=$target;Target=$target;DirectoryOS='';DirectoryEnabled=$null;DirectoryDN=''}}
    }
}

function Invoke-W10Fleet {
    param([object[]]$Targets,[scriptblock]$Probe,[int]$Throttle,[int]$Timeout,[pscredential]$Access,[bool]$SSL,[string]$Customer,[string]$Site)
    $queue=New-Object Collections.Generic.Queue[object];foreach($target in $Targets){$queue.Enqueue($target)}
    $active=New-Object Collections.Generic.List[object]
    try{
        while($queue.Count -or $active.Count){
            while($queue.Count -and $active.Count -lt $Throttle){
                $target=$queue.Dequeue()
                try{
                    $options=New-PSSessionOption -OpenTimeout ([math]::Min(10000,$Timeout*1000)) -OperationTimeout ($Timeout*1000)
                    $arguments=@{ComputerName=$target.Target;ScriptBlock=$Probe;AsJob=$true;SessionOption=$options;ErrorAction='Stop'}
                    if($Access){$arguments.Credential=$Access};if($SSL){$arguments.UseSSL=$true}
                    $job=Invoke-Command @arguments
                    $active.Add([pscustomobject]@{Target=$target;Job=$job;Started=[datetime]::UtcNow})
                }catch{New-W10Row -Target $target -Source 'Live WinRM' -Problem $_.Exception.Message -Customer $Customer -Site $Site}
            }
            foreach($work in @($active.ToArray())){
                $timedOut=(([datetime]::UtcNow-$work.Started).TotalSeconds -ge $Timeout -and $work.Job.State -in 'Running','NotStarted')
                if($work.Job.State -in 'Running','NotStarted' -and -not $timedOut){continue}
                if($timedOut){Stop-Job -Job $work.Job -ErrorAction SilentlyContinue}
                $errors=@();$data=@(Receive-Job -Job $work.Job -ErrorAction SilentlyContinue -ErrorVariable +errors)
                $problem='';$raw=$null
                if($timedOut){$problem='Timed out; current OS is unknown.'}
                elseif($work.Job.State -ne 'Completed' -or $errors.Count){
                    $problem=(@($errors | ForEach-Object ToString) -join '; ')
                    if(-not $problem){$problem='Remote query failed. Check reachability, WinRM and permissions.'}
                }elseif($data.Count -ne 1){$problem='Remote query did not return exactly one OS record.'}
                else{$raw=$data[0]}
                New-W10Row -Raw $raw -Target $work.Target -Source 'Live WinRM' -Problem $problem -Customer $Customer -Site $Site
                Remove-Job -Job $work.Job -Force -ErrorAction SilentlyContinue;[void]$active.Remove($work)
            }
            if($active.Count){Start-Sleep -Milliseconds 100}
        }
    }finally{foreach($work in $active){Stop-Job -Job $work.Job -ErrorAction SilentlyContinue;Remove-Job -Job $work.Job -Force -ErrorAction SilentlyContinue}}
}

function Merge-W10Reports {
    param([string]$Folder,[string]$Expected,[int]$Days,[datetime]$Now)
    if(-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)){throw 'Merge needs -InputFolder containing this tool''s endpoint .win10.json files.'}
    $files=@(Get-ChildItem -LiteralPath $Folder -Filter '*.win10.json' -File -ErrorAction Stop)
    if(-not $files.Count){throw 'No endpoint .win10.json files found. Retrieve this tool''s raw Local reports; N-central wrappers/CSV exports are not accepted.'}
    $latest=@{};$identities=@{};$conflicts=@{};$problems=New-Object Collections.Generic.List[string]
    foreach($file in $files){
        try{
            if($file.Length -gt 5MB){throw 'File exceeds the 5 MB endpoint-report limit.'}
            $r=[IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
            if($r.Schema -ne 'Toolkit.Windows10.v1' -or $r.Mode -ne 'Local' -or @($r.Rows).Count -ne 1){throw 'Not a single-endpoint report from this tool.'}
            $row=$r.Rows[0]
            if(-not $row.ComputerName){throw 'Computer name missing.'}
            if([string]$row.CollectedAtUtc -notmatch '^\d{4}-\d{2}-\d{2}T.+(Z|[+-]\d{2}:\d{2})$'){throw 'Timestamp must contain an ISO date/time and timezone.'}
            $stamp=[datetimeoffset]::Parse([string]$row.CollectedAtUtc,[Globalization.CultureInfo]::InvariantCulture)
            if($stamp.UtcDateTime -gt $Now.AddMinutes(5)){throw 'Collection timestamp is in the future.'}
            $key=(@($row.CustomerName,$row.SiteName,$row.Domain,$row.ComputerName) -join [char]31).ToLowerInvariant()
            if($row.InstallationId){
                if($identities.ContainsKey($key) -and $identities[$key] -ne $row.InstallationId){$conflicts[$key]='Conflicting installation IDs for the same scoped computer name. Separate customer/site results or review reinstalled/renamed devices.'}
                else{$identities[$key]=[string]$row.InstallationId}
            }
            if($latest.ContainsKey($key) -and $stamp.UtcDateTime -eq $latest[$key].Time){
                $prior=$latest[$key].Row
                if((@($prior.Status,$prior.OSVersion,$prior.BuildNumber,$prior.ProductType) -join '|') -cne (@($row.Status,$row.OSVersion,$row.BuildNumber,$row.ProductType) -join '|')){$conflicts[$key]='Conflicting OS results at the same collection time. Recheck this computer.'}
            }
            if(-not $latest.ContainsKey($key) -or $stamp.UtcDateTime -gt $latest[$key].Time){$latest[$key]=[pscustomobject]@{Time=$stamp.UtcDateTime;Row=$row;Path=$file.FullName}}
        }catch{$problems.Add($file.Name+': '+$_.Exception.Message)}
    }
    if(-not $latest.Count){throw ('No valid endpoint reports. '+($problems -join '; '))}
    $rows=New-Object Collections.Generic.List[object]
    foreach($entryKey in $latest.Keys){
        $entry=$latest[$entryKey]
        $old=$entry.Row;$problem=''
        if($conflicts.ContainsKey($entryKey)){$problem=$conflicts[$entryKey]}
        elseif($old.Status -ne 'Checked'){$problem='Endpoint reported an incomplete check: '+$old.Error}
        elseif($entry.Time -lt $Now.AddDays(-$Days)){$problem='Report is older than '+$Days+' days. Recheck this PC.'}
        $row=New-W10Row -Raw $old -Target ([pscustomobject]@{Name=$old.ComputerName;Target=$old.RequestedComputerName}) -Source 'Imported endpoint report' -Problem $problem -Customer $old.CustomerName -Site $old.SiteName
        $rows.Add($row)
    }
    if(@($rows | Where-Object {-not $_.CustomerName -or -not $_.SiteName}).Count){$problems.Add('Some reports lack customer/site labels. Merge only one known site at a time; names alone cannot establish cross-customer coverage.')}
    $coverage='Received endpoint reports only; missing/offline targets cannot be counted without -ExpectedListPath.'
    if($Expected){
        $contexts=@($rows | ForEach-Object {@($_.CustomerName,$_.SiteName,$_.Domain) -join [char]31} | Sort-Object -Unique)
        if($contexts.Count -gt 1){throw 'Use one customer/site/domain per merge when supplying an expected computer-name list.'}
        $names=@(Read-W10Names -File $Expected)
        if(-not $names.Count){throw 'Expected computer list is empty.'}
        $present=@($rows | ForEach-Object ComputerName)
        foreach($name in $names){if($name -notin $present){$rows.Add((New-W10Row -Target ([pscustomobject]@{Name=$name;Target=$name}) -Source 'Expected target' -Problem 'No endpoint report received. Offline, unrun or uncollected; OS unknown.'))}}
        foreach($name in $present){if($name -notin $names){$problems.Add('Received a computer outside the expected list: '+$name)}}
        $coverage='Compared received computer names against the expected list. Use short computer names from the endpoint results.'
    }
    [pscustomobject]@{Rows=$rows.ToArray();Warnings=$problems.ToArray();Coverage=$coverage;ExpectedProvided=[bool]$Expected;Files=$files.Count}
}

function Export-W10Csv {
    param([object[]]$Rows,[string]$Path,[string[]]$Columns)
    if($Rows.Count){$Rows | Select-Object $Columns | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8}
    else{[IO.File]::WriteAllText($Path,(($Columns | ForEach-Object {'"'+$_+'"'}) -join ',')+"`r`n",(New-Object Text.UTF8Encoding($false)))}
}

if($Interactive){
    Write-Host '1. This PC (N-central uses this mode unattended)';Write-Host '2. Fleet from a computer-name TXT list';Write-Host '3. Fleet from Active Directory';Write-Host '4. Merge downloaded endpoint reports'
    switch((Read-Host 'Choose 1-4').Trim()){
        '1'{$Mode='Local'}
        '2'{$Mode='Fleet';$ComputerListPath=(Read-Host 'Path to computer-name TXT list').Trim('"')}
        '3'{$Mode='Fleet';$FromAD=$true;$SearchBase=(Read-Host 'OU/domain distinguished name (Enter for current domain)').Trim();$DirectoryServer=(Read-Host 'Domain controller (Enter for current domain)').Trim()}
        '4'{$Mode='Merge';$InputFolder=(Read-Host 'Folder containing downloaded .win10.json files').Trim('"');$ExpectedListPath=(Read-Host 'Expected computer-name TXT list (Enter if unavailable)').Trim('"')}
        default{throw 'No valid mode selected; no inventory was run.'}
    }
}
if($Display -and $OutputFormat -eq 'Json'){throw 'Choose -Display or -OutputFormat Json, not both.'}
if($Mode -ne 'Fleet' -and ($ComputerName -or $ComputerListPath -or $FromAD -or $SearchBase -or $DirectoryServer -or $EnabledOnly -or $Credential -or $UseSSL)){throw 'Fleet target/connection options require -Mode Fleet.'}
if($Mode -eq 'Fleet' -and -not $FromAD -and ($SearchBase -or $DirectoryServer -or $EnabledOnly)){throw 'AD options require -FromAD.'}
if($Mode -ne 'Merge' -and ($InputFolder -or $ExpectedListPath)){throw 'Import options require -Mode Merge.'}
$started=[datetime]::UtcNow;$encoding=New-Object Text.UTF8Encoding($false)
$report=[pscustomobject][ordered]@{
    Schema='Toolkit.Windows10.v1';Mode=$Mode;Collector=$env:COMPUTERNAME;StartedAtUtc=$started.ToString('o');CompletedAtUtc=''
    Status='Running';Coverage='';TargetCount=0;CheckedCount=0;Windows10Count=0;OtherCount=0;UnknownCount=0
    Warnings=@();Error='';Rows=@();SummaryPath='';AllCsvPath='';Windows10CsvPath='';NamesPath='';UnknownCsvPath='';JsonPath=''
}
if(-not $NoReport){
    $folder=Get-W10Folder $ReportPath
    $stem=Join-Path $folder ('Windows10_{0}_{1}_{2}' -f $env:COMPUTERNAME,$started.ToString('yyyyMMdd-HHmmss'),[guid]::NewGuid().ToString('N').Substring(0,8))
    $report.SummaryPath=$stem+'.txt';$report.AllCsvPath=$stem+'-All.csv';$report.Windows10CsvPath=$stem+'-Windows10.csv';$report.NamesPath=$stem+'-Windows10-Names.txt';$report.UnknownCsvPath=$stem+'-Unknown.csv';$report.JsonPath=$stem+'.win10.json'
    [IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 6),$encoding)
}
$rows=@();$fatal=$null
try{
    switch($Mode){
        'Local'{
            $target=[pscustomobject]@{Name=$env:COMPUTERNAME;Target=$env:COMPUTERNAME}
            try{$raw=& $probe;$rows=@(New-W10Row -Raw $raw -Target $target -Source 'Live local' -Customer $CustomerName -Site $SiteName)}
            catch{$rows=@(New-W10Row -Target $target -Source 'Live local' -Problem $_.Exception.Message -Customer $CustomerName -Site $SiteName)}
            $report.Coverage='This PC only. N-central must target each intended endpoint.'
        }
        'Fleet'{
            $targets=@(Get-W10Targets -AD ([bool]$FromAD) -Names $ComputerName -List $ComputerListPath -Base $SearchBase -Server $DirectoryServer -OnlyEnabled ([bool]$EnabledOnly) -Access $Credential | Sort-Object Target -Unique)
            if(-not $targets.Count){throw 'No fleet targets were returned. This is not a completed check of an empty fleet.'}
            $report.TargetCount=$targets.Count
            $report.Coverage=if($FromAD){'AD computers in the selected naming context/subtree; disabled accounts included unless -EnabledOnly. AD OS metadata is not live proof.'}else{'Only computers in the supplied list. No network discovery or inventory outside that list.'}
            if($Display){Write-Host ('Checking '+$targets.Count+' targets over existing WinRM. Unreachable or denied targets remain Unknown.')}
            $rows=@(Invoke-W10Fleet -Targets $targets -Probe $probe -Throttle $ThrottleLimit -Timeout $TimeoutSeconds -Access $Credential -SSL ([bool]$UseSSL) -Customer $CustomerName -Site $SiteName)
        }
        'Merge'{
            $merged=Merge-W10Reports -Folder $InputFolder -Expected $ExpectedListPath -Days $MaxAgeDays -Now $started
            $rows=@($merged.Rows);$report.Warnings=@($merged.Warnings);$report.Coverage=$merged.Coverage
            $report.Warnings+=('Imported results describe their collection time, not a new live check. Maximum accepted age: '+$MaxAgeDays+' days.')
        }
    }
    $rows=@($rows | Sort-Object CustomerName,SiteName,Domain,ComputerName)
    $report.Rows=$rows;$report.TargetCount=$rows.Count
    $report.CheckedCount=@($rows | Where-Object Status -eq 'Checked').Count
    $report.Windows10Count=@($rows | Where-Object {$_.IsWindows10 -eq $true}).Count
    $report.UnknownCount=@($rows | Where-Object Status -ne 'Checked').Count
    $report.OtherCount=$report.CheckedCount-$report.Windows10Count
    $report.Status=if($report.UnknownCount -or ($Mode -eq 'Merge' -and (-not $merged.ExpectedProvided -or $merged.Warnings.Count))){'Partial'}else{'Completed'}
    if($Mode -eq 'Local' -and $report.UnknownCount){$report.Status='Failed'}
}catch{$fatal=$_;$report.Status='Failed';$report.Error=$_.Exception.Message;$rows=@();$report.Rows=@()}
$report.CompletedAtUtc=[datetime]::UtcNow.ToString('o')
$text=New-Object Text.StringBuilder
[void]$text.AppendLine('WINDOWS 10 COMPUTER INVENTORY')
[void]$text.AppendLine(('Mode: {0}; Status: {1}; Collected (UTC): {2}' -f $Mode,$report.Status,$report.CompletedAtUtc))
[void]$text.AppendLine($report.Coverage)
[void]$text.AppendLine(('Targets: {0}; checked: {1}; Windows 10: {2}; other OS: {3}; unknown: {4}' -f $report.TargetCount,$report.CheckedCount,$report.Windows10Count,$report.OtherCount,$report.UnknownCount))
[void]$text.AppendLine('Unknown or missing results do not mean a PC has been upgraded. Read the Unknown CSV and RMM target/task status.')
[void]$text.AppendLine('This does not assess Windows 11 hardware readiness, ESU enrollment or edition-specific support entitlement.')
if($report.Error){[void]$text.AppendLine('FAILED: '+$report.Error)}
foreach($warning in $report.Warnings){[void]$text.AppendLine('NOTE: '+$warning)}
$matches=@($rows | Where-Object {$_.IsWindows10 -eq $true})
[void]$text.AppendLine('');[void]$text.AppendLine('WINDOWS 10 NAMES (within this report scope, as of each check)')
if($matches.Count){foreach($row in $matches){[void]$text.AppendLine(('  {0} | {1} | {2} | build {3} | {4}' -f $row.ComputerName,$row.CustomerName,$row.OSName,$row.BuildNumber,$row.CollectedAtUtc))}}
else{[void]$text.AppendLine('  No confirmed Windows 10 rows in the available checks. Review coverage/unknowns.')}
if(-not $NoReport){
    if(-not $fatal){
        $columns=@((New-W10Row -Target ([pscustomobject]@{Name='';Target=''}) -Source '').PSObject.Properties.Name)
        Export-W10Csv $rows $report.AllCsvPath $columns
        Export-W10Csv $matches $report.Windows10CsvPath $columns
        Export-W10Csv @($rows | Where-Object Status -ne 'Checked') $report.UnknownCsvPath $columns
        $names=@($matches | ForEach-Object ComputerName | Sort-Object -Unique)
        [IO.File]::WriteAllText($report.NamesPath,($names -join "`r`n")+$(if($names.Count){"`r`n"}else{''}),$encoding)
        [void]$text.AppendLine("`r`nNames: "+$report.NamesPath);[void]$text.AppendLine('Windows 10 details: '+$report.Windows10CsvPath);[void]$text.AppendLine('Unknown/failures: '+$report.UnknownCsvPath)
    }
    [IO.File]::WriteAllText($report.SummaryPath,$text.ToString(),$encoding)
    [IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 6),$encoding)
}
if($OutputFormat -eq 'Json'){$report | ConvertTo-Json -Depth 6 -Compress}
elseif($Display){Write-Host $text.ToString();if($report.JsonPath){Write-Host ('Endpoint/merge JSON: '+$report.JsonPath)}}
else{$rows}
if($fatal){throw $report.Error}
if($Mode -eq 'Local' -and $report.Status -eq 'Failed'){throw 'Local OS check failed. Read the Unknown row/report.'}
