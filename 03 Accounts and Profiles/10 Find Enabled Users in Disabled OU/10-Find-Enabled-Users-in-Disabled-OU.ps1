<#
.SYNOPSIS
    Find enabled AD user accounts still inside a disabled-users OU.
.DESCRIPTION
    Read-only Active Directory query. Searches the selected OU and sub-OUs
    by default. Saves TXT, CSV and JSON reports. Does not change AD objects.
.EXAMPLE
    .\10-Find-Enabled-Users-in-Disabled-OU.ps1 -Interactive -Display
.EXAMPLE
    .\10-Find-Enabled-Users-in-Disabled-OU.ps1 -SearchBase 'OU=Disabled Users,DC=example,DC=com' -Server 'dc01.example.com' -Display
.EXAMPLE
    .\10-Find-Enabled-Users-in-Disabled-OU.ps1 -OUName 'Disabled Accounts' -SearchScope OneLevel -Credential (Get-Credential)
.NOTES
    Toolkit-Class: Diagnostic
    Toolkit-Context: Domain
    Toolkit-Elevation: None
    Windows PowerShell 5.1. Requires the ActiveDirectory (RSAT) module.
    Enabled means the account is not disabled, not that it recently signed in.
    This standalone tool does not use the shared runtime or Fleet runner.
#>
[CmdletBinding()]
param(
    [switch]$Display,
    [switch]$Interactive,
    [ValidateNotNullOrEmpty()][string]$OUName='Disabled Users',
    [Alias('OU')][string]$SearchBase,
    [ValidateSet('Subtree','OneLevel')][string]$SearchScope='Subtree',
    [string]$Server,
    [pscredential]$Credential,
    [ValidateNotNullOrEmpty()][string]$ReportPath='C:\Temp\Toolkit'
)
$ErrorActionPreference='Stop'

function ConvertTo-OULdapValue {
    param([string]$Value)
    $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}

function Initialize-ADQuery {
    try {Import-Module ActiveDirectory -ErrorAction Stop}
    catch {throw 'The ActiveDirectory PowerShell module is unavailable. Run this tool on a PC with RSAT AD tools or a domain controller. No directory query was completed.'}
}

function Resolve-DisabledOU {
    param([hashtable]$Connection,[string]$DefaultNamingContext,[string]$Name,[string]$ExactDN,[bool]$Choose)
    if ($ExactDN) {
        # Validate that the supplied object actually is an OU; never fall back to the domain.
        return Get-ADOrganizationalUnit -Identity $ExactDN @Connection -ErrorAction Stop
    }
    $filter='(name='+(ConvertTo-OULdapValue $Name)+')'
    $ous=@(Get-ADOrganizationalUnit -LDAPFilter $filter -SearchBase $DefaultNamingContext -SearchScope Subtree @Connection -ErrorAction Stop | Sort-Object DistinguishedName)
    if ($ous.Count -eq 0) {throw ('No OU named "'+$Name+'" was found in '+$DefaultNamingContext+'. Supply -OUName or the exact -SearchBase OU distinguished name.')}
    if ($ous.Count -eq 1) {return $ous[0]}
    if (-not $Choose) {throw ("Multiple matching OUs were found. Supply one exact -SearchBase, or use -Interactive.`r`n"+($ous.DistinguishedName -join "`r`n"))}
    for ($i=0;$i -lt $ous.Count;$i++) {Write-Host ('{0}. {1}' -f ($i+1),$ous[$i].DistinguishedName)}
    $answer=Read-Host 'Choose the OU number to check (blank cancels)'
    $selection=0
    if (-not [int]::TryParse($answer,[ref]$selection) -or $selection -lt 1 -or $selection -gt $ous.Count) {throw 'No valid OU was selected. No user query was run.'}
    $ous[$selection-1]
}

function Get-ADReportFolder {
    param([string]$Path)
    $provider=$null;$drive=$null
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path,[ref]$provider,[ref]$drive)
    if ($provider.Name -ne 'FileSystem') {throw 'ReportPath must be a filesystem folder.'}
    $walk=$full
    while ($walk) {
        if (Test-Path -LiteralPath $walk) {
            $item=Get-Item -LiteralPath $walk -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw ('Report path contains a link or junction: '+$walk)}
        }
        $parent=[IO.Path]::GetDirectoryName($walk)
        if ($parent -eq $walk) {break}
        $walk=$parent
    }
    $null=[IO.Directory]::CreateDirectory($full)
    $full
}

$folder=Get-ADReportFolder $ReportPath
$started=[datetime]::Now
$stem=Join-Path $folder ('EnabledUsersInDisabledOU_{0}_{1}_{2}' -f $env:COMPUTERNAME,$started.ToString('yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8)))
$encoding=New-Object Text.UTF8Encoding($false)
$report=[pscustomobject][ordered]@{
    ComputerName=$env:COMPUTERNAME; CollectedAt=$started; Status='NotCompleted'
    DomainController=$Server; SearchBase=$SearchBase; SearchScope=$SearchScope
    EnabledUserCount=$null; Users=@(); Error=''
    Meaning='Enabled=True only. Does not prove a recent sign-in or check disabled-group membership.'
    TextPath=($stem+'.txt'); CsvPath=($stem+'.csv'); JsonPath=($stem+'.json')
}
# Confirm reports can be written before doing a potentially long directory query.
[IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 5),$encoding)
$rows=@();$failure=$null
try {
    Initialize-ADQuery
    if ($Interactive) {
        if (-not $Server) {$Server=([string](Read-Host 'Domain controller hostname (Enter for current domain)')).Trim()}
        if (-not $SearchBase -and -not $PSBoundParameters.ContainsKey('OUName')) {
            $inputOU=([string](Read-Host 'OU name or OU distinguished name (Enter for Disabled Users)')).Trim()
            if ($inputOU -match '^OU=.+,') {$SearchBase=$inputOU}
            elseif ($inputOU) {$OUName=$inputOU}
        }
    }
    $connection=@{}
    if ($Server) {$connection.Server=$Server}
    if ($Credential) {$connection.Credential=$Credential}
    try {$rootDse=Get-ADRootDSE @connection -ErrorAction Stop}
    catch {throw ('Cannot contact Active Directory. Check VPN/network access, directory permissions and -Server. '+$_.Exception.Message)}
    if (-not $rootDse.dnsHostName -or -not $rootDse.defaultNamingContext) {throw 'The server did not return an AD domain naming context and DC hostname.'}
    # Pin OU resolution and user enumeration to the same DC.
    $connection.Server=[string]$rootDse.dnsHostName
    $report.DomainController=$connection.Server
    $ou=Resolve-DisabledOU -Connection $connection -DefaultNamingContext $rootDse.defaultNamingContext -Name $OUName -ExactDN $SearchBase -Choose ([bool]$Interactive)
    if (-not $ou.DistinguishedName) {throw 'OU resolution returned no distinguished name. No user query was run.'}
    $report.SearchBase=[string]$ou.DistinguishedName
    if ($Display -or $Interactive) {Write-Host ('Checking: '+$report.SearchBase);Write-Host ('Server: '+$report.DomainController+'; scope: '+$SearchScope)}
    # Microsoft's enabled-account LDAP filter; UAC bit 2 is ACCOUNTDISABLE.
    # Get-ADUser limits this query to users. No client-side domain-wide scan.
    $users=@(Get-ADUser -LDAPFilter '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' -SearchBase $report.SearchBase -SearchScope $SearchScope -Properties whenChanged @connection -ErrorAction Stop)
    $rows=@(foreach ($user in $users | Sort-Object SamAccountName,DistinguishedName) {
        [pscustomobject][ordered]@{
            ComputerName=$env:COMPUTERNAME; CollectedAt=$started
            DomainController=$report.DomainController; SearchBase=$report.SearchBase; SearchScope=$SearchScope
            Name=[string]$user.Name; SamAccountName=[string]$user.SamAccountName
            UserPrincipalName=[string]$user.UserPrincipalName; Enabled=[bool]$user.Enabled
            DistinguishedName=[string]$user.DistinguishedName; WhenChanged=$user.whenChanged
        }
    })
    $report.EnabledUserCount=$rows.Count;$report.Users=$rows
    $columns=@('ComputerName','CollectedAt','DomainController','SearchBase','SearchScope','Name','SamAccountName','UserPrincipalName','Enabled','DistinguishedName','WhenChanged')
    if ($rows.Count) {$rows | Export-Csv -LiteralPath $report.CsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop}
    else {[IO.File]::WriteAllText($report.CsvPath,(($columns | ForEach-Object {'"'+$_+'"'}) -join ',')+"`r`n",$encoding)}
    $report.Status='Completed'
} catch {
    $failure=$_;$report.Status='Failed';$report.EnabledUserCount=$null;$report.Users=@();$rows=@()
    $report.Error=$_.Exception.Message
}
$text=New-Object Text.StringBuilder
[void]$text.AppendLine('ENABLED USERS IN DISABLED OU')
[void]$text.AppendLine(('Checked: {0:o} | Status: {1}' -f $started,$report.Status))
[void]$text.AppendLine('Domain controller: '+$report.DomainController)
[void]$text.AppendLine('OU: '+$report.SearchBase)
[void]$text.AppendLine('Scope: '+$SearchScope+' (Subtree includes child OUs; OneLevel is direct users only)')
[void]$text.AppendLine($report.Meaning)
[void]$text.AppendLine('WhenChanged is any account change, not the date it was re-enabled.')
if ($failure) {[void]$text.AppendLine('QUERY FAILED - no complete result: '+$report.Error)}
else {
    [void]$text.AppendLine(('Enabled accounts found: {0}' -f $rows.Count))
    if ($rows.Count) {[void]$text.AppendLine(($rows | Select-Object Name,SamAccountName,UserPrincipalName,DistinguishedName,WhenChanged | Format-List | Out-String -Width 240))}
    else {[void]$text.AppendLine('No enabled user accounts were returned in this OU and scope by this DC. Results are limited to what this account can read.')}
    [void]$text.AppendLine('CSV: '+$report.CsvPath)
}
[IO.File]::WriteAllText($report.TextPath,$text.ToString(),$encoding)
[IO.File]::WriteAllText($report.JsonPath,($report | ConvertTo-Json -Depth 5),$encoding)
if ($Display) {Write-Host $text.ToString();Write-Host ('Report: '+$report.TextPath)}
else {Write-Verbose ('Report: '+$report.TextPath)}
if ($failure) {throw ('{0} Report: {1}' -f $report.Error,$report.TextPath)}
if (-not $Display) {$rows}
