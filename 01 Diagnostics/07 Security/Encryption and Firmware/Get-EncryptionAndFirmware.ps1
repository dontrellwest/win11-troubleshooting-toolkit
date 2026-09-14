<#
.SYNOPSIS
    Report BitLocker protector IDs, TPM, Secure Boot and device security.
.DESCRIPTION
    Read-only diagnostics. Missing or restricted data is reported as unknown.
.PARAMETER Display
    Show the report instead of emitting objects.
.PARAMETER ReportPath
    Save the displayed report to this folder.
.EXAMPLE
    .\Get-EncryptionAndFirmware.ps1 -Display
.NOTES
    Toolkit-Class: ReadOnly
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Requires Windows PowerShell 5.1. Inbox modules only.
#>
[CmdletBinding()]
param([switch]$Display, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
# ---------------------------------------------------------------- toolkit helpers (verbatim, do not edit)
$script:ToolName  = 'Get-EncryptionAndFirmware'
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



function Get-RegistryValues {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) { Get-ItemProperty -LiteralPath $Path -ErrorAction Stop }
    } catch { Add-Warning ("Registry {0}: {1}" -f $Path, $_.Exception.Message) }
}
function Copy-Fields {
    param($Target, $Source, [string[]]$Names)
    if ($null -ne $Source) { foreach ($n in $Names) { if ($null -ne $Source.$n) { $Target[$n] = $Source.$n } } }
}
function Get-WindowEvents {
    param([string]$LogName, [int[]]$Id, [int]$Days = 30, [int]$MaxEvents = 1000)
    $filter = @{LogName=$LogName; StartTime=[DateTime]::Now.AddDays(-$Days)}
    if ($Id) { $filter.Id = $Id }
    try { Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}
function Get-OptionalDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { $date = [datetime]$Value; if ($date.Year -gt 1900) { $date } } catch { }
}
function Get-AgeDays {
    param($Value)
    $date = Get-OptionalDate $Value
    if ($null -ne $date) { [int][math]::Floor(([DateTime]::Now - $date).TotalDays) }
}
function Convert-PolicyValue {
    param($Value, [hashtable]$Map)
    if ($null -eq $Value) { return $null }
    $key = [int]$Value
    if ($Map.ContainsKey($key)) { $Map[$key] } else { "Unknown ($Value)" }
}

$admin=Test-IsAdmin
$o=[ordered]@{ComputerName=$env:COMPUTERNAME;CollectedAt=[datetime]::Now;Elevated=$admin;FirmwareType=$null;SecureBootEnabled=$null;TpmPresent=$null;TpmReady=$null;TpmEnabled=$null;TpmActivated=$null;TpmOwned=$null;TpmVersion=$null;TpmManufacturer=$null;TpmFirmware=$null;TpmLockedOut=$null;TpmAutoProvisioning=$null;VbsStatus=$null;CredentialGuard=$null;Hvci=$null;SystemGuard=$null;RunAsPPL=$null;KernelDmaProtection=$null;VbsAvailableProperties=$null;Win11BaselineOk=$null;BaselineGaps='';SystemDriveEncrypted=$null;SystemDriveProtection=$null;VolumesEncrypted=$null;VolumesUnencrypted=$null;RecoveryKeyEscrow='Unknown';RecoveryKeyLastBackup=$null;RecoveryKeyBackupFailed=$null;Volumes=@();Warnings=''}
$secure=Get-RegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
if($null -ne $secure.UEFISecureBootEnabled){$o.SecureBootEnabled=($secure.UEFISecureBootEnabled -eq 1);$o.FirmwareType='UEFI'}
elseif($env:firmware_type -in 'UEFI','Legacy'){$o.FirmwareType=$env:firmware_type}
else{Add-Warning 'Firmware type and Secure Boot state could not be established from the available values.'}
if($admin){
    $confirmed=Invoke-Section 'Secure Boot confirmation' {Confirm-SecureBootUEFI -ErrorAction Stop}
    if($null -ne $confirmed){$o.SecureBootEnabled=[bool]$confirmed;$o.FirmwareType='UEFI'}
    $tpm=Invoke-Section 'TPM state' {Get-Tpm -ErrorAction Stop}
    Copy-Fields $o $tpm @('TpmPresent','TpmReady','TpmEnabled','TpmActivated','TpmOwned')
    if($tpm){$o.TpmLockedOut=$tpm.LockedOut;$o.TpmAutoProvisioning=[string]$tpm.AutoProvisioning}
    $detail=Invoke-Section 'TPM firmware' {Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop}
    if($detail){$o.TpmVersion=([string]$detail.SpecVersion -split ',')[0].Trim();$o.TpmManufacturer=[string]$detail.ManufacturerIdTxt;$o.TpmFirmware=[string]$detail.ManufacturerVersion}
}else{
    $o.TpmVersion='(needs admin)';$o.TpmManufacturer='(needs admin)';$o.TpmFirmware='(needs admin)';$o.TpmAutoProvisioning='(needs admin)'
    Add-Warning 'TPM and full BitLocker information need admin access.'
}
$device=Invoke-Section 'Device Guard' {Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop}
if($device){
    $o.VbsStatus=Convert-PolicyValue $device.VirtualizationBasedSecurityStatus @{0='Not enabled';1='Enabled, not running';2='Running'}
    foreach($pair in @(@('CredentialGuard',1),@('Hvci',2),@('SystemGuard',3))){
        $o[$pair[0]]=if($device.SecurityServicesRunning -contains $pair[1]){'Running'}elseif($device.SecurityServicesConfigured -contains $pair[1]){'Configured'}else{'Off'}
    }
    $available=@{1='Base VBS';2='Secure Boot';3='DMA protection';4='Secure memory overwrite';5='UEFI code read-only';6='SMM mitigations';7='MBEC';8='APIC virtualization'}
    $o.VbsAvailableProperties=(@($device.AvailableSecurityProperties | ForEach-Object {Convert-PolicyValue $_ $available}) -join '; ')
}
$lsa=Get-RegistryValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
if($null -ne $lsa.RunAsPPL){$o.RunAsPPL=($lsa.RunAsPPL -in 1,2)}
Add-Warning 'Kernel DMA protection and effective LSASS protection are not inferred from capabilities or missing policy values.'
if($admin){
    $o.Volumes=@(Invoke-Section 'BitLocker volumes' {
        $volumes=@(Get-BitLockerVolume -ErrorAction Stop)
        $o.VolumesEncrypted=[int]@($volumes | Where-Object {$_.VolumeStatus -eq 'FullyEncrypted'}).Count
        $o.VolumesUnencrypted=[int]@($volumes | Where-Object {$_.VolumeStatus -eq 'FullyDecrypted'}).Count
        foreach($v in $volumes){
            if($v.MountPoint -eq $env:SystemDrive){
                $o.SystemDriveProtection=[string]$v.ProtectionStatus
                if($v.VolumeStatus -eq 'FullyEncrypted'){$o.SystemDriveEncrypted=$true}
                elseif($v.VolumeStatus -eq 'FullyDecrypted'){$o.SystemDriveEncrypted=$false}
            }
            [pscustomobject]@{MountPoint=[string]$v.MountPoint;VolumeType=[string]$v.VolumeType;CapacityGB=(Round1 $v.CapacityGB);VolumeStatus=[string]$v.VolumeStatus;ProtectionStatus=[string]$v.ProtectionStatus;EncryptionMethod=[string]$v.EncryptionMethod;EncryptionPercentage=[int]$v.EncryptionPercentage;KeyProtectors=(@($v.KeyProtector | ForEach-Object KeyProtectorType) -join '; ');RecoveryKeyIds=(@($v.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | ForEach-Object KeyProtectorId) -join '; ');AutoUnlock=$v.AutoUnlockEnabled}
        }
    } -Default @())
}else{
    $o.Volumes=@(Invoke-Section 'Explorer encryption indicators' {
        $shell=New-Object -ComObject Shell.Application
        foreach($v in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)){
            $state=$null
            try{$folder=$shell.NameSpace($v.DeviceID+'\');if($folder){$raw=$folder.Self.ExtendedProperty('System.Volume.BitLockerProtection');$state=Convert-PolicyValue $raw @{1='On';2='Off';3='Encrypting';4='Decrypting';5='Suspended';6='Locked'}}}catch{Add-Warning ("Encryption indicator "+$v.DeviceID+': '+$_.Exception.Message)}
            if($v.DeviceID -eq $env:SystemDrive){$o.SystemDriveProtection=$state}
            [pscustomobject]@{MountPoint=$v.DeviceID;VolumeType='Fixed';CapacityGB=(Round1 ($v.Size/1GB));VolumeStatus=$null;ProtectionStatus=$state;EncryptionMethod=$null;EncryptionPercentage=$null;KeyProtectors='(needs admin)';RecoveryKeyIds='(needs admin)';AutoUnlock=$null}
        }
    } -Default @())
}
$gaps=@()
if($o.FirmwareType -eq 'Legacy'){$gaps+='Legacy firmware'}
if($null -ne $o.SecureBootEnabled -and -not $o.SecureBootEnabled){$gaps+='Secure Boot disabled'}
if($null -ne $o.TpmPresent -and -not $o.TpmPresent){$gaps+='TPM absent'}
if($null -ne $o.TpmReady -and -not $o.TpmReady){$gaps+='TPM not ready'}
if($o.TpmVersion -and $o.TpmVersion -ne '(needs admin)' -and $o.TpmVersion -ne '2.0'){$gaps+='TPM version is not 2.0'}
if($gaps.Count){$o.Win11BaselineOk=$false}
elseif($o.FirmwareType -eq 'UEFI' -and $o.SecureBootEnabled -eq $true -and $o.TpmPresent -eq $true -and $o.TpmReady -eq $true -and $o.TpmVersion -eq '2.0'){$o.Win11BaselineOk=$true}
$o.BaselineGaps=$gaps -join '; '
$policy=Get-RegistryValues 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if($policy.OSActiveDirectoryBackup -eq 1){$o.RecoveryKeyEscrow='AD policy configured; backup not verified'}
Add-Warning 'Recovery-key backup success is not established by policy. Verify the protector ID in AD or Entra. No recovery passwords are collected.'
Add-Warning 'Win11BaselineOk covers firmware, Secure Boot and TPM only; CPU, storage and other compatibility requirements are not checked.'
$o.Warnings=$script:Warnings -join '; ';$result=[pscustomobject]$o
if($Display){$result | Show-Result -Title $script:ToolName -ReportPath $ReportPath}else{$result}
