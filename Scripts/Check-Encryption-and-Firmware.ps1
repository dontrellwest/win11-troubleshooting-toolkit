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
    .\Check-Encryption-and-Firmware.ps1 -Display
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
$script:ToolName  = 'Check-Encryption-and-Firmware'
$script:Warnings  = New-Object System.Collections.Generic.List[string]
$script:Findings  = New-Object System.Collections.Generic.List[object]

function Add-Warning { param([string]$Message) $script:Warnings.Add($Message) }

# '1 crash' / '3 crashes': a count with the singular or plural noun, for summary text.
function Format-Count { param([int]$Count, [string]$One, [string]$Many) if ($Count -eq 1) { '1 ' + $One } else { '{0} {1}' -f $Count, $Many } }

# Plain-language summary line for -Display. Level: Problem | Warning | NotChecked | Info | OK. Next: what to do about it.
function Add-Finding {
    param([ValidateSet('Problem', 'Warning', 'NotChecked', 'Info', 'OK')][string]$Level, [string]$Text, [string]$Next)
    $script:Findings.Add([PSCustomObject]@{ Level = $Level; Text = $Text; Next = $Next })
}

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

# Readable report for -Display. With -About/-Findings/-NextSteps/-Result a plain-language SUMMARY comes first
# (result line, then findings ranked by severity, each with its next step) and the RESULT is repeated at the end.
# DETAILS: scalars as a list, array properties as tables (never silently dropping columns).
function Show-Result {
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [string]$Title, [string]$ReportPath,
          [string]$About, [object[]]$Findings, [string[]]$NextSteps, [string]$Result)
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
        # Word-wraps summary text at 78 columns: the first line starts with $Lead, later lines align under it.
        $wrap = {
            param([string]$Text, [string]$Lead)
            $pad = ' ' * $Lead.Length; $line = $Lead; $has = $false
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($word in @(('{0}' -f $Text).Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)') -split '\s+' | Where-Object { $_ })) {
                if ($has -and ($line.Length + 1 + $word.Length) -gt 78) { $out.Add($line); $line = $pad; $has = $false }
                if ($has) { $line += ' ' + $word } else { $line += $word; $has = $true }
            }
            if ($has) { $out.Add($line) }
            $out.ToArray()
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine(('  {0}   {1}   {2}' -f $Title, $env:COMPUTERNAME, [DateTime]::Now.ToString('yyyy-MM-dd HH:mm')))
        [void]$sb.AppendLine(('=' * 78))
        $found = @($Findings | Where-Object { $null -ne $_ })
        $summary = [bool]($About -or $found.Count -or $NextSteps -or $Result)
        if ($summary) {
            if ($About) { foreach ($l in (& $wrap $About '  ')) { [void]$sb.AppendLine($l) }; [void]$sb.AppendLine('') }
            $rank  = @{ Problem = 0; Warning = 1; NotChecked = 2; Info = 3; OK = 4 }
            $label = @{ Problem = 'PROBLEM'; Warning = 'WARNING'; NotChecked = 'NOT CHECKED'; Info = 'INFO'; OK = 'OK' }
            $n = @{}; foreach ($k in @($rank.Keys)) { $n[$k] = @($found | Where-Object { [string]$_.Level -eq $k }).Count }
            $counts = @()
            if ($n.Problem)    { $counts += $(if ($n.Problem -eq 1) { '1 problem' } else { '{0} problems' -f $n.Problem }) }
            if ($n.Warning)    { $counts += $(if ($n.Warning -eq 1) { '1 warning' } else { '{0} warnings' -f $n.Warning }) }
            if ($n.NotChecked) { $counts += $(if ($n.NotChecked -eq 1) { '1 item not checked' } else { '{0} items not checked' -f $n.NotChecked }) }
            if (-not $Result) {
                if ($n.Problem)        { $Result = 'ACTION NEEDED - {0}.' -f ($counts -join ', ') }
                elseif ($n.Warning)    { $Result = 'REVIEW - {0}. No problems found.' -f ($counts -join ', ') }
                elseif ($n.NotChecked) { $Result = 'INCOMPLETE - {0}. Nothing else needs attention.' -f ($counts -join ', ') }
                else                   { $Result = 'NO PROBLEMS FOUND by this check.' }
            }
            [void]$sb.AppendLine('SUMMARY'); [void]$sb.AppendLine('-------')
            foreach ($l in (& $wrap $Result '  RESULT: ')) { [void]$sb.AppendLine($l) }
            $ranked = New-Object System.Collections.Generic.List[object]
            for ($k = 0; $k -lt $found.Count; $k++) {
                $lv = [string]$found[$k].Level; $r = 3; if ($rank.ContainsKey($lv)) { $r = $rank[$lv] }
                $ranked.Add([PSCustomObject]@{ Rank = $r; Index = $k; Finding = $found[$k] })
            }
            if ($ranked.Count) { [void]$sb.AppendLine('') }
            foreach ($e in @($ranked | Sort-Object Rank, Index)) {
                $lv = [string]$e.Finding.Level; $tag = $lv.ToUpper(); if ($label.ContainsKey($lv)) { $tag = $label[$lv] }
                foreach ($l in (& $wrap $e.Finding.Text ('  ' + $tag.PadRight(13)))) { [void]$sb.AppendLine($l) }
                if ($e.Finding.Next) { foreach ($l in (& $wrap $e.Finding.Next ((' ' * 15) + 'Next: '))) { [void]$sb.AppendLine($l) } }
            }
            if ($NextSteps) {
                [void]$sb.AppendLine(''); [void]$sb.AppendLine('NEXT STEPS'); [void]$sb.AppendLine('----------')
                foreach ($s in $NextSteps) { if ($s) { foreach ($l in (& $wrap $s '  - ')) { [void]$sb.AppendLine($l) } } }
            }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('DETAILS'); [void]$sb.AppendLine('-------')
        }
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
        if ($summary) {
            [void]$sb.AppendLine(('-' * 78))
            foreach ($l in (& $wrap ($Result + ' The summary and next steps are at the top of this report.') '  RESULT: ')) { [void]$sb.AppendLine($l) }
        }
        # Registered, trademark and copyright signs (from device and product names) and invisible direction marks, as ASCII.
        $text = $sb.ToString().Replace([string][char]0x00AE, '(R)').Replace([string][char]0x2122, '(TM)').Replace([string][char]0x00A9, '(C)').Replace([string][char]0x200E, '').Replace([string][char]0x200F, '')
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

# ---------------------------------------------------------------- plain-language summary (-Display only)
$script:SummaryAbout = 'Disk encryption and hardware security: BitLocker on each fixed drive and its recovery key protectors, TPM, Secure Boot, UEFI firmware, and virtualization-based protections (memory integrity, Credential Guard).'
$script:SummaryNext = @(
    'Before any BIOS, firmware, TPM or Secure Boot change, find the BitLocker recovery key: in Active Directory or Entra ID (Intune) for a business PC, or at account.microsoft.com/devices/recoverykey for a personal Microsoft account. Match the key ID from DETAILS (it needs an elevated run). Otherwise the PC may ask for a key nobody has.',
    'Drive not encrypted or protection suspended: follow the site''s encryption policy; suspended protection usually resumes after a restart.',
    'TPM or Secure Boot off: change firmware settings only with the site''s approval, and suspend BitLocker first.'
)
function Add-SummaryFindings {
    param($R)
    $admin = 'Run Security - Check Security.cmd again and approve the admin prompt.'
    # Where the recovery key is normally kept depends on how the PC is joined (read for this summary only).
    $homeEdition = $false; $keyHome = 'the user''s Microsoft account (account.microsoft.com/devices/recoverykey), or wherever it was saved or printed'
    try {
        $homeEdition = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption -match 'Home'
        $joined = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
        $entra = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue).Count -gt 0
        if ($joined -and $entra) { $keyHome = 'Active Directory or Entra ID (Intune)' } elseif ($joined) { $keyHome = 'Active Directory (the computer object''s BitLocker Recovery tab)' } elseif ($entra) { $keyHome = 'Entra ID or Intune (the device''s BitLocker keys)' }
    } catch {}
    $name = $(if ($homeEdition) { 'Device encryption (BitLocker)' } else { 'BitLocker' })
    $sys = [string]$R.SystemDriveProtection
    if ($sys -eq 'On') { Add-Finding OK ('{0} protects the system drive.' -f $name) }
    elseif ($sys -eq 'Suspended') { Add-Finding Warning ('{0} protection is suspended on the system drive: it is encrypted but not protected.' -f $name) $(if ($homeEdition) { 'It usually resumes after a restart. If it stays suspended, turn it back on in Settings > Privacy & security > Device encryption.' } else { 'It usually resumes after a restart. If it stays suspended, resume it in Control Panel > BitLocker Drive Encryption.' }) }
    elseif ($sys -match 'Encrypting|Decrypting') { Add-Finding Info ('{0} is {1} the system drive.' -f $name, $sys.ToLower()) 'Leave the PC on and plugged in until it finishes.' }
    elseif ($sys -eq 'Off') { Add-Finding Warning ('The system drive is not encrypted ({0} is off).' -f $name) 'Follow the site''s encryption policy; a lost or stolen PC exposes its data.' }
    if ($R.VolumesUnencrypted) { Add-Finding Info ('Other fixed drives not encrypted: {0}.' -f $R.VolumesUnencrypted) }
    if ($R.RecoveryKeyBackupFailed) { Add-Finding Problem 'Backing up the BitLocker recovery key to AD or Entra failed.' 'Back up the key to AD or Entra now, before any hardware or firmware change.' }
    elseif ($sys -in 'On', 'Suspended') {
        $sysVolume = @($R.Volumes | Where-Object { [string]$_.MountPoint -eq $env:SystemDrive }) | Select-Object -First 1
        $ids = [string]$sysVolume.RecoveryKeyIds
        $policy = $(if ($R.RecoveryKeyEscrow -and $R.RecoveryKeyEscrow -ne 'Unknown') { ' (' + $R.RecoveryKeyEscrow + ')' } else { '' })
        $next = $(if ($ids -and $ids -ne '(needs admin)') { 'Before any BIOS, TPM or Secure Boot change, find the key with ID ' + $ids + ' there.' } else { 'Before any BIOS, TPM or Secure Boot change, run Security - Check Security.cmd and approve the admin prompt to see the key ID, then find that key there.' })
        Add-Finding Warning ('The BitLocker recovery key backup is not confirmed by this PC{0}. It is normally kept in {1}.' -f $policy, $keyHome) $next
    }
    if ($R.TpmPresent -eq $false) { Add-Finding Problem 'No TPM was found. Windows 11 and BitLocker with TPM need one.' 'Check that the TPM (or Intel PTT / AMD fTPM) is enabled in the firmware settings.' }
    elseif ($R.TpmPresent -and $R.TpmReady -eq $false) { Add-Finding Warning 'A TPM is present but not ready for use.' 'Open tpm.msc to see why; clearing or preparing a TPM needs the site''s approval.' }
    elseif ($R.TpmPresent -and $R.TpmVersion -and $R.TpmVersion -ne '2.0') { Add-Finding Warning ('The TPM is version {0}; Windows 11 needs 2.0.' -f $R.TpmVersion) 'Check whether a firmware update or setting enables TPM 2.0.' }
    elseif ($R.TpmReady) { Add-Finding OK ('TPM {0} is present and ready.' -f $R.TpmVersion) }
    if ($R.SecureBootEnabled -eq $false) { Add-Finding Warning 'Secure Boot is off.' 'Turn it on in the firmware settings only with the site''s approval, and suspend BitLocker first.' }
    elseif ($R.SecureBootEnabled) { Add-Finding OK ('Secure Boot is on ({0} firmware).' -f $R.FirmwareType) }
    if ($R.FirmwareType -eq 'Legacy') { Add-Finding Warning 'The PC boots in legacy BIOS mode, not UEFI, so Secure Boot is not possible.' 'Converting to UEFI (MBR2GPT) is a planned change, not a quick fix.' }
    if ($R.Win11BaselineOk -eq $false -and $R.BaselineGaps) { Add-Finding Warning ('Windows 11 security baseline gaps: {0}.' -f $R.BaselineGaps) 'Fix them in the firmware settings with the site''s approval, or plan a hardware replacement if the PC cannot meet them.' }
    if ($R.Hvci) {
        $state = @{ Running = 'on'; Configured = 'set up but not running yet (a restart or an incompatible driver)'; Off = 'off' }
        $cg = $(if ($R.CredentialGuard -eq 'Running') { 'Credential Guard is on.' } else { 'Credential Guard is ' + $state[[string]$R.CredentialGuard] + ', which is normal unless the site requires it (it is an Enterprise and Education feature).' })
        Add-Finding Info ('Memory integrity (Core isolation) is {0}. {1}' -f $state[[string]$R.Hvci], $cg) $(if ($R.Hvci -ne 'Running') { 'If the site requires memory integrity, turn it on in Windows Security > Device security > Core isolation, then restart.' } else { '' })
    }
    # Failed Secure Boot database updates (event 1796) need newer firmware; Windows retries after each restart.
    try {
        $sbFail = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'; Id = 1796; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction Stop)
        if ($sbFail.Count) { Add-Finding Warning ('Windows could not apply a Secure Boot update: {0} in the last 30 days, latest {1} (System log, event 1796).' -f (Format-Count $sbFail.Count 'failure' 'failures'), $sbFail[0].TimeCreated.ToString('yyyy-MM-dd')) 'Install the latest BIOS/UEFI firmware from the PC maker (suspend BitLocker first); Windows retries the update after each restart.' }
    } catch {}
    if (-not $R.Elevated) { Add-Finding NotChecked 'TPM details, recovery key protectors and full BitLocker status need administrator rights.' $admin }
    foreach ($w in $script:Warnings) {
        if ($w -match '^(TPM and full BitLocker information need admin|Kernel DMA protection and effective LSASS|Recovery-key backup success is not established|Win11BaselineOk covers)') { continue }
        Add-Finding NotChecked $w 'This part of the check is blank or partial; the rest is still valid.'
    }
}

if($Display){
    try { Add-SummaryFindings $result } catch { Add-Finding NotChecked ('The summary could not be completed: {0}' -f $_.Exception.Message) 'Read the DETAILS below.' }
    $result | Show-Result -Title $script:ToolName -ReportPath $ReportPath -About $script:SummaryAbout -Findings $script:Findings -NextSteps $script:SummaryNext
}else{$result}
