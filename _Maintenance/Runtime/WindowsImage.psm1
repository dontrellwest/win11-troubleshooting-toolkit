# Separate Windows image checks and repair. Windows PowerShell 5.1.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Test-WindowsImageAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsImageReadiness {
    $busy = @(Get-Process -ErrorAction Stop | Where-Object ProcessName -in 'dism','sfc','TiWorker')
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop) -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop)
    [pscustomobject]@{Busy=(($busy | ForEach-Object {$_.ProcessName}) -join ', '); RebootPending=[bool]$pending}
}

function Invoke-WindowsImageCommand {
    [CmdletBinding()]
    param([string]$Mode, [string]$LogFile, [string]$Source, [bool]$LimitAccess)
    Import-Module Dism -ErrorAction Stop
    $parameters = @{Online=$true; NoRestart=$true; LogPath=$LogFile; ErrorAction='Stop'}
    $parameters[$Mode] = $true
    if ($Source) {$parameters.Source = $Source}
    if ($LimitAccess) {$parameters.LimitAccess = $true}
    Repair-WindowsImage @parameters
}

function Get-WindowsImageConclusion {
    param([string]$Mode, [string]$State)
    switch ($State) {
        'Healthy' {
            if ($Mode -eq 'CheckHealth') {
                return [pscustomobject]@{
                    Result='No corruption flagged. A full scan was not performed.'
                    NextStep='Use 02 Scan Windows Image if a full check is needed. This does not check update freshness.'
                }
            }
            if ($Mode -eq 'ScanHealth') {
                return [pscustomobject]@{
                    Result='DISM found no component-store corruption in this scan.'
                    NextStep='For protected system-file problems, use 04 Run SFC Only, then retest the original issue.'
                }
            }
            return [pscustomobject]@{
                Result='DISM completed and reports a healthy component store. This does not prove files were changed.'
                NextStep='Use 04 Run SFC Only, then retest the original issue.'
            }
        }
        'Repairable' {
            $next = 'Use 03 Repair Windows Image, then 04 Run SFC Only.'
            if ($Mode -eq 'RestoreHealth') {$next='Review the DISM log and repair source; corruption remains after this attempt.'}
            return [pscustomobject]@{Result='Windows reports repairable component-store corruption.'; NextStep=$next}
        }
        'NonRepairable' {
            return [pscustomobject]@{
                Result='Windows reports component-store corruption that DISM cannot repair.'
                NextStep='Review the log and plan Windows recovery or a repair installation. Do not repeat DISM in a loop.'
            }
        }
        default {throw ('DISM returned an unknown image state: '+$State)}
    }
}

function Save-WindowsImageReport {
    param($Record)
    [IO.File]::WriteAllText($Record.JsonPath, ($Record | ConvertTo-Json -Depth 4), [Text.Encoding]::UTF8)
    $text = ($Record | Format-List -Property * | Out-String -Width 220)
    [IO.File]::WriteAllText($Record.ReportPath, $text, [Text.Encoding]::UTF8)
}

function Invoke-ToolkitWindowsImage {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$true)][ValidateSet('CheckHealth','ScanHealth','RestoreHealth')][string]$Mode,
        [Alias('ReportPath')][ValidateNotNullOrEmpty()][string]$LogPath='C:\Temp\Toolkit',
        [string]$Source,
        [switch]$LimitAccess,
        [switch]$Display
    )
    if ($Mode -ne 'RestoreHealth' -and ($Source -or $LimitAccess)) {
        throw '-Source and -LimitAccess apply only to DISM repair.'
    }
    if ($Source -and ($Source -match '[\r\n]' -or [string]::IsNullOrWhiteSpace($Source))) {
        throw 'Supply one valid Windows repair source.'
    }
    # Checks do not repair files and need no additional prompt after UAC.
    # An explicit -Confirm still works, and -WhatIf always prevents DISM.
    if ($Mode -ne 'RestoreHealth' -and -not $PSBoundParameters.ContainsKey('Confirm')) {
        $ConfirmPreference = 'None'
    }
    $folder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogPath)
    # Never write elevated output through a link or junction anywhere on the report path.
    $walk = $folder
    while ($walk) {
        if (Test-Path -LiteralPath $walk) {
            $item = Get-Item -LiteralPath $walk -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw ('Report path contains a link or junction: '+$walk)}
        }
        $parent = [IO.Path]::GetDirectoryName($walk); if ($parent -eq $walk) {break}; $walk = $parent
    }
    $null = [IO.Directory]::CreateDirectory($folder)
    $id = 'DISM-{0}_{1}_{2}_{3}' -f $Mode,$env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8))
    $stem = Join-Path $folder $id
    $record = [pscustomobject][ordered]@{
        ComputerName=$env:COMPUTERNAME; CollectedAt=[datetime]::Now; Mode=$Mode
        Status='Planned'; Performed=$false; WhatIf=[bool]$WhatIfPreference
        ImageHealthState='Unknown'; Result='Not run'; NextStep=''
        RebootPending=$null; RestartNeeded=$null; Source=$Source; LimitAccess=[bool]$LimitAccess
        Minutes=0.0; DismLogPath=($stem+'.dism.log'); ReportPath=($stem+'.txt'); JsonPath=($stem+'.json')
        Warnings=''; Error=''
    }
    # Prove the evidence destination works before asking permission or servicing Windows.
    Save-WindowsImageReport $record
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $failure = $null
    try {
        if (-not $WhatIfPreference) {
            if (-not (Test-WindowsImageAdmin)) {
                $record.Status='Blocked'; throw 'Administrator rights are required. Open the matching CMD launcher.'
            }
            $readiness = Get-WindowsImageReadiness
            $record.RebootPending = $readiness.RebootPending
            if ($readiness.Busy) {
                $record.Status='Blocked'; throw ('Windows servicing is already running: '+$readiness.Busy+'. Wait for it to finish.')
            }
            if ($readiness.RebootPending) {
                if ($Mode -ne 'CheckHealth') {
                    $record.Status='Blocked'; throw 'Windows reports a pending restart. Save work, restart manually, then try again.'
                }
                $record.Warnings='Windows has a pending restart. Recheck after restarting.'
            }
        }
        $action = switch ($Mode) {
            'CheckHealth' {'Read recorded Windows image corruption status; no full scan or repair'}
            'ScanHealth' {'Scan the Windows component store without repairing it; may take considerable time'}
            'RestoreHealth' {'Scan and repair the Windows component store; may download files; SFC is not run'}
        }
        Write-Verbose $action
        if ($Display) {Write-Host $action; Write-Host ('DISM log: '+$record.DismLogPath)}
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
            $record.Status='Running'
            Save-WindowsImageReport $record
            $record.Performed=$true
            $commandWarnings = @()
            $results = @(Invoke-WindowsImageCommand -Mode $Mode -LogFile $record.DismLogPath -Source $Source -LimitAccess ([bool]$LimitAccess) -WarningVariable commandWarnings)
            if ($commandWarnings.Count) {$record.Warnings=(@($record.Warnings)+@($commandWarnings | ForEach-Object {"$_"}) | Where-Object {$_}) -join '; '}
            if ($results.Count -ne 1 -or -not $results[0].PSObject.Properties['ImageHealthState'] -or
                -not $results[0].PSObject.Properties['RestartNeeded'] -or $results[0].RestartNeeded -isnot [bool]) {
                throw 'DISM returned no usable health result. Read its log; no health conclusion is available.'
            }
            $state = [string]$results[0].ImageHealthState
            $conclusion = Get-WindowsImageConclusion -Mode $Mode -State $state
            $record.ImageHealthState=$state
            $record.RestartNeeded=$results[0].RestartNeeded
            $record.Status='Completed'; $record.Result=$conclusion.Result; $record.NextStep=$conclusion.NextStep
            if ($record.RestartNeeded) {$record.NextStep='Save work and restart manually, then recheck. '+$record.NextStep}
        } else {
            $record.Status=if ($WhatIfPreference) {'Preview'} else {'Declined'}
            $record.Result='DISM was not run.'
            $record.NextStep='No health conclusion is available from this run.'
        }
    } catch {
        $failure=$_
        if ($record.Status -ne 'Blocked') {$record.Status='Failed'}
        $record.Result='No health conclusion is available from this run.'
        $record.Error=$_.Exception.Message
        $record.NextStep='Resolve the reported error and review the logs before retrying.'
    } finally {
        $record.Minutes=[math]::Round($watch.Elapsed.TotalMinutes,2)
        Save-WindowsImageReport $record
    }
    if ($Display) {Write-Host ([IO.File]::ReadAllText($record.ReportPath))}
    if ($failure) {throw ('{0} Report: {1}' -f $record.Error,$record.ReportPath)}
    if (-not $Display) {$record}
}

Export-ModuleMember -Function Invoke-ToolkitWindowsImage
