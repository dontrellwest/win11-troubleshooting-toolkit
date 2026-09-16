$ErrorActionPreference='Stop'
foreach($part in 'Core','Cases','Network','Apps','Repairs','Devices'){. (Join-Path $PSScriptRoot ($part+'.ps1'))}
function Invoke-ToolkitTool {
    [CmdletBinding()]
    param([string]$ToolId,[hashtable]$Options,$Caller,[string]$ToolkitRoot)
    $script:ToolId=$ToolId;$script:Options=$Options;$script:Caller=$Caller;$script:ToolkitRoot=$ToolkitRoot
    $script:Rows=New-Object Collections.Generic.List[object]
    $script:RunId=(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
    $failure=$null
    try {
        if($Options.CasePath){$null=Get-TkCase $Options.CasePath}
        if($ToolId -in 'RepairNetwork','ReconnectDrive','RepairOneDrive','ResyncTime','RefreshPolicy','RepairTrust','CleanTemp','CancelPrintJob','OutlookIsolation','RepairApp','ResetApp','RepairTeams','RepairDevice'){Get-TkReadiness}
        switch($ToolId){
            StartCase {Start-TkCase}
            CaptureCase {Capture-TkCase}
            CompareCase {Compare-TkCase}
            ExportCase {Export-TkCase}
            MonitorNetwork {Monitor-TkNetwork}
            RepairNetwork {Repair-TkNetwork}
            ReconnectDrive {Repair-TkMappedDrive}
            RepairOneDrive {Repair-TkOneDrive}
            ResyncTime {Repair-TkTime}
            RefreshPolicy {Repair-TkPolicy}
            RepairTrust {Repair-TkTrust}
            StorageHealth {Get-TkStorage}
            CleanTemp {Clear-TkTemporaryFiles}
            CancelPrintJob {Cancel-TkPrintJob}
            PrintTestPage {Test-TkPrinterPage}
            OutlookIsolation {Repair-TkOutlook}
            CheckApp {Get-TkAppCheck}
            RepairApp {Repair-TkApp}
            ResetApp {Reset-TkApp}
            VerifyApp {Verify-TkApp}
            CheckTeams {Get-TkTeams}
            RepairTeams {Repair-TkTeams}
            CheckDevices {Get-TkDevices}
            RepairDevice {Repair-TkDevice}
            RepairUpdates {Repair-TkWindowsUpdate}
            default {throw "Unknown toolkit operation: $ToolId"}
        }
    }catch{$failure=$_;Add-TkResult 'Execution' $ToolId 'Failed' $_.Exception.Message}
    finally {
    # Runs even when the tool is interrupted with Ctrl+C, so the rows collected so far are kept.
    try {
        $folder=Get-TkOutputFolder
        $base=Join-Path $folder ($ToolId+'-'+$script:RunId)
        Write-TkJson ($base+'.json') @($script:Rows.ToArray())
        $text=($script:Rows.ToArray() | Format-List * | Out-String -Width 160)
        [IO.File]::WriteAllText(($base+'.txt'),$text,(New-Object Text.UTF8Encoding($false)))
        if($Options.CasePath){$case=Get-TkCase $Options.CasePath;if($case.Folder -ine $folder){Write-TkJson (Join-Path $case.Folder ($ToolId+'-'+$script:RunId+'.json')) @($script:Rows.ToArray())}}
        if($Options.Display){Write-Host $text;Write-Host ('Reports: '+$base+'.txt / .json')}
    }catch{if(-not $failure){$failure=$_};Write-Warning ('Report could not be saved: '+$_.Exception.Message)}
    }
    if(-not $Options.Display){$script:Rows.ToArray()}
    if($failure){throw $failure}
}
Export-ModuleMember -Function Invoke-ToolkitTool
