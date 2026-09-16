<#
.SYNOPSIS
    Run SFC only; DISM is not started.
.NOTES
    Toolkit-Class: Remediation
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Windows PowerShell 5.1. Read README.txt before use.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[Alias('ReportPath')][string]$LogPath='C:\Temp\Toolkit')
$ErrorActionPreference='Stop'
$repair=Join-Path $PSScriptRoot '..\08-Repair-Windows-System-Files.ps1'
if (-not (Test-Path -LiteralPath $repair -PathType Leaf)) {throw 'Missing parent Windows system-file repair script. Keep this folder with the toolkit.'}
$options=@{SkipDism=$true;LogPath=$LogPath}
foreach ($key in $PSBoundParameters.Keys) {if ($key -ne 'Display') {$options[$key]=$PSBoundParameters[$key]}}
$result=& $repair @options
if ($Display) {Write-Host ($result | Format-List -Property * | Out-String -Width 220)} else {$result}
if ($result.SfcRan -and ($result.SfcExitCode -ne 0 -or $result.SfcResult -in 'Could not run','Could not repair all' -or $result.SfcResult -like 'Unclassified*')) {
    throw ('SFC did not complete a successful repair/check. Review '+$result.LogPath)
}
