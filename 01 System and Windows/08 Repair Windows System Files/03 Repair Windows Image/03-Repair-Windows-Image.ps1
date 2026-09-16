<#
.SYNOPSIS
    Repair the Windows component store with DISM only.
.NOTES
    Toolkit-Class: Remediation
    Toolkit-Context: Machine
    Toolkit-Elevation: Required
    Windows PowerShell 5.1. Read README.txt before use.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[Alias('ReportPath')][string]$LogPath='C:\Temp\Toolkit',[string]$Source,[switch]$LimitAccess)
$ErrorActionPreference='Stop'
$probe=$PSScriptRoot
$runtime=$null
while ($probe) {
    $candidate=Join-Path $probe '_Maintenance\Runtime\WindowsImage.psm1'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {$runtime=$candidate;break}
    $probe=[IO.Path]::GetDirectoryName($probe)
}
if (-not $runtime) {throw 'Missing _Maintenance\Runtime\WindowsImage.psm1. Keep the toolkit together.'}
Import-Module $runtime -Force -ErrorAction Stop
$options=@{Mode='RestoreHealth';LogPath=$LogPath;Display=$Display}
foreach ($key in $PSBoundParameters.Keys) {$options[$key]=$PSBoundParameters[$key]}
Invoke-ToolkitWindowsImage @options
