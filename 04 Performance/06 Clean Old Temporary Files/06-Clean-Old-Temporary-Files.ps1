<#
.SYNOPSIS
Previews and deletes only old files in the selected Windows or user Temp folder.
.NOTES
Toolkit-Class: Remediation
Toolkit-Elevation: None
Windows PowerShell 5.1. Requires the full toolkit including _Maintenance\Runtime.
Read README.txt. Reports are written even when -WhatIf prevents a repair.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[switch]$Interactive,[string]$ReportPath='C:\Temp\Toolkit',[string]$CasePath,[ValidateSet('CurrentUserTemp','WindowsTemp')][string]$Scope,[ValidateRange(1,3650)][int]$OlderThanDays=7,[string]$Subfolder)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
while($root -and -not (Test-Path -LiteralPath (Join-Path $root '_Maintenance\Runtime\Toolkit.psm1'))){$root=Split-Path $root -Parent}
if(-not $root){throw 'Shared toolkit runtime is missing. Keep the full toolkit folder structure together.'}
$options=@{}
foreach($name in 'Display','Interactive','ReportPath','CasePath','Scope','OlderThanDays','Subfolder'){$options[$name]=(Get-Variable -Name $name -ValueOnly)}
$options.WhatIf=[bool]$WhatIfPreference
Import-Module (Join-Path $root '_Maintenance\Runtime\Toolkit.psm1') -Force -ErrorAction Stop
Invoke-ToolkitTool -ToolId 'CleanTemp' -Options $options -Caller $PSCmdlet -ToolkitRoot $root
