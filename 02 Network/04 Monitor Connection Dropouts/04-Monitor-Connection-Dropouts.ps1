<#
.SYNOPSIS
Repeats gateway ping, DNS and TCP checks and reads recent Wi-Fi events.
.NOTES
Toolkit-Class: Diagnostic
Toolkit-Elevation: None
Windows PowerShell 5.1. Requires the full toolkit including _Maintenance\Runtime.
Read README.txt. Reports are written even when -WhatIf prevents a repair.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Display,[switch]$Interactive,[string]$ReportPath='C:\Temp\Toolkit',[string]$CasePath,[string]$Target,[ValidateRange(1,65535)][int]$Port=443,[ValidateRange(1,600)][int]$Samples=12,[ValidateRange(1,60)][int]$IntervalSeconds=5)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
while($root -and -not (Test-Path -LiteralPath (Join-Path $root '_Maintenance\Runtime\Toolkit.psm1'))){$root=Split-Path $root -Parent}
if(-not $root){throw 'Shared toolkit runtime is missing. Keep the full toolkit folder structure together.'}
$options=@{}
foreach($name in 'Display','Interactive','ReportPath','CasePath','Target','Port','Samples','IntervalSeconds'){$options[$name]=(Get-Variable -Name $name -ValueOnly)}
$options.WhatIf=[bool]$WhatIfPreference
Import-Module (Join-Path $root '_Maintenance\Runtime\Toolkit.psm1') -Force -ErrorAction Stop
Invoke-ToolkitTool -ToolId 'MonitorNetwork' -Options $options -Caller $PSCmdlet -ToolkitRoot $root
