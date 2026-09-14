FLEET RUNNER
============

WHAT IT DOES

  Runs ReadOnly-labelled toolkit scripts on selected PCs over WinRM.
  Saves a main CSV, separate detail CSVs and a per-computer status CSV.

WHEN TO USE IT

  Collecting the same diagnostic information from several managed PCs.
  Preview the target list before starting a larger run.

HOW TO RUN IT

  Run from PowerShell in this folder. Choose a diagnostic:
    $base = '..\01 Diagnostics\01 System Information'
    $tool = "$base\Boot and Shutdown History\Get-BootHistory.ps1"
    .\Invoke-FleetRunner.ps1 -Script $tool -ComputerName PC1,PC2 -WhatIf
    .\Invoke-FleetRunner.ps1 -Script $tool -ComputerListPath .\PCs.txt
    .\Invoke-FleetRunner.ps1 -Script $tool -SearchBase 'DC=example,DC=com'

  Remove -WhatIf after checking the plan. Add -Display for a summary.
  -ScriptArgs @{Days=7} passes named parameters to the selected tool.
  Default output: C:\Temp\Toolkit\Fleet. Override with -OutputFolder.
  -ThrottleLimit defaults to 16; -TimeoutSeconds defaults to 300 per PC.

WHAT TO LOOK AT

  Read _Status.csv before trusting the main CSV.
  No WinRM, Access denied and Timeout mean results were not complete.
  Details such as Volumes and Tickets are in their own CSV files.

LIMITS

  WinRM must already be configured with suitable access and firewall rules.
  This runner does not enable remoting or change remote settings.
  Only one ReadOnly header is accepted; repair tools are refused.
  A header is a label, not a sandbox. Use scripts you have reviewed.
  Preview checks TCP 5985 but runs no remote scripts and writes no files.
  Logged-off or session-only user data may be unavailable remotely.
  Real WinRM, credential and OU queries still need domain field tests.
