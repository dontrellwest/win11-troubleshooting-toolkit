COLLECT DIAGNOSTICS FROM PCS
============================

WHAT IT DOES

  Runs reviewed ReadOnly-labelled scripts on selected PCs over WinRM.
  Saves main/detail CSV files and a per-computer status CSV.

WHEN TO USE IT

  Collecting the same diagnostic from several managed PCs.
  Test the chosen diagnostic on one PC before a larger run.

HOW TO RUN IT

  Open PowerShell in this folder. Set a diagnostic path and targets:
    $base = '..\..\01 System and Windows'
    $dir = Join-Path $base '03 Check Restarts and Shutdowns'
    $tool = Join-Path $dir '03-Check-Restarts-and-Shutdowns.ps1'
    $runner = '.\01-Collect-Diagnostics-from-PCs.ps1'
    & $runner -Script $tool -ComputerName PC1,PC2 -WhatIf
  Review the target list, then remove -WhatIf to collect results.
  -ComputerListPath .\PCs.txt reads one PC per line.
  -SearchBase 'DC=example,DC=com' selects computers from an AD location.
  -ScriptArgs @{Days=7} passes named parameters to the diagnostic.
  Add -Display for a summary. Default output: C:\Temp\Toolkit\Fleet.

WHAT TO LOOK AT

  Read _Status.csv before trusting the main CSV.
  No WinRM, Access denied and Timeout mean results are incomplete.
  Detail arrays are saved as separate CSV files.

LIMITS

  Requires existing WinRM, suitable access and firewall rules.
  Does not enable remoting or change remote settings. Repairs are refused.
  A ReadOnly label is not a sandbox; review the selected script first.
  -WhatIf checks TCP 5985 but runs no remote script or file export.
  Logged-off or session-only user data may be unavailable remotely.
  Domain, OU and successful remote runs need additional field testing.
