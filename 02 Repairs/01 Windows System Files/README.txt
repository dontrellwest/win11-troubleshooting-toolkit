WINDOWS SYSTEM FILE REPAIR
==========================

WHAT IT DOES

  Checks or repairs Windows component files, then runs System File Checker.
  Changes Windows files. Usually takes 10-40 minutes. Requires admin.

WHEN TO USE IT

  Suspected Windows corruption, failed servicing or repeated system errors.
  Save work first. Let an existing update or repair finish before starting.

HOW TO RUN IT

  Double-click Repair-WindowsSystemFiles.cmd and approve the prompts.
  Preview from an administrator PowerShell in this folder:
    .\Repair-WindowsSystemFiles.ps1 -WhatIf -Display
  The preview also needs admin; without it the tool stops with an error.
  -DismScanOnly checks the component store; SFC still repairs unless skipped.
  Use -SkipSfc with -DismScanOnly for a scan without SFC repairs.
  Use -SkipDism or -SkipSfc to omit a step.
  -Source 'WIM:D:\sources\install.wim:1' uses matching repair media.
  Select the right image index for the installed Windows edition.
  Logs go to C:\Temp\Toolkit, or the folder given by -LogPath.

WHAT TO LOOK AT

  NextStep, DISM exit code and SfcResult guide the follow-up.
  The CBS extract lists repair messages recorded during this run.
  A successful DISM command alone does not prove corruption was repaired.

LIMITS

  English text is classified; localized output may require reading the log.
  The CBS extract reads at most the last 50 MB. Some details may be absent.
  Native option: Repair-WindowsSystemFiles-NoPowerShell.cmd /? or /whatif.
  The native option has fewer summaries and supports the default sequence.
  Preview creates only a plan log. It does not run DISM or SFC.
