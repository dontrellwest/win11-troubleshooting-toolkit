REPAIR WINDOWS SYSTEM FILES
===========================

WHAT IT DOES

  Runs DISM RestoreHealth on the Windows component store, then SFC /scannow.
  Changes Windows files. Usually takes 10-40 minutes. Requires admin.
  The numbered subfolders 01-04 run the same steps separately (see LIMITS).

WHEN TO USE IT

  Suspected Windows corruption, failed servicing or repeated system errors.
  Start with 06 Check Windows Updates for update or servicing problems.
  Save work, let running updates or repairs finish and complete any
  pending restart first.

HOW TO RUN IT

  Double-click 08-Repair-Windows-System-Files.cmd and approve the prompts.
  Preview from an administrator PowerShell in this folder:
    .\08-Repair-Windows-System-Files.ps1 -WhatIf -Display
  The preview also needs admin; without it the tool stops with an error.
  -DismScanOnly scans the component store; add -SkipSfc for a scan only.
  -SkipDism or -SkipSfc omits that step.
  -Source 'WIM:D:\sources\install.wim:1' uses matching repair media and
  disables the Windows Update fallback. Choose the right image index.
  Logs go to C:\Temp\Toolkit, or the folder given by -LogPath.

WHAT TO LOOK AT

  NextStep, DismResult, SfcResult and the exit codes guide the follow-up.
  The CBS extract lists repair messages recorded during this run.
  A successful DISM command alone does not prove corruption was repaired.
  Restart manually if asked, then repeat the original task to verify.

LIMITS

  English text is classified; localized output may require reading the log.
  The CBS extract reads at most the last 50 MB. Some details may be absent.
  Native option: 08-Repair-Windows-System-Files-NoPowerShell.cmd /? or
  /whatif. It has fewer summaries and runs the default sequence only.
  Preview creates only a plan log. It does not run DISM or SFC.
  Separate steps, each with its own guide:
    01 Quick Check Windows Image   DISM CheckHealth: recorded corruption only
    02 Scan Windows Image          DISM ScanHealth: full scan, no repair
    03 Repair Windows Image        DISM RestoreHealth only; then use 04
    04 Run SFC Only                SFC without DISM
  A repair includes a scan; you do not need to run every step.
  Steps 01-03 need _Maintenance\Runtime; keep the toolkit together.
