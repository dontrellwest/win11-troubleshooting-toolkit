REPAIR WINDOWS IMAGE
====================

WHAT IT DOES
  Runs DISM RestoreHealth to scan and repair the Windows component store.
  May download repair files. Can take many minutes. Does not run SFC.

WHEN TO USE IT
  Component-store corruption is suspected or reported, or SFC cannot repair.
  You may go straight to repair; CheckHealth and ScanHealth are optional.
  Windows Update normally supplies repair files, subject to machine policy.

HOW TO RUN IT
  Double-click 03-Repair-Windows-Image.cmd and approve both prompts.
  Preview in PowerShell: .\03-Repair-Windows-Image.ps1 -WhatIf -Display
  Equivalent command: DISM /Online /Cleanup-Image /RestoreHealth
  Save work. Complete pending restarts and let other servicing finish first.

IF REPAIR FILES CANNOT BE FOUND
  Check connectivity and repair-source policy before trying again.
  Optional: -Source 'WIM:D:\sources\install.wim:1' -LimitAccess
  Choose the correct image index, Windows version, language and patch level.
  -LimitAccess prevents Windows Update fallback.
  Without -LimitAccess, Windows Update fallback remains available.

WHAT TO LOOK AT
  After success, use sibling 04 Run SFC Only, then test the original problem.
  Restart manually first if requested. This tool never restarts Windows.
  Completion does not prove files were changed or the original issue fixed.
  Failure or NonRepairable: read the log before choosing another action.

LIMITS
  TXT/JSON and DISM logs go to C:\Temp\Toolkit, or use -LogPath.
  Preview writes only plan reports. Keep _Maintenance\Runtime with the kit.
