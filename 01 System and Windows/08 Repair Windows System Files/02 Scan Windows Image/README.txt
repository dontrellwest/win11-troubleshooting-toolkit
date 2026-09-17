SCAN WINDOWS IMAGE
==================

  [CHECK]  Collects information; does not change the PC. Admin: yes.

WHAT IT DOES
------------
  - Runs DISM ScanHealth to check the component store for corruption.
  - Does not repair files or run SFC.
  - Can take many minutes.

WHEN TO USE IT
--------------
  - You want a full corruption check before choosing a repair.
  - Optional: repair already includes a scan.
  - Doing both takes longer.
  - It does not tell you whether Windows or repair downloads are up to date.

HOW TO RUN IT
-------------
  - Double-click 02-Scan-Windows-Image.cmd and approve administrator access.
  - Preview in PowerShell: .\02-Scan-Windows-Image.ps1 -WhatIf -Display
  - Equivalent command: DISM /Online /Cleanup-Image /ScanHealth Let servicing
    finish and complete any pending restart before starting.

WHAT TO LOOK AT
---------------
  - Healthy: no store corruption found in this scan.
  - SFC checks system files.
  - Repairable: use sibling 03 Repair Windows Image, then 04 Run SFC Only.
  - NonRepairable: review recovery or repair-install options.
  - Unknown or failed: read the error; this is not a clean result.

LIMITS
------
  - TXT/JSON and DISM logs go to C:\Temp\Toolkit, or use -LogPath.
  - Preview writes only plan reports.
  - Keep _Maintenance\Runtime with the kit.
  - Never run another DISM, SFC or Windows update alongside this scan.
