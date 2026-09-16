QUICK CHECK WINDOWS IMAGE
=========================

WHAT IT DOES
  Reads corruption already flagged by Windows using DISM CheckHealth.
  Usually quick. Does not scan files, repair them or check update freshness.

WHEN TO USE IT
  For a quick first look before deciding on a deeper corruption check.
  A clean result means no corruption is flagged; unscanned damage can exist.

HOW TO RUN IT
  Double-click 01-Quick-Check-Windows-Image.cmd.
  Approve administrator access.
  Preview in PowerShell: .\01-Quick-Check-Windows-Image.ps1 -WhatIf -Display
  Equivalent command: DISM /Online /Cleanup-Image /CheckHealth

WHAT TO LOOK AT
  Repairable: use sibling 03 Repair Windows Image, then 04 Run SFC Only.
  No corruption flagged: use 02 Scan Windows Image if a full check is needed.
  NonRepairable: review recovery or repair-install options.
  Unknown or failed: read the error; this is not a clean result.

LIMITS
  Read Result and NextStep. TXT/JSON and DISM logs go to C:\Temp\Toolkit.
  Use -LogPath for another folder. Preview writes only TXT/JSON plan reports.
  Keep _Maintenance\Runtime with the toolkit. SFC never runs from this tool.
  A pending restart is reported; the quick check does not restart Windows.
