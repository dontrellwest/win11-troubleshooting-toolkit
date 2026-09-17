RUN SFC ONLY
============

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: yes.

WHAT IT DOES
------------
  - Checks protected Windows system files and repairs them with SFC /scannow.
  - Does not start DISM.
  - Uses the existing parent repair script and its logs.

WHEN TO USE IT
--------------
  - After successful DISM repair, or when you deliberately choose SFC alone.
  - Microsoft's standard repair sequence is DISM RestoreHealth, then SFC.
  - A successful SFC check does not certify the entire component store.

HOW TO RUN IT
-------------
  - Double-click 04-Run-SFC-Only.cmd and approve both prompts.
  - Preview in administrator PowerShell:
      .\04-Run-SFC-Only.ps1 -WhatIf -Display
  - Save work.
  - Complete pending restarts and let other servicing finish first.

WHAT TO LOOK AT
---------------
  - No violations: retest the original issue.
  - Repaired: restart if needed, then retest.
  - Repeat SFC to verify if needed.
  - Could not repair all: review CBS details and use 03 Repair Windows Image.
  - After successful DISM repair, run SFC again.
  - Could not run: read the error and resolve the cause before retrying.

LIMITS
------
  - Logs and the CBS repair extract go to C:\Temp\Toolkit, or use -LogPath.
  - Preview writes a plan log.
  - Keep this folder with its parent repair script.
  - Localized SFC output may require reading the log for the final result.
