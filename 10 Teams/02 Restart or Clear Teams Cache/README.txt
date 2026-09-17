02 RESTART OR CLEAR TEAMS CACHE
===============================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Restarts New Teams, optionally moving its current-user cache aside first.

WHEN TO USE IT
--------------
  - Teams remains stuck after app and connection checks.
  - First: 01 Check Teams.
  - Try Restart before ClearCache; recheck after.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Action Restart -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Backup path when cache was moved; then login, messaging and a test call.

LIMITS
------
  - Closes Teams and interrupts calls.
  - ClearCache moves the whole MSTeams cache folder (settings and backgrounds
    included) beside the original.
  - If the move fails, Teams is started again and the failure is reported.
  - New Teams only; no automatic cleanup of backups.
  - -WhatIf previews the action and writes reports; no repair runs.
