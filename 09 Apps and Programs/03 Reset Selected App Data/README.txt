03 RESET SELECTED APP DATA
==========================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Resets one exact packaged app for the current user after confirmation.

WHEN TO USE IT
--------------
  - Repair did not solve the problem and local app data can be discarded.
  - First: 02 Repair Selected App and test.
  - After reset: 04 Verify.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Target Microsoft.WindowsCalculator -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Exact selected app and deletion notice, then sign-in and original task
    after reset.

LIMITS
------
  - Closes the app and DELETES local app data, preferences and sign-in state.
  - LocalState, RoamingState and Settings are copied to a .ToolkitBackup
    folder first when under 1 GB; caches are not.
  - Export unsynced data first.
  - Desktop apps are not supported.
  - -WhatIf previews the action and writes reports; no repair runs.
