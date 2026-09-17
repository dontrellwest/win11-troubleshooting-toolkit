02 TEST SAFE MODE AND ISOLATE ADDINS
====================================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Starts safe mode, lists add-ins, or disables/restores one current-user
    add-in.

WHEN TO USE IT
--------------
  - Classic Outlook fails or hangs and an add-in might be responsible.
  - First: 01 Check Classic Outlook.
  - Try this before 03 Rebuild Cache.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Action SafeMode -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Does the failed task work in safe mode and then normal mode with one
    add-in disabled?

LIMITS
------
  - Close Outlook first.
  - Add-in changes save their prior setting; restore with -Action RestoreAddin
    -BackupPath <saved JSON from the result>.
  - Only the current-user entry is changed; per-machine or policy add-ins are
    listed and need owner review.
  - No mailbox cache or view is deleted.
  - -WhatIf previews the action and writes reports; no repair runs.
