08 REFRESH SELECTED GROUP POLICY
================================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Refreshes either current-user or computer Group Policy and records output.

WHEN TO USE IT
--------------
  - Connectivity works but expected organizational settings are missing.
  - First: 02 Check Group Policy.
  - Rerun it after this action.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Scope User -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Refresh output and the follow-up Group Policy report.

LIMITS
------
  - User scope must run as that user; Computer scope needs an admin window.
  - Applies organizational policy.
  - Sign-out or restart remains manual; a log-off question from gpupdate is
    answered No.
  - Exit 0 means the refresh was requested and reported within 60 seconds, not
    that every setting finished applying.
  - -WhatIf previews the action and writes reports; no repair runs.
