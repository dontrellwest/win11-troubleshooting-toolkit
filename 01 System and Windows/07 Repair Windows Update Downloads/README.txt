07 REPAIR WINDOWS UPDATE DOWNLOADS
==================================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: yes.

WHAT IT DOES
------------
  - Starts enabled update services or moves the download cache aside for a
    fresh download.

WHEN TO USE IT
--------------
  - The update diagnostic identifies a service or corrupt-download problem.
  - First: 06 Check Windows Updates.
  - Use cache reset only if needed.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Action StartServices -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Service states, any backup path, then a fresh update scan and retry.

LIMITS
------
  - Refuses while DISM, SFC or TiWorker runs or a restart is pending; other
    installer processes are only reported.
  - Keeps update history, service startup types and policy.
  - The old download cache stays beside the new one as
    Download.ToolkitBackup-<run>; remove it after updates succeed.
  - -WhatIf previews the action and writes reports; no repair runs.
