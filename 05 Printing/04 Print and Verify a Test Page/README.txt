04 PRINT AND VERIFY A TEST PAGE
===============================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Sends one Windows test page to the selected printer and records your
    observation.

WHEN TO USE IT
--------------
  - After resolving a queue, driver or connection problem.
  - First: check the printer and use only the needed repair.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -PrinterName "Office printer" -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Windows submission result AND whether a readable physical page printed.

LIMITS
------
  - Uses paper and ink.
  - Software cannot prove physical output.
  - The launcher asks for the observed result; pressing Enter records
    NotChecked.
  - -WhatIf previews the action and writes reports; no repair runs.
