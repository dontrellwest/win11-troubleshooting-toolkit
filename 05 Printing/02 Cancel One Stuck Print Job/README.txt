02 CANCEL ONE STUCK PRINT JOB
=============================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Cancels one selected job while leaving other queued jobs alone.

WHEN TO USE IT
--------------
  - One identified job blocks the printer queue.
  - First: 01 Check Printers.
  - Try this before 03 Reset Print Queue.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -PrinterName "Office printer" -JobId 12 -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - The exact job identity before cancellation and whether it remains queued.

LIMITS
------
  - Your account must have permission to cancel the job.
  - Already transmitted pages may still print.
  - An empty queue needs no cancellation.
  - -WhatIf previews the action and writes reports; no repair runs.
