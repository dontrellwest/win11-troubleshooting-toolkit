01 CHECK APP INSTALLATION
=========================

  [CHECK]  Collects information; does not change the PC. Admin: no.

WHAT IT DOES
------------
  - Identifies one app, its installation type, repair choices and name-matched
    crash events.

WHEN TO USE IT
--------------
  - An app will not open, crashes or behaves incorrectly.
  - Next: 02 Repair Selected App, then 04 Verify App Works.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Target Microsoft.WindowsCalculator
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Exact app identity, version and whether Repair or Reset is appropriate.

LIMITS
------
  - Current-user packages plus registered desktop programs.
  - Some app errors use executable names and will not match the product name.
