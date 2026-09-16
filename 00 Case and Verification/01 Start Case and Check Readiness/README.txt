01 START CASE AND CHECK READINESS
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Creates a case folder with the reported problem and PC readiness checks.

WHEN TO USE IT
  Before changing the PC, or when handing a case to another technician.
  Next: 02 Capture Before or After Checks; select Before.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Issue "App fails to open"
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Save the Case folder path. Read pending restart, free space and account
  details.

LIMITS
  Creates reports only. Does not restart the PC or start a repair.
