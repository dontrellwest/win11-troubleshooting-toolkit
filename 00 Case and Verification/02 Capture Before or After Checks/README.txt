02 CAPTURE BEFORE OR AFTER CHECKS
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Saves diagnostic facts for one problem area, plus recent System events.

WHEN TO USE IT
  Once before a repair, then again after it or after a manual restart.
  First: create a case. Supply -CasePath or use the interactive launcher.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Phase Before -Area Network
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Select the same area, target and affected user for both captures.

LIMITS
  Some areas need admin. Update capture skips the online update search. A
  snapshot can contain user, PC, file and server names.
