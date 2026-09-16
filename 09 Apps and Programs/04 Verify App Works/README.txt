04 VERIFY APP WORKS
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Rechecks the app and records whether the original task now works.

WHEN TO USE IT
  After Repair, Reset, an app update or a manual fix.
  Use after 02 Repair; use 03 Reset only if still justified.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Target Microsoft.WindowsCalculator -Outcome NotChecked
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Your observed outcome plus installation status and related crash events.

LIMITS
  Open and test the app yourself. No crash events or a healthy registration
  alone does not prove a fix.
