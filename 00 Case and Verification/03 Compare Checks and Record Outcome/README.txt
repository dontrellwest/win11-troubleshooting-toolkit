03 COMPARE CHECKS AND RECORD OUTCOME
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Compares the newest matching Before and After snapshots and records your
  outcome.

WHEN TO USE IT
  After rerunning the relevant checks and testing the original task.
  First: capture Before and After in the same case. Supply -CasePath.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Area Network -Resolution NotChecked
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Changed, unchanged and missing results. Changed values alone do not prove
  a fix.

LIMITS
  Rejects mismatched users, PCs, cases or targets. Lists can change order.
  No repair runs.
