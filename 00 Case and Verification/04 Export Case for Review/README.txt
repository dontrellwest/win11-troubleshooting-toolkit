04 EXPORT CASE FOR REVIEW
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Creates a local ZIP of the case reports after listing its contents.

WHEN TO USE IT
  When another technician needs the case evidence.
  First: compare results and review the case. Supply -CasePath.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Review the listed files and the resulting ZIP path before sharing.

LIMITS
  Includes TXT, JSON, CSV and LOG files at the case root only. No automatic
  upload or credential collection.
  -WhatIf previews the action and writes reports; no repair runs.
