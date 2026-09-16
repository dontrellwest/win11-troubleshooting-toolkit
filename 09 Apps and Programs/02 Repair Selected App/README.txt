02 REPAIR SELECTED APP
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Opens the app Repair settings or uses supported WinGet or MSI repair.

WHEN TO USE IT
  One identified app has failed after basic checks and restarting it.
  First: 01 Check App. Test afterward; use Reset only if needed.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Target Microsoft.WindowsCalculator -Method Settings -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Settings requires you to click Repair. Automated repair reports the
  command result.

LIMITS
  Repair support varies by app. Close it and save work first. MSI may need
  installer media or admin approval. WinGet applies to desktop programs
  only, matches by name, and may download and run the publisher installer
  (30-minute limit). No automatic fallback to Reset.
  -WhatIf previews the action and writes reports; no repair runs.
