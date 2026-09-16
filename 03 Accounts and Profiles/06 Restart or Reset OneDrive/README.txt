06 RESTART OR RESET ONEDRIVE
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Restarts OneDrive or uses its supported reset command for the current
  user.

WHEN TO USE IT
  OneDrive is stuck after account, connectivity and folder checks.
  First: 05 Check OneDrive. Try Restart before Reset, then recheck.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Action Restart -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Tray sync status, account and folder selection; verify a file on the
  website too.

LIMITS
  Reset triggers a full sync for every account signed in to this OneDrive
  and may require folder selection again. Does not delete your OneDrive
  folders. Run in a normal window, not elevated. Process launch is not
  proof of sync.
  -WhatIf previews the action and writes reports; no repair runs.
