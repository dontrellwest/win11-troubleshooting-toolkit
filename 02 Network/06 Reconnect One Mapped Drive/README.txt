06 RECONNECT ONE MAPPED DRIVE
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Recreates one existing drive mapping after checking server and share
  access.

WHEN TO USE IT
  The UNC share works but its existing drive letter is disconnected or
  stale.
  First: 01 Connection and 03 Mapped Drives checks. Fix access first.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -DriveLetter Z: -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Original mapping backup and final status. Open the drive in Explorer.

LIMITS
  Run as the affected user, NOT elevated. Close files first. A saved mapping
  that uses another account is refused. A session-only mapping (no saved
  entry) is recreated under the signed-in account, which can change access.
  Credentials are not deleted.
  -WhatIf previews the action and writes reports; no repair runs.
