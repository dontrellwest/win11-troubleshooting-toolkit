BOOT AND SHUTDOWN HISTORY
=========================

WHAT IT DOES

  Lists recorded boots, shutdowns, crashes and unexpected restarts.
  Shows the user or process that requested a shutdown when available.

WHEN TO USE IT

  - Investigating unexpected restarts or a reported blue screen.
  - Checking whether the PC was restarted recently.

HOW TO RUN IT

  Double-click Get-BootHistory.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-BootHistory.ps1 -Display
  Add -Days 7 to shorten the default 30-day history.

WHAT TO LOOK AT

  - Read the summary at the end, then the newest relevant events.
  - Kind, Time and Detail describe what Windows recorded.
  - A BugCheck row may include a crash code and dump location.

LIMITS

  - Several events can describe the same restart.
  - Missing or cleared logs leave gaps; absence is not proof.
  - An unexpected shutdown event alone does not establish its cause.
  - Warnings appear on screen and may not be in the saved report.

  Diagnostic only. Changes no settings and performs no repairs.
