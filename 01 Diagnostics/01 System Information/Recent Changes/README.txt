RECENT CHANGES
==============

WHAT IT DOES

  Lists recent updates, driver activity and recorded app changes.
  Combines event logs, update history and uninstall registry entries.

WHEN TO USE IT

  - Something stopped working after an update or installation.
  - Comparing changes with the time a problem began.

HOW TO RUN IT

  Double-click Get-RecentChanges.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-RecentChanges.ps1 -Display
  Default history: 14 days. Add -Days 30 to widen it.
  Add -IncludeStoreApps to include Store app information.

WHAT TO LOOK AT

  - Compare Date and Detail with the reported start of the problem.
  - Repeated failed updates may warrant checking their error codes.
  - A change near the failure time is a lead, not proof of the cause.

LIMITS

  - Some installers and self-updating apps leave incomplete records.
  - Registry dates may have no time of day or reflect a later update.
  - An empty list does not prove that nothing was installed.
  - Other-user and domain attribution still needs field validation.

  Diagnostic only. Changes no settings and performs no repairs.
