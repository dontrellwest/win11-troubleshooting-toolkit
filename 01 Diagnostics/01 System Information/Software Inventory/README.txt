SOFTWARE INVENTORY
==================

WHAT IT DOES

  Lists installed apps, versions, publishers and available install dates.
  Uses registry entries; it does not run installers or uninstallers.

WHEN TO USE IT

  - Checking versions during a software incident or licence review.
  - Finding per-user apps missed by machine-only inventory.

HOW TO RUN IT

  Double-click Get-SoftwareInventory.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-SoftwareInventory.ps1 -Display
  Options: -IncludeStoreApps -IncludeUpdates -IncludeSystemComponents
  Without -Display, pipe rows to Export-Csv -NoTypeInformation.

WHAT TO LOOK AT

  - Compare Name, Version, Publisher and Scope.
  - Install dates may reflect an update rather than the first install.

LIMITS

  - Only loaded user hives are visible; logged-off hives are not loaded.
  - Without admin, optional Store results cover the running account.
  - Registry entries can remain after an app is removed.
  - Blank dates or sizes mean they were not available.

  Diagnostic only. Changes no settings and performs no repairs.
