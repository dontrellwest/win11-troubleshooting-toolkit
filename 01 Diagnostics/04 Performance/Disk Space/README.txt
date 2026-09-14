DISK SPACE BREAKDOWN
====================

WHAT IT DOES

  Shows large folders and files, caches, recycle bins and profile sizes.
  Estimates potential reclaimable space. It does not delete anything.

WHEN TO USE IT

  - Investigating low disk space.
  - Estimating the benefit of Windows cleanup tools.

HOW TO RUN IT

  Double-click Get-DiskSpaceBreakdown.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-DiskSpaceBreakdown.ps1 -Display
  Usually takes 1-3 minutes; larger drives can take longer.
  Options: -Drive C: -Top 15 -Depth 2 -StaleProfileDays 90

WHAT TO LOOK AT

  - Start with FreeGB, TopFolders and LargeFiles.
  - EstimatedReclaimGB is an estimate, not approval to delete those files.
  - Use supported cleanup tools after checking what must be retained.

LIMITS

  - Unreadable folders, hard links and compression affect totals.
  - UnaccountedGB does not identify the cause of missing space.
  - Admin access is needed for protected folders and DISM details.
  - Use the system drive for the full category breakdown.
  - Never delete a profile solely because it is old or large.

  Diagnostic only. Changes no settings and performs no repairs.
