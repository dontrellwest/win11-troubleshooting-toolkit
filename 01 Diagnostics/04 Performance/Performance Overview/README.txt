PERFORMANCE OVERVIEW
====================

WHAT IT DOES

  Gives a broad CPU, memory, disk, startup and event-log snapshot.
  Writes a transcript. Does not apply repairs.

WHEN TO USE IT

  A general first look at a slow PC.
  Use the Resource Usage folder to measure current load over a sample period.

HOW TO RUN IT

  Double-click Get-PerformanceOverview.cmd.
  Or run .\Get-PerformanceOverview.ps1 from PowerShell in this folder.
  Administrator access may expose additional counters and logs.
  Use -NoLog to omit the transcript or -LogPath to choose its folder.
  PowerShell logs: C:\Temp\PerformanceOverview_<computer>_<date>.txt
  Native fallback: Get-PerformanceOverview-NoPowerShell.cmd.
  Native report: C:\Temp\PerformanceOverview_<computer>.txt (replaced).

WHAT TO LOOK AT

  Compare memory pressure, free disk space and repeated samples.
  CPUSeconds is accumulated process CPU time, not current CPU percentage.
  A single threshold or an HDD alone does not establish the cause.

LIMITS

  Localized performance counters may be unavailable.
  Without WMIC, the native version shows system-drive space and registry
  startup entries. Disk model/health, tasks and startup folders are omitted.
  Use the focused diagnostics if a section fails.
