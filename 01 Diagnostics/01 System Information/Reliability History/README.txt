RELIABILITY SUMMARY
===================

WHAT IT DOES

  Counts recent crashes, hangs, service failures and restarts.
  Groups events to help identify recurring applications or components.

WHEN TO USE IT

  - Investigating repeated crashes or instability.
  - Comparing recorded failures before and after a change.

HOW TO RUN IT

  Double-click Get-ReliabilitySummary.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-ReliabilitySummary.ps1 -Display
  Add -Days 7 for a shorter history; the default is 30 days.

WHAT TO LOOK AT

  - Start with BugChecks, ByApplication and RecentEvents.
  - Verdict is a rough score, not a diagnosis.
  - Healthy requires at most 0.2 issues/day and no counted bugchecks.
  - Watch is at most one issue/day; higher scores are Sick.

LIMITS

  - Counts are events, so one incident may contribute several entries.
  - Cleared logs and missing records can understate the failure rate.
  - Warnings identify unavailable sources and collection limits.

  Diagnostic only. Changes no settings and performs no repairs.
