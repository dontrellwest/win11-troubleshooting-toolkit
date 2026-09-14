GROUP POLICY RESULT
===================

WHAT IT DOES

  Summarizes applied and denied Group Policy results from gpresult.
  Includes readable apply times and recent Group Policy error events.

WHEN TO USE IT

  - Expected policy settings or managed printers are missing.
  - Investigating policy filtering or processing errors.

HOW TO RUN IT

  Double-click Get-GPResultSummary.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-GPResultSummary.ps1 -Display
  Usually takes 5-30 seconds. Add -TargetUser DOMAIN\user if needed.

WHAT TO LOOK AT

  - Read Warnings first if counts or times are blank.
  - Compare denied policy names with their reported reasons.
  - A directory/SYSVOL version mismatch warrants replication checks.

LIMITS

  If XML is unavailable, NativeSummary shows gpresult /R text.
  Structured GPO counts remain unknown in this mode.

  - Computer results and another user's results need admin access.
  - No policy refresh or repair is performed.
  - Slow-link behavior depends on policy extension configuration.
  - Domain XML and successful policy paths still need field validation.
  - A temporary XML report is deleted after collection.

  Diagnostic only. Changes no settings and performs no repairs.
