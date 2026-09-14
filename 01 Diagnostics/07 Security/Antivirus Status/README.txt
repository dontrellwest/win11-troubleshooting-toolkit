DEFENDER STATUS
===============

WHAT IT DOES

  Reports Defender protection, signature age, scans and policy settings.
  Includes readable exclusions, threat history and registered antivirus.

WHEN TO USE IT

  - Checking whether endpoint protection is running.
  - Investigating old definitions or unexpected exclusions.

HOW TO RUN IT

  Double-click Get-DefenderStatus.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-DefenderStatus.ps1 -Display
  Default history: 30 days. Use -Days 7 for a shorter window.

WHAT TO LOOK AT

  - Check AMRunningMode and RealTimeProtectionEnabled together.
  - DefinitionsStale flags signatures older than three days.
  - Compare exclusions with your approved baseline.
  - Read Warnings before interpreting blank counts.

LIMITS

  - Exclusions and some threat information may need admin access.
  - Passive mode can be intentional when another product is in use.
  - Registered third-party AV does not prove that it is protecting the PC.
  - Event fallback results are events, not unique threats.
  - No scans, definition updates or setting changes are performed.

  Diagnostic only. Changes no settings and performs no repairs.
