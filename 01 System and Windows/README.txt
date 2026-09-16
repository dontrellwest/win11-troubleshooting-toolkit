SYSTEM AND WINDOWS - SUGGESTED WORKFLOW
======================================

01 Computer Details gives basic Windows, hardware and account context.
02 Windows Crashes and 03 Restarts explain failures and shutdowns.
04 Recent Changes and 05 Installed Software help identify a trigger.

WINDOWS UPDATE
  Start with 06 Check Windows Updates. Resolve connectivity, policy and
  pending restart issues first.
  07 Repair Windows Update Downloads offers service start or download-cache
  replacement. Use only the action justified by the findings, then recheck.
  Open 08 Repair Windows System Files for separate DISM/SFC choices:
    01 Quick Check Windows Image: recorded corruption; no full scan.
    02 Scan Windows Image: full corruption scan, no repair; can be slow.
    03 Repair Windows Image: DISM repair only; then use 04 Run SFC Only.
    04 Run SFC Only: protected system-file check and repair.
  The original combined DISM-then-SFC launcher remains in that parent folder.
  Choose the needed route; a repair includes a scan, so do not run every step.
  None of these checks certifies that repair downloads are up to date.
  DISM/SFC were NOT executed in laptop validation.

EXPLORER AND ICONS
  09 Repair Explorer and Icons applies to shell, taskbar or icon problems.
  Finish file copies first. -RestartOnly leaves icon caches alone.

For one broken application, use 09 Apps and Programs instead.
For storage errors, check 04 Performance storage reliability first.
Repairs are optional, separate decisions. Preview and retest afterward.
