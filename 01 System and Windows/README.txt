SYSTEM AND WINDOWS
==================

  Order: checks 01-06 first; repairs 07-09 only when a check justifies them.

CHECKS
------
  01  Check Computer Details
      - Basic Windows, hardware and account context.
  02  Check Windows Crashes / 03  Check Restarts and Shutdowns
      - Explain failures and shutdowns.
  04  Check Recent System Changes / 05  List Installed Software
      - Help identify a trigger.
  06  Check Windows Updates
      - Start here for update problems. Resolve connectivity, policy and
        pending-restart issues first.

REPAIRS
-------
  07  Repair Windows Update Downloads
      - Service start or download-cache replacement. Use only the action the
        findings justify, then recheck.
  08  Repair Windows System Files
      - Separate DISM/SFC choices in its subfolders:
          01 Quick Check Windows Image   recorded corruption; no full scan
          02 Scan Windows Image          full corruption scan, no repair; slow
          03 Repair Windows Image        DISM repair only; then use 04
          04 Run SFC Only                system-file check and repair
      - The combined DISM-then-SFC launcher remains in the parent folder.
      - A repair includes a scan; choose the needed route, not every step.
      - None of these checks certifies that repair downloads are up to date.
  09  Repair Explorer and Icons
      - Shell, taskbar or icon problems. Finish file copies first.
      - -RestartOnly leaves icon caches alone.

NOTES
-----
  - For one broken application, use 09 Apps and Programs instead.
  - For storage errors, check 04 Performance storage reliability first.
  - Repairs are optional, separate decisions. Preview and retest afterward.
  - DISM/SFC were not executed in laptop validation.
