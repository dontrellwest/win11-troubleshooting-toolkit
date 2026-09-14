EXPLORER AND ICON CACHE REPAIR
=============================

WHAT IT DOES

  Restarts Explorer and removes the affected user's icon/thumbnail caches.
  The taskbar and desktop disappear briefly. Caches rebuild during use.

WHEN TO USE IT

  Explorer or the taskbar is hung, or icons and thumbnails display wrongly.
  Finish file copies and close Explorer windows before running it.

HOW TO RUN IT

  In the affected user's session, double-click Repair-Explorer.cmd.
  Preview from PowerShell in this folder:
    .\Repair-Explorer.ps1 -WhatIf -Display
  Add -RestartOnly to restart Explorer without clearing its caches.
  -TargetUser 'DOMAIN\user' selects a user explicitly.
  Another account requires admin and one identifiable desktop session.
  Logs go to C:\Temp\Toolkit, falling back to the target user's Temp folder.

WHAT TO LOOK AT

  ExplorerRunningAfter should be True. Check the taskbar afterward.
  CacheFilesLocked lists files that could not be removed.
  NextStep gives manual restart steps if Explorer did not return.

LIMITS

  SYSTEM, missing profiles and uncertain desktop targets are refused.
  Only Explorer in the selected session is stopped.
  Another-user restart uses a temporary task, removed afterward.
  Native option: Repair-Explorer-NoPowerShell.cmd /? or /whatif.
  Native mode supports a verified local console session, without elevation.
  Preview writes a plan log and leaves processes and caches unchanged.
