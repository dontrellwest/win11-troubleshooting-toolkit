REBUILD CLASSIC OUTLOOK MAIL CACHE
==================================

WHAT IT DOES

  Closes classic Outlook, renames OST caches as backups and reopens Outlook.
  Outlook downloads mailbox data again. PST files and New Outlook stay intact.

WHEN TO USE IT

  After step 01, Check Classic Outlook Sync, indicates a local cache issue.
  Rule out Work Offline, view filters and service problems first.
  Confirm important mail and drafts are on the server before proceeding.
  Unsynced items may be hard to recover even with the old OST retained.

HOW TO RUN IT

  In the affected user's session, double-click:
    03-Rebuild-Classic-Outlook-Mail-Cache.cmd
  Preview from PowerShell in this folder:
    .\03-Rebuild-Classic-Outlook-Mail-Cache.ps1 -WhatIf -Display
  Read the plan before confirming. Recent OST writes produce a warning.
  -TargetUser 'DOMAIN\user' selects a user; another account needs admin.
  Logs go to C:\Temp\Toolkit, with the user's Temp folder as a fallback.
  Native alternative: 03-Rebuild-Classic-Outlook-Mail-Cache-NoPowerShell.cmd
  Use /? for native help or /whatif to preview.

WHAT TO LOOK AT

  Check OstRenamed, RenameFailed and NextStep.
  Let Outlook resync, then rerun step 01 and compare with web mail.
  OldFilesLeftBehindMB reports retained backups.

LIMITS

  Needs connectivity, free space and time for a mailbox download.
  Checks the default Outlook folder and Office 16 ForceOSTPath.
  Other custom per-account OST locations may not be found.
  Missing, linked or uncertain profiles and SYSTEM are refused.
  Native mode supports the default folder in a local, unelevated session.
  Preview writes only a plan log; it does not close or rename anything.
