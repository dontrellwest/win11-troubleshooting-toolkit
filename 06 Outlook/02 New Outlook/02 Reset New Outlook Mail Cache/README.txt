RESET NEW OUTLOOK MAIL CACHE
============================

WHAT IT DOES

  Closes New Outlook, moves its local app/mail data aside as backups,
  then reopens it to rebuild local data. Sign-in may be required.
  Classic Outlook and its OST/PST files are not changed.

WHEN TO USE IT

  After step 01, Check New Outlook App and Service, suggests a local issue.
  Rule out service access, filters, sorting and Focused/Other settings first.
  Confirm important mail and drafts are on the server.
  Unsynced drafts and offline-only items may be lost from the active app.

HOW TO RUN IT

  In the affected user's session, double-click:
    02-Reset-New-Outlook-Mail-Cache.cmd
  Preview from PowerShell in this folder:
    .\02-Reset-New-Outlook-Mail-Cache.ps1 -WhatIf -Display
  Read the plan before confirming. Recent data writes produce a warning.
  -TargetUser 'DOMAIN\user' selects a user; another account needs admin.
  Logs go to C:\Temp\Toolkit, with the user's Temp folder as a fallback.
  Native alternative: 02-Reset-New-Outlook-Mail-Cache-NoPowerShell.cmd
  Use /? for native help or /whatif to preview.

WHAT TO LOOK AT

  Check FoldersMoved, MoveFailed and NextStep.
  Sign in if prompted, let data rebuild, then rerun step 01.
  OldBackupsMB reports retained data from earlier resets.

LIMITS

  Moves Microsoft\Olk and package LocalCache, LocalState, RoamingState,
  TempState and Settings aside. Backups are retained, not deleted.
  Missing, linked or uncertain user paths and SYSTEM are refused.
  Native mode requires a local, unelevated console session.
  Preview writes a plan log; it does not close the app or move its data.
