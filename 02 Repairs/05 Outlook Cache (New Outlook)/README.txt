NEW OUTLOOK CACHE RESET
=======================

WHAT IT DOES

  Closes the new Outlook app, moves its local data folders aside as
  backups, and opens it again. The app signs in again through Windows and
  rebuilds its cache from the server. Nothing is deleted. Classic Outlook,
  its OST and PST files are left alone.

WHEN TO USE IT

  New Outlook opens blank, spins forever, or keeps showing stale mail after
  Outlook on the web is confirmed current. Run Get-NewOutlookSyncState
  (Diagnostics > Accounts and Profiles) first; a filter, sort or Focused/
  Other setting looks the same to the user and needs no reset.
  Warn the user: drafts not yet sent and offline-only items may be lost.

HOW TO RUN IT

  In the affected user's session, double-click Reset-NewOutlookCache.cmd.
  Preview from PowerShell in this folder:
    .\Reset-NewOutlookCache.ps1 -WhatIf -Display
  -TargetUser 'DOMAIN\user' selects a user; another account requires admin.
  Logs go to C:\Temp\Toolkit, with the target user's Temp as a fallback.
  If local data was written in the last 10 minutes the confirmation prompt
  says so: the app is active, and a reset is probably the wrong fix.

WHAT TO LOOK AT

  FoldersMoved and MoveFailed show what happened to the data folders.
  NextStep says whether to sign in, wait for the app, or retry.
  OldBackupsMB shows backups from earlier runs, safe to remove once the
  app works.

LIMITS

  The moved folders are LocalCache, LocalState, RoamingState, TempState
  and Settings under the app's package folder; nothing else is touched.
  Missing, linked or uncertain user paths and SYSTEM are refused.
  Native option: Reset-NewOutlookCache-NoPowerShell.cmd /? or /whatif.
  Native mode needs a local, unelevated console session.
  Preview writes a plan log; it does not close the app or move folders.
  Verified with the app installed but not signed in; a signed-in reset
  and the sign-in prompt afterwards have not been observed yet.
