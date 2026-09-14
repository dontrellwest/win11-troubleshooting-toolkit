CLASSIC OUTLOOK OST REBUILD
==========================

WHAT IT DOES

  Closes classic Outlook, renames its OST cache files and opens Outlook.
  Outlook downloads fresh mailbox data. Old caches are kept, never deleted.
  PST files and the new Outlook app are left alone. For the new Outlook
  app use the Outlook Cache (New Outlook) folder.

WHEN TO USE IT

  Only after ruling out a display problem, which looks the same to the
  user: mail is current in Outlook on the web or new Outlook, and View >
  Reset View did not fix classic Outlook. Run Get-OutlookSyncState
  (Diagnostics > Accounts and Profiles) first; it says which case this is.
  Confirm mail and drafts are synced to the server before rebuilding.
  Unsynced local items may be hard to recover, even from a saved old OST.

HOW TO RUN IT

  In the affected user's session, double-click Rebuild-OutlookOST.cmd.
  Preview from PowerShell in this folder:
    .\Rebuild-OutlookOST.ps1 -WhatIf -Display
  -TargetUser 'DOMAIN\user' selects a user; another account requires admin.
  The default Outlook folder and Office 16 ForceOSTPath are checked.
  Logs go to C:\Temp\Toolkit, with the target user's Temp as a fallback.
  If the OST was written in the last 10 minutes the confirmation prompt
  says so: sync is alive, and a rebuild is probably the wrong fix.

WHAT TO LOOK AT

  OstRenamed and RenameFailed show what happened to the selected caches.
  NextStep explains whether to open Outlook or retry after closing it.
  OldFilesLeftBehindMB shows backups from earlier runs.

LIMITS

  Resync needs network access, free disk space and time for large mailboxes.
  Custom per-account OST paths outside the selected folder are not found.
  Missing, linked or uncertain user paths and SYSTEM are refused.
  Native option: Rebuild-OutlookOST-NoPowerShell.cmd /? or /whatif.
  Native mode accepts the default folder and a local, unelevated console.
  Preview writes a plan log; it does not close Outlook or rename files.
