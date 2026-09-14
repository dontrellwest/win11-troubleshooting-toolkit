OUTLOOK SYNC STATE
==================

Read-only. Changes nothing on this machine. Never starts or closes Outlook.

WHAT IT DOES

  Tells a sync problem from a display problem in classic Outlook before
  anyone spends an hour on an OST rebuild. Reads the connection mode, Work
  Offline, cached mode and sync window, how recently the OST was written,
  the view and filter on screen, the newest Inbox item and the Sync Issues
  count, then gives a verdict and the next step.

WHEN TO USE IT

  - "My newest emails are not showing" while Outlook on the web is current.
  - Before running the Outlook Cache repair, every time.
  - "Outlook is not syncing", "stuck at Updating Inbox", or a red X.

HOW TO RUN IT

  Double-click Get-OutlookSyncState.cmd with classic Outlook open.
  Run it as the signed-in user, without elevating. The report appears on
  screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-OutlookSyncState.ps1 -Display
  -StaleMinutes 30 changes when an OST write or Inbox item counts as old.
  Takes about 5 seconds.

  Outlook automation only works from the user's own session. Elevated with
  your own account, or with Outlook closed, the report still covers the
  profile, OST files and settings, and Warnings says what was skipped.

WHAT TO LOOK AT

  Verdict / NextStep   Read these first. "Sync looks healthy" with mail
                       missing on screen means View > Reset View, not a
                       rebuild. "Working Offline is on" is a one-click fix.
  ActiveViewFilter     Anything here is hiding mail in the folder on screen.
  ConnectionMode       "connected (full items)" is normal cached mode.
                       "disconnected" or "Working Offline" is the problem.
  OstAgeMinutes        Single digits means sync is alive right now.
  SyncIssuesCount      Growing means the server is rejecting items.
  ExchangeMailboxPresent
                       False means there is no OST to rebuild.

LIMITS

  - The verdict is a hint from local signals. Outlook on the web is the
    authority on what the server actually holds.
  - Verified on a Microsoft 365 mailbox in cached mode: healthy, view filter,
    Work Offline and Outlook-closed cases. Online (non-cached) mode and a
    growing Sync Issues folder have not been seen yet.
  - Accounts can read 0 with a mailbox signed in; classic Outlook does not
    always expose modern accounts to automation. Stores is the reliable list.
  - Exchange and Microsoft 365 checks need a domain or cloud-joined machine.
