NEW OUTLOOK SYNC STATE
======================

Read-only. Changes nothing on this machine. Never starts or closes the app.

WHAT IT DOES

  Checks the new Outlook app (olk.exe) for the signed-in user. New Outlook
  has no automation interface, no profile and no OST, so this reads what
  exists: the Store package and version, whether it is running, the
  WebView2 runtime it depends on, the local data folders and how recently
  they changed, the default mail client, the classic/new switch policies,
  and whether the Microsoft 365 endpoints answer. Then a verdict.

WHEN TO USE IT

  - New Outlook opens blank, spins, or shows old mail.
  - "Which Outlook is this user on?" and whether policy forced the switch.
  - Before running the New Outlook cache reset, every time.

HOW TO RUN IT

  Double-click Get-NewOutlookSyncState.cmd with new Outlook open.
  Run it as the signed-in user, without elevating. The report appears on
  screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-NewOutlookSyncState.ps1 -Display
  -StaleMinutes 30 changes when local data counts as not updating.
  Takes about 5 seconds; longer if the service endpoints do not answer.

  For classic Outlook use the Outlook Sync State (Classic) folder.

WHAT TO LOOK AT

  Verdict / NextStep     Read these first. "Local data active" with mail
                         missing means a filter, sort or Focused/Other
                         setting, not a broken app.
  WebView2Present        False and the app will never open. Install the
                         WebView2 runtime; nothing else matters until then.
  ServiceOutlookOffice   False with ServiceLogin False is a network
                         problem, not an Outlook problem.
  SignedInHint           False means no account data on this PC yet.
  LocalDataAgeMinutes    Single digits means the app is syncing right now.
  DefaultMailClient      Which Outlook mailto links open in.
  AutoMigrationPolicy    A policy value here is why the user was moved.

LIMITS

  - The mailbox cannot be read. Outlook on the web is the authority on what
    the server holds; this tool reports app, data and service signals only.
  - Verified on a machine where new Outlook was installed but never signed
    in. The signed-in data layout has not been observed yet.
  - Another user's package version needs admin; without it the install is
    inferred from the data folder.
