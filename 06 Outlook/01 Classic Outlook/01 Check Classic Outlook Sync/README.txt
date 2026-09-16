CHECK CLASSIC OUTLOOK SYNC AND VIEW
===================================

WHAT IT DOES

  Reads classic Outlook's connection mode, Work Offline, current view/filter,
  Inbox freshness, Sync Issues count, profile settings and OST details.
  Read-only. Attaches to a running Outlook; never starts or closes it.

WHEN TO USE IT

  New mail is missing, Outlook seems stuck, or before rebuilding an OST.
  This is step 01 in the Classic Outlook folder.

HOW TO RUN IT

  Open classic Outlook in the affected user's session.
  Double-click 01-Check-Classic-Outlook-Sync.cmd without elevating.
  PowerShell: .\01-Check-Classic-Outlook-Sync.ps1 -Display
  Reports appear on screen and in C:\Temp\Toolkit.
  -StaleMinutes 30 changes the local freshness threshold.
  With Outlook closed or automation unavailable, read Warnings for gaps.

WHAT TO LOOK AT

  Start with Verdict and NextStep. Check Work Offline and the current filter.
  Compare missing messages with Outlook on the web.
  A recent OST write suggests activity; it does not prove full mailbox sync.
  Correct a view/filter or offline setting before considering a rebuild.
  If a local cache problem remains, read step 02's rebuild guide next.

LIMITS

  Classic Outlook only. Use the separate New Outlook folder for that app.
  Local timestamps, counts and verdicts are clues, not server verification.
  Accounts may show zero despite a mailbox being present; check Stores.
  Online mode and a growing Sync Issues folder need further field coverage.
