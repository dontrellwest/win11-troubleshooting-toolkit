CHECK NEW OUTLOOK APP AND SERVICE
=================================

WHAT IT DOES

  Checks the installed app, running state, WebView2, local data activity,
  mail-client settings, migration policies and Microsoft service endpoints.
  Read-only. Does not open or close Outlook or inspect mailbox messages.

WHEN TO USE IT

  New Outlook opens blank, spins or appears to show old mail.
  This is step 01, before considering a local app/cache reset.

HOW TO RUN IT

  In the affected user's session, double-click:
    01-Check-New-Outlook-App-and-Service.cmd
  PowerShell:
    .\01-Check-New-Outlook-App-and-Service.ps1 -Display
  Reports appear on screen and in C:\Temp\Toolkit.
  -StaleMinutes 30 changes the local-data freshness threshold.
  Service timeouts can make the check take longer.

WHAT TO LOOK AT

  Start with Verdict, NextStep and Warnings.
  Check WebView2 and service reachability before changing app data.
  Compare mail with Outlook on the web; check sorting and Focused/Other.
  LocalDataAgeMinutes shows activity, not proof of successful mailbox sync.
  If a local app/cache problem remains, read step 02's reset guide next.

LIMITS

  New Outlook only. Use the Classic Outlook folder for the older app.
  Local data under Microsoft\Olk and package state are indirect signals.
  The script cannot verify message content or server-side synchronization.
  Another user's package details may be unavailable without admin access.
