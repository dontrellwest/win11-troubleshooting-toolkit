UPDATE STATE
============

WHAT IT DOES

  Reports update settings, history, pending updates and reboot flags.
  An online search checks what the configured update service offers.

WHEN TO USE IT

  - A PC appears behind on updates.
  - Investigating repeated update failures or pending restarts.

HOW TO RUN IT

  Double-click Get-UpdateState.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-UpdateState.ps1 -Display
  Usually takes 20 seconds to 3 minutes.
  Add -SkipSearch to omit the online scan and return history faster.

WHAT TO LOOK AT

  - Check LatestCumulativeInstalled and the recent update history.
  - Compare failed KB numbers and error codes across attempts.
  - Check policy pauses, update source and reboot flags together.
  - Read Warnings before treating an empty pending list as up to date.

LIMITS

  - An offered update may simply not have been downloaded yet.
  - Policy values alone do not prove which service handled each update.
  - With -SkipSearch, pending counts are unknown, not zero.
  - WSUS and managed-policy paths still need field validation.

  Diagnostic only. Changes no settings and performs no repairs.
