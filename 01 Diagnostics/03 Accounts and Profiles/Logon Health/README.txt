LOGON DIAGNOSTIC
================

WHAT IT DOES

  Checks domain connectivity, Kerberos, clock offset and sign-in signals.
  Uses the selected user where data is accessible.

WHEN TO USE IT

  - Domain logon or Microsoft 365 single sign-on is failing.
  - Investigating password, ticket or secure-channel problems.

HOW TO RUN IT

  Double-click Test-LogonHealth.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Test-LogonHealth.ps1 -Display
  Run as the affected user for their live token and PRT.
  Use -TargetUser DOMAIN\user to select another user.

WHAT TO LOOK AT

  - Confirm TargetUser and read Warnings first.
  - Large absolute TimeSkewSeconds warrants checking the time service.
  - Compare tickets, account state and connectivity before choosing a fix.

LIMITS

  - Clock offset retains w32tm's sign; use its absolute size for triage.
  - Another user's PRT is not read from the technician's session.
  - English native-command labels are required for some details.
  - No ticket purge, time resync or domain rejoin is performed.
  - Domain and Entra success paths still need field validation.

  Diagnostic only. Changes no settings and performs no repairs.
