MAPPED DRIVE AND CREDENTIAL AUDIT
=================================

WHAT IT DOES

  Lists mapped drives, saved mappings and credential metadata.
  Checks file-server reachability. It does not display passwords.

WHEN TO USE IT

  - A drive letter is missing or shows a red X.
  - Investigating access-denied messages or repeated sign-in prompts.

HOW TO RUN IT

  Double-click Get-MappedDriveAudit.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-MappedDriveAudit.ps1 -Display
  Run as the affected user without elevating for session details.
  Add -TargetUser DOMAIN\user for another user's stored mappings.

WHAT TO LOOK AT

  - Compare Port445Reachable, PathReachable and the mapping Status.
  - Credential age and account names are clues, not proof of a bad password.
  - Read on-screen warnings for information that could not be collected.

LIMITS

  - Live mappings and credentials belong to a particular logon session.
  - Another account can read fewer details, even with admin access.
  - Warnings are separate from the returned rows.
  - Domain scenarios still need validation on a managed PC.

  Diagnostic only. Changes no settings and performs no repairs.
