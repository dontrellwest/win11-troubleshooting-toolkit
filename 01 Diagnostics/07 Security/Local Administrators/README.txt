LOCAL ADMINISTRATOR AUDIT
=========================

WHAT IT DOES

  Lists local administrators, local accounts and LAPS policy signals.
  Flags entries to compare with your site's approved account baseline.

WHEN TO USE IT

  - Investigating unexpected administrator access.
  - Checking local accounts and password-management configuration.

HOW TO RUN IT

  Double-click Get-LocalAdminAudit.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-LocalAdminAudit.ps1 -Display
  Use -ExpectedAdmins 'DOMAIN\Helpdesk','PC\Admin' for your baseline.
  Use -KnownLocalAccounts to adjust the standard local-account list.

WHAT TO LOOK AT

  - Review UnexpectedAdmins and UnexpectedLocalAccounts.
  - Check unresolved SIDs before deciding that an account was deleted.
  - Compare LAPS settings and recent errors with your management console.

LIMITS

  - Default known accounts include localuser, the original build account.
  - Domain Admins and the built-in admin are default expected members.
  - A LAPS policy is not proof that a usable password was backed up.
  - LAPS event age is a heuristic; directory-side validation remains due.
  - Unresolved domain names can be caused by connectivity or permissions.

  Diagnostic only. Changes no settings and performs no repairs.
