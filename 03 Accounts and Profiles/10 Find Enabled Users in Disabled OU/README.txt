FIND ENABLED USERS IN DISABLED OU
=================================

  [CHECK]  Collects information; does not change the PC. Admin: no.

WHAT IT DOES
------------
  - Lists enabled AD user accounts still in the selected disabled-users OU.
  - Includes child OUs by default.
  - Read-only; makes no AD changes.

WHEN TO USE IT
--------------
  - Accounts were re-enabled but may still be in the disabled-users OU.
  - Active here means Enabled=True, not a recent sign-in.

HOW TO RUN IT
-------------
  - Use a PC with the RSAT ActiveDirectory module and access to the domain.
  - Run as an account allowed to read the OU.
  - Local admin is not required.
  - Double-click 10-Find-Enabled-Users-in-Disabled-OU.cmd.
  - Enter a domain controller or press Enter for the current domain.
  - Enter the OU name/path, or press Enter for Disabled Users.
  - If several OUs match, choose the correct full path from the list.
  - From PowerShell in this folder:
      .\10-Find-Enabled-Users-in-Disabled-OU.ps1 -Display
  - Add -SearchBase 'OU=Disabled Users,DC=example,DC=com' for an exact OU.
  - Add -Server 'dc01.example.com' to select a domain controller.
  - Replace the example domain and OU with your own.
  - -SearchScope OneLevel checks only users directly inside the OU.
  - -Credential (Get-Credential) uses another account for directory reads.

WHAT TO LOOK AT
---------------
  - Name, SamAccountName and DistinguishedName identify each account.
  - Review the list with the account owner before making any changes.
  - TXT, CSV and JSON reports go to C:\Temp\Toolkit, or use -ReportPath.
  - An empty completed report means this query returned no enabled users.
  - A failed query is reported as Failed, never as a clean result.

LIMITS
------
  - Checks OU location, not membership in a Disabled Users group.
  - Enabled accounts can still be expired, locked out or unused.
  - WhenChanged is any account change, not specifically re-enabling.
  - Results reflect one DC and your read access; replication can lag.
  - No account is moved, enabled, disabled or removed from any group.
