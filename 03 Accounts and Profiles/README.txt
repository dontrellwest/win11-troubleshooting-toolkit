ACCOUNTS AND PROFILES
=====================

  Order: checks 01-05 (and 10) first; repairs 06-09 only when justified.

CHECKS
------
  01  Check User Sign In
      - Domain, tickets, time and account context.
  02  Check Group Policy
      - Applied policy and errors.
  03  Check User Profile Health
      - Profile records and paths.
  04  List User Profile Data
      - Detailed inventory; does not delete profiles.
  05  Check OneDrive and Folder Backup
      - Account, folders and sync hints.
  10  Find Enabled Users in Disabled OU
      - Lists enabled AD accounts left in the disabled-users OU. Read-only.
      - Needs RSAT AD tools and domain access. Includes sub-OUs.
      - Select the OU, review the list and use the CSV for follow-up.

REPAIRS
-------
  06  Restart or Reset OneDrive
      - Try Restart first, Reset only if needed.
  07  Resync Windows Time
      - Keeps the configured time source; recheck it afterward.
  08  Refresh Selected Group Policy
      - Choose User or Computer scope.
  09  Repair Domain Computer Trust
      - Advanced AD member-only repair. Resolve DNS, VPN and time first;
        provide an authorized domain account.

NOTES
-----
  - Run user actions in the affected desktop session. Machine actions need
    admin.
  - No automatic profile deletion, domain unjoin or time-policy replacement.
  - Afterward, rerun the relevant check and repeat the original sign-in or
    sync.
