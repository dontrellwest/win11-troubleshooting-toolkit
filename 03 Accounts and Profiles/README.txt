ACCOUNTS AND PROFILES - SUGGESTED WORKFLOW
========================================

01 Check User Sign In: domain, tickets, time and account context.
02 Check Group Policy: applied policy and errors.
03 Check User Profile Health: profile records and paths.
04 List User Profile Data: detailed inventory; does not delete profiles.
05 Check OneDrive and Folder Backup: account, folders and sync hints.

REPAIRS WHEN THE CHECKS JUSTIFY THEM
  06 Restart or Reset OneDrive: try Restart first, Reset only if needed.
  07 Resync Windows Time: keep the configured time source and recheck it.
  08 Refresh Selected Group Policy: choose User or Computer scope.
  09 Repair Domain Computer Trust: advanced AD member-only repair.
     Resolve DNS, VPN and time first; provide an authorized domain account.

Run user actions in the affected desktop session. Machine actions need admin.
No automatic profile deletion, domain unjoin or time-policy replacement.
Afterward, rerun the relevant check and repeat the original sign-in or sync.
