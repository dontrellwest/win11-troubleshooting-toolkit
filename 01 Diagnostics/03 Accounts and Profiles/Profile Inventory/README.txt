PROFILE INVENTORY
=================

WHAT IT DOES

  Lists non-system Windows profiles, selected folder sizes and preserve flags.
  Writes a CSV and transcript. Does not remove profiles or registry entries.

WHEN TO USE IT

  Reviewing existing profile data before planning any separate cleanup.
  For general diagnosis, also see the Profile Health folder.

HOW TO RUN IT

  Double-click Get-ProfileInventory.cmd and approve administrator access.
  Keep it beside Get-ProfileInventory.ps1.
  Results go to C:\ProfileAudit\yyyy-MM-dd on the computer being checked.
  The script displays the CSV and transcript paths before it finishes.

WHAT TO LOOK AT

  PRESERVE marks localuser and Public; add site accounts in the script.
  Loaded means the profile is in use. LocalDataMB covers selected folders.
  Check the CSV and transcript for missing or incomplete information.

LIMITS

  Preserve names are site-specific; do not assume they fit another customer.
  SID lookup failure does not prove an account is orphaned.
  Age and small measured size are not permission to delete a profile.
  Repeated runs on the same day replace that computer's CSV.
  Only this inventory phase exists here. No cleanup stage was implemented.
