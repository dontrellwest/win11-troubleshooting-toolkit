05 REPAIR SELECTED NETWORK PROBLEM
==================================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: yes.

WHAT IT DOES
------------
  - Clears the local DNS cache OR renews one selected IPv4 DHCP lease.

WHEN TO USE IT
--------------
  - Only when the network check points to a cache or DHCP problem.
  - First: 01 Check Network Connection.
  - Afterward: rerun that check.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Action ClearDnsCache -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Before and after adapter, address, DNS and TCP results.
  - Retry the original task.

LIMITS
------
  - RenewDhcp requires -InterfaceIndex and can interrupt remote support.
  - Does not reset all adapters, Winsock, VPN or proxy settings.
  - -WhatIf previews the action and writes reports; no repair runs.
