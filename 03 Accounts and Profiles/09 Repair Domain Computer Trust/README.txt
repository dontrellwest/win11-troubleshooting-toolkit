09 REPAIR DOMAIN COMPUTER TRUST
===============================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: yes.

WHAT IT DOES
------------
  - Repairs a confirmed failed AD computer secure channel and tests it again.

WHEN TO USE IT
--------------
  - A domain member has broken trust after DNS, VPN and time were checked.
  - First: 01 Check User Sign In.
  - Repair trust only when its test fails.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Server dc.example.com -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Before and after secure-channel results, followed by a real domain sign-in
    test.

LIMITS
------
  - AD members only; not Entra-only PCs or domain controllers.
  - Needs an authorized domain credential.
  - Never unjoins the PC.
  - -WhatIf previews the action and writes reports; no repair runs.
