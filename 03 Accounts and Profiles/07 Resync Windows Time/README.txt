07 RESYNC WINDOWS TIME
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Requests a time resync using the configured Windows time source.

WHEN TO USE IT
  Sign-in checks show time trouble and the configured source is reachable.
  First: 01 Check User Sign In. Afterward: rerun it and retry access.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Time source, last successful synchronization and the original sign-in
  result.

LIMITS
  Requires the Windows Time service running. Does not replace domain time
  policy or select a public NTP server.
  -WhatIf previews the action and writes reports; no repair runs.
