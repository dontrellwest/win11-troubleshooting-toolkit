01 CHECK TEAMS APP AND CONNECTION
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Checks the current-user New Teams package, process and basic endpoint
  reachability.

WHEN TO USE IT
  Teams will not open or has sign-in, message or call trouble.
  Next: 02 Restart or Clear Teams Cache only if findings justify it.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Package state, process count and endpoint reachability.

LIMITS
  TCP probes do not validate tenant service health, login, proxies, audio or
  calls. Classic Teams is not covered.
