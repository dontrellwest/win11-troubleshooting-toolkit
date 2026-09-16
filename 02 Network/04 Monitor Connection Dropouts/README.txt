04 MONITOR CONNECTION DROPOUTS
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Repeats gateway ping, DNS and TCP checks and reads recent Wi-Fi events.

WHEN TO USE IT
  For intermittent drops missed by a one-time connection check.
  First: 01 Check Network Connection. Then monitor the failing service.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Target www.microsoft.com -Samples 12
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Compare timestamps of gateway, DNS and target failures with the reported
  dropout.

LIMITS
  Ping may be blocked. TCP success does not prove app health. Maximum 600
  samples. Ctrl+C stops early; samples taken so far are still reported.
  A lost default route is recorded as a failed gateway sample.
