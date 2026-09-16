INTERNET SPEED TEST
===================

WHAT IT DOES

  Measures download/upload throughput and connection timing.
  Uses external Cloudflare endpoints and consumes network data.
  PowerShell uses .NET; the native version uses curl. No admin needed.

WHEN TO USE IT

  Compare a slow PC with another PC on the same connection.
  Run one test at a time per site so tests do not compete.

HOW TO RUN IT

  Double-click 02-Test-Internet-Speed.cmd.
  Native fallback: 02-Test-Internet-Speed-NoPowerShell.cmd.
  For unattended PowerShell output:
    02-Test-Internet-Speed.cmd KeyValue NoPause
  For unattended native output:
    02-Test-Internet-Speed-NoPowerShell.cmd /q
  Add SkipUpload to PowerShell or /noup to the native version to omit upload.
  02-Test-Internet-Speed-NoPowerShell.cmd /? shows native options.

WHAT TO LOOK AT

  Down and Up are Mbps. Compare repeated runs under similar conditions.
  PowerShell Latency measures TCP timing.
  Native TTFB also includes server and TLS response time.
  Compare the reported proxy when the two versions differ.

LIMITS

  A single-stream result does not establish the connection's maximum speed.
  SYSTEM and interactive users can have different proxy settings.
  The native version creates a temporary upload file and removes it afterward.
