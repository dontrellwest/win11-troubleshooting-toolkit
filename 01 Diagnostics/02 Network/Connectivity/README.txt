CONNECTIVITY TRIAGE
===================

WHAT IT DOES

  Checks network addressing, DNS and selected service connections.
  Includes gateway, domain, internet, proxy, Wi-Fi and VPN information.

WHEN TO USE IT

  - Internet, mapped drives or sign-in services are unavailable.
  - Checking connectivity while a problem is happening.

HOW TO RUN IT

  Double-click Test-Connectivity.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Test-Connectivity.ps1 -Display
  Add -FileServer '\\fs01\data' to check an extra share.

WHAT TO LOOK AT

  - Check addressing first, then DNS and the affected destination.
  - GatewayReachable can be False when the gateway blocks ping.
  - Read Warnings and compare related results before choosing a fix.

LIMITS

  - A failed probe has several possible causes.
  - Proxy, Wi-Fi and domain checks may be unavailable or incomplete.
  - User settings require the affected user's registry hive.
  - Usually takes about 13-20 seconds; domain paths need field tests.

  Diagnostic only. Changes no settings and performs no repairs.
