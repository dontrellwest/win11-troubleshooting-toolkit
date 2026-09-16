NETWORK - SUGGESTED WORKFLOW
===========================

01 Check Network Connection
  Start with adapter, DHCP, DNS, gateway, proxy, VPN and service reachability.
02 Test Internet Speed
  Use for throughput and brief latency samples when the link is working.
03 Check Mapped Drives and Credentials
  Inspect mappings and credential names for share access problems.
04 Monitor Connection Dropouts
  Sample the failing target over time and compare Wi-Fi event timestamps.
05 Repair Selected Network Problem
  Clear DNS cache OR renew one DHCP adapter, based on the checks.
  DHCP renewal can interrupt remote support.
06 Reconnect One Mapped Drive
  Recreate one existing mapping only after server and share access work.
  Run unelevated in the affected user's session; close mapped-drive files.

Rerun the relevant check, then test the actual website, share or application.
No blanket network reset, VPN removal or credential purge is performed.
