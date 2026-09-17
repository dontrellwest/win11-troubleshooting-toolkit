NETWORK
=======

  Order: checks 01-04, then only the repair (05 or 06) the checks justify.

CHECKS
------
  01  Check Network Connection
      - Adapter, DHCP, DNS, gateway, proxy, VPN and service reachability.
  02  Test Internet Speed
      - Throughput and brief latency samples when the link is working.
  03  Check Mapped Drives and Credentials
      - Mappings and credential names for share access problems.
  04  Monitor Connection Dropouts
      - Sample the failing target over time; compare Wi-Fi event timestamps.

REPAIRS
-------
  05  Repair Selected Network Problem
      - Clear DNS cache OR renew one DHCP adapter, based on the checks.
      - DHCP renewal can interrupt remote support.
  06  Reconnect One Mapped Drive
      - Recreate one existing mapping only after server and share access
        work.
      - Run unelevated in the affected user's session; close mapped-drive
        files first.

NOTES
-----
  - Rerun the relevant check, then test the actual website, share or app.
  - No blanket network reset, VPN removal or credential purge is performed.
