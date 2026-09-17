FIND WINDOWS 10 COMPUTERS
========================

  [CHECK]  Collects information; does not change the PC. Admin: no.

WHAT IT DOES
------------
  - Lists Windows 10 computer names, edition, version/build and check time.
  - Excludes Windows 11 and Windows Server using live OS type/build data.
  - Reports unreachable, failed and stale imported checks as Unknown.

WHEN TO USE IT
--------------
  - Finding remaining Windows 10 PCs for upgrade planning or follow-up.
  - Use N-central agents for remote customers and offsite laptops.
  - Use Fleet mode from a technician PC with existing WinRM access.

HOW TO RUN IT
-------------
  - Double-click the CMD to choose Local, Fleet or Merge.
  - Local checks this PC only. N-central must target every intended device.
  - For N-central setup and combined results, read RUN-FROM-N-CENTRAL.txt.
  - For AD or a computer list, read RUN-FROM-ADMIN-PC.txt.
  - From PowerShell in this folder, to check this PC:
      .\02-Find-Windows-10-Computers.ps1 -Mode Local -Display
  - Output: C:\Temp\Toolkit\Windows10, or your -ReportPath folder.

WHAT TO LOOK AT
---------------
  - Windows10-Names.txt is the plain computer-name list.
  - Windows10.csv adds customer/site, OS, build and hardware model details.
  - All.csv includes every returned target; Unknown.csv lists follow-up PCs.
  - Read the summary counts and scope before trusting an empty names file.
  - CollectedAtUtc shows when the OS was actually read.
  - Computer names may repeat across customers; use the detailed CSV.

LIMITS
------
  - N-central run success means inventory ran, not that Windows 10 is absent.
  - AD metadata can be outdated; only successful live checks confirm the OS.
  - Fleet needs existing WinRM and remote rights, not just local admin.
  - AD discovery needs RSAT; AD does not include unmanaged/non-domain PCs.
  - Merge reads downloaded endpoint reports, not the N-central API.
  - Missing/offline devices must be reconciled with the intended target list.
  - Imported reports older than 7 days are Unknown; use -MaxAgeDays to change.
  - No upgrade, reboot, remoting setup, ESU or hardware-readiness assessment.
