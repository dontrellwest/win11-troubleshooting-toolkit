05 CHECK STORAGE ERRORS AND RELIABILITY
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Checks volumes, physical disks, exposed reliability counters and storage
  events.

WHEN TO USE IT
  Repeated freezes, corruption, disk warnings or unexplained slow I/O.
  Use before intensive repairs if storage faults are suspected.

HOW TO RUN IT
  Open the matching CMD; approve or decline the administrator prompt.
  Or open PowerShell in this folder. Example options:
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Unhealthy disks and recurring controller, NTFS or I/O errors.

LIMITS
  Some controllers do not expose counters. The dirty-bit query needs
  admin; declining the prompt runs the rest unelevated. No CHKDSK repair,
  DISM or SFC is run.
