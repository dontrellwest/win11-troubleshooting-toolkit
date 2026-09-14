PRINTER INVENTORY
=================

WHAT IT DOES

  Lists printers, drivers, ports, spooler state and queued-job hints.
  Also reports the signed-in user's default printer and connections.

WHEN TO USE IT

  - A printer is missing, offline or has a stuck queue.
  - Recording the print configuration before a repair.

HOW TO RUN IT

  Double-click Get-PrinterInventory.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-PrinterInventory.ps1 -Display
  Add -TargetUser DOMAIN\user to specify the affected user.
  Usually takes a few seconds; unreachable print servers can take longer.

WHAT TO LOOK AT

  - Check SpoolerStatus, the affected printer and its port address.
  - StuckJobs identifies jobs to investigate before clearing a queue.
  - Compare driver names and the user's default printer.

LIMITS

  - Spool folder details require admin access.
  - GPO attribution is a name match, not proof of deployment source.
  - An old spool file alone does not prove that it cannot finish.
  - Domain and other-user success paths still need field validation.

  Diagnostic only. Changes no settings and performs no repairs.
