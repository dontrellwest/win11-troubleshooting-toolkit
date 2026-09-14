PRINT SPOOLER RESET
===================

WHAT IT DOES

  Stops Print Spooler, removes queued SPL/SHD files, then starts it again.
  Cancelled print jobs must be sent again. Requires administrator rights.

WHEN TO USE IT

  Print jobs are stuck across printers or the queue will not clear.
  Warn affected users before starting. This does not fix a faulty driver.

HOW TO RUN IT

  Double-click Reset-PrintSpooler.cmd and approve the prompts.
  Preview from an administrator PowerShell in this folder:
    .\Reset-PrintSpooler.ps1 -WhatIf -Display
  The preview also needs admin; without it the tool stops with an error.
  Logs go to C:\Temp\Toolkit. Use -LogPath to choose another folder.

WHAT TO LOOK AT

  SpoolerStatusAfter should say Running. Send a test page afterward.
  FilesFailed lists jobs that could not be removed.
  Printers, drivers and ports are listed for follow-up checks.

LIMITS

  Only SPL and SHD files present in the initial inventory are removed.
  Other file types, subfolders and linked paths are left alone.
  Broad or linked spool folders and running dependent services are refused.
  Use Get-PrinterInventory for printer deployment and policy details.
  Native option: Reset-PrintSpooler-NoPowerShell.cmd /? or /whatif.
  The native option accepts only the standard Windows spool directory.
  Preview creates a plan log; it does not stop services or remove jobs.
