PRINT SPOOLER RESET
===================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: yes.

WHAT IT DOES
------------
  - Stops Print Spooler, removes queued SPL/SHD files, then starts it again.
  - Cancelled print jobs must be sent again.
  - Requires administrator rights.

WHEN TO USE IT
--------------
  - First run nearby 01 Check Printers and Queue.
  - Use a reset only for a stuck local queue/spooler, not every printer error.
  - Print jobs are stuck across printers or the queue will not clear.
  - Warn affected users before starting.
  - This does not fix a faulty driver.

HOW TO RUN IT
-------------
  - Double-click 03-Reset-Print-Queue.cmd and approve the prompts.
  - Preview from an administrator PowerShell in this folder:
      .\03-Reset-Print-Queue.ps1 -WhatIf -Display
  - The preview also needs admin; without it the tool stops with an error.
  - Logs go to C:\Temp\Toolkit.
  - Use -LogPath to choose another folder.

WHAT TO LOOK AT
---------------
  - SpoolerStatusAfter should say Running.
  - Send a test page afterward.
  - FilesFailed lists jobs that could not be removed.
  - Printers, drivers and ports are listed for follow-up checks.

LIMITS
------
  - Only SPL and SHD files present in the initial inventory are removed.
  - Other file types, subfolders and linked paths are left alone.
  - Broad or linked spool folders and running dependent services are refused.
  - Use 01-Check-Printers-and-Queue for printer deployment and policy details.
  - Native option: 03-Reset-Print-Queue-NoPowerShell.cmd /? or /whatif.
  - The native option accepts only the standard Windows spool directory.
  - Preview creates a plan log; it does not stop services or remove jobs.
