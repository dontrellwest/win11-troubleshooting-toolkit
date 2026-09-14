RESOURCE SNAPSHOT
=================

WHAT IT DOES

  Samples CPU, memory, disk and network activity for about one minute.
  Lists processes seen during the sampling window.

WHEN TO USE IT

  - A PC is slow while the user can reproduce the problem.
  - Comparing activity before and after a change.

HOW TO RUN IT

  Double-click Get-ResourceSnapshot.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-ResourceSnapshot.ps1 -Display
  For a longer run: -DurationSeconds 300 -IntervalSeconds 10

WHAT TO LOOK AT

  - Read Verdict alongside the measurements and Warnings.
  - Compare TopProcesses across CPU, memory, I/O and handle counts.
  - Repeat during the problem if the first sample looks normal.

LIMITS

  - The verdict uses simple thresholds; it is not a root-cause diagnosis.
  - Brief spikes and processes between samples may be missed.
  - Process owner and image details may need admin access.
  - Disk queue and paging readings depend on workload and hardware.

  Diagnostic only. Changes no settings and performs no repairs.
