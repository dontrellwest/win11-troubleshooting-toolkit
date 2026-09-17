FLEET
=====

  Choose the inventory you need; read its run-location instructions first.

TOOLS
-----
  01  Collect Diagnostics from PCs
      - Open the folder and read its README.txt.
      - Choose a diagnostic and the intended PCs, then preview with -WhatIf.
      - Review the target list before running the collection.
  02  Find Windows 10 Computers
      - Computer names, OS/build details, check times and Unknown targets.
      - Run on endpoints through N-central or centrally over existing WinRM.
      - Supports AD discovery, computer lists and merging endpoint reports.

NOTES
-----
  - WinRM and access must already be configured.
  - Only reviewed ReadOnly-labelled scripts are accepted.
  - The runner does not enable remoting or run repairs.
  - Local endpoint mode needs no WinRM. AD discovery needs RSAT AD tools.
  - Offline or failed targets are not evidence that Windows 10 is absent.
