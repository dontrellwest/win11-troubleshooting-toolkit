WINDOWS 11 TROUBLESHOOTING TOOLKIT
=================================

START HERE
  Open 01 Diagnostics and choose the folder for the problem.
  For an unfamiliar PC, start with System Information\Machine Fact Sheet.
  Each tool has a brief README.txt explaining when and how to use it.

HOW TO RUN
  Double-click the CMD with the same name as the PS1 script.
  Keep the files together. Approve administrator access when requested.
  Most diagnostic reports go to C:\Temp\Toolkit on the PC being checked.
  The Internet Speed and Profile Inventory guides explain their outputs.
  Performance Overview writes to C:\Temp unless its guide says otherwise.
  Read warnings: missing data does not mean the check passed.

BEFORE USING THIS ON A CLIENT PC
  The diagnostics list Kerberos tickets, saved credential names, local
  administrators and security settings - the same activity EDR products
  watch for. Building this toolkit set off SentinelOne on a managed
  laptop, so assume a field run can too until an exclusion is confirmed.
  Arrange a path exclusion, a hash exclusion or code signing first.
  Files copied from the internet carry a "blocked" flag. The launchers
  work around it; if a tool still refuses to start, run once in PowerShell:
    Get-ChildItem "D:\Troubleshooting Scripts" -Recurse -File | Unblock-File
  Do not change the PC's execution policy or the .ps1 file association.

FOLDERS
  01 Diagnostics
    01 System Information
      Machine Fact Sheet         Hardware, Windows and basic security
      Boot and Shutdown History  Restarts, crashes and shutdown reasons
      Reliability History        Application and Windows failures
      Recent Changes             Updates, installs and driver changes
      Software Inventory         Installed applications
    02 Network
      Connectivity               Network, DNS and endpoint checks
      Mapped Drives and Credentials
      Internet Speed             Download, upload and connection timing
    03 Accounts and Profiles
      Group Policy               Applied policy and recent errors
      Logon Health               Domain, tickets, time and Entra status
      OneDrive and Folder Backup  Account and folder configuration
      Profile Health             Profile records and size estimates
      Profile Inventory          CSV inventory; does not delete profiles
    04 Performance
      Disk Space                 Space usage and cleanup candidates
      Resource Usage             Sampled CPU, memory and disk activity
      Startup Programs           Startup entries, tasks and services
      Performance Overview       Broad system snapshot
    05 Windows Update
      Update Status              Updates, policy and reboot indicators
    06 Printing
      Printer Inventory          Printers, drivers, ports and spooler
    07 Security
      Antivirus Status           Microsoft Defender status
      Local Administrators       Administrators group membership
      Encryption and Firmware    BitLocker, TPM and firmware
  02 Repairs
    01 Windows System Files      DISM and System File Checker
    02 Print Queue               Clear jobs and restart the spooler
    03 Explorer and Icon Cache   Restart Explorer and rebuild icon caches
    04 Outlook Cache             Rename classic Outlook OST caches
  03 Fleet                       Run reviewed diagnostics over existing WinRM
  _Maintenance                   Test scripts, results and archived material

REPAIRS
  Read the tool's guide and preview before applying a repair.
  Example from the Explorer repair folder in PowerShell:
    .\Repair-Explorer.ps1 -WhatIf -Display
  Repairs ask for confirmation and write a log.
  Run user repairs in the affected user's session.
  A -NoPowerShell.cmd file is a separate native version with fewer options.
  Read its /? help; use /whatif to preview native repairs.

NOTES
  27 tools: 22 local diagnostics, four repairs and one fleet runner.
  Domain/Entra and successful fleet runs need a managed test environment.
  Outlook cache repair requires classic Outlook and a local OST cache.
  DISM/SFC commands were checked; execution was excluded from laptop tests.
  Current test summary: _Maintenance\Documentation\TEST-RESULTS.txt.
  The original folders and files are preserved in _Maintenance\Archive.
