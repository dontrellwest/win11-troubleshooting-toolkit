WINDOWS 11 TROUBLESHOOTING TOOLKIT
==================================

HOW TO USE IT
-------------
  - Double-click the tool you need. Every tool is a CMD file in this folder,
    named "Area - What it does".
  - Checks only read and report. Repairs say what they will change and ask
    "Start now? [Y/N]" before doing it.
  - Tools that need administrator rights ask for them. If no prompt appears,
    right-click the file and choose "Run as administrator".
  - Tools marked (user) change the signed-in user's own files. Double-click
    them in that user's session, without "Run as administrator".
  - Check reports are saved in C:\Temp\Toolkit as well as shown on screen.
    Test Speed only shows its result on screen.

READING A CHECK REPORT
----------------------
  - SUMMARY comes first. Its RESULT line is the verdict: NO PROBLEMS FOUND,
    REVIEW, ACTION NEEDED or INCOMPLETE.
  - Findings follow, most serious first: PROBLEM, WARNING, NOT CHECKED
    (could not be read; not a pass), INFO and OK.
  - Every PROBLEM and WARNING has a "Next:" line with the step to take.
  - DETAILS lists every value that was read.

CHECKS
------
  Windows - Check Computer
      Fact sheet: hardware, Windows version, uptime, pending restart, disk
      space and health, domain or Entra join, BitLocker, battery.
  Windows - Check Crashes and Restarts
      Blue screens, crashing programs, failed drivers and services, and who
      or what restarted the PC.
  Windows - Check Recent Changes
      Updates, drivers and programs installed or removed in the last 14 days.
  Windows - List Installed Software
      Every installed program with its version and install date.
  Windows - Check Updates
      Windows Update: latest updates, pending and failed ones, restarts.
  Network - Check Connection
      Adapter, IP address, gateway, DNS, internet access and Wi-Fi signal.
  Network - Check Mapped Drives                                    (user)
      Mapped drives, whether their servers answer, and saved credentials.
  Network - Test Speed
      Download and upload speed and latency. Takes about 30 seconds.
  Accounts - Check User Sign-In
      Account state, lockout, password expiry, domain trust and clock.
  Accounts - Check Group Policy
      When policy last applied, policy errors and filtered policies.
  Accounts - Check User Profiles
      Temporary or corrupt profiles, leftover profile folders and sizes.
  Accounts - Check Profile Last Sign-In
      When each local profile was last used. A review list only, never proof
      that a profile can be deleted.
  Accounts - Check OneDrive                                        (user)
      OneDrive running and signed in, sync folder, folder backup, errors.
  Performance - Check Slow PC
      What uses CPU, memory and disk right now, then what starts with
      Windows.
  Performance - Check Disk Space
      Where the space on C: went. Takes a few minutes; plug a laptop in.
  Printing - Check Printers
      Printers, ports, the print spooler and stuck print jobs.
  Outlook - Check Outlook                                          (user)
      Classic Outlook data files and sync, and the new Outlook app.
  Security - Check Security
      Defender, local administrators, BitLocker, TPM and Secure Boot.
  Admin - Find Enabled Users in Disabled OU
      Active Directory: enabled accounts left in a disabled-users OU. Run it
      on a domain PC with RSAT.

REPAIRS
-------
  Windows - Repair System Files with DISM and SFC
      DISM /RestoreHealth, then sfc /scannow. Takes 15-40 minutes.
  Windows - Reset Windows Update
      Stops the update services, renames SoftwareDistribution and catroot2,
      and starts the services again.
  Windows - Restart Explorer and Icons                             (user)
      Restarts Explorer and clears the icon and thumbnail caches.
  Network - Reset Network
      Clears the DNS cache and renews the IP address; optionally resets
      Winsock and TCP/IP (needs a restart).
  Accounts - Reset OneDrive                                        (user)
      Microsoft's OneDrive reset. No files are deleted.
  Performance - Clean Temp Files                                   (user)
      Deletes the user's temp files older than 7 days.
  Printing - Reset Print Queue
      Restarts the print spooler and deletes every waiting print job.
  Outlook - Rebuild Classic Mail Cache                             (user)
      Renames the .ost files so Outlook downloads the mailbox again. For
      Microsoft 365 or Exchange: an IMAP account keeps "This computer only"
      calendar and contacts in its .ost.
  Outlook - Reset New Outlook                                      (user)
      Moves new Outlook's local data aside, like resetting the app.
  Teams - Reset Teams                                              (user)
      Clears the new Teams cache and starts Teams again.
  Devices - Restart Audio
      Restarts the Windows audio services.
  - The Outlook repairs keep every earlier copy (.old, then .old2 and so
    on). Windows Update and Teams replace their previous cache copy.

QUICK COMMANDS
--------------
  These need no tool. Press Windows key + R, or use an admin prompt.
  - Refresh Group Policy:
      gpupdate /force
  - Resync the clock (admin prompt):
      w32tm /resync /force
  - Repair the domain trust (admin PowerShell, domain admin account):
      Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
  - Start classic Outlook without add-ins:
      outlook.exe /safe
  - Repair or reset a Store app: Settings, Apps, Installed apps, the app,
    Advanced options.

BEFORE USING THIS ON A CLIENT PC
--------------------------------
  - The checks read Kerberos tickets, saved credential names, local admins
    and security settings, which EDR products watch. Building this toolkit
    once set off SentinelOne; arrange an exclusion or code signing first.
  - Files copied from the internet can be blocked. If a tool will not
    start, run this once in PowerShell, using the toolkit's own folder:
      Get-ChildItem "D:\Troubleshooting Scripts" -Recurse | Unblock-File

MORE
----
  - Scripts holds the PowerShell behind the checks. In PowerShell in that
    folder, Get-Help .\<name>.ps1 -Full shows options such as -Days.
  - Remote or scripted use (RMM): set TOOLKIT_UNATTENDED=1 to skip the
    "Start now?" question and the final pause.
  - _Maintenance holds notes, tests and the archive. The tools do not need
    it: the CMD files and the Scripts folder are the whole toolkit.
