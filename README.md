# Windows 11 Troubleshooting Toolkit

A field toolkit for an MSP technician: **27 PowerShell diagnostic and repair tools** for Windows 11 laptops and desktops on Active Directory and Microsoft 365. It runs straight from a flash drive, installs nothing, and needs only Windows PowerShell 5.1 with inbox modules.

Every tool has a double-click `.cmd` launcher and a one-page plain-text guide, returns structured objects so the same script can answer one ticket at a desk or run across a fleet into CSV, and is built to a written specification with an automated acceptance suite.

> The field guides are deliberately `README.txt`, not Markdown: they have to open in Notepad on whatever machine a technician is standing at. `README.txt` in this folder is the drive's own front page; it mentions a maintenance folder (test harness, documentation, evidence) that is internal and not published here.

## Layout

```
01 Diagnostics/          22 read-only tools, grouped by problem area
  01 System Information    Machine Fact Sheet, Boot and Shutdown History, Reliability History,
                           Recent Changes, Software Inventory
  02 Network               Connectivity, Internet Speed, Mapped Drives and Credentials
  03 Accounts and Profiles Group Policy, Logon Health, OneDrive and Folder Backup,
                           Profile Health, Profile Inventory
  04 Performance           Disk Space, Performance Overview, Resource Usage, Startup Programs
  05 Windows Update        Update Status
  06 Printing              Printer Inventory
  07 Security              Antivirus Status, Encryption and Firmware, Local Administrators
02 Repairs/              4 guarded repair tools: Windows System Files (DISM + SFC), Print Queue,
                         Explorer and Icon Cache, Outlook Cache - each with a native CMD fallback
03 Fleet/                Runs any read-only tool over WinRM against a host list or AD search base
```

Each tool folder contains exactly `<Verb-Noun>.ps1`, `<Verb-Noun>.cmd` and `README.txt`; repair tools add `<Verb-Noun>-NoPowerShell.cmd` for machines where PowerShell is blocked by policy.

## Design rules that every tool follows

- **Read-only means read-only.** Diagnostics have an explicit denylist (no `Win32_Product`, no `gpupdate`, no state-changing verbs) and are scanned for it. There is no `-Fix` switch anywhere, and the fleet runner refuses repair-class scripts by header.
- **Repairs are guarded.** `SupportsShouldProcess` with `ConfirmImpact='High'`, one confirmation naming exactly what will change, a log for every run including previews, and `-WhatIf` that changes nothing.
- **The tech at the user's desk.** A per-user tool describes the person signed in, not the technician who elevated with their own admin account. Tools never read `HKCU:` or the process's own profile variables; they resolve the console user's hive and profile path. Per-user repairs relaunch programs *as that user*.
- **Fleet-ready output.** Every object starts `ComputerName`, `CollectedAt` and ends `Warnings`; numbers are typed and rounded with the unit in the property name (`FreeSpaceGB`, `AgeDays`); empty lists are `@()`, never `$null`; anything that needed admin or could not be read is named in `Warnings` rather than silently blank.
- **Nothing hangs.** Every network probe goes through a TCP check with a real timeout before anything that could block; external commands run through a wrapper that captures exit codes safely under `$ErrorActionPreference = 'Stop'`.
- **Launchers work from any drive letter**, self-elevate with an `fltmc` check (no service dependency), never use `wmic` (removed in 24H2+), and survive paths with spaces and apostrophes.

## Quick start

1. Open `01 Diagnostics\01 System Information\Machine Fact Sheet` and double-click `Get-MachineFactSheet.cmd`. That is the first screen for any ticket.
2. Approve the UAC prompt with your own admin account. The tools work out who is signed in, so the report describes the person at the desk, not your admin profile.
3. Read the report on screen. A copy is saved to `C:\Temp\Toolkit\` on the machine.

From PowerShell, `.\Get-Example.ps1` returns objects for `Export-Csv` or `ConvertTo-Json`; add `-Display` for the readable screen.

## Status

All 27 tools are built, reviewed and verified on a workgroup Windows 11 Home machine: every diagnostic run elevated and unelevated, every guard and preview path exercised, and the Print Spooler and Explorer repairs executed for real. The acceptance suite (800 static, 49 regression and 76 launcher checks) passes with zero failures.

**Not yet proven:** the domain and Entra paths (Group Policy, Kerberos, secure channel, LAPS, WSUS targeting, GPO printer attribution) are written to specification and degrade to `$null` plus a warning on a non-domain machine, but have not yet returned real data from a domain controller. A successful remote fleet run, DISM/SFC execution, and repairing another signed-in user's session as an elevated technician are likewise untested. Validation on a domain-joined machine is the next step.

**Before deploying on managed machines:** the diagnostics enumerate Kerberos tickets, saved credential names, local administrators and security settings - the same activity EDR products watch for. Arrange a path exclusion, a hash exclusion or code signing first.

## How it was built

Each tool went through a multi-agent pipeline: build grounded in live queries of the real data sources, adversarial review under safety, correctness and conventions lenses, a fix pass, and an independent verifier that re-runs the full test battery. Batches of about five tools so a session limit could not lose a run. The conventions specification went through its own adversarial review (25 findings, each proven on a live machine) before any tool was built against it. The acceptance suite, project documentation and raw test evidence are maintained separately and are not part of this repository.
