# Windows 11 Troubleshooting Toolkit

A field toolkit for an MSP technician: **60 PowerShell diagnostic and repair tools** for Windows 11 laptops and desktops on Active Directory and Microsoft 365. It runs straight from a flash drive, installs nothing, and needs only Windows PowerShell 5.1 with inbox modules.

Every tool has a double-click `.cmd` launcher and a one-page plain-text guide that opens with a CHECK or REPAIR tag and the admin requirement, writes a report the technician can attach to the ticket, and is built to a written specification with an automated acceptance suite. The folders are organised the way a ticket is worked: **check, repair only what the check justifies, then verify**.

> The field guides are deliberately `README.txt`, not Markdown: they have to open in Notepad on whatever machine a technician is standing at. `README.txt` in this folder is the drive's own front page. The maintenance folder it mentions (test harness, documentation, evidence, archives) is internal; only its `Runtime` part, which the newer tools require, is published here.

## Layout

```
00 Case and Verification     Start a case, capture Before/After checks, compare them, export a ZIP
01 System and Windows        Computer details, crashes, restarts, recent changes, software, updates;
                             update-download repair, DISM/SFC choices, Explorer and icon repair
02 Network                   Connection, speed, mapped drives, dropout monitor;
                             DNS/DHCP repair, reconnect one mapped drive
03 Accounts and Profiles     Sign-in, Group Policy, profile health, profile data, OneDrive;
                             OneDrive restart/reset, time resync, policy refresh, domain trust repair;
                             enabled accounts left in a disabled-users OU (needs RSAT)
04 Performance               Live resources, disk space, startup programs, overview, storage
                             reliability; scoped cleanup of old temporary files
05 Printing                  Printers and queue; cancel one job, full queue reset, test page
06 Outlook                   Classic: sync check, safe mode and add-in isolation, mail-cache rebuild
                             New Outlook: app and service check, mail-cache reset
07 Security                  Defender, local administrators, encryption and firmware
08 Fleet                     Run any read-only standalone tool over WinRM against a host list or OU
09 Apps and Programs         Check one app, Repair, Reset, verify it works
10 Teams                     Check New Teams; restart or clear its cache
11 Audio Camera and Devices  Check audio, camera and dock devices; restart one device or the audio service
_Maintenance\Runtime         Shared implementation required by the 29 newer tools
```

Every tool folder holds `NN-Name.ps1`, `NN-Name.cmd` and `README.txt`. Seven of the original tools also ship a `-NoPowerShell.cmd` for machines where PowerShell is blocked by policy. The number is a suggested order inside its area, not a mandatory sequence.

Two generations live side by side. The original 30 tools are standalone scripts with an identical embedded helper block, return structured objects, and are the only scripts the fleet runner accepts. The 29 newer tools are thin frontends over the shared runtime: a common approval gate, path guards, process-ownership checks, evidence records and TXT/JSON reports. One further standalone tool, the enabled-accounts-in-disabled-OU check, queries Active Directory read-only, needs the RSAT module, and has its own fixture harness.

## Design rules that every tool follows

- **Read-only means read-only.** Checks never change services, processes, registry or files; they are scanned for a denylist of state-changing verbs, and the fleet runner refuses anything without a `ReadOnly` header.
- **Repairs are guarded.** `SupportsShouldProcess` with `ConfirmImpact='High'`; exactly one confirmation that names what will change; an intent record written before the question is asked; `-WhatIf` that writes the report and touches nothing else.
- **Least scope.** One print job, one drive letter, one adapter, one package, one device, one add-in. Caches are moved aside as `.ToolkitBackup` folders rather than deleted; the only deletion is old temporary files by explicit age, and every candidate is re-validated before removal.
- **The tech at the user's desk.** Per-user tools act on the signed-in user's own desktop session and refuse SYSTEM, service accounts and uncertain sessions. Original per-user tools resolve the console user's hive and profile path instead of `HKCU:`.
- **Restore what you stop.** Services stopped for a repair are restarted in reverse order, including on the failure path, and the report says so if one could not be.
- **Honest reports.** A command result is never a fix. Repairs end with a `NeedsUserCheck` row, before/after comparison records changes without claiming resolution, and anything that could not be read is reported as unavailable, never as healthy.
- **Nothing hangs.** Network probes go through a TCP check with a real timeout; native commands run with redirected output, closed input and a time limit; launchers self-elevate with an `fltmc` check, never use `wmic`, and survive paths with spaces, apostrophes and ampersands.

## Quick start

1. Open `01 System and Windows\01 Check Computer Details` and double-click `01-Check-Computer-Details.cmd`. That is the first screen for any ticket.
2. For anything you might change, start a case in `00 Case and Verification` first, capture a Before check for the area, run the smallest justified repair with its preview, then capture After and compare.
3. Reports go to `C:\Temp\Toolkit` on the machine; the newer tools also accept `-CasePath` to copy results and evidence into the case folder.

From PowerShell, any `NN-Name.ps1` returns objects for `Export-Csv` or `ConvertTo-Json`; add `-Display` for the readable screen and `-WhatIf` on a repair to see the plan without acting.

## Status

All 60 tools are built and reviewed. On a workgroup Windows 11 Home machine the checks run elevated and unelevated, every guard and preview path is exercised by fixtures, and these repairs have run for real: Print Spooler reset, Explorer and icon cache, classic and new Outlook cache, Windows time, DNS cache, user and computer policy refresh, Teams restart and cache move, OneDrive restart, Calculator reset with package verification, single print-job cancellation and a physically confirmed test page, and old-file cleanup against fixtures. An independent audit of the shared runtime followed, and its findings were fixed and re-verified.

The acceptance suite passes with zero failures: 922 static and runtime checks, 55 regression checks and 104 launcher checks on the original tools; 160 fixture, 62 launcher and 390 delivery checks on the newer tools; 33 fixture, 32 launcher and 3 preview checks on the DISM/SFC choices, none of which start DISM or SFC; 23 fixture checks on the directory tool with no live directory access.

**Not yet proven:** the domain and Entra paths (Group Policy against a domain controller, Kerberos, machine trust repair, the disabled-OU directory query, LAPS, WSUS targeting, GPO printer attribution) degrade to a warning on a non-domain machine but have not returned real data from a domain. DISM and SFC execution, a live update-cache reset, a live audio or camera restart, OneDrive reset, WinGet and MSI repair, Outlook safe mode and add-in changes, and a real mapped-drive reconnect are covered by fixtures and previews only. Validation on a domain-joined machine is the next step.

**Before deploying on managed machines:** the diagnostics enumerate Kerberos tickets, saved credential names, local administrators and security settings - the same activity EDR products watch for. Arrange a path exclusion, a hash exclusion or code signing first.

## How it was built

The original tools went through a multi-agent pipeline: build grounded in live queries of the real data sources, adversarial review under safety, correctness and conventions lenses, a fix pass, and an independent verifier that re-runs the full test battery. The expansion added the case workflow, the targeted repairs and the DISM/SFC choices on a shared runtime, each with fixtures that stub the mutating command and prove the preview path never reaches it, followed by an independent adversarial audit of every runtime file. The acceptance suite, project documentation and raw test evidence are maintained separately and are not part of this repository.
