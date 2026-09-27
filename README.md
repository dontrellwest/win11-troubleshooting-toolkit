# Windows 11 Troubleshooting Toolkit

A field toolkit for an MSP technician: **30 double-click tools** for Windows 11 laptops and desktops on Active Directory and Microsoft 365. **19 checks** read the PC and explain what they found in plain language; **11 repairs** run the standard Windows fix after a single Y/N question. It runs straight from a flash drive, installs nothing, and needs only Windows PowerShell 5.1 and CMD.

> `README.txt` is the drive's own front page. It is deliberately plain text, so it opens in Notepad on whatever machine a technician is standing at, and it lists every tool and when to use it.

## Layout

Every tool is a CMD file in one folder, named "Area - What it does", so the tools sort by area. The PowerShell behind the checks lives in `Scripts`, one standalone script per check.

| Area | Checks | Repairs |
|---|---|---|
| Windows | Check Computer, Check Crashes and Restarts, Check Recent Changes, List Installed Software, Check Updates | Repair System Files with DISM and SFC, Reset Windows Update, Restart Explorer and Icons |
| Network | Check Connection, Check Mapped Drives, Test Speed | Reset Network |
| Accounts | Check User Sign-In, Check Group Policy, Check User Profiles, Check Profile Last Sign-In, Check OneDrive | Reset OneDrive |
| Performance | Check Slow PC, Check Disk Space | Clean Temp Files |
| Printing | Check Printers | Reset Print Queue |
| Outlook | Check Outlook (classic and new) | Rebuild Classic Mail Cache, Reset New Outlook |
| Security | Check Security (Defender, local admins, BitLocker, TPM, Secure Boot) | |
| Teams | | Reset Teams |
| Devices | | Restart Audio |
| Admin | Find Enabled Users in Disabled OU (Active Directory, needs RSAT) | |

## How the checks report

Every check prints the same layout on screen and saves a copy to `C:\Temp\Toolkit`:

- **SUMMARY** with one RESULT line: NO PROBLEMS FOUND, REVIEW, ACTION NEEDED or INCOMPLETE.
- **Findings** ranked PROBLEM, WARNING, NOT CHECKED, INFO and OK. Every PROBLEM and WARNING has a "Next:" step that names the tool to run, a complete command or a Settings path.
- **Missing data is never a pass.** Anything a check could not read is NOT CHECKED. An automated test makes each part of the checks fail in turn and requires the failure to show up in the summary.
- **DETAILS** with every value that was read.

The profile checks treat file dates as old dates, never as proof that a user stopped signing in, and the sign-in check never calls a profile safe to delete.

## How the repairs work

- **Plain Windows commands.** DISM and SFC, the standard Windows Update reset, `ipconfig`, the print spooler, the audio services and Microsoft's own OneDrive reset, with Windows' own output on screen. Each repair says what it will change, asks `Start now? [Y/N]` and ends with what the result means.
- **Honest exit codes.** A repair exits 0 only when the change was made and every service it stopped is running again, so a remote tool can trust the result.
- **Outlook data is moved aside, never deleted,** and every earlier copy is kept (`.old`, `.old2`, ...). The only files a repair deletes are the user's temp files older than 7 days (Clean Temp Files) and the previous copy of a Windows Update or Teams cache.
- **Right account, right rights.** Admin tools ask for administrator rights themselves. Tools that change the signed-in user's own files (Outlook, Teams, OneDrive, Explorer, Temp) are meant to run as that user: started with administrator rights, they stop when unattended and ask first otherwise, so they never repair the admin's profile by mistake. They close only that user's copy of an app.
- **Built for RMM.** `TOOLKIT_UNATTENDED=1` skips the question and the final pause, and the checks start 64-bit PowerShell even from a 32-bit remote agent.

## Status

All 30 tools have run for real on a Windows 11 laptop through their own CMD files, the way an RMM agent runs them, repairs included: DISM and SFC, the Windows Update reset, a network renew, the print queue, audio, Explorer, Teams, OneDrive and both Outlook cache repairs. A second, independent run of all 30 tools confirmed the results; its findings were fixed and re-tested live.

The automated checks pass with zero failures: a static check of every file, report-summary fixtures, and fixtures for the profile sign-in and Active Directory checks.

**Not yet proven:** the domain paths (the Active Directory query, Group Policy against a domain controller, domain trust) have run only against fixtures and a workgroup machine. A second signed-in user, a stuck print job and physical printing were not tested live.

**Before deploying on managed machines:** the checks enumerate Kerberos tickets, saved credential names, local administrators and security settings, the same activity EDR products watch for. Arrange a path or hash exclusion, or code signing, first.

## How it was built

In September 2026 the toolkit was cut from 62 tools in 12 folders to these 30 in one folder, because finding and fixing the tools had become more work than the problems they solve. The checks kept their plain-language reports; the repairs became plain Windows commands; a shared runtime, a case workflow and the fleet tools were dropped. The project notes, test suites and raw test evidence are maintained separately and are not part of this repository.
