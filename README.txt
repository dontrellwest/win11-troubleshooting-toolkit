WINDOWS 11 TROUBLESHOOTING TOOLKIT
=================================

START HERE
  Choose the folder for the problem, then read the tool's short README.txt.
  Open its matching CMD. Numbers suggest an order, not a mandatory sequence.
  New to the PC? Use 01 System and Windows\01 Check Computer Details.

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

CHECK -> REPAIR IF NEEDED -> VERIFY
  00 Case and Verification keeps the issue, before/after checks and outcome.
  Save the original error before changing anything.
  Choose the smallest repair justified by the check. Preview with -WhatIf.
  Retest the original task. Command success alone does not prove a fix.
  Save work and restart manually when required; then capture After checks.

PROBLEM AREAS
  00 Case and Verification
    Start a case, capture checks, compare results and export a local ZIP.
  01 System and Windows
    Details, crashes, restarts, recent changes, software and updates.
    Update repair, DISM checks/repair, SFC and Explorer/icon repair.
  02 Network
    Connection, speed, mapped drives, dropouts and targeted repairs.
  03 Accounts and Profiles
    Sign-in, policy, profiles and OneDrive; time, policy and trust repairs.
  04 Performance
    Resources, space, startup, storage reliability and scoped Temp cleanup.
  05 Printing
    Check -> cancel one job -> full queue reset if needed -> test page.
  06 Outlook
    Classic: check -> safe mode/add-ins -> cache rebuild if justified.
    New: check app/service -> cache reset if justified.
  07 Security
    Defender, local administrators, encryption and firmware checks.
  08 Fleet
    Reviewed standalone diagnostics over existing WinRM.
  09 Apps and Programs
    Check -> Repair -> test -> Reset only if needed -> verify again.
  10 Teams
    Check -> restart -> clear cache only if needed -> test sign-in/calls.
  11 Audio Camera and Devices
    Check defaults/devices -> targeted restart or Settings -> practical test.

RUNNING AND REPORTS
  Run user tools in the affected user's desktop session.
  Some machine tools request administrator access.
  Reports normally go to C:\Temp\Toolkit; check each tool's guide.
  The 25 workflow additions also write JSON and accept -ReportPath/-CasePath.
  DISM choices use -LogPath and write TXT/JSON plus a DISM log.
  Unavailable information is not a passing check.
  Repair and Reset differ: app Reset deletes local app data and settings.

KEEP THE TOOLKIT TOGETHER
  59 tools: the original 30, 25 workflow additions and 4 DISM/SFC choices.
  Each numbered CMD has a matching PS1 and short README.txt.
  New tools require _Maintenance\Runtime; keep that folder when copying.
  Seven older tools also have a -NoPowerShell.cmd alternative.
  The new shared-runtime tools are local tools, not Fleet runner inputs.
  DISM/SFC execution was excluded from testing at the owner's request.

REVIEW RECORDS
  _Maintenance\Documentation\PROJECT-STATUS.txt
  _Maintenance\Documentation\TEST-RESULTS.txt
  _Maintenance\Documentation\CLAUDE-REVIEW-HANDOFF.txt
