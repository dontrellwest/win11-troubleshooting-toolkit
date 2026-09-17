CHECK PROFILE SIGN-IN AGE
========================

  [CHECK]  Collects information; does not change the PC. Admin: yes.

WHAT IT DOES
------------
  - Lists registered local profiles and their last recorded desktop sign-in.
  - Shows the date, time and an age such as 6 months ago.
  - Uses Security and Winlogon sign-ins matched by SID, not file dates.
  - Cross-checks session, unlock, reconnect and sign-out records on this PC.
  - Includes locally stored profiles for local, domain and Entra accounts.

WHEN TO USE IT
--------------
  - Reviewing old profiles before deciding whether to remove their data.
  - Background services have made profile activity dates misleading.
  - Use 04 List User Profile Data to check the data taking up space.

HOW TO RUN IT
-------------
  - Run on the PC holding the profiles. Open the matching CMD; approve UAC.
  - The default review threshold is 6 calendar months.
  - From an administrator PowerShell in this folder:
      .\11-Check-Profile-Sign-In-Age.ps1 -StaleMonths 6 -Display
  - TXT, CSV and JSON reports go to C:\Temp\Toolkit.
  - Use -ReportPath to choose another report folder.
  - It reads retained events. Large logs can take a minute or more.

WHAT TO LOOK AT
---------------
  - LastRecordedSignIn and SignInAge show the newest qualifying record.
  - Protected: system profile, loaded profile or current logon session.
  - Recent evidence: recent sign-in, unlock or other interactive activity.
  - Older sign-in - review: old evidence worth investigating, not deletion
    approval. Check its data and your retention rules before removal.
  - Rerun before any removal decision; sessions can change after collection.
  - Unknown: missing, short or incomplete history; do not assume stale.
  - Read the retained-log dates and coverage notes at the top of the report.
  - Completed means collection finished, not proof of historical inactivity.
  - The events.csv file lists supporting events, sources and SID/name matches.

LIMITS
------
  - Overwritten or never-audited sign-ins cannot be recovered by this tool.
  - Audit policy is read, not changed. Past audit continuity is not proven.
  - Services, batch jobs and network logons are excluded from sign-in dates.
  - Unlock/reconnect evidence is separate; it does not mean a new sign-in.
  - RUNAS/other logon processes are separate from User32 desktop sign-ins.
  - Auto-sign-in can count; no event proves a person was at the keyboard.
  - Session/reconnect name matches are weaker than SID matches.
  - Reads up to 100000 matches per log; raise -MaxEvents if marked partial.
  - Unregistered folders are not included. No profile or account is deleted.
