APPS AND PROGRAMS
=================

  Order: 01 check -> 02 repair -> 04 verify -> 03 reset only if repair did
  not help -> 04 verify again.

TOOLS
-----
  01  Check App Installation
      - Select one exact app and inspect its version, type and repair
        options.
  02  Repair Selected App
      - Settings opens the relevant page; click Repair yourself if available.
      - WinGet and Windows Installer methods run supported repairs directly.
  03  Reset Selected App Data
      - Fallback only if Repair did not help. Deletes the selected packaged
        app's local data, preferences and sign-in state. Export unsynced data
        first. There is no automatic undo.
  04  Verify App Works
      - Open the app, repeat the failed task and record the observed
        outcome.

NOTES
-----
  - Repair availability varies by app. Desktop programs have
    publisher-specific options.
  - No failed Repair automatically falls back to Reset or reinstall.
  - Run in the affected user's desktop session and close the app before
    repair.
