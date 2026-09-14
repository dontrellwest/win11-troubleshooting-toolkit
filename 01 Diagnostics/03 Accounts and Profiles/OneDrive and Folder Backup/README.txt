ONEDRIVE AND FOLDER BACKUP STATUS
=================================

WHAT IT DOES

  Reports the target user's OneDrive client and first business account.
  Checks Desktop, Documents and Pictures paths and file metadata.

WHEN TO USE IT

  - Files are missing from expected backed-up folders.
  - Checking account, client or folder configuration during a sync issue.

HOW TO RUN IT

  Double-click Get-OneDriveStatus.cmd.
  Administrator access is not required.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-OneDriveStatus.ps1 -Display
  Add -TargetUser DOMAIN\user to select the affected user.
  Add -SkipFileCounts for a faster run. -MaxFiles defaults to 200000.

WHAT TO LOOK AT

  - Confirm TargetUser, AccountEmail and SyncRoot first.
  - KfmState reports folder paths, not successful upload.
  - Check the OneDrive tray icon for current sync status.

LIMITS

  - Reports Business1; other business accounts are not combined.
  - File counting stops after 30 seconds or the file cap.
  - Reparse subfolders are skipped; CountsComplete marks partial totals.
  - Only file metadata is read; cloud content is not opened.
  - A running process and registry account do not prove healthy sync.

  Diagnostic only. Changes no settings and performs no repairs.
