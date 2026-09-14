PROFILE STATE
=============

WHAT IT DOES

  Compares profile registry entries with folders on disk.
  Reports missing folders, .bak entries, temporary profiles and sizes.

WHEN TO USE IT

  - Investigating a temporary profile or sign-in profile problem.
  - Reviewing old profiles before an approved cleanup.

HOW TO RUN IT

  Double-click Get-ProfileState.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-ProfileState.ps1 -Display
  Use -SkipSizes for a quick inventory.
  -StaleDays defaults to 90; sizing stops at 60 seconds per profile.

WHAT TO LOOK AT

  - Check DataIssue, InRegistry, FolderExists and Loaded.
  - Stale is a review flag; confirm ownership, retention and backups.
  - SizeComplete indicates whether a measured size is partial.

LIMITS

  - Background tasks can update profile dates.
  - Other users' folders need administrator access.
  - Reparse folders are not followed; each size has a 200000-file cap.
  - Never delete profile folders manually. Use Windows User Profiles
  -   or an approved Win32_UserProfile removal workflow after review.

  Diagnostic only. Changes no settings and performs no repairs.
