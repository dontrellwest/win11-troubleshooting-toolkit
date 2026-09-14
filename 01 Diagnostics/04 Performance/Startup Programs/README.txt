STARTUP INVENTORY
=================

WHAT IT DOES

  Lists startup registry entries, folders, tasks and automatic services.
  Includes command paths, enabled state and available publisher details.

WHEN TO USE IT

  - Investigating slow sign-in or an unwanted startup program.
  - Checking for entries left behind by an uninstall.

HOW TO RUN IT

  Double-click Get-StartupInventory.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-StartupInventory.ps1 -Display
  Add -TargetUser DOMAIN\user to specify the affected user.

WHAT TO LOOK AT

  - Check Enabled before treating an entry as active.
  - Compare Source, Command and ExeExists for suspicious entries.
  - Use Signed and Publisher as evidence to investigate an item.

LIMITS

  - This inventories startup items; it does not measure their delay.
  - A delayed task or service can still contribute to poor performance.
  - Wrapper signatures describe the wrapper, not the hosted script or DLL.
  - Other-account tasks may be hidden without admin access.
  - Warnings appear on screen, separately from the report rows.

  Diagnostic only. Changes no settings and performs no repairs.
