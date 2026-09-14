MACHINE FACT SHEET
==================

WHAT IT DOES

  Collects hardware, Windows version, uptime, disk space and memory.
  Also reports identity, encryption, firmware and battery information.

WHEN TO USE IT

  - Starting a troubleshooting ticket.
  - Recording the PC's configuration before a change.

HOW TO RUN IT

  Double-click Get-MachineFactSheet.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-MachineFactSheet.ps1 -Display

WHAT TO LOOK AT

  - Confirm the computer name, model, serial and Windows build.
  - Check free space, uptime and pending-reboot flags.
  - Read Warnings before interpreting blank security fields.

LIMITS

  - TPM details and full BitLocker information need admin access.
  - Recovery key IDs do not prove a recovery password is backed up.
  - This is not a complete Windows 11 compatibility assessment.
  - Domain, Entra and MDM behavior still needs field validation.

  Diagnostic only. Changes no settings and performs no repairs.
