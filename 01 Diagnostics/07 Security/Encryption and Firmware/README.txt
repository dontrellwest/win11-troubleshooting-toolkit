ENCRYPTION AND FIRMWARE
=======================

WHAT IT DOES

  Reports BitLocker volumes, TPM, Secure Boot and device security.
  Lists recovery protector IDs without displaying recovery passwords.

WHEN TO USE IT

  - Checking encryption before firmware or hardware work.
  - Investigating missing TPM or security features.

HOW TO RUN IT

  Double-click Get-EncryptionAndFirmware.cmd.
  The launcher asks for administrator access.
  The report appears on screen and is saved in C:\Temp\Toolkit.

  PowerShell: .\Get-EncryptionAndFirmware.ps1 -Display

WHAT TO LOOK AT

  - Check Elevated and Warnings before interpreting empty fields.
  - Protection status and encryption completion are different checks.
  - Match RecoveryKeyIds with the records held in AD or Entra.

LIMITS

  - Without admin, only limited Explorer encryption indicators are shown.
  - A backup policy does not prove a usable recovery key was saved.
  - Win11BaselineOk checks only firmware, Secure Boot and TPM.
  - Some effective security states remain unknown when no source is read.
  - Elevated and managed-device paths still need field validation.

  Diagnostic only. Changes no settings and performs no repairs.
