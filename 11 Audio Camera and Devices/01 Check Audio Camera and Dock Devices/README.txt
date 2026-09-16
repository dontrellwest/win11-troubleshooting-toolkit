01 CHECK AUDIO CAMERA AND DOCK DEVICES
============================================================

  Collects information. Writes reports; does not repair the PC.

WHAT IT DOES
  Lists connected audio, camera, USB, display and Bluetooth devices, audio
  defaults and consent summaries.

WHEN TO USE IT
  No sound, wrong microphone, camera failure or dock-connected devices
  missing.
  Next: 02 Restart Selected Device or Audio, if appropriate.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Device errors, default audio endpoint IDs, services and app device
  selection.

LIMITS
  Some consent is app or policy specific. A listed device still needs a
  playback, recording, camera or dock test.
