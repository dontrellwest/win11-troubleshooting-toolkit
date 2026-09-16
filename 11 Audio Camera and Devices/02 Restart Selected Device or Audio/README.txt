02 RESTART SELECTED DEVICE OR AUDIO
============================================================

  Changes only the selected target after confirmation.

WHAT IT DOES
  Restarts Windows Audio, one selected audio/camera device, or opens
  relevant Settings.

WHEN TO USE IT
  The device check identifies a stuck audio service or specific device.
  First: 01 Check Devices. Choose the smallest relevant action.

HOW TO RUN IT
  Open the matching CMD and answer its short selection prompts.
  Or open PowerShell in this folder. Example options:
  -Action RestartAudio -WhatIf
  Use Get-Help on the matching PS1 for all parameter names.
  Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  Use -CasePath to copy the result into an existing case.
  Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
  Service/device status followed by a real app playback, recording or camera
  test.

LIMITS
  Interrupts active use; restarting a MEDIA-class device drops calls.
  Live restarts need the elevated launcher; -WhatIf works unelevated.
  A device restart can report RestartRequired. Does not restart USB hubs,
  docks, storage, displays, keyboards or network devices. No driver
  removal.
  -WhatIf previews the action and writes reports; no repair runs.
