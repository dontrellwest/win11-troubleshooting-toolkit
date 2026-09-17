06 CLEAN OLD TEMPORARY FILES
============================

  [REPAIR] Changes the PC after you confirm. -WhatIf previews. Admin: no.

WHAT IT DOES
------------
  - Previews and deletes only old files in the selected Windows or user Temp
    folder.

WHEN TO USE IT
--------------
  - The disk-space check identifies temporary files worth removing.
  - First: 02 Check Disk Space Usage.
  - Preview before deletion.

HOW TO RUN IT
-------------
  - Open the matching CMD and answer its short selection prompts.
  - Or open PowerShell in this folder.
  - Example options:
      -Scope CurrentUserTemp -WhatIf
  - Use Get-Help on the matching PS1 for all parameter names.
  - Reports: C:\Temp\Toolkit, or your -ReportPath folder.
  - Use -CasePath to copy the result into an existing case.
  - Keep the full toolkit together; _Maintenance\Runtime is required.

WHAT TO LOOK AT
---------------
  - Candidate list, deleted bytes, skipped files and free space after cleanup.
  - Optional -Subfolder limits work to a child of the selected Temp folder.

LIMITS
------
  - WindowsTemp needs admin in the signed-in user's own session.
  - Skips links, inaccessible folders and changed or in-use files.
  - Refuses folders with more than 20,000 entries; narrow with -Subfolder.
  - Empty folders stay.
  - No personal-folder or profile deletion.
  - No undo.
  - -WhatIf previews the action and writes reports; no repair runs.
