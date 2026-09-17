PERFORMANCE
===========

  Order: checks 01-05, then 06 only after previewing what would be deleted.

CHECKS
------
  01  Check Live Resource Usage
      - CPU, memory, disk and busy processes.
  02  Check Disk Space Usage
      - Identify where space is going.
  03  List Startup Programs
      - Identify entries; does not measure startup impact.
  04  Check Performance Overview
      - Broad legacy system snapshot.
  05  Check Storage Errors and Reliability
      - Deeper disk and event checks.

REPAIRS
-------
  06  Clean Old Temporary Files
      - Preview selected Temp files, then confirm.
      - Acts only inside Windows Temp or the current user's Temp folder;
        -Subfolder narrows it further.
      - Personal folders and profiles are not cleanup targets. In-use files
        and inaccessible folders are skipped.

NOTES
-----
  - If I/O errors or unhealthy disks appear, investigate storage before
    intensive repairs. Missing reliability counters do not mean the disk is
    healthy.
  - Recheck free space and the original performance problem afterward.
