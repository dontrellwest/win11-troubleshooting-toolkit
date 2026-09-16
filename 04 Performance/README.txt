PERFORMANCE - SUGGESTED WORKFLOW
===============================

01 Check Live Resource Usage: CPU, memory, disk and busy processes.
02 Check Disk Space Usage: identify where space is going.
03 List Startup Programs: identify entries; does not measure startup impact.
04 Check Performance Overview: broad legacy system snapshot.
05 Check Storage Errors and Reliability: deeper disk and event checks.
06 Clean Old Temporary Files: preview selected Temp files, then confirm.

If I/O errors or unhealthy disks appear, investigate storage before intensive
repairs. Missing reliability counters do not mean the disk is healthy.

Cleanup acts only inside Windows Temp or the current user's Temp folder.
Optional -Subfolder narrows it further. Personal folders and profiles are
not cleanup targets. In-use files and inaccessible folders are skipped.
Recheck free space and the original performance problem afterward.
