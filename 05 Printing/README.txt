PRINTING
========

  Order: 01 check -> 02 cancel one job -> 03 full reset only if needed ->
  04 test page.

TOOLS
-----
  01  Check Printers and Queue
      - Identify the printer, driver, port, queue and exact failing job.
  02  Cancel One Stuck Print Job
      - Try this when one job is the problem; other jobs remain alone.
  03  Reset Print Queue
      - Full local spooler reset only when the smaller action is
        insufficient.
      - Removes inventoried local spool files, affecting queued jobs.
  04  Print and Verify a Test Page
      - Select the printer and submit one page. Confirm physical output
        yourself.

NOTES
-----
  - Preview any repair first.
  - Permission to cancel another user's job may require an administrator.
  - A job already sent to printer hardware may still print.
  - An empty queue or running spooler alone is not proof that printing works.
