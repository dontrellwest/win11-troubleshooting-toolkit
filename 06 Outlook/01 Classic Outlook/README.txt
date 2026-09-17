CLASSIC OUTLOOK
===============

  Order: 01 check -> 02 safe mode and add-ins -> 03 cache rebuild only if
  justified.

TOOLS
-----
  01  Check Classic Outlook Sync
      - Open Outlook, run the check and read Verdict, NextStep and the
        view/offline findings.
      - Compare missing messages with Outlook on the web.
  02  Test Safe Mode and Isolate Addins
      - Close Outlook. Test safe mode before considering a cache rebuild.
      - If safe mode helps, list add-ins and disable only one current-user
        add-in. The tool saves its setting for RestoreAddin. Retest in
        normal mode.
  03  Rebuild Classic Outlook Mail Cache
      - Use only for a supported local-cache diagnosis. Confirm expected
        mail and drafts are on the server, then preview and follow its guide.

NOTES
-----
  - View/filter problems should be corrected before rebuilding the cache.
  - Machine-installed or policy-controlled add-ins require their owner's
    review.
  - After any action, repeat the original task and run check 01 again.
