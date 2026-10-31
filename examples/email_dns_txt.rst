Email-related TXT observations
==============================

``examples/email_dns_txt.py`` shows concurrent TXT lookups with the aiodns4.x
``query_dns()`` interface. It reads the system resolver configuration and makes
DNS queries only. It does not contact an SMTP server or an HTTP service.

Run::

    python examples/email_dns_txt.py example.com --selector actual-selector

Obtain the actual selector from a DKIM-Signature header or the sender's provider
configuration. Omit ``--selector`` to skip that lookup, rather than guessing
common names. The domain is a sender domain, not an email address or a URL.

The output preserves separate TXT resource records, their TTLs, DNS errors and
the per-query deadline. TXT character-strings within one RR are already combined
by pycares. Non-ASCII bytes are shown as hexadecimal rather than replaced or
misinterpreted as policy text. In applications, reuse a long-lived resolver;
this short-lived CLI uses its async context manager for cleanup.

These are observations, not PASS/FAIL authentication results:

* SPF also needs the connecting IP and an actual policy evaluation, including
  its processing limits; seeing ``v=spf1`` does not prove a pass.
* DKIM verification needs the signed message and its actual selector. An
  unknown selector or lookup error does not prove a signature failure.
* DMARC needs message-level authentication/alignment and its policy discovery
  rules. This example does not implement organizational-domain fallback.
* An empty answer, NXDOMAIN, a resolver error and a deadline are different
  outcomes. None establishes whether a mailbox exists or where mail will land.

This example changes no resolver API or DNS records and needs no account,
credentials, third-party API key or additional runtime dependency.
