Examples
========

This directory contains small, runnable examples of the aiodns API. Each
example has usage notes that describe its inputs, output, and scope.

Email-related TXT observations
------------------------------

`email_dns_txt.py <email_dns_txt.py>`_ concurrently queries TXT records for a
sender domain, its DMARC name, and an optional DKIM selector. It demonstrates
``query_dns()`` while preserving resource-record boundaries, TTLs, DNS errors,
and per-query deadlines.

See `Email-related TXT observations <email_dns_txt.rst>`_ for the command,
input requirements, and interpretation notes. The short-lived command-line
example uses an async context manager for resolver cleanup; applications
should reuse a long-lived resolver for their queries.
