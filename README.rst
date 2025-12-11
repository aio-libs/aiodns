===============================
Simple DNS resolver for asyncio
===============================

.. image:: https://badge.fury.io/py/aiodns.png
    :target: https://pypi.org/project/aiodns/

.. image:: https://github.com/saghul/aiodns/workflows/CI/badge.svg
    :target: https://github.com/saghul/aiodns/actions

aiodns provides a simple way for doing asynchronous DNS resolutions using `pycares <https://github.com/saghul/pycares>`_.


Example
=======

.. code:: python

    import asyncio
    import aiodns

    async def main():
        resolver = aiodns.DNSResolver()
        result = await resolver.query_dns('google.com', 'A')
        for record in result.answer:
            print(record.data.addr)

    asyncio.run(main())


The following query types are supported: A, AAAA, ANY, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT.


API
===

The API is pretty simple, the following functions are provided in the ``DNSResolver`` class:

* ``query_dns(host, type)``: Do a DNS resolution of the given type for the given hostname. It returns an
  instance of ``asyncio.Future``. The result is a ``pycares.DNSResult`` object with ``answer``,
  ``authority``, and ``additional`` attributes containing lists of ``pycares.DNSRecord`` objects.
  Each record has ``type``, ``ttl``, and ``data`` attributes. Check the `pycares documentation
  <https://pycares.readthedocs.io/>`_ for details on the data attributes for each record type.
* ``query(host, type)``: **Deprecated** - use ``query_dns()`` instead. This method returns results
  in a legacy format compatible with aiodns 3.x for backward compatibility.
* ``gethostbyname(host, socket_family)``: Do a DNS resolution for the given
  hostname and the desired type of address family (i.e. ``socket.AF_INET``).
  While ``query_dns()`` always performs a request to a DNS server,
  ``gethostbyname()`` first looks into ``/etc/hosts`` and thus can resolve
  local hostnames (such as ``localhost``). The actual result of the call is a ``asyncio.Future``.
* ``gethostbyaddr(name)``: Make a reverse lookup for an address.
* ``getaddrinfo(host, family, port, proto, type, flags)``: Resolve a host and port into a list of
  address info entries.
* ``getnameinfo(sockaddr, flags)``: Resolve a socket address to a host and port.
* ``cancel()``: Cancel all pending DNS queries. All futures will get ``DNSError`` exception set, with
  ``ARES_ECANCELLED`` errno.
* ``close()``: Close the resolver. This releases all resources and cancels any pending queries. It must be called
  when the resolver is no longer needed (e.g., application shutdown). The resolver should only be closed from the
  event loop that created the resolver.


Migrating from aiodns 3.x
=========================

aiodns 4.x introduces a new ``query_dns()`` method that returns native pycares 5.x result types.
The old ``query()`` method is deprecated but continues to work for backward compatibility.

.. code:: python

    # Old API (deprecated)
    result = await resolver.query('example.com', 'MX')
    for record in result:
        print(record.host, record.priority)

    # New API (recommended)
    result = await resolver.query_dns('example.com', 'MX')
    for record in result.answer:
        print(record.data.exchange, record.data.priority)


Async Context Manager Support
=============================

While not recommended for typical use cases, ``DNSResolver`` can be used as an async context manager
for scenarios where automatic cleanup is desired:

.. code:: python

    async with aiodns.DNSResolver() as resolver:
        result = await resolver.query_dns('example.com', 'A')
        # resolver.close() is called automatically when exiting the context

**Important**: This pattern is discouraged for most applications because ``DNSResolver`` instances
are designed to be long-lived and reused for many queries. Creating and destroying resolvers
frequently adds unnecessary overhead. Use the context manager pattern only when you specifically
need automatic cleanup for short-lived resolver instances, such as in tests or one-off scripts.


Note for Windows users
======================

This library requires the use of an ``asyncio.SelectorEventLoop`` or ``winloop`` on Windows
**only** when using a custom build of ``pycares`` that links against a system-
provided ``c-ares`` library **without** thread-safety support. This is because
non-thread-safe builds of ``c-ares`` are incompatible with the default
``ProactorEventLoop`` on Windows.

If you're using the official prebuilt ``pycares`` wheels on PyPI (version 4.7.0 or
later), which include a thread-safe version of ``c-ares``, this limitation does
**not** apply and can be safely ignored.

The default event loop can be changed as follows (do this very early in your application):

.. code:: python

    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

This may have other implications for the rest of your codebase, so make sure to test thoroughly.


Running the test suite
======================

To run the test suite: ``python -m pytest tests/``


Author
======

Saúl Ibarra Corretgé <s@saghul.net>


License
=======

aiodns uses the MIT license, check LICENSE file.


Contributing
============

If you'd like to contribute, fork the project, make a patch and send a pull
request. Have a look at the surrounding code and please, make yours look
alike :-)
