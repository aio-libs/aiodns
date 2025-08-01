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

    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)

    async def query(name, query_type):
        return await resolver.query(name, query_type)

    coro = query('google.com', 'A')
    result = loop.run_until_complete(coro)


The following query types are supported: A, AAAA, ANY, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT.


API
===

The API is pretty simple, the following functions are provided in the ``DNSResolver`` class:

* ``query(host, type)``: Do a DNS resolution of the given type for the given hostname. It returns an
  instance of ``asyncio.Future``. The actual result of the DNS query is taken directly from pycares.
  As of version 1.0.0 of aiodns (and pycares, for that matter) results are always namedtuple-like
  objects with different attributes. Please check the `documentation
  <http://pycares.readthedocs.org/latest/channel.html#pycares.Channel.query>`_
  for the result fields.
* ``gethostbyname(host, socket_family)``: Do a DNS resolution for the given
  hostname and the desired type of address family (i.e. ``socket.AF_INET``).
  While ``query()`` always performs a request to a DNS server,
  ``gethostbyname()`` first looks into ``/etc/hosts`` and thus can resolve
  local hostnames (such as ``localhost``).  Please check `the documentation
  <http://pycares.readthedocs.io/latest/channel.html#pycares.Channel.gethostbyname>`_
  for the result fields. The actual result of the call is a ``asyncio.Future``.
* ``gethostbyaddr(name)``: Make a reverse lookup for an address.
* ``cancel()``: Cancel all pending DNS queries. All futures will get ``DNSError`` exception set, with
  ``ARES_ECANCELLED`` errno.
* ``close()``: Close the resolver. This releases all resources and cancels any pending queries. It must be called
  when the resolver is no longer needed (e.g., application shutdown). The resolver should only be closed from the
  event loop that created the resolver.


Async Context Manager Support
=============================

While not recommended for typical use cases, ``DNSResolver`` can be used as an async context manager
for scenarios where automatic cleanup is desired:

.. code:: python

    async with aiodns.DNSResolver() as resolver:
        result = await resolver.query('example.com', 'A')
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

To run the test suite: ``python tests.py``


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
