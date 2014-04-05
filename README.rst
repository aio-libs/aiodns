===============================
Simple DNS resolver for asyncio
===============================

.. image:: https://secure.travis-ci.org/saghul/aiodns.png?branch=master
    :target: http://travis-ci.org/saghul/aiodns

aiodns provides a simple way for doing asynchronous DNS resolutions
with a synchronous looking interface by using `pycares <https://github.com/saghul/pycares>`_.


Example
=======

::

    import asyncio
    import aiodns

    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)
    f = resolver.query('google.com','A')
    result = loop.run_until_complete(f)
    print(result)


The following query types are supported: A, AAAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT.


API
===

The API is pretty simple, two functions are provided in the ``DNSResolver`` class:

* ``query(host, type)``: Do a DNS resolution of the given type for the given hostname. It returns an
  instance of ``asyncio.Future``.
* ``cancel()``: Cancel all pending DNS queries. All futures will get ``DNSError`` exception set, with
  ``ARES_ECANCELLED`` errno.


Running the test suite
======================

To run the test suite: ``python test_aiodns.py``


Author
======

Saúl Ibarra Corretgé <saghul@gmail.com>


License
=======

aiodns uses the MIT license, check LICENSE file.


Python versions
===============

Python 3.4 is natively supported. Python 3.3 supported using the `asyncio package <https://pypi.python.org/pypi/asyncio>`_.
Older Python versions(2.6 - 3.2) are supported using `trollius <https://pypi.python.org/pypi/trollius>`_.


Contributing
============

If you'd like to contribute, fork the project, make a patch and send a pull
request. Have a look at the surrounding code and please, make yours look
alike :-)

