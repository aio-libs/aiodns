
===============================
Simple DNS resolver for asyncio
===============================

aiodns provides a simple way for doing asynchronous DNS resolutions
with a synchronous looking interface by using `pycares <https://github.com/saghul/pycares>`_.


Usage
=====

Example:

::

    import asyncio
    import aiodns

    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)
    f = resolver.query('google.com','A')
    result = loop.run_until_complete(f)
    print(result)


The following query types are supported: A, AAAA, CNAME, MX, NAPTR, NS, PTR, SOA, SRV, TXT.


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

Python >= 3.3 are supported.


Contributing
============

If you'd like to contribute, fork the project, make a patch and send a pull
request. Have a look at the surrounding code and please, make yours look
alike :-)

