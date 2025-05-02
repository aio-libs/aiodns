#!/usr/bin/env python

import asyncio
import ipaddress
import unittest
import pytest
import socket
import sys
import time
import unittest.mock

import aiodns

try:
    if sys.platform == "win32":
        import winloop as uvloop
        skip_uvloop = False
    else:
        import uvloop 
        skip_uvloop = False
except ModuleNotFoundError:
    skip_uvloop = True


class DNSTest(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

    def tearDown(self):
        self.resolver = None

    def test_query_a(self):
        f = self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f)

    def test_query_async_await(self):
        async def f():
            return await self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f())
        self.assertTrue(result)

    def test_query_a_bad(self):
        f = self.resolver.query('hgf8g2od29hdohid.com', 'A')
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ENOTFOUND)

    def test_query_aaaa(self):
        f = self.resolver.query('ipv6.google.com', 'AAAA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_cname(self):
        f = self.resolver.query('www.amazon.com', 'CNAME')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_mx(self):
        f = self.resolver.query('google.com', 'MX')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_ns(self):
        f = self.resolver.query('google.com', 'NS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_txt(self):
        f = self.resolver.query('google.com', 'TXT')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_soa(self):
        f = self.resolver.query('google.com', 'SOA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_srv(self):
        f = self.resolver.query('_xmpp-server._tcp.jabber.org', 'SRV')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_naptr(self):
        f = self.resolver.query('sip2sip.info', 'NAPTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_ptr(self):
        ip = '172.253.122.26'
        f = self.resolver.query(ipaddress.ip_address(ip).reverse_pointer, 'PTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_bad_type(self):
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'XXX')

    def test_query_txt_chaos(self):
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']
        f = self.resolver.query('id.server', 'TXT', 'CHAOS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_bad_class(self):
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'A', "INVALIDCLASS")

    def test_query_timeout(self):
        self.resolver = aiodns.DNSResolver(timeout=0.1, tries=1, loop=self.loop)
        self.resolver.nameservers = ['1.2.3.4']
        f = self.resolver.query('google.com', 'A')
        started = time.monotonic()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ETIMEOUT)
        # Ensure timeout really cuts time deadline. Limit duration to one second
        self.assertLess(time.monotonic() - started, 1)

    def test_query_cancel(self):
        f = self.resolver.query('google.com', 'A')
        self.resolver.cancel()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ECANCELLED)

    def test_future_cancel(self):
        f = self.resolver.query('google.com', 'A')
        f.cancel()
        async def coro():
            await asyncio.sleep(0.1)
            await f
        try:
            self.loop.run_until_complete(coro())
        except asyncio.CancelledError as e:
            self.assertTrue(e)

    def test_query_twice(self):
        async def coro(self, host, qtype, n=2):
            for i in range(n):
                result = await self.resolver.query(host, qtype)
                self.assertTrue(result)
        self.loop.run_until_complete(coro(self, 'gmail.com', 'MX'))

    def test_gethostbyname(self):
        f = self.resolver.gethostbyname('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_getaddrinfo_address_family_0(self):
        f = self.resolver.getaddrinfo('google.com')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(len(result.nodes) > 1)

    def test_getaddrinfo_address_family_af_inet(self):
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(all(node.family == socket.AF_INET for node in result.nodes))

    def test_getaddrinfo_address_family_af_inet6(self):
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(all(node.family == socket.AF_INET6 for node in result.nodes))

    def test_getnameinfo_ipv4(self):
        f = self.resolver.getnameinfo(('127.0.0.1', 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    def test_getnameinfo_ipv6(self):
        f = self.resolver.getnameinfo(('::1', 0, 0, 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    @unittest.skipIf(sys.platform == 'win32', 'skipped on Windows')
    def test_gethostbyaddr(self):
        f = self.resolver.gethostbyaddr('127.0.0.1')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_gethostbyname_ipv6(self):
        f = self.resolver.gethostbyname('ipv6.google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_gethostbyname_bad_family(self):
        f = self.resolver.gethostbyname('ipv6.google.com', -1)
        with self.assertRaises(aiodns.error.DNSError):
            self.loop.run_until_complete(f)

#    def test_query_bad_chars(self):
#        f = self.resolver.query('xn--cardeosapeluqueros-r0b.com', 'MX')
#        result = self.loop.run_until_complete(f)
#        self.assertTrue(result)

@unittest.skipIf(skip_uvloop, "We don't have a uvloop or winloop module")
class TestUV_DNS(DNSTest):
    def setUp(self):
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']


class TestNoEventThreadDNS(DNSTest):
    """Test DNSResolver with no event thread."""

    def setUp(self):
        with unittest.mock.patch('aiodns.pycares.ares_threadsafety', return_value=False):
            super().setUp()


@unittest.skipIf(sys.platform != 'win32', 'Only run on Windows')
def test_win32_no_selector_event_loop():
    """Test DNSResolver with Windows without SelectorEventLoop."""
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    with (
        pytest.raises(RuntimeError, match="aiodns needs a SelectorEventLoop on Windows"),
        unittest.mock.patch('aiodns.pycares.ares_threadsafety', return_value=False)
    ):
        aiodns.DNSResolver(loop=asyncio.new_event_loop(), timeout=5.0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
