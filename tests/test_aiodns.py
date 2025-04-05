#!/usr/bin/env python

import asyncio
import ipaddress
import unittest
import socket
import sys
import time
from typing import Any

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
    def setUp(self) -> None:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

    def tearDown(self) -> None:
        self.resolver = None  # type: ignore[assignment]

    def test_query_a(self) -> None:
        f = self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f)

    def test_query_async_await(self) -> None:
        async def f() -> Any:
            return await self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f())
        self.assertTrue(result)

    def test_query_a_bad(self) -> None:
        f = self.resolver.query('hgf8g2od29hdohid.com', 'A')
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ENOTFOUND)

    def test_query_aaaa(self) -> None:
        f = self.resolver.query('ipv6.google.com', 'AAAA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_cname(self) -> None:
        f = self.resolver.query('www.amazon.com', 'CNAME')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_mx(self) -> None:
        f = self.resolver.query('google.com', 'MX')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_ns(self) -> None:
        f = self.resolver.query('google.com', 'NS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_txt(self) -> None:
        f = self.resolver.query('google.com', 'TXT')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_soa(self) -> None:
        f = self.resolver.query('google.com', 'SOA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_srv(self) -> None:
        f = self.resolver.query('_xmpp-server._tcp.jabber.org', 'SRV')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_naptr(self) -> None:
        f = self.resolver.query('sip2sip.info', 'NAPTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_ptr(self) -> None:
        ip = '172.253.122.26'
        f = self.resolver.query(ipaddress.ip_address(ip).reverse_pointer, 'PTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_bad_type(self) -> None:
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'XXX')

    def test_query_txt_chaos(self) -> None:
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']
        f = self.resolver.query('id.server', 'TXT', 'CHAOS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_bad_class(self) -> None:
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'A', "INVALIDCLASS")

    def test_query_timeout(self) -> None:
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

    def test_query_cancel(self) -> None:
        f = self.resolver.query('google.com', 'A')
        self.resolver.cancel()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ECANCELLED)

    def test_future_cancel(self) -> None:
        f = self.resolver.query('google.com', 'A')
        f.cancel()
        async def coro() -> None:
            await asyncio.sleep(0.1)
            await f
        try:
            self.loop.run_until_complete(coro())
        except asyncio.CancelledError as e:
            self.assertTrue(e)

    def test_query_twice(self) -> None:
        async def coro(self: DNSTest) -> None:
            for i in range(2):
                result = await self.resolver.query("gmail.com", "MX")
                self.assertTrue(result)
        self.loop.run_until_complete(coro(self))

    def test_gethostbyname(self) -> None:
        f = self.resolver.gethostbyname('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_getaddrinfo_address_family_0(self) -> None:
        f = self.resolver.getaddrinfo('google.com')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(len(result.nodes) > 1)

    def test_getaddrinfo_address_family_af_inet(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(all(node.family == socket.AF_INET for node in result.nodes))

    def test_getaddrinfo_address_family_af_inet6(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(all(node.family == socket.AF_INET6 for node in result.nodes))

    def test_getnameinfo_ipv4(self) -> None:
        f = self.resolver.getnameinfo(('127.0.0.1', 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    def test_getnameinfo_ipv6(self) -> None:
        f = self.resolver.getnameinfo(('::1', 0, 0, 0))
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(result.node)

    @unittest.skipIf(sys.platform == 'win32', 'skipped on Windows')
    def test_gethostbyaddr(self) -> None:
        f = self.resolver.gethostbyaddr('127.0.0.1')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_gethostbyname_ipv6(self) -> None:
        f = self.resolver.gethostbyname('ipv6.google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_gethostbyname_bad_family(self) -> None:
        f = self.resolver.gethostbyname('ipv6.google.com', -1)  # type: ignore[arg-type]
        with self.assertRaises(aiodns.error.DNSError):
            self.loop.run_until_complete(f)

#    def test_query_bad_chars(self) -> None:
#        f = self.resolver.query('xn--cardeosapeluqueros-r0b.com', 'MX')
#        result = self.loop.run_until_complete(f)
#        self.assertTrue(result)

@unittest.skipIf(skip_uvloop, "We don't have a uvloop or winloop module")
class TestUV_DNS(DNSTest):
    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

if __name__ == '__main__':
    unittest.main(verbosity=2)
