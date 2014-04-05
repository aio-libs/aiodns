#!/usr/bin/env python

import asyncio
import unittest

import aiodns
import pycares


class DNSTest(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop)

    def tearDown(self):
        self.resolver = None

    def test_query_a(self):
        f = self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f)
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
        f = self.resolver.query('livechat.ripe.net', 'CNAME')
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
        ip = '173.194.69.102'
        f = self.resolver.query(pycares.reverse_address(ip), 'PTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

    def test_query_bad_type(self):
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'XXX')

    def test_query_timeout(self):
        self.resolver = aiodns.DNSResolver(timeout=0.1, loop=self.loop)
        self.resolver.nameservers = ['1.2.3.4']
        f = self.resolver.query('google.com', 'A')
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ETIMEOUT)

    def test_query_cancel(self):
        f = self.resolver.query('google.com', 'A')
        self.resolver.cancel()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ECANCELLED)


if __name__ == '__main__':
    unittest.main(verbosity=2)

