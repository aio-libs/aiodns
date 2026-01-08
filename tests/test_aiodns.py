#!/usr/bin/env python

import asyncio
import gc
import ipaddress
import logging
import socket
import sys
import time
import unittest
import unittest.mock
from typing import Any, cast

import pycares
import pytest

import aiodns

try:
    if sys.platform == 'win32':
        import winloop as uvloop

        skip_uvloop = False
    else:
        import uvloop

        skip_uvloop = False
except ModuleNotFoundError:
    skip_uvloop = True

# Skip uvloop tests on Python 3.14+ due to EventLoopPolicy deprecation
if sys.version_info >= (3, 14):
    skip_uvloop = True


class DNSTest(unittest.TestCase):
    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                # Policy deprecated in 3.14, create SelectorEventLoop directly
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

    def tearDown(self) -> None:
        self.loop.run_until_complete(self.resolver.close())
        self.resolver = None  # type: ignore[assignment]

    def test_query_a(self) -> None:
        f = self.resolver.query('google.com', 'A')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryAResult)

    def test_query_async_await(self) -> None:
        async def f() -> list[aiodns.AresQueryAResult]:
            return await self.resolver.query('google.com', 'A')

        result = self.loop.run_until_complete(f())
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryAResult)

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
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryAAAAResult)

    def test_query_cname(self) -> None:
        f = self.resolver.query('www.amazon.com', 'CNAME')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, aiodns.AresQueryCNAMEResult)

    def test_query_mx(self) -> None:
        f = self.resolver.query('google.com', 'MX')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryMXResult)

    def test_query_ns(self) -> None:
        f = self.resolver.query('google.com', 'NS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryNSResult)

    @unittest.skipIf(
        sys.platform == 'darwin', 'skipped on Darwin as it is flakey on CI'
    )
    def test_query_txt(self) -> None:
        f = self.resolver.query('google.com', 'TXT')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryTXTResult)

    def test_query_soa(self) -> None:
        f = self.resolver.query('google.com', 'SOA')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, aiodns.AresQuerySOAResult)

    def test_query_srv(self) -> None:
        f = self.resolver.query('_xmpp-server._tcp.jabber.org', 'SRV')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQuerySRVResult)

    def test_query_naptr(self) -> None:
        f = self.resolver.query('sip2sip.info', 'NAPTR')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryNAPTRResult)

    def test_query_ptr(self) -> None:
        ip = '172.253.122.26'
        f = self.resolver.query(
            ipaddress.ip_address(ip).reverse_pointer, 'PTR'
        )
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], aiodns.AresQueryPTRResult)

    def test_query_bad_type(self) -> None:
        self.assertRaises(ValueError, self.resolver.query, 'google.com', 'XXX')

    def test_query_bad_class(self) -> None:
        self.assertRaises(
            ValueError, self.resolver.query, 'google.com', 'A', 'INVALIDCLASS'
        )

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
            for _ in range(2):
                result = await self.resolver.query('gmail.com', 'MX')
                self.assertTrue(result)

        self.loop.run_until_complete(coro(self))

    def test_gethostbyname(self) -> None:
        f = self.resolver.gethostbyname('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertIsInstance(result, aiodns.AresHostResult)
        self.assertGreater(len(result.addresses), 0)

    def test_getaddrinfo_address_family_0(self) -> None:
        f = self.resolver.getaddrinfo('google.com')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(len(result.nodes) > 1)

    def test_getaddrinfo_address_family_af_inet(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(
            all(node.family == socket.AF_INET for node in result.nodes)
        )

    def test_getaddrinfo_address_family_af_inet6(self) -> None:
        f = self.resolver.getaddrinfo('google.com', socket.AF_INET6)
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)
        self.assertTrue(
            all(node.family == socket.AF_INET6 for node in result.nodes)
        )

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
        self.assertGreater(len(result.addresses), 0)

    def test_gethostbyname_bad_family(self) -> None:
        f = self.resolver.gethostbyname('ipv6.google.com', -1)  # type: ignore[arg-type]
        with self.assertRaises(aiodns.error.DNSError):
            self.loop.run_until_complete(f)


#    def test_query_bad_chars(self) -> None:
#        f = self.resolver.query('xn--cardeosapeluqueros-r0b.com', 'MX')
#        result = self.loop.run_until_complete(f)
#        self.assertTrue(result)


class TestQueryTxtChaos(DNSTest):
    """Test DNS queries with CHAOS class."""

    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']

    def test_query_txt_chaos(self) -> None:
        f = self.resolver.query('id.server', 'TXT', 'CHAOS')
        # CHAOS queries may be refused by some servers
        try:
            result = self.loop.run_until_complete(f)
            self.assertTrue(result)
        except aiodns.error.DNSError:
            # CHAOS queries are often refused, that's ok
            pass


class TestQueryTimeout(unittest.TestCase):
    """Test DNS queries with timeout configuration."""

    def setUp(self) -> None:
        if sys.platform == 'win32':
            if sys.version_info >= (3, 14):
                self.loop = asyncio.SelectorEventLoop()
            else:
                asyncio.set_event_loop_policy(
                    asyncio.WindowsSelectorEventLoopPolicy()
                )
                self.loop = asyncio.new_event_loop()
        else:
            self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(
            timeout=0.1, tries=1, loop=self.loop
        )
        self.resolver.nameservers = ['1.2.3.4']

    def tearDown(self) -> None:
        self.loop.run_until_complete(self.resolver.close())
        self.resolver = None  # type: ignore[assignment]

    def test_query_timeout(self) -> None:
        f = self.resolver.query('google.com', 'A')
        started = time.monotonic()
        try:
            self.loop.run_until_complete(f)
        except aiodns.error.DNSError as e:
            self.assertEqual(e.args[0], aiodns.error.ARES_ETIMEOUT)
        # Ensure timeout really cuts time deadline.
        # Limit duration to one second
        self.assertLess(time.monotonic() - started, 1)


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_DNS(DNSTest):
    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_QueryTxtChaos(TestQueryTxtChaos):
    """Test DNS queries with CHAOS class using uvloop."""

    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']


@unittest.skipIf(skip_uvloop, 'uvloop/winloop unavailable or Python 3.14+')
class TestUV_QueryTimeout(TestQueryTimeout):
    """Test DNS queries with timeout configuration using uvloop."""

    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(
            timeout=0.1, tries=1, loop=self.loop
        )
        self.resolver.nameservers = ['1.2.3.4']


@unittest.skipIf(sys.platform != 'win32', 'Only run on Windows')
def test_win32_no_selector_event_loop() -> None:
    """Test DNSResolver with Windows without SelectorEventLoop.

    With pycares 5, event_thread is used by default. The SelectorEventLoop
    check only triggers when event_thread creation fails and we fall back
    to sock_state_cb mode.
    """
    # Create a non-SelectorEventLoop to trigger the error
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)
    mock_loop.__class__ = (
        asyncio.AbstractEventLoop  # type: ignore[assignment]
    )

    # Mock channel creation to fail on first call (event_thread),
    # triggering the fallback path where SelectorEventLoop is required
    mock_channel = unittest.mock.MagicMock()

    with (
        pytest.raises(
            RuntimeError, match='aiodns needs a SelectorEventLoop on Windows'
        ),
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch(
            'aiodns.pycares.Channel',
            side_effect=[
                pycares.AresError(1, 'mock error'),  # First call fails
                mock_channel,  # Second call would succeed
            ],
        ),
    ):
        aiodns.DNSResolver(loop=mock_loop, timeout=5.0)


@pytest.mark.parametrize(
    ('platform', 'expected_msg_parts', 'unexpected_msg_parts'),
    [
        (
            'linux',
            [
                'automatic monitoring of',
                'resolver configuration changes',
                'system ran out of inotify watches',
                'Falling back to socket state callback',
                'Consider increasing the system inotify watch limit',
            ],
            [],
        ),
        (
            'darwin',
            [
                'automatic monitoring',
                'resolver configuration changes',
                'Falling back to socket state callback',
            ],
            [
                'system ran out of inotify watches',
                'Consider increasing the system inotify watch limit',
            ],
        ),
        (
            'win32',
            [
                'automatic monitoring',
                'resolver configuration changes',
                'Falling back to socket state callback',
            ],
            [
                'system ran out of inotify watches',
                'Consider increasing the system inotify watch limit',
            ],
        ),
    ],
)
async def test_make_channel_ares_error(
    platform: str,
    expected_msg_parts: list[str],
    unexpected_msg_parts: list[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test exception handling in _make_channel on different platforms."""
    # Set log level to capture warnings
    caplog.set_level(logging.WARNING)

    # Create a mock loop that is a SelectorEventLoop to
    # avoid Windows-specific errors
    mock_loop = unittest.mock.MagicMock(spec=asyncio.SelectorEventLoop)
    mock_channel = unittest.mock.MagicMock()

    with (
        unittest.mock.patch('sys.platform', platform),
        # Configure first Channel call to raise AresError,
        # second call to return our mock
        unittest.mock.patch(
            'aiodns.pycares.Channel',
            side_effect=[
                pycares.AresError('Mock error'),
                mock_channel,
            ],
        ),
        # Also patch asyncio.get_event_loop to return our mock loop
        unittest.mock.patch('asyncio.get_event_loop', return_value=mock_loop),
    ):
        # Create resolver which will call _make_channel
        resolver = aiodns.DNSResolver(loop=mock_loop)

        # Check that event_thread is False due to fallback
        assert resolver._event_thread is False

        # Check expected message parts in the captured log
        for part in expected_msg_parts:
            assert part in caplog.text

        # Check unexpected message parts aren't in the captured log
        for part in unexpected_msg_parts:
            assert part not in caplog.text

        # Manually set _closed to True to prevent cleanup logic from
        # running during the test.
        resolver._closed = True


def test_win32_import_winloop_error() -> None:
    """Test winloop import error on Windows.

    Test handling of ModuleNotFoundError when importing
    winloop on Windows.
    """
    # Create a mock event loop that is not a SelectorEventLoop
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)

    # Setup patching for this test
    original_import = __import__

    def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == 'winloop':
            raise ModuleNotFoundError("No module named 'winloop'")
        return original_import(name, *args, **kwargs)

    # Patch the Channel class to:
    # 1. First call (event_thread) raises AresError to trigger fallback
    # 2. Second call (sock_state_cb) would succeed but we should hit
    #    RuntimeError before that
    mock_channel = unittest.mock.MagicMock()
    channel_side_effect = [
        pycares.AresError(1, 'mock error'),  # First call fails
        mock_channel,  # Second call would succeed
    ]

    with (
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch('builtins.__import__', side_effect=mock_import),
        unittest.mock.patch(
            'importlib.import_module', side_effect=mock_import
        ),
        unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=channel_side_effect
        ),
        pytest.raises(RuntimeError, match=aiodns.WINDOWS_SELECTOR_ERR_MSG),
    ):
        aiodns.DNSResolver(loop=mock_loop)


def test_win32_winloop_not_loop_instance() -> None:
    """Test non-winloop.Loop instance on Windows.

    Test handling of a loop that is not a winloop.Loop
    instance on Windows.
    """
    # Create a mock event loop that is not a SelectorEventLoop
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)

    original_import = __import__

    # Create a mock winloop module with a Loop class that's an actual type
    class MockLoop:
        pass

    mock_winloop_module = unittest.mock.MagicMock()
    mock_winloop_module.Loop = MockLoop

    def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == 'winloop':
            return mock_winloop_module
        return original_import(name, *args, **kwargs)

    # Patch the Channel class to:
    # 1. First call (event_thread) raises AresError to trigger fallback
    # 2. Second call (sock_state_cb) would succeed but we should hit
    #    RuntimeError before that
    mock_channel = unittest.mock.MagicMock()
    channel_side_effect = [
        pycares.AresError(1, 'mock error'),  # First call fails
        mock_channel,  # Second call would succeed
    ]

    with (
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch('builtins.__import__', side_effect=mock_import),
        unittest.mock.patch(
            'importlib.import_module', side_effect=mock_import
        ),
        unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=channel_side_effect
        ),
        pytest.raises(RuntimeError, match=aiodns.WINDOWS_SELECTOR_ERR_MSG),
    ):
        aiodns.DNSResolver(loop=mock_loop)


def test_win32_winloop_loop_instance() -> None:
    """Test winloop.Loop instance on Windows.

    Test handling of a loop that IS a winloop.Loop instance on Windows.
    """

    # Create a mock winloop module with a Loop class
    class MockLoop:
        pass

    # Create a mock event loop that IS a winloop.Loop instance
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)
    # Make isinstance check pass
    mock_loop.__class__ = MockLoop  # type: ignore[assignment]

    mock_winloop_module = unittest.mock.MagicMock()
    mock_winloop_module.Loop = MockLoop

    original_import = __import__

    def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == 'winloop':
            return mock_winloop_module
        return original_import(name, *args, **kwargs)

    # Mock channel creation to avoid actual DNS resolution
    mock_channel = unittest.mock.MagicMock()

    with (
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch('builtins.__import__', side_effect=mock_import),
        unittest.mock.patch(
            'importlib.import_module', side_effect=mock_import
        ),
        unittest.mock.patch(
            'aiodns.pycares.Channel', return_value=mock_channel
        ),
    ):
        # This should not raise an exception since loop
        # is a winloop.Loop instance
        aiodns.DNSResolver(loop=mock_loop)


@pytest.mark.asyncio
async def test_close_resolver() -> None:
    """Test that DNSResolver.close() properly shuts down the resolver."""
    # Use a non-routable IP to ensure the query doesn't complete before close
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['192.0.2.1']  # TEST-NET-1, non-routable

    # Create a query to ensure resolver is active
    query_future = resolver.query('google.com', 'A')

    # Close the resolver
    await resolver.close()

    # Verify resolver is marked as closed
    assert resolver._closed

    # Verify timers are cancelled
    assert resolver._timer is None

    # Verify file descriptors are cleared
    assert len(resolver._read_fds) == 0
    assert len(resolver._write_fds) == 0

    # The query should fail with cancellation
    with pytest.raises(aiodns.error.DNSError) as exc_info:
        await query_future
    assert exc_info.value.args[0] == aiodns.error.ARES_ECANCELLED


@pytest.mark.asyncio
async def test_close_resolver_multiple_times() -> None:
    """Test that close() is idempotent and safe to call multiple times."""
    resolver = aiodns.DNSResolver()

    # Close multiple times
    await resolver.close()
    await resolver.close()
    await resolver.close()

    # All closes should succeed without error
    assert resolver._closed


def test_del_with_no_running_loop() -> None:
    """Test __del__ when there's no running event loop."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)

    # Track if cleanup was called via channel.close
    cleanup_called = False
    original_close = resolver._channel.close

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    resolver._channel.close = mock_close  # type: ignore[method-assign]
    loop.close()

    # Delete the resolver without closing it
    del resolver
    gc.collect()

    # Should have called cleanup
    assert cleanup_called


def test_del_with_stopped_event_loop() -> None:
    """Test __del__ when event loop is not running."""
    # Create a new event loop
    loop = asyncio.new_event_loop()

    # Create resolver with this loop
    resolver = aiodns.DNSResolver(loop=loop)

    # Track if cleanup was called via channel.close
    cleanup_called = False
    original_close = resolver._channel.close

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    resolver._channel.close = mock_close  # type: ignore[method-assign]

    # Close the loop so it's not running
    loop.close()

    # Delete resolver when its loop is not running
    del resolver
    gc.collect()

    # Should have called cleanup
    assert cleanup_called


@pytest.mark.asyncio
async def test_del_with_running_event_loop() -> None:
    """Test __del__ when event loop is running performs cleanup."""
    resolver = aiodns.DNSResolver()

    # Mark that cleanup was called by checking if channel.close was called
    original_close = resolver._channel.close
    cleanup_called = False

    def mock_close() -> None:
        nonlocal cleanup_called
        cleanup_called = True
        original_close()

    resolver._channel.close = mock_close  # type: ignore[method-assign]

    # Delete resolver while loop is running
    del resolver
    gc.collect()

    # Verify cleanup was called
    assert cleanup_called


@pytest.mark.asyncio
async def test_cleanup_method() -> None:
    """Test that _cleanup() properly cleans up resources."""
    resolver = aiodns.DNSResolver()

    # Mock file descriptors and timer
    resolver._read_fds.add(1)
    resolver._read_fds.add(2)
    resolver._write_fds.add(3)
    resolver._write_fds.add(4)

    # Mock timer
    mock_timer = unittest.mock.MagicMock()
    resolver._timer = mock_timer

    # Mock loop methods
    resolver.loop.remove_reader = unittest.mock.MagicMock()  # type: ignore[method-assign]
    resolver.loop.remove_writer = unittest.mock.MagicMock()  # type: ignore[method-assign]

    # Call cleanup
    resolver._cleanup()

    # Verify timer was cancelled
    mock_timer.cancel.assert_called_once()
    assert resolver._timer is None

    # Verify file descriptors were removed
    resolver.loop.remove_reader.assert_any_call(1)  # type: ignore[unreachable]
    resolver.loop.remove_reader.assert_any_call(2)
    resolver.loop.remove_writer.assert_any_call(3)
    resolver.loop.remove_writer.assert_any_call(4)

    # Verify sets are cleared
    assert len(resolver._read_fds) == 0
    assert len(resolver._write_fds) == 0


@pytest.mark.asyncio
async def test_context_manager() -> None:
    """Test DNSResolver as async context manager."""
    resolver_closed = False

    # Create resolver and use as context manager
    async with aiodns.DNSResolver() as resolver:
        # Check resolver is not closed
        assert not resolver._closed

        # Mock the close method to track if it's called
        original_close = resolver.close

        async def mock_close() -> None:
            nonlocal resolver_closed
            resolver_closed = True
            await original_close()

        resolver.close = mock_close  # type: ignore[method-assign]

        # Resolver should be usable within context
        assert isinstance(resolver, aiodns.DNSResolver)

    # After exiting context, close should have been called
    assert resolver_closed


@pytest.mark.asyncio
async def test_context_manager_with_exception() -> None:
    """Test DNSResolver context manager handles exceptions properly."""
    resolver_closed = False

    try:
        async with aiodns.DNSResolver() as resolver:
            # Mock the close method to track if it's called
            original_close = resolver.close

            async def mock_close() -> None:
                nonlocal resolver_closed
                resolver_closed = True
                await original_close()

            resolver.close = mock_close  # type: ignore[method-assign]

            # Raise an exception within the context
            raise ValueError('Test exception')
    except ValueError:
        pass  # Expected

    # Close should still be called even with exception
    assert resolver_closed


@pytest.mark.asyncio
async def test_context_manager_close_idempotent() -> None:
    """Test that close() can be called multiple times safely."""
    close_count = 0

    async with aiodns.DNSResolver() as resolver:
        original_close = resolver.close

        async def mock_close() -> None:
            nonlocal close_count
            close_count += 1
            await original_close()

        resolver.close = mock_close  # type: ignore[method-assign]

        # Manually close resolver within context
        await resolver.close()
        assert close_count == 1

    # Context manager should call close again, but it should be idempotent
    assert close_count == 2


@pytest.mark.asyncio
async def test_temporary_resolver_not_garbage_collected() -> None:
    """Test temporary resolver is not garbage collected before query completes.

    Regression test for https://github.com/aio-libs/aiodns/issues/209

    When calling query() on a temporary resolver (not stored in a variable),
    the resolver should not be garbage collected before the query completes.
    Previously, the callback was a @staticmethod which didn't hold a reference
    to self, causing the resolver to be garbage collected and the query
    cancelled.
    """
    # Force garbage collection to ensure any weak references are cleared
    gc.collect()

    # This pattern previously failed with DNSError(24, 'DNS query cancelled')
    # because the resolver was garbage collected before the query completed
    result = await aiodns.DNSResolver(nameservers=['8.8.8.8']).query(
        'google.com', 'A'
    )

    # Query should succeed
    assert result
    assert len(result) > 0
    assert isinstance(result[0], aiodns.AresQueryAResult)


def test_sock_state_cb_fallback_with_real_query() -> None:
    """Test that sock_state_cb fallback path works for actual DNS queries.

    This test forces the event_thread channel creation to fail, triggering
    the sock_state_cb fallback, then performs a real DNS query to verify
    the fallback path works correctly.
    """
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Perform a real DNS query through the sock_state_cb path
            result = await resolver.query('google.com', 'A')

            # Query should succeed
            assert result
            assert len(result) > 0
            assert isinstance(result[0], aiodns.AresQueryAResult)

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


@pytest.mark.asyncio
async def test_gethostbyname_cancelled_future() -> None:
    """Test _gethostbyname_callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['192.0.2.1']  # Non-routable

    # Start a query
    fut = resolver.gethostbyname('example.com', socket.AF_INET)

    # Cancel the future
    fut.cancel()

    # Manually invoke the callback with a cancelled future
    # This should not raise and should return early
    resolver._gethostbyname_callback(fut, 'example.com', None, None)

    await resolver.close()


def test_gethostbyname_with_sock_state_cb_fallback() -> None:
    """Test gethostbyname works with sock_state_cb fallback path."""
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Perform gethostbyname through the sock_state_cb path
            result = await resolver.gethostbyname('google.com', socket.AF_INET)

            # Query should succeed
            assert isinstance(result, aiodns.AresHostResult)
            assert len(result.addresses) > 0

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_sock_state_cb_wrapper_with_dead_weak_ref() -> None:
    """Test sock_state_cb_wrapper handles dead weak reference.

    When the resolver is garbage collected but the callback is still
    referenced by pycares, calling the callback should not raise an error.
    The weak reference will return None and the callback should exit early.
    """
    call_count = 0
    captured_callback: Any = None

    def patched_channel(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count, captured_callback
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call - capture the sock_state_cb and return a mock
        captured_callback = kwargs.get('sock_state_cb')
        return unittest.mock.MagicMock()

    # Use a mock loop to avoid any real socket operations
    mock_loop = unittest.mock.MagicMock(spec=asyncio.SelectorEventLoop)

    # Create a mock weak ref that returns None (simulating dead resolver)
    mock_dead_weak_ref = unittest.mock.MagicMock(return_value=None)

    with unittest.mock.patch(
        'aiodns.pycares.Channel', side_effect=patched_channel
    ):
        with unittest.mock.patch(
            'aiodns.weakref.ref', return_value=mock_dead_weak_ref
        ):
            resolver = aiodns.DNSResolver(loop=mock_loop, timeout=5.0)

            # Verify we captured the callback and are using fallback path
            assert resolver._event_thread is False
            assert captured_callback is not None

            # Mark as closed to prevent cleanup issues
            resolver._closed = True

    # Call the captured callback - should not raise since weak ref returns None
    # This exercises the "if this is not None:" branch when this IS None
    captured_callback(5, True, False)


def test_nameservers_property_getter() -> None:
    """Test that nameservers property getter returns channel servers."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)

    # Get nameservers through the property (covers _channel.servers getter)
    servers = resolver.nameservers

    # Should return a sequence (might be empty or have system defaults)
    assert isinstance(servers, (list, tuple))

    resolver._closed = True
    loop.close()


def test_nameservers_strips_port() -> None:
    """Test that nameservers getter strips port suffix."""
    loop = asyncio.new_event_loop()
    resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)

    # Set nameservers - pycares 5.x will store them with :53 suffix
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    # Getter should return without port suffix for backward compatibility
    servers = resolver.nameservers
    assert servers == ['8.8.8.8', '8.8.4.4']

    # Verify no port suffix in any server
    for server in servers:
        assert ':' not in server

    resolver._closed = True
    loop.close()


@pytest.mark.asyncio
async def test_query_dns() -> None:
    """Test query_dns returns native pycares DNSResult."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    result = await resolver.query_dns('google.com', 'A')

    # Should return pycares.DNSResult
    assert isinstance(result, pycares.DNSResult)
    assert hasattr(result, 'answer')
    assert hasattr(result, 'authority')
    assert hasattr(result, 'additional')

    # Answer should contain DNSRecord objects
    assert len(result.answer) > 0
    record = result.answer[0]
    assert hasattr(record, 'type')
    assert hasattr(record, 'ttl')
    assert hasattr(record, 'data')
    assert record.type == pycares.QUERY_TYPE_A

    await resolver.close()


@pytest.mark.asyncio
async def test_query_deprecation_warning() -> None:
    """Test that query() emits deprecation warning."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        await resolver.query('google.com', 'A')

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert 'query() is deprecated' in str(w[0].message)

    await resolver.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == 'win32', reason='CHAOS class unreliable')
async def test_query_dns_with_qclass() -> None:
    """Test query_dns with qclass parameter."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['1.1.1.1']

    # CHAOS class queries may be refused by some servers
    try:
        result = await resolver.query_dns('id.server', 'TXT', 'CHAOS')
        assert isinstance(result, pycares.DNSResult)
        assert len(result.answer) > 0
    except aiodns.error.DNSError:
        # CHAOS queries are often refused, that's ok
        pass

    await resolver.close()


@pytest.mark.asyncio
async def test_compat_txt_returns_str() -> None:
    """Test deprecated query() TXT returns str for ASCII text."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        result = await resolver.query('google.com', 'TXT')

    assert len(result) > 0
    # pycares 4.x returned str for ASCII TXT records
    assert isinstance(result[0].text, str)

    await resolver.close()


@pytest.mark.asyncio
async def test_compat_naptr_returns_str() -> None:
    """Test deprecated query() NAPTR returns str fields."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        result = await resolver.query('sip2sip.info', 'NAPTR')

    assert len(result) > 0
    # pycares 4.x returned str for these fields
    assert isinstance(result[0].flags, str)
    assert isinstance(result[0].service, str)
    assert isinstance(result[0].regex, str)

    await resolver.close()


@pytest.mark.asyncio
async def test_compat_caa_returns_str() -> None:
    """Test deprecated query() CAA returns str fields."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    resolver.nameservers = ['8.8.8.8']

    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        try:
            result = await resolver.query('google.com', 'CAA')
        except aiodns.error.DNSError:
            # CAA may not exist, skip test
            await resolver.close()
            return

    if len(result) > 0:
        # pycares 4.x returned str for these fields
        assert isinstance(result[0].property, str)
        assert isinstance(result[0].value, str)

    await resolver.close()


def test_getaddrinfo_with_sock_state_cb_fallback() -> None:
    """Test getaddrinfo with sock_state_cb fallback.

    This covers the non-event_thread callback path in _get_future_callback.
    """
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (event_thread) fails
            raise pycares.AresError(1, 'Simulated failure')
        # Second call (sock_state_cb) succeeds with real channel
        return original_channel(*args, **kwargs)

    async def run_test() -> None:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=5.0)
            resolver.nameservers = ['8.8.8.8']

            # Verify we're using the fallback path
            assert resolver._event_thread is False

            # Call getaddrinfo - this uses _get_future_callback
            # which exercises line 190 (non-event_thread cb path)
            result = await resolver.getaddrinfo(
                'google.com', family=socket.AF_INET
            )

            # Query should succeed
            assert result is not None
            assert result.nodes

            await resolver.close()

    try:
        loop.run_until_complete(run_test())
    finally:
        loop.close()


def test_sock_state_cb_and_timer_cb() -> None:
    """Test _sock_state_cb and _timer_cb with real file descriptors."""
    loop = asyncio.SelectorEventLoop()
    original_channel = pycares.Channel
    call_count = 0

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise pycares.AresError(1, 'Simulated failure')
        return original_channel(*args, **kwargs)

    # Create real socket pairs for testing
    sock1, sock2 = socket.socketpair()
    sock3, sock4 = socket.socketpair()
    fd1 = sock1.fileno()
    fd2 = sock3.fileno()

    try:
        with unittest.mock.patch(
            'aiodns.pycares.Channel', side_effect=patched_channel
        ):
            resolver = aiodns.DNSResolver(loop=loop, timeout=0)
            assert resolver._event_thread is False

            # Test writable only (readable=False, writable=True)
            resolver._sock_state_cb(fd1, False, True)
            assert fd1 in resolver._write_fds
            assert fd1 not in resolver._read_fds
            assert resolver._timer is not None

            # Test _timer_cb with active fds - should restart timer
            resolver._timer_cb()
            assert resolver._timer is not None

            # Test socket close for write fd
            resolver._sock_state_cb(fd1, False, False)
            assert fd1 not in resolver._write_fds

            # Test readable and writable together
            resolver._sock_state_cb(fd2, True, True)
            assert fd2 in resolver._read_fds
            assert fd2 in resolver._write_fds

            # Test socket close for both
            resolver._sock_state_cb(fd2, False, False)
            assert fd2 not in resolver._read_fds
            assert fd2 not in resolver._write_fds

            # Timer should be cancelled when no fds left
            assert resolver._timer is None

            # Test _timer_cb without active fds - should clear timer
            resolver._timer = loop.call_later(1, lambda: None)  # type: ignore[unreachable]
            resolver._timer_cb()
            assert resolver._timer is None

            resolver._closed = True
    finally:
        sock1.close()
        sock2.close()
        sock3.close()
        sock4.close()
        loop.close()


@pytest.mark.asyncio
async def test_callback_cancelled_future() -> None:
    """Test _callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[str] = asyncio.get_event_loop().create_future()
    fut.cancel()

    # Directly call _callback with cancelled future - should return early
    resolver._callback(fut, 'result', None)

    # Also test with errorno - should still return early
    # Pass empty string as result (ignored when errorno is set)
    resolver._callback(fut, '', 1)

    resolver._closed = True


@pytest.mark.asyncio
async def test_callback_error() -> None:
    """Test _callback handles error."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[str] = asyncio.get_event_loop().create_future()

    # Call _callback with an error
    # Pass empty string as result (ignored when errorno is set)
    resolver._callback(fut, '', pycares.errno.ARES_ENOTFOUND)

    # Future should have exception set
    with pytest.raises(aiodns.error.DNSError):
        fut.result()

    resolver._closed = True


@pytest.mark.asyncio
async def test_query_callback_cancelled_future() -> None:
    """Test _query_callback handles cancelled future."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    fut.cancel()

    # Directly call _query_callback with cancelled future - should return early
    # Cast None to DNSResult since the result is not used when cancelled
    resolver._query_callback(
        fut, pycares.QUERY_TYPE_A, cast(pycares.DNSResult, None), None
    )

    resolver._closed = True


@pytest.mark.asyncio
async def test_query_callback_error() -> None:
    """Test _query_callback handles error."""
    resolver = aiodns.DNSResolver(timeout=5.0)
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()

    # Call _query_callback with an error
    # Cast None to DNSResult since the result is not used when errorno is set
    resolver._query_callback(
        fut,
        pycares.QUERY_TYPE_A,
        cast(pycares.DNSResult, None),
        pycares.errno.ARES_ENOTFOUND,
    )

    # Future should have exception set
    with pytest.raises(aiodns.error.DNSError):
        fut.result()

    resolver._closed = True


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
