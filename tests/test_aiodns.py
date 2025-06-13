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
from typing import Any

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


class DNSTest(unittest.TestCase):
    def setUp(self) -> None:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']

    def tearDown(self) -> None:
        self.loop.run_until_complete(self.resolver.close())
        self.resolver = None  # type: ignore[assignment]

    def test_query_a(self) -> None:
        f = self.resolver.query('google.com', 'A')
        self.loop.run_until_complete(f)

    def test_query_async_await(self) -> None:
        async def f() -> list[pycares.ares_query_a_result]:
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

    @unittest.skipIf(
        sys.platform == 'darwin', 'skipped on Darwin as it is flakey on CI'
    )
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
        f = self.resolver.query(
            ipaddress.ip_address(ip).reverse_pointer, 'PTR'
        )
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)

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
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']

    def test_query_txt_chaos(self) -> None:
        f = self.resolver.query('id.server', 'TXT', 'CHAOS')
        result = self.loop.run_until_complete(f)
        self.assertTrue(result)


class TestQueryTimeout(unittest.TestCase):
    """Test DNS queries with timeout configuration."""

    def setUp(self) -> None:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy()
            )
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


@unittest.skipIf(skip_uvloop, "We don't have a uvloop or winloop module")
class TestUV_DNS(DNSTest):
    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop, timeout=5.0)
        self.resolver.nameservers = ['8.8.8.8']


class TestNoEventThreadDNS(DNSTest):
    """Test DNSResolver with no event thread."""

    def setUp(self) -> None:
        with unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ):
            super().setUp()


@unittest.skipIf(skip_uvloop, "We don't have a uvloop or winloop module")
class TestUV_QueryTxtChaos(TestQueryTxtChaos):
    """Test DNS queries with CHAOS class using uvloop."""

    def setUp(self) -> None:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.resolver.nameservers = ['1.1.1.1']


@unittest.skipIf(skip_uvloop, "We don't have a uvloop or winloop module")
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


class TestNoEventThreadQueryTxtChaos(TestQueryTxtChaos):
    """Test DNS queries with CHAOS class without event thread."""

    def setUp(self) -> None:
        with unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ):
            super().setUp()


class TestNoEventThreadQueryTimeout(TestQueryTimeout):
    """Test DNS queries with timeout configuration without event thread."""

    def setUp(self) -> None:
        with unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ):
            super().setUp()


@unittest.skipIf(sys.platform != 'win32', 'Only run on Windows')
def test_win32_no_selector_event_loop() -> None:
    """Test DNSResolver with Windows without SelectorEventLoop."""
    # Create a non-SelectorEventLoop to trigger the error
    mock_loop = unittest.mock.MagicMock(spec=asyncio.AbstractEventLoop)
    mock_loop.__class__ = (
        asyncio.AbstractEventLoop  # type: ignore[assignment]
    )

    with (
        pytest.raises(
            RuntimeError, match='aiodns needs a SelectorEventLoop on Windows'
        ),
        unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ),
        unittest.mock.patch('sys.platform', 'win32'),
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
        unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=True
        ),
        # Also patch asyncio.get_event_loop to return our mock loop
        unittest.mock.patch('asyncio.get_event_loop', return_value=mock_loop),
    ):
        # Create resolver which will call _make_channel
        resolver = aiodns.DNSResolver(loop=mock_loop)

        # Check that event_thread is False due to exception
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

    # Patch the Channel class to avoid creating real network resources
    mock_channel = unittest.mock.MagicMock()

    with (
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ),
        unittest.mock.patch('builtins.__import__', side_effect=mock_import),
        unittest.mock.patch(
            'importlib.import_module', side_effect=mock_import
        ),
        # Also patch Channel creation to avoid socket resource leak
        unittest.mock.patch(
            'aiodns.pycares.Channel', return_value=mock_channel
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

    # Patch the Channel class to avoid creating real network resources
    mock_channel = unittest.mock.MagicMock()

    with (
        unittest.mock.patch('sys.platform', 'win32'),
        unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ),
        unittest.mock.patch('builtins.__import__', side_effect=mock_import),
        unittest.mock.patch(
            'importlib.import_module', side_effect=mock_import
        ),
        # Also patch Channel creation to avoid socket resource leak
        unittest.mock.patch(
            'aiodns.pycares.Channel', return_value=mock_channel
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
        unittest.mock.patch(
            'aiodns.pycares.ares_threadsafety', return_value=False
        ),
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
    resolver = aiodns.DNSResolver()

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


if __name__ == '__main__':  # pragma: no cover
    unittest.main(verbosity=2)
