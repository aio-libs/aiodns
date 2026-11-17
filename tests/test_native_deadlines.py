import asyncio
import gc
import logging
import socket
import time
import warnings
import weakref
from collections.abc import Callable
from typing import Any, cast

import pycares
import pytest

import aiodns


class _LocalDNSServer(asyncio.DatagramProtocol):
    def __init__(
        self, *, drop_all: bool = False, nxdomain: bool = False
    ) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.drop_all = drop_all
        self.nxdomain = nxdomain
        self.requests: asyncio.Queue[tuple[str, ...]] = asyncio.Queue()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, packet: bytes, addr: Any) -> None:
        assert self.transport is not None
        offset = 12
        labels = []
        while packet[offset]:
            label_size = packet[offset]
            offset += 1
            labels.append(packet[offset : offset + label_size].decode())
            offset += label_size
        self.requests.put_nowait(tuple(labels))
        if self.drop_all or any(label.startswith('drop') for label in labels):
            return

        response = (
            packet[:2]
            + (
                b'\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00'
                if self.nxdomain
                else b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
            )
            + packet[12 : offset + 5]
            + (
                b''
                if self.nxdomain
                else b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04'
                b'\x7f\x00\x00\x01'
            )
        )
        self.transport.sendto(response, addr)


@pytest.mark.asyncio
async def test_local_dns_server_edns_response_has_valid_answer() -> None:
    """An EDNS request receives one answer and no undeclared records."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        _LocalDNSServer, local_addr=('127.0.0.1', 0)
    )
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setblocking(False)
    request = bytes.fromhex(
        '1234 0100 0001 0000 0000 0001'
        '07 73756363657373 04 74657374 00 0001 0001'
        '00 0029 04d0 00000000 0000'
    )
    expected_response = bytes.fromhex(
        '1234 8180 0001 0001 0000 0000'
        '07 73756363657373 04 74657374 00 0001 0001'
        'c00c 0001 0001 00000000 0004 7f000001'
    )
    try:
        await loop.sock_connect(client, server.get_extra_info('sockname'))
        await loop.sock_sendall(client, request)
        response = await asyncio.wait_for(
            loop.sock_recv(client, 512), timeout=1
        )
        assert response == expected_response
    finally:
        client.close()
        server.close()


@pytest.mark.asyncio
async def test_stayopen_last_query_completion_clears_timer(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Idle sockets neither keep processing active nor retain the resolver."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        _LocalDNSServer, local_addr=('127.0.0.1', 0)
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    # Capturing the fallback exception would retain the constructor's frame.
    with caplog.at_level(logging.ERROR, logger='aiodns'):
        resolver = aiodns.DNSResolver(
            loop=loop, timeout=5, tries=1, flags=pycares.ARES_FLAG_STAYOPEN
        )
    resolver.nameservers = [f'127.0.0.1:{port}']
    resolver_ref = weakref.ref(resolver)
    try:
        await resolver.query_dns('success.test', 'A')
        await asyncio.sleep(0)

        assert resolver._read_fds
        assert cast(Callable[[], float], resolver._channel.timeout)() == 0
        assert resolver._timer is None

        del resolver
        gc.collect()
        assert resolver_ref() is None
    finally:
        if remaining := resolver_ref():
            await remaining.close()
        server.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'method',
    [
        'query',
        'query_dns',
        'getaddrinfo',
        'gethostbyname',
        'getnameinfo',
        'gethostbyaddr',
    ],
)
async def test_cancelled_future_keeps_native_timeout_processing(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    """All query APIs process native completion after Future cancellation."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        lambda: _LocalDNSServer(drop_all=True),
        local_addr=('127.0.0.1', 0),
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    resolver = aiodns.DNSResolver(
        loop=loop, timeout=0.05, tries=1, flags=pycares.ARES_FLAG_STAYOPEN
    )
    resolver.nameservers = [f'127.0.0.1:{port}']
    submit: dict[str, Callable[[], asyncio.Future[Any]]] = {
        'query': lambda: resolver.query('drop.test', 'A'),
        'query_dns': lambda: resolver.query_dns('drop.test', 'A'),
        'getaddrinfo': lambda: resolver.getaddrinfo(
            'drop.test', socket.AF_INET
        ),
        'gethostbyname': lambda: resolver.gethostbyname(
            'drop.test', socket.AF_INET
        ),
        'getnameinfo': lambda: resolver.getnameinfo(
            ('192.0.2.1', 80), pycares.ARES_NI_NAMEREQD
        ),
        'gethostbyaddr': lambda: resolver.gethostbyaddr('192.0.2.1'),
    }
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            future = submit[method]()
        native_deadline = cast(
            Callable[[], float], resolver._channel.timeout
        )()
        assert future.cancel()
        await asyncio.sleep(0)
        assert resolver._timer is not None

        await asyncio.sleep(native_deadline + 0.2)
        assert future.cancelled()
        assert resolver._timer is None
    finally:
        await resolver.close()
        server.close()


@pytest.mark.asyncio
async def test_fallback_timeout_tracks_native_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Process c-ares deadlines within 200 ms of its reported deadline."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        _LocalDNSServer, local_addr=('127.0.0.1', 0)
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    resolver = aiodns.DNSResolver(loop=loop, timeout=5, tries=1)
    resolver.nameservers = [f'127.0.0.1:{port}']
    try:
        for index in range(5):
            await resolver.query_dns(f'warm-{index}.test', 'A')
            assert resolver._timer is None

        started = time.monotonic()
        future = resolver.query_dns('drop-deadline.test', 'A')
        native_deadline = cast(
            Callable[[], float], resolver._channel.timeout
        )()
        with pytest.raises(aiodns.error.DNSError):
            await future
        elapsed = time.monotonic() - started

        assert native_deadline < 0.5
        assert abs(elapsed - native_deadline) < 0.2
        assert resolver._timer is None
    finally:
        await resolver.close()
        server.close()


@pytest.mark.asyncio
async def test_search_followup_rearms_earlier_native_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Search replies can shorten the deadline before getaddrinfo completes."""
    loop = asyncio.get_running_loop()
    server, protocol = await loop.create_datagram_endpoint(
        lambda: _LocalDNSServer(nxdomain=True),
        local_addr=('127.0.0.1', 0),
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    resolver = aiodns.DNSResolver(
        loop=loop,
        timeout=5,
        tries=1,
        ndots=0,
        domains=[f'suffix-{index}.test' for index in range(5)] + ['drop.test'],
        flags=pycares.ARES_FLAG_STAYOPEN,
    )
    resolver.nameservers = [f'127.0.0.1:{port}']
    try:
        future = resolver.getaddrinfo('missing', socket.AF_INET)
        assert cast(Callable[[], float], resolver._channel.timeout)() > 4

        async def wait_for_dropped_followup() -> None:
            while await protocol.requests.get() != ('missing', 'drop', 'test'):
                pass

        await asyncio.wait_for(wait_for_dropped_followup(), timeout=1)
        assert not future.done()
        native_deadline = cast(
            Callable[[], float], resolver._channel.timeout
        )()
        assert 0 < native_deadline < 0.5
        started = time.monotonic()
        with pytest.raises(aiodns.error.DNSError):
            await asyncio.wait_for(future, native_deadline + 0.2)
        assert time.monotonic() - started < native_deadline + 0.2
        assert resolver._timer is None
    finally:
        await resolver.close()
        server.close()


@pytest.mark.asyncio
async def test_new_query_rearms_earlier_native_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new deadline is honored when c-ares reuses its existing socket."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        _LocalDNSServer, local_addr=('127.0.0.1', 0)
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    resolver = aiodns.DNSResolver(loop=loop, timeout=5, tries=1)
    resolver.nameservers = [f'127.0.0.1:{port}']
    socket_state_notifications = 0
    original_sock_state_cb = resolver._sock_state_cb

    def count_sock_state_notifications(
        fd: int, readable: bool, writable: bool
    ) -> None:
        nonlocal socket_state_notifications
        socket_state_notifications += 1
        original_sock_state_cb(fd, readable, writable)

    resolver._sock_state_cb = (  # type: ignore[method-assign]
        count_sock_state_notifications
    )
    try:
        first_pending_query = resolver.query_dns('drop-first.test', 'A')
        assert cast(Callable[[], float], resolver._channel.timeout)() > 4

        for index in range(5):
            await resolver.query_dns(f'warm-{index}.test', 'A')

        read_fds_before = resolver._read_fds.copy()
        write_fds_before = resolver._write_fds.copy()
        notifications_before = socket_state_notifications
        assert read_fds_before or write_fds_before
        started = time.monotonic()
        second_pending_query = resolver.query_dns('drop-second.test', 'A')
        assert socket_state_notifications == notifications_before
        assert resolver._read_fds == read_fds_before
        assert resolver._write_fds == write_fds_before
        native_deadline = cast(
            Callable[[], float], resolver._channel.timeout
        )()
        assert native_deadline < 0.5
        with pytest.raises(aiodns.error.DNSError):
            await asyncio.wait_for(second_pending_query, native_deadline + 0.2)

        assert time.monotonic() - started < native_deadline + 0.2
    finally:
        await resolver.close()
        assert resolver._timer is None
        server.close()
    with pytest.raises(aiodns.error.DNSError):
        await first_pending_query


@pytest.mark.asyncio
async def test_overdue_native_deadline_is_processed_on_new_submission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An overdue deadline is processed when submission observes timeout 0."""
    loop = asyncio.get_running_loop()
    server, _ = await loop.create_datagram_endpoint(
        _LocalDNSServer, local_addr=('127.0.0.1', 0)
    )
    port = server.get_extra_info('sockname')[1]
    native_channel = pycares.Channel
    channel_calls = 0

    def channel_factory(*args: Any, **kwargs: Any) -> pycares.Channel:
        nonlocal channel_calls
        channel_calls += 1
        if channel_calls == 1:
            raise pycares.AresError(1, 'force fallback integration')
        return native_channel(*args, **kwargs)

    monkeypatch.setattr(pycares, 'Channel', channel_factory)
    resolver = aiodns.DNSResolver(loop=loop, timeout=5, tries=1)
    resolver.nameservers = [f'127.0.0.1:{port}']
    try:
        for index in range(5):
            await resolver.query_dns(f'warm-{index}.test', 'A')

        first_pending_query = resolver.query_dns(
            'drop-overdue-first.test', 'A'
        )
        native_deadline = cast(
            Callable[[], float], resolver._channel.timeout
        )()
        assert 0.2 < native_deadline < 0.3

        time.sleep(0.3)
        second_pending_query = resolver.query_dns(
            'drop-overdue-second.test', 'A'
        )
        assert cast(Callable[[], float], resolver._channel.timeout)() == 0

        results = await asyncio.wait_for(
            asyncio.gather(
                first_pending_query,
                second_pending_query,
                return_exceptions=True,
            ),
            timeout=0.4,
        )
        assert all(
            isinstance(result, aiodns.error.DNSError) for result in results
        )
    finally:
        await resolver.close()
        server.close()
