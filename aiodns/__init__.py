from __future__ import annotations

import asyncio
import functools
import socket
import sys
from collections.abc import Callable, Iterable, Sequence
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import pycares

from . import error
from .compat import (
    AresHostResult,
    AresQueryAAAAResult,
    AresQueryAResult,
    AresQueryCAAResult,
    AresQueryCNAMEResult,
    AresQueryMXResult,
    AresQueryNAPTRResult,
    AresQueryNSResult,
    AresQueryPTRResult,
    AresQuerySOAResult,
    AresQuerySRVResult,
    AresQueryTXTResult,
    QueryResult,
    convert_result,
)

__version__ = '4.0.0'

__all__ = (
    'AresHostResult',
    'AresQueryAAAAResult',
    # Compatibility types for pycares 4.x API
    'AresQueryAResult',
    'AresQueryCAAResult',
    'AresQueryCNAMEResult',
    'AresQueryMXResult',
    'AresQueryNAPTRResult',
    'AresQueryNSResult',
    'AresQueryPTRResult',
    'AresQuerySOAResult',
    'AresQuerySRVResult',
    'AresQueryTXTResult',
    'DNSResolver',
    'error',
)

_T = TypeVar('_T')

WINDOWS_SELECTOR_ERR_MSG = (
    'aiodns needs a SelectorEventLoop on Windows. See more: '
    'https://github.com/aio-libs/aiodns#note-for-windows-users'
)

query_type_map = {
    'A': pycares.QUERY_TYPE_A,
    'AAAA': pycares.QUERY_TYPE_AAAA,
    'ANY': pycares.QUERY_TYPE_ANY,
    'CAA': pycares.QUERY_TYPE_CAA,
    'CNAME': pycares.QUERY_TYPE_CNAME,
    'MX': pycares.QUERY_TYPE_MX,
    'NAPTR': pycares.QUERY_TYPE_NAPTR,
    'NS': pycares.QUERY_TYPE_NS,
    'PTR': pycares.QUERY_TYPE_PTR,
    'SOA': pycares.QUERY_TYPE_SOA,
    'SRV': pycares.QUERY_TYPE_SRV,
    'TXT': pycares.QUERY_TYPE_TXT,
}

query_class_map = {
    'IN': pycares.QUERY_CLASS_IN,
    'CHAOS': pycares.QUERY_CLASS_CHAOS,
    'HS': pycares.QUERY_CLASS_HS,
    'NONE': pycares.QUERY_CLASS_NONE,
    'ANY': pycares.QUERY_CLASS_ANY,
}


class DNSResolver:
    def __init__(
        self,
        nameservers: Sequence[str] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        **kwargs: Any,
    ) -> None:  # TODO(PY311): Use Unpack for kwargs.
        self._closed = True
        self.loop = loop or asyncio.get_event_loop()
        if TYPE_CHECKING:
            assert self.loop is not None
        kwargs.pop('sock_state_cb', None)
        timeout = kwargs.pop('timeout', None)
        self._timeout = timeout
        self._channel = self._make_channel(**kwargs)
        if nameservers:
            self.nameservers = nameservers
        self._read_fds: set[int] = set()
        self._write_fds: set[int] = set()
        self._timer: asyncio.TimerHandle | None = None
        self._closed = False

    def _make_channel(self, **kwargs: Any) -> pycares.Channel:
        if sys.platform == 'win32' and not isinstance(
            self.loop, asyncio.SelectorEventLoop
        ):
            try:
                import winloop

                if not isinstance(self.loop, winloop.Loop):
                    raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG)
            except ModuleNotFoundError as ex:
                raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG) from ex
        return pycares.Channel(
            sock_state_cb=self._sock_state_cb, timeout=self._timeout, **kwargs
        )

    @property
    def nameservers(self) -> Sequence[str]:
        return self._channel.servers

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        self._channel.servers = list(value)

    def _callback(
        self, fut: asyncio.Future[_T], result: _T, errorno: int | None
    ) -> None:
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            fut.set_result(result)

    def _query_callback(
        self,
        fut: asyncio.Future[QueryResult],
        qtype: int,
        result: pycares.DNSResult,
        errorno: int | None,
    ) -> None:
        """Callback for query that converts results to compatible format."""
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            fut.set_result(convert_result(result, qtype))

    def _get_future_callback(
        self,
    ) -> tuple[asyncio.Future[_T], Callable[[_T, int], None]]:
        """Return a future and a callback to set the result of the future."""
        cb: Callable[[_T, int], None]
        future: asyncio.Future[_T] = self.loop.create_future()
        cb = functools.partial(self._callback, future)
        return future, cb

    @overload
    def query(
        self, host: str, qtype: Literal['A'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryAResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['AAAA'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryAAAAResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['CNAME'], qclass: str | None = None
    ) -> asyncio.Future[AresQueryCNAMEResult]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['MX'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryMXResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['NAPTR'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryNAPTRResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['NS'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryNSResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['PTR'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryPTRResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['SOA'], qclass: str | None = None
    ) -> asyncio.Future[AresQuerySOAResult]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['SRV'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQuerySRVResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['TXT'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryTXTResult]]: ...

    @overload
    def query(
        self, host: str, qtype: Literal['CAA'], qclass: str | None = None
    ) -> asyncio.Future[list[AresQueryCAAResult]]: ...

    @overload
    def query(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[QueryResult]: ...

    def query(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[QueryResult]:
        try:
            qtype_int = query_type_map[qtype]
        except KeyError as e:
            raise ValueError(f'invalid query type: {qtype}') from e
        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = query_class_map[qclass]
            except KeyError as e:
                raise ValueError(f'invalid query class: {qclass}') from e

        fut: asyncio.Future[QueryResult] = self.loop.create_future()
        cb = functools.partial(self._query_callback, fut, qtype_int)
        if qclass_int is not None:
            self._channel.query(
                host, qtype_int, query_class=qclass_int, callback=cb
            )
        else:
            self._channel.query(host, qtype_int, callback=cb)
        return fut

    def gethostbyname(
        self, host: str, family: socket.AddressFamily
    ) -> asyncio.Future[AresHostResult]:
        """
        Resolve hostname to addresses.

        This is implemented using getaddrinfo as pycares 5.x removed
        the gethostbyname method.
        """
        fut: asyncio.Future[AresHostResult] = self.loop.create_future()

        def callback(
            result: pycares.AddrInfoResult | None, errorno: int | None
        ) -> None:
            if fut.cancelled():
                return
            if errorno is not None:
                fut.set_exception(
                    error.DNSError(errorno, pycares.errno.strerror(errorno))
                )
            else:
                assert result is not None  # noqa: S101
                addresses = [node.addr for node in result.nodes]
                # Get canonical name from cnames if available
                name = result.cnames[0].name if result.cnames else host
                fut.set_result(
                    AresHostResult(name=name, aliases=[], addresses=addresses)
                )

        self._channel.getaddrinfo(host, None, family=family, callback=callback)
        return fut

    def getaddrinfo(
        self,
        host: str,
        family: socket.AddressFamily = socket.AF_UNSPEC,
        port: int | None = None,
        proto: int = 0,
        type: int = 0,
        flags: int = 0,
    ) -> asyncio.Future[pycares.AddrInfoResult]:
        fut: asyncio.Future[pycares.AddrInfoResult]
        fut, cb = self._get_future_callback()
        self._channel.getaddrinfo(
            host,
            port,
            family=family,
            type=type,
            proto=proto,
            flags=flags,
            callback=cb,
        )
        return fut

    def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> asyncio.Future[pycares.NameInfoResult]:
        fut: asyncio.Future[pycares.NameInfoResult]
        fut, cb = self._get_future_callback()
        self._channel.getnameinfo(sockaddr, flags, callback=cb)
        return fut

    def gethostbyaddr(self, name: str) -> asyncio.Future[pycares.HostResult]:
        fut: asyncio.Future[pycares.HostResult]
        fut, cb = self._get_future_callback()
        self._channel.gethostbyaddr(name, callback=cb)
        return fut

    def cancel(self) -> None:
        self._channel.cancel()

    def _sock_state_cb(self, fd: int, readable: bool, writable: bool) -> None:
        if readable or writable:
            if readable:
                self.loop.add_reader(
                    fd, self._channel.process_fd, fd, pycares.ARES_SOCKET_BAD
                )
                self._read_fds.add(fd)
            if writable:
                self.loop.add_writer(
                    fd, self._channel.process_fd, pycares.ARES_SOCKET_BAD, fd
                )
                self._write_fds.add(fd)
            if self._timer is None:
                self._start_timer()
        else:
            # socket is now closed
            if fd in self._read_fds:
                self._read_fds.discard(fd)
                self.loop.remove_reader(fd)

            if fd in self._write_fds:
                self._write_fds.discard(fd)
                self.loop.remove_writer(fd)

            if (
                not self._read_fds
                and not self._write_fds
                and self._timer is not None
            ):
                self._timer.cancel()
                self._timer = None

    def _timer_cb(self) -> None:
        if self._read_fds or self._write_fds:
            self._channel.process_fd(
                pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD
            )
            self._start_timer()
        else:
            self._timer = None

    def _start_timer(self) -> None:
        timeout = self._timeout
        if timeout is None or timeout < 0 or timeout > 1:
            timeout = 1
        elif timeout == 0:
            timeout = 0.1

        self._timer = self.loop.call_later(timeout, self._timer_cb)

    def _cleanup(self) -> None:
        """Cleanup timers and file descriptors when closing resolver."""
        if self._closed:
            return
        # Mark as closed first to prevent double cleanup
        self._closed = True
        # Cancel timer if running
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

        # Remove all file descriptors
        for fd in self._read_fds:
            self.loop.remove_reader(fd)
        for fd in self._write_fds:
            self.loop.remove_writer(fd)

        self._read_fds.clear()
        self._write_fds.clear()
        self._channel.close()

    async def close(self) -> None:
        """
        Cleanly close the DNS resolver.

        This should be called to ensure all resources are properly released.
        After calling close(), the resolver should not be used again.
        """
        self._cleanup()

    async def __aenter__(self) -> DNSResolver:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the async context manager."""
        await self.close()

    def __del__(self) -> None:
        """Handle cleanup when the resolver is garbage collected."""
        # Check if we have a channel to clean up
        # This can happen if an exception occurs during __init__ before
        # _channel is created (e.g., RuntimeError on Windows
        # without proper loop)
        if hasattr(self, '_channel'):
            self._cleanup()
