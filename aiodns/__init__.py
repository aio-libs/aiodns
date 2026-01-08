from __future__ import annotations

import asyncio
import functools
import logging
import socket
import sys
import warnings
import weakref
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
    'DNSResolver',
    'error',
)

_T = TypeVar('_T')

WINDOWS_SELECTOR_ERR_MSG = (
    'aiodns needs a SelectorEventLoop on Windows. See more: '
    'https://github.com/aio-libs/aiodns#note-for-windows-users'
)

_LOGGER = logging.getLogger(__name__)

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
        self._event_thread, self._channel = self._make_channel(**kwargs)
        if nameservers:
            self.nameservers = nameservers
        self._read_fds: set[int] = set()
        self._write_fds: set[int] = set()
        self._timer: asyncio.TimerHandle | None = None
        self._closed = False

    def _make_channel(self, **kwargs: Any) -> tuple[bool, pycares.Channel]:
        # pycares 5+ uses event_thread by default when sock_state_cb
        # is not provided
        try:
            return True, pycares.Channel(timeout=self._timeout, **kwargs)
        except pycares.AresError as e:
            if sys.platform == 'linux':
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. This '
                    'usually means the system ran out of inotify watches. '
                    'Falling back to socket state callback. Consider '
                    'increasing the system inotify watch limit: %s',
                    e,
                )
            else:
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. '
                    'Falling back to socket state callback: %s',
                    e,
                )
        # Fall back to sock_state_cb (needs SelectorEventLoop on Windows)
        if sys.platform == 'win32' and not isinstance(
            self.loop, asyncio.SelectorEventLoop
        ):
            try:
                import winloop

                if not isinstance(self.loop, winloop.Loop):
                    raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG)
            except ModuleNotFoundError as ex:
                raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG) from ex
        # Use weak reference for deterministic cleanup. Without it there's a
        # reference cycle (DNSResolver -> _channel -> callback -> DNSResolver).
        # Python 3.4+ can handle cycles with __del__, but weak ref ensures
        # cleanup happens immediately when last reference is dropped.
        weak_self = weakref.ref(self)

        def sock_state_cb_wrapper(
            fd: int, readable: bool, writable: bool
        ) -> None:
            this = weak_self()
            if this is not None:
                this._sock_state_cb(fd, readable, writable)

        return False, pycares.Channel(
            sock_state_cb=sock_state_cb_wrapper,
            timeout=self._timeout,
            **kwargs,
        )

    @property
    def nameservers(self) -> Sequence[str]:
        # pycares 5.x returns servers with port (e.g., '8.8.8.8:53')
        # Strip port for backward compatibility with pycares 4.x
        return [s.rsplit(':', 1)[0] for s in self._channel.servers]

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        self._channel.servers = value

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

    def _get_future_callback(
        self,
    ) -> tuple[asyncio.Future[_T], Callable[[_T, int | None], None]]:
        """Return a future and a callback to set the result of the future."""
        cb: Callable[[_T, int | None], None]
        future: asyncio.Future[_T] = self.loop.create_future()
        if self._event_thread:
            cb = functools.partial(  # type: ignore[assignment]
                self.loop.call_soon_threadsafe,
                self._callback,  # type: ignore[arg-type]
                future,
            )
        else:
            cb = functools.partial(self._callback, future)
        return future, cb

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

    def _get_query_future_callback(
        self, qtype: int
    ) -> tuple[asyncio.Future[QueryResult], Callable[..., None]]:
        """Return a future and callback for query with result conversion."""
        future: asyncio.Future[QueryResult] = self.loop.create_future()
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(  # type: ignore[assignment]
                self.loop.call_soon_threadsafe,
                self._query_callback,  # type: ignore[arg-type]
                future,
                qtype,
            )
        else:
            cb = functools.partial(self._query_callback, future, qtype)
        return future, cb

    @overload
    def query(
        self, host: str, qtype: Literal['A'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['AAAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAAAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryCAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CNAME'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryCNAMEResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['MX'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryMXResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NAPTR'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNAPTRResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NS'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNSResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['PTR'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryPTRResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SOA'], qclass: str | None = ...
    ) -> asyncio.Future[AresQuerySOAResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SRV'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQuerySRVResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['TXT'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryTXTResult]]: ...

    def query(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[list[Any]] | asyncio.Future[Any]:
        """Query DNS records (deprecated, use query_dns instead)."""
        warnings.warn(
            'query() is deprecated, use query_dns() instead',
            DeprecationWarning,
            stacklevel=2,
        )
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

        fut, cb = self._get_query_future_callback(qtype_int)
        if qclass_int is not None:
            self._channel.query(
                host, qtype_int, query_class=qclass_int, callback=cb
            )
        else:
            self._channel.query(host, qtype_int, callback=cb)
        return fut

    def query_dns(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[pycares.DNSResult]:
        """Query DNS records, returning native pycares 5.x DNSResult."""
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

        fut: asyncio.Future[pycares.DNSResult]
        fut, cb = self._get_future_callback()
        if qclass_int is not None:
            self._channel.query(
                host, qtype_int, query_class=qclass_int, callback=cb
            )
        else:
            self._channel.query(host, qtype_int, callback=cb)
        return fut

    def _gethostbyname_callback(
        self,
        fut: asyncio.Future[AresHostResult],
        host: str,
        result: pycares.AddrInfoResult | None,
        errorno: int | None,
    ) -> None:
        """Callback for gethostbyname that converts AddrInfoResult."""
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            assert result is not None  # noqa: S101
            # node.addr is (address_bytes, port) - extract and decode
            addresses = [node.addr[0].decode() for node in result.nodes]
            # Get canonical name from cnames if available
            name = result.cnames[0].name if result.cnames else host
            fut.set_result(
                AresHostResult(name=name, aliases=[], addresses=addresses)
            )

    def gethostbyname(
        self, host: str, family: socket.AddressFamily
    ) -> asyncio.Future[AresHostResult]:
        """
        Resolve hostname to addresses.

        Deprecated: Use getaddrinfo() instead. This is implemented using
        getaddrinfo as pycares 5.x removed the gethostbyname method.
        """
        warnings.warn(
            'gethostbyname() is deprecated, use getaddrinfo() instead',
            DeprecationWarning,
            stacklevel=2,
        )
        fut: asyncio.Future[AresHostResult] = self.loop.create_future()
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(  # type: ignore[assignment]
                self.loop.call_soon_threadsafe,
                self._gethostbyname_callback,  # type: ignore[arg-type]
                fut,
                host,
            )
        else:
            cb = functools.partial(self._gethostbyname_callback, fut, host)
        self._channel.getaddrinfo(host, None, family=family, callback=cb)
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
        if not self._closed:
            self._channel.cancel()
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
