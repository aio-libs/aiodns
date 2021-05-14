
import asyncio
import functools
import pycares
import socket

from typing import (
    Any,
    List,
    Optional,
    Set
)

from . import error


__version__ = '3.0.0'

__all__ = ('DNSResolver', 'error')


READ = 1
WRITE = 2

query_type_map = {'A'     : pycares.QUERY_TYPE_A,
                  'AAAA'  : pycares.QUERY_TYPE_AAAA,
                  'ANY'   : pycares.QUERY_TYPE_ANY,
                  'CAA'   : pycares.QUERY_TYPE_CAA,
                  'CNAME' : pycares.QUERY_TYPE_CNAME,
                  'MX'    : pycares.QUERY_TYPE_MX,
                  'NAPTR' : pycares.QUERY_TYPE_NAPTR,
                  'NS'    : pycares.QUERY_TYPE_NS,
                  'PTR'   : pycares.QUERY_TYPE_PTR,
                  'SOA'   : pycares.QUERY_TYPE_SOA,
                  'SRV'   : pycares.QUERY_TYPE_SRV,
                  'TXT'   : pycares.QUERY_TYPE_TXT
        }

query_class_map = {'IN'    : pycares.QUERY_CLASS_IN,
                   'CHAOS' : pycares.QUERY_CLASS_CHAOS,
                   'HS'    : pycares.QUERY_CLASS_HS,
                   'NONE'  : pycares.QUERY_CLASS_NONE,
                   'ANY'   : pycares.QUERY_CLASS_ANY
                   }

class DNSResolver:
    def __init__(self, nameservers: Optional[List[str]] = None,
                 loop: Optional[asyncio.AbstractEventLoop] = None,
                 **kwargs: Any) -> None:
        self.loop = loop or asyncio.get_event_loop()
        assert self.loop is not None
        kwargs.pop('sock_state_cb', None)
        self._channel = pycares.Channel(sock_state_cb=self._sock_state_cb, **kwargs)
        if nameservers:
            self.nameservers = nameservers
        self._read_fds = set() # type: Set[int]
        self._write_fds = set() # type: Set[int]
        self._timer = None  # type: Optional[asyncio.TimerHandle]

    @property
    def nameservers(self) -> pycares.Channel:
        return self._channel.servers

    @nameservers.setter
    def nameservers(self, value: List[str]) -> None:
        self._channel.servers = value

    @staticmethod
    def _callback(fut: asyncio.Future, result: Any, errorno: int) -> None:
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(error.DNSError(errorno, pycares.errno.strerror(errorno)))
        else:
            fut.set_result(result)

    def query(self, host: str, qtype: str, qclass: str=None) -> asyncio.Future:
        try:
            qtype = query_type_map[qtype]
        except KeyError:
            raise ValueError('invalid query type: {}'.format(qtype))
        if qclass is not None:
            try:
                qclass = query_class_map[qclass]
            except KeyError:
                raise ValueError('invalid query class: {}'.format(qclass))

        fut = asyncio.Future(loop=self.loop)  # type: asyncio.Future
        cb = functools.partial(self._callback, fut)
        self._channel.query(host, qtype, cb, query_class=qclass)
        return fut

    def gethostbyname(self, host: str, family: socket.AddressFamily) -> asyncio.Future:
        fut = asyncio.Future(loop=self.loop)  # type: asyncio.Future
        cb = functools.partial(self._callback, fut)
        self._channel.gethostbyname(host, family, cb)
        return fut

    def gethostbyaddr(self, name: str) -> asyncio.Future:
        fut = asyncio.Future(loop=self.loop)  # type: asyncio.Future
        cb = functools.partial(self._callback, fut)
        self._channel.gethostbyaddr(name, cb)
        return fut

    def cancel(self) -> None:
        self._channel.cancel()

    def _sock_state_cb(self, fd: int, readable: bool, writable: bool) -> None:
        if readable or writable:
            if readable:
                self.loop.add_reader(fd, self._handle_event, fd, READ)
                self._read_fds.add(fd)
            if writable:
                self.loop.add_writer(fd, self._handle_event, fd, WRITE)
                self._write_fds.add(fd)
            if self._timer is None:
                self._timer = self.loop.call_later(1.0, self._timer_cb)
        else:
            # socket is now closed
            if fd in self._read_fds:
                self._read_fds.discard(fd)
                self.loop.remove_reader(fd)

            if fd in self._write_fds:
                self._write_fds.discard(fd)
                self.loop.remove_writer(fd)

            if not self._read_fds and not self._write_fds and self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _handle_event(self, fd: int, event: Any) -> None:
        read_fd = pycares.ARES_SOCKET_BAD
        write_fd = pycares.ARES_SOCKET_BAD
        if event == READ:
            read_fd = fd
        elif event == WRITE:
            write_fd = fd
        self._channel.process_fd(read_fd, write_fd)

    def _timer_cb(self) -> None:
        if self._read_fds or self._write_fds:
            self._channel.process_fd(pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD)
            self._timer = self.loop.call_later(1.0, self._timer_cb)
        else:
            self._timer = None
