import functools

try:
    import asyncio
except ImportError:
    import trollius as asyncio
import pycares

from . import error


__version__ = '1.1.1'

__all__ = ('DNSResolver', 'error')


READ = 1
WRITE = 2

query_type_map = {'A'     : pycares.QUERY_TYPE_A,
                  'AAAA'  : pycares.QUERY_TYPE_AAAA,
                  'CNAME' : pycares.QUERY_TYPE_CNAME,
                  'MX'    : pycares.QUERY_TYPE_MX,
                  'NAPTR' : pycares.QUERY_TYPE_NAPTR,
                  'NS'    : pycares.QUERY_TYPE_NS,
                  'PTR'   : pycares.QUERY_TYPE_PTR,
                  'SOA'   : pycares.QUERY_TYPE_SOA,
                  'SRV'   : pycares.QUERY_TYPE_SRV,
                  'TXT'   : pycares.QUERY_TYPE_TXT
        }


class DNSResolver(object):

    def __init__(self, nameservers=None, loop=None, **kwargs):
        self.loop = loop or asyncio.get_event_loop()
        assert self.loop is not None
        kwargs.pop('sock_state_cb', None)
        self._channel = pycares.Channel(sock_state_cb=self._sock_state_cb, **kwargs)
        if nameservers:
            self.nameservers = nameservers
        self._read_fds = set()
        self._write_fds = set()
        self._timer = None

    @property
    def nameservers(self):
        return self._channel.servers

    @nameservers.setter
    def nameservers(self, value):
        self._channel.servers = value

    @staticmethod
    def _callback(fut, result, errorno):
        if fut.cancelled():
            return
        if errorno is not None:
            fut.set_exception(error.DNSError(errorno, pycares.errno.strerror(errorno)))
        else:
            fut.set_result(result)

    def query(self, host, qtype):
        try:
            qtype = query_type_map[qtype]
        except KeyError:
            raise ValueError('invalid query type: {}'.format(qtype))
        fut = asyncio.Future(loop=self.loop)
        cb = functools.partial(self._callback, fut)
        self._channel.query(host, qtype, cb)
        return fut

    def gethostbyname(self, host, family):
        fut = asyncio.Future(loop=self.loop)
        cb = functools.partial(self._callback, fut)
        self._channel.gethostbyname(host, family, cb)
        return fut

    def cancel(self):
        self._channel.cancel()

    def _sock_state_cb(self, fd, readable, writable):
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

    def _handle_event(self, fd, event):
        read_fd = pycares.ARES_SOCKET_BAD
        write_fd = pycares.ARES_SOCKET_BAD
        if event == READ:
            read_fd = fd
        elif event == WRITE:
            write_fd = fd
        self._channel.process_fd(read_fd, write_fd)

    def _timer_cb(self):
        if self._read_fds or self._write_fds:
            self._channel.process_fd(pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD)
            self._timer = self.loop.call_later(1.0, self._timer_cb)
        else:
            self._timer = None

    def __del__(self):
        self._channel.destroy()

