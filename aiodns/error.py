from pycares.errno import (
    ARES_SUCCESS as ARES_SUCCESS,
    ARES_ENODATA as ARES_ENODATA,
    ARES_EFORMERR as ARES_EFORMERR,
    ARES_ESERVFAIL as ARES_ESERVFAIL,
    ARES_ENOTFOUND as ARES_ENOTFOUND,
    ARES_ENOTIMP as ARES_ENOTIMP,
    ARES_EREFUSED as ARES_EREFUSED,
    ARES_EBADQUERY as ARES_EBADQUERY,
    ARES_EBADNAME as ARES_EBADNAME,
    ARES_EBADFAMILY as ARES_EBADFAMILY,
    ARES_EBADRESP as ARES_EBADRESP,
    ARES_ECONNREFUSED as ARES_ECONNREFUSED,
    ARES_ETIMEOUT as ARES_ETIMEOUT,
    ARES_EOF as ARES_EOF,
    ARES_EFILE as ARES_EFILE,
    ARES_ENOMEM as ARES_ENOMEM,
    ARES_EDESTRUCTION as ARES_EDESTRUCTION,
    ARES_EBADSTR as ARES_EBADSTR,
    ARES_EBADFLAGS as ARES_EBADFLAGS,
    ARES_ENONAME as ARES_ENONAME,
    ARES_EBADHINTS as ARES_EBADHINTS,
    ARES_ENOTINITIALIZED as ARES_ENOTINITIALIZED,
    ARES_ELOADIPHLPAPI as ARES_ELOADIPHLPAPI,
    ARES_EADDRGETNETWORKPARAMS as ARES_EADDRGETNETWORKPARAMS,
    ARES_ECANCELLED as ARES_ECANCELLED,
    ARES_ESERVICE as ARES_ESERVICE
)


class DNSError(Exception):
    pass
