"""
Compatibility layer for pycares 5.x API.

This module provides result types compatible with pycares 4.x API
to maintain backward compatibility with existing code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Union

import pycares


@dataclass(frozen=True, slots=True)
class AresQueryAResult:
    """A record result (compatible with pycares 4.x ares_query_a_result)."""

    host: str
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryAAAAResult:
    """AAAA record result (pycares 4.x compat)."""

    host: str
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryCNAMEResult:
    """CNAME record result (pycares 4.x compat)."""

    cname: str
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryMXResult:
    """MX record result (pycares 4.x compat)."""

    host: str
    priority: int
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryNSResult:
    """NS record result (pycares 4.x compat)."""

    host: str
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryTXTResult:
    """TXT record result (pycares 4.x compat)."""

    text: bytes
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQuerySOAResult:
    """SOA record result (pycares 4.x compat)."""

    nsname: str
    hostmaster: str
    serial: int
    refresh: int
    retry: int
    expires: int
    minttl: int
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQuerySRVResult:
    """SRV record result (pycares 4.x compat)."""

    host: str
    port: int
    priority: int
    weight: int
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryNAPTRResult:
    """NAPTR record result (pycares 4.x compat)."""

    order: int
    preference: int
    flags: bytes
    service: bytes
    regex: bytes
    replacement: str
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryCAAResult:
    """CAA record result (pycares 4.x compat)."""

    critical: int
    property: str
    value: bytes
    ttl: int


@dataclass(frozen=True, slots=True)
class AresQueryPTRResult:
    """PTR record result (pycares 4.x compat)."""

    name: str
    ttl: int
    aliases: list[str]


@dataclass(frozen=True, slots=True)
class AresHostResult:
    """Host result (compatible with pycares 4.x ares_host_result)."""

    name: str
    aliases: list[str]
    addresses: list[str]


# Type alias for a single converted record
ConvertedRecord = Union[
    AresQueryAResult,
    AresQueryAAAAResult,
    AresQueryCNAMEResult,
    AresQueryMXResult,
    AresQueryNSResult,
    AresQueryTXTResult,
    AresQuerySOAResult,
    AresQuerySRVResult,
    AresQueryNAPTRResult,
    AresQueryCAAResult,
    AresQueryPTRResult,
    pycares.DNSRecord,  # Unknown types returned as-is
]

# Type alias for query results
QueryResult = Union[
    list[AresQueryAResult],
    list[AresQueryAAAAResult],
    AresQueryCNAMEResult,
    list[AresQueryMXResult],
    list[AresQueryNSResult],
    list[AresQueryTXTResult],
    AresQuerySOAResult,
    list[AresQuerySRVResult],
    list[AresQueryNAPTRResult],
    list[AresQueryCAAResult],
    list[AresQueryPTRResult],
    list[ConvertedRecord],  # For ANY query type
]


def _convert_record(record: pycares.DNSRecord) -> ConvertedRecord:
    """Convert a single DNS record to pycares 4.x compatible format."""
    data = record.data
    ttl = record.ttl
    record_type = record.type

    if record_type == pycares.QUERY_TYPE_A:
        return AresQueryAResult(host=data.addr, ttl=ttl)
    elif record_type == pycares.QUERY_TYPE_AAAA:
        return AresQueryAAAAResult(host=data.addr, ttl=ttl)
    elif record_type == pycares.QUERY_TYPE_CNAME:
        return AresQueryCNAMEResult(cname=data.cname, ttl=ttl)
    elif record_type == pycares.QUERY_TYPE_MX:
        return AresQueryMXResult(
            host=data.exchange, priority=data.priority, ttl=ttl
        )
    elif record_type == pycares.QUERY_TYPE_NS:
        # pycares 5: nsdname -> host
        return AresQueryNSResult(host=data.nsdname, ttl=ttl)
    elif record_type == pycares.QUERY_TYPE_TXT:
        # pycares 5: data -> text
        return AresQueryTXTResult(text=data.data, ttl=ttl)
    elif record_type == pycares.QUERY_TYPE_SOA:
        # pycares 5 renames: mname->nsname, rname->hostmaster, etc.
        return AresQuerySOAResult(
            nsname=data.mname,
            hostmaster=data.rname,
            serial=data.serial,
            refresh=data.refresh,
            retry=data.retry,
            expires=data.expire,
            minttl=data.minimum,
            ttl=ttl,
        )
    elif record_type == pycares.QUERY_TYPE_SRV:
        # pycares 5: target -> host
        return AresQuerySRVResult(
            host=data.target,
            port=data.port,
            priority=data.priority,
            weight=data.weight,
            ttl=ttl,
        )
    elif record_type == pycares.QUERY_TYPE_NAPTR:
        # pycares 5: flags/service/regexp are strings, encode to bytes
        return AresQueryNAPTRResult(
            order=data.order,
            preference=data.preference,
            flags=data.flags.encode()
            if isinstance(data.flags, str)
            else data.flags,
            service=data.service.encode()
            if isinstance(data.service, str)
            else data.service,
            regex=data.regexp.encode()
            if isinstance(data.regexp, str)
            else data.regexp,
            replacement=data.replacement,
            ttl=ttl,
        )
    elif record_type == pycares.QUERY_TYPE_CAA:
        # pycares 5: tag -> property, value is str (encode to bytes for compat)
        return AresQueryCAAResult(
            critical=data.critical,
            property=data.tag,
            value=data.value.encode()
            if isinstance(data.value, str)
            else data.value,
            ttl=ttl,
        )
    elif record_type == pycares.QUERY_TYPE_PTR:
        # pycares 5: dname -> name, aliases not available in pycares 5
        return AresQueryPTRResult(name=data.dname, ttl=ttl, aliases=[])
    else:
        # Return raw record for unknown types
        return record


def convert_result(dns_result: pycares.DNSResult, qtype: int) -> QueryResult:
    """Convert pycares 5.x DNSResult to pycares 4.x compatible format."""
    # For ANY - convert all records and return mixed list
    if qtype == pycares.QUERY_TYPE_ANY:
        return [_convert_record(record) for record in dns_result.answer]

    results: list[Any] = []

    for record in dns_result.answer:
        record_type = record.type

        # Filter by query type since answer can contain other types
        # (e.g., CNAME records when querying for A/AAAA)
        if record_type != qtype:
            continue

        converted = _convert_record(record)

        # CNAME and SOA return single result, not list
        if record_type in (pycares.QUERY_TYPE_CNAME, pycares.QUERY_TYPE_SOA):
            return converted

        results.append(converted)

    return results
