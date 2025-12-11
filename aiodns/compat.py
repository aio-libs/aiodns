"""
Compatibility layer for pycares 5.x API.

This module provides result types compatible with pycares 4.x API
to maintain backward compatibility with existing code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union, cast

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
    ttl = record.ttl
    record_type = record.type

    if record_type == pycares.QUERY_TYPE_A:
        a_data = cast(pycares.ARecordData, record.data)
        return AresQueryAResult(host=a_data.addr, ttl=ttl)
    if record_type == pycares.QUERY_TYPE_AAAA:
        aaaa_data = cast(pycares.AAAARecordData, record.data)
        return AresQueryAAAAResult(host=aaaa_data.addr, ttl=ttl)
    if record_type == pycares.QUERY_TYPE_CNAME:
        cname_data = cast(pycares.CNAMERecordData, record.data)
        return AresQueryCNAMEResult(cname=cname_data.cname, ttl=ttl)
    if record_type == pycares.QUERY_TYPE_MX:
        mx_data = cast(pycares.MXRecordData, record.data)
        return AresQueryMXResult(
            host=mx_data.exchange, priority=mx_data.priority, ttl=ttl
        )
    if record_type == pycares.QUERY_TYPE_NS:
        ns_data = cast(pycares.NSRecordData, record.data)
        return AresQueryNSResult(host=ns_data.nsdname, ttl=ttl)
    if record_type == pycares.QUERY_TYPE_TXT:
        txt_data = cast(pycares.TXTRecordData, record.data)
        return AresQueryTXTResult(text=txt_data.data, ttl=ttl)
    if record_type == pycares.QUERY_TYPE_SOA:
        soa_data = cast(pycares.SOARecordData, record.data)
        return AresQuerySOAResult(
            nsname=soa_data.mname,
            hostmaster=soa_data.rname,
            serial=soa_data.serial,
            refresh=soa_data.refresh,
            retry=soa_data.retry,
            expires=soa_data.expire,
            minttl=soa_data.minimum,
            ttl=ttl,
        )
    if record_type == pycares.QUERY_TYPE_SRV:
        srv_data = cast(pycares.SRVRecordData, record.data)
        return AresQuerySRVResult(
            host=srv_data.target,
            port=srv_data.port,
            priority=srv_data.priority,
            weight=srv_data.weight,
            ttl=ttl,
        )
    if record_type == pycares.QUERY_TYPE_NAPTR:
        naptr_data = cast(pycares.NAPTRRecordData, record.data)
        return AresQueryNAPTRResult(
            order=naptr_data.order,
            preference=naptr_data.preference,
            flags=naptr_data.flags.encode(),
            service=naptr_data.service.encode(),
            regex=naptr_data.regexp.encode(),
            replacement=naptr_data.replacement,
            ttl=ttl,
        )
    if record_type == pycares.QUERY_TYPE_CAA:
        caa_data = cast(pycares.CAARecordData, record.data)
        return AresQueryCAAResult(
            critical=caa_data.critical,
            property=caa_data.tag,
            value=caa_data.value.encode(),
            ttl=ttl,
        )
    if record_type == pycares.QUERY_TYPE_PTR:
        ptr_data = cast(pycares.PTRRecordData, record.data)
        return AresQueryPTRResult(name=ptr_data.dname, ttl=ttl, aliases=[])
    # Return raw record for unknown types
    return record


def convert_result(dns_result: pycares.DNSResult, qtype: int) -> QueryResult:
    """Convert pycares 5.x DNSResult to pycares 4.x compatible format."""
    # For ANY - convert all records and return mixed list
    if qtype == pycares.QUERY_TYPE_ANY:
        return [_convert_record(record) for record in dns_result.answer]

    results: list[ConvertedRecord] = []

    for record in dns_result.answer:
        record_type = record.type

        # Filter by query type since answer can contain other types
        # (e.g., CNAME records when querying for A/AAAA)
        if record_type != qtype:
            continue

        converted = _convert_record(record)

        # CNAME and SOA return single result, not list
        if record_type in (pycares.QUERY_TYPE_CNAME, pycares.QUERY_TYPE_SOA):
            return cast(QueryResult, converted)

        results.append(converted)

    return results
