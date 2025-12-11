"""Tests for aiodns.compat module."""

from __future__ import annotations

import unittest.mock
from dataclasses import fields
from typing import Any

import pycares
import pytest

from aiodns.compat import (
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
    _convert_record,
    convert_result,
)

# Expected field names from pycares 4.x (in order)
# These were extracted from pycares 4.11.0 __slots__
PYCARES4_SLOTS = {
    'ares_query_a_result': ('host', 'ttl'),
    'ares_query_aaaa_result': ('host', 'ttl'),
    'ares_query_cname_result': ('cname', 'ttl'),
    'ares_query_mx_result': ('host', 'priority', 'ttl'),
    'ares_query_ns_result': ('host', 'ttl'),
    'ares_query_txt_result': ('text', 'ttl'),
    'ares_query_soa_result': (
        'nsname',
        'hostmaster',
        'serial',
        'refresh',
        'retry',
        'expires',
        'minttl',
        'ttl',
    ),
    'ares_query_srv_result': ('host', 'port', 'priority', 'weight', 'ttl'),
    'ares_query_naptr_result': (
        'order',
        'preference',
        'flags',
        'service',
        'regex',
        'replacement',
        'ttl',
    ),
    'ares_query_caa_result': ('critical', 'property', 'value', 'ttl'),
    'ares_query_ptr_result': ('name', 'ttl', 'aliases'),
    'ares_host_result': ('name', 'aliases', 'addresses'),
}

# Map pycares 4 type names to our compat types
COMPAT_TYPE_MAP = {
    'ares_query_a_result': AresQueryAResult,
    'ares_query_aaaa_result': AresQueryAAAAResult,
    'ares_query_cname_result': AresQueryCNAMEResult,
    'ares_query_mx_result': AresQueryMXResult,
    'ares_query_ns_result': AresQueryNSResult,
    'ares_query_txt_result': AresQueryTXTResult,
    'ares_query_soa_result': AresQuerySOAResult,
    'ares_query_srv_result': AresQuerySRVResult,
    'ares_query_naptr_result': AresQueryNAPTRResult,
    'ares_query_caa_result': AresQueryCAAResult,
    'ares_query_ptr_result': AresQueryPTRResult,
    'ares_host_result': AresHostResult,
}


@pytest.mark.parametrize(
    'pycares4_name,expected_slots',
    list(PYCARES4_SLOTS.items()),
    ids=list(PYCARES4_SLOTS.keys()),
)
def test_compat_type_matches_pycares4_slots(
    pycares4_name: str, expected_slots: tuple[str, ...]
) -> None:
    """Verify compat types have same fields as pycares 4.x types."""
    compat_type = COMPAT_TYPE_MAP[pycares4_name]
    actual_fields = tuple(f.name for f in fields(compat_type))
    assert actual_fields == expected_slots, (
        f'{compat_type.__name__} fields {actual_fields} '
        f'do not match pycares 4 {pycares4_name} slots {expected_slots}'
    )


def make_mock_record(record_type: int, data: Any, ttl: int = 300) -> Any:
    """Create a mock DNS record."""
    record = unittest.mock.MagicMock()
    record.type = record_type
    record.data = data
    record.ttl = ttl
    return record


def make_mock_dns_result(records: list[Any]) -> Any:
    """Create a mock DNSResult."""
    result = unittest.mock.MagicMock(spec=pycares.DNSResult)
    result.answer = records
    return result


class TestResultDataclasses:
    """Test that result dataclasses have correct structure."""

    def test_ares_query_a_result(self) -> None:
        result = AresQueryAResult(host='192.168.1.1', ttl=300)
        assert result.host == '192.168.1.1'
        assert result.ttl == 300

    def test_ares_query_aaaa_result(self) -> None:
        result = AresQueryAAAAResult(host='::1', ttl=300)
        assert result.host == '::1'
        assert result.ttl == 300

    def test_ares_query_cname_result(self) -> None:
        result = AresQueryCNAMEResult(cname='www.example.com', ttl=300)
        assert result.cname == 'www.example.com'
        assert result.ttl == 300

    def test_ares_query_mx_result(self) -> None:
        result = AresQueryMXResult(
            host='mail.example.com', priority=10, ttl=300
        )
        assert result.host == 'mail.example.com'
        assert result.priority == 10
        assert result.ttl == 300

    def test_ares_query_ns_result(self) -> None:
        result = AresQueryNSResult(host='ns1.example.com', ttl=300)
        assert result.host == 'ns1.example.com'
        assert result.ttl == 300

    def test_ares_query_txt_result(self) -> None:
        result = AresQueryTXTResult(text=b'v=spf1 -all', ttl=300)
        assert result.text == b'v=spf1 -all'
        assert result.ttl == 300

    def test_ares_query_soa_result(self) -> None:
        result = AresQuerySOAResult(
            nsname='ns1.example.com',
            hostmaster='admin.example.com',
            serial=2021010101,
            refresh=3600,
            retry=600,
            expires=604800,
            minttl=86400,
            ttl=300,
        )
        assert result.nsname == 'ns1.example.com'
        assert result.hostmaster == 'admin.example.com'
        assert result.serial == 2021010101
        assert result.refresh == 3600
        assert result.retry == 600
        assert result.expires == 604800
        assert result.minttl == 86400
        assert result.ttl == 300

    def test_ares_query_srv_result(self) -> None:
        result = AresQuerySRVResult(
            host='sip.example.com', port=5060, priority=10, weight=50, ttl=300
        )
        assert result.host == 'sip.example.com'
        assert result.port == 5060
        assert result.priority == 10
        assert result.weight == 50
        assert result.ttl == 300

    def test_ares_query_naptr_result(self) -> None:
        result = AresQueryNAPTRResult(
            order=100,
            preference=10,
            flags=b'S',
            service=b'SIP+D2U',
            regex=b'',
            replacement='_sip._udp.example.com',
            ttl=300,
        )
        assert result.order == 100
        assert result.preference == 10
        assert result.flags == b'S'
        assert result.service == b'SIP+D2U'
        assert result.regex == b''
        assert result.replacement == '_sip._udp.example.com'
        assert result.ttl == 300

    def test_ares_query_caa_result(self) -> None:
        result = AresQueryCAAResult(
            critical=0, property='issue', value=b'letsencrypt.org', ttl=300
        )
        assert result.critical == 0
        assert result.property == 'issue'
        assert result.value == b'letsencrypt.org'
        assert result.ttl == 300

    def test_ares_query_ptr_result(self) -> None:
        result = AresQueryPTRResult(
            name='host.example.com', ttl=300, aliases=['alias.example.com']
        )
        assert result.name == 'host.example.com'
        assert result.ttl == 300
        assert result.aliases == ['alias.example.com']

    def test_ares_host_result(self) -> None:
        result = AresHostResult(
            name='example.com',
            aliases=['www.example.com'],
            addresses=['192.168.1.1', '192.168.1.2'],
        )
        assert result.name == 'example.com'
        assert result.aliases == ['www.example.com']
        assert result.addresses == ['192.168.1.1', '192.168.1.2']

    def test_dataclasses_are_frozen(self) -> None:
        """Test that dataclasses are immutable."""
        result = AresQueryAResult(host='192.168.1.1', ttl=300)
        with pytest.raises(AttributeError):
            result.host = '10.0.0.1'  # type: ignore[misc]


class TestConvertRecord:
    """Test _convert_record function."""

    def test_convert_a_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.addr = '192.168.1.1'
        record = make_mock_record(pycares.QUERY_TYPE_A, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryAResult)
        assert result.host == '192.168.1.1'
        assert result.ttl == 300

    def test_convert_aaaa_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.addr = '2001:db8::1'
        record = make_mock_record(pycares.QUERY_TYPE_AAAA, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryAAAAResult)
        assert result.host == '2001:db8::1'
        assert result.ttl == 300

    def test_convert_cname_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.cname = 'www.example.com'
        record = make_mock_record(pycares.QUERY_TYPE_CNAME, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryCNAMEResult)
        assert result.cname == 'www.example.com'
        assert result.ttl == 300

    def test_convert_mx_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.exchange = 'mail.example.com'
        data.priority = 10
        record = make_mock_record(pycares.QUERY_TYPE_MX, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryMXResult)
        assert result.host == 'mail.example.com'
        assert result.priority == 10
        assert result.ttl == 300

    def test_convert_ns_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.nsdname = 'ns1.example.com'
        record = make_mock_record(pycares.QUERY_TYPE_NS, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryNSResult)
        assert result.host == 'ns1.example.com'
        assert result.ttl == 300

    def test_convert_txt_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.data = b'v=spf1 -all'
        record = make_mock_record(pycares.QUERY_TYPE_TXT, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryTXTResult)
        assert result.text == b'v=spf1 -all'
        assert result.ttl == 300

    def test_convert_soa_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.mname = 'ns1.example.com'
        data.rname = 'admin.example.com'
        data.serial = 2021010101
        data.refresh = 3600
        data.retry = 600
        data.expire = 604800
        data.minimum = 86400
        record = make_mock_record(pycares.QUERY_TYPE_SOA, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQuerySOAResult)
        assert result.nsname == 'ns1.example.com'
        assert result.hostmaster == 'admin.example.com'
        assert result.serial == 2021010101
        assert result.refresh == 3600
        assert result.retry == 600
        assert result.expires == 604800
        assert result.minttl == 86400
        assert result.ttl == 300

    def test_convert_srv_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.target = 'sip.example.com'
        data.port = 5060
        data.priority = 10
        data.weight = 50
        record = make_mock_record(pycares.QUERY_TYPE_SRV, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQuerySRVResult)
        assert result.host == 'sip.example.com'
        assert result.port == 5060
        assert result.priority == 10
        assert result.weight == 50
        assert result.ttl == 300

    def test_convert_naptr_record_with_string_fields(self) -> None:
        data = unittest.mock.MagicMock()
        data.order = 100
        data.preference = 10
        data.flags = 'S'
        data.service = 'SIP+D2U'
        data.regexp = '!^.*$!sip:info@example.com!'
        data.replacement = '_sip._udp.example.com'
        record = make_mock_record(pycares.QUERY_TYPE_NAPTR, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryNAPTRResult)
        assert result.order == 100
        assert result.preference == 10
        assert result.flags == b'S'
        assert result.service == b'SIP+D2U'
        assert result.regex == b'!^.*$!sip:info@example.com!'
        assert result.replacement == '_sip._udp.example.com'
        assert result.ttl == 300

    def test_convert_caa_record_with_string_value(self) -> None:
        data = unittest.mock.MagicMock()
        data.critical = 0
        data.tag = 'issue'
        data.value = 'letsencrypt.org'
        record = make_mock_record(pycares.QUERY_TYPE_CAA, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryCAAResult)
        assert result.critical == 0
        assert result.property == 'issue'
        assert result.value == b'letsencrypt.org'
        assert result.ttl == 300

    def test_convert_ptr_record(self) -> None:
        data = unittest.mock.MagicMock()
        data.dname = 'host.example.com'
        record = make_mock_record(pycares.QUERY_TYPE_PTR, data, ttl=300)

        result = _convert_record(record)

        assert isinstance(result, AresQueryPTRResult)
        assert result.name == 'host.example.com'
        assert result.ttl == 300
        assert result.aliases == []  # pycares 5 doesn't provide aliases

    def test_convert_unknown_record_type(self) -> None:
        data = unittest.mock.MagicMock()
        record = make_mock_record(9999, data, ttl=300)

        result = _convert_record(record)

        # Unknown types return the raw record
        assert result is record


class TestConvertResult:
    """Test convert_result function."""

    def test_convert_a_query_result(self) -> None:
        data1 = unittest.mock.MagicMock()
        data1.addr = '192.168.1.1'
        data2 = unittest.mock.MagicMock()
        data2.addr = '192.168.1.2'

        records = [
            make_mock_record(pycares.QUERY_TYPE_A, data1, ttl=300),
            make_mock_record(pycares.QUERY_TYPE_A, data2, ttl=300),
        ]
        dns_result = make_mock_dns_result(records)

        result = convert_result(dns_result, pycares.QUERY_TYPE_A)

        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(r, AresQueryAResult) for r in result)
        assert result[0].host == '192.168.1.1'
        assert result[1].host == '192.168.1.2'

    def test_convert_cname_query_returns_single_result(self) -> None:
        data = unittest.mock.MagicMock()
        data.cname = 'www.example.com'

        records = [make_mock_record(pycares.QUERY_TYPE_CNAME, data, ttl=300)]
        dns_result = make_mock_dns_result(records)

        result = convert_result(dns_result, pycares.QUERY_TYPE_CNAME)

        assert isinstance(result, AresQueryCNAMEResult)
        assert result.cname == 'www.example.com'

    def test_convert_soa_query_returns_single_result(self) -> None:
        data = unittest.mock.MagicMock()
        data.mname = 'ns1.example.com'
        data.rname = 'admin.example.com'
        data.serial = 2021010101
        data.refresh = 3600
        data.retry = 600
        data.expire = 604800
        data.minimum = 86400

        records = [make_mock_record(pycares.QUERY_TYPE_SOA, data, ttl=300)]
        dns_result = make_mock_dns_result(records)

        result = convert_result(dns_result, pycares.QUERY_TYPE_SOA)

        assert isinstance(result, AresQuerySOAResult)
        assert result.nsname == 'ns1.example.com'

    def test_convert_filters_by_query_type(self) -> None:
        """Test that convert_result filters out non-matching record types."""
        a_data = unittest.mock.MagicMock()
        a_data.addr = '192.168.1.1'
        cname_data = unittest.mock.MagicMock()
        cname_data.cname = 'www.example.com'

        records = [
            make_mock_record(pycares.QUERY_TYPE_CNAME, cname_data, ttl=300),
            make_mock_record(pycares.QUERY_TYPE_A, a_data, ttl=300),
        ]
        dns_result = make_mock_dns_result(records)

        result = convert_result(dns_result, pycares.QUERY_TYPE_A)

        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], AresQueryAResult)
        assert result[0].host == '192.168.1.1'

    def test_convert_any_query_returns_all_records(self) -> None:
        """Test that ANY query converts all records."""
        a_data = unittest.mock.MagicMock()
        a_data.addr = '192.168.1.1'
        mx_data = unittest.mock.MagicMock()
        mx_data.exchange = 'mail.example.com'
        mx_data.priority = 10

        records = [
            make_mock_record(pycares.QUERY_TYPE_A, a_data, ttl=300),
            make_mock_record(pycares.QUERY_TYPE_MX, mx_data, ttl=300),
        ]
        dns_result = make_mock_dns_result(records)

        result = convert_result(dns_result, pycares.QUERY_TYPE_ANY)

        assert isinstance(result, list)
        assert len(result) == 2
        assert isinstance(result[0], AresQueryAResult)
        assert isinstance(result[1], AresQueryMXResult)

    def test_convert_empty_result(self) -> None:
        """Test conversion of empty DNS result."""
        dns_result = make_mock_dns_result([])

        result = convert_result(dns_result, pycares.QUERY_TYPE_A)

        assert isinstance(result, list)
        assert len(result) == 0
