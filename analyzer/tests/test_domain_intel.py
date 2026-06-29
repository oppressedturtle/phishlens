"""Tests for the Phase 1 domain-intelligence collectors.

All network access is faked, so these run offline and deterministically.
"""

from __future__ import annotations

import datetime as dt

from app.domain_intel import (
    AsnInfo,
    DnsRecords,
    DomainAge,
    DomainIntel,
    collect_dns_records,
    collect_domain_intel,
    domain_signals,
    lookup_asn,
    parse_cymru_as_name,
    parse_cymru_origin,
    parse_rdap_age,
    registrable_domain,
)


class FakeResolver:
    """Maps (qname, rdtype) -> answers; raises for keys flagged to fail."""

    def __init__(self, table: dict[tuple[str, str], list[str]], fail: set[tuple[str, str]] | None = None):
        self._table = table
        self._fail = fail or set()

    def resolve(self, qname: str, rdtype: str) -> list[str]:
        if (qname, rdtype) in self._fail:
            raise RuntimeError("simulated DNS failure")
        return self._table.get((qname, rdtype), [])


class FakeRdap:
    def __init__(self, payload: dict | None):
        self._payload = payload

    def fetch_domain(self, domain: str) -> dict | None:
        return self._payload


# --- registrable_domain -----------------------------------------------------


def test_registrable_domain_basic():
    assert registrable_domain("www.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"


def test_registrable_domain_multi_label_suffix():
    assert registrable_domain("login.foo.co.uk") == "foo.co.uk"
    assert registrable_domain("shop.example.com.au") == "example.com.au"


def test_registrable_domain_rejects_ip_and_short():
    assert registrable_domain("127.0.0.1") is None
    assert registrable_domain("localhost") is None
    assert registrable_domain("::1") is None


# --- DNS records ------------------------------------------------------------


def test_collect_dns_records_maps_types():
    resolver = FakeResolver(
        {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "MX"): ["mail.example.com"],
            ("example.com", "NS"): ["a.iana-servers.net"],
            ("example.com", "TXT"): ["v=spf1 -all"],
        }
    )
    records = collect_dns_records("example.com", resolver)
    assert records.a == ["93.184.216.34"]
    assert records.mx == ["mail.example.com"]
    assert records.ns == ["a.iana-servers.net"]
    assert records.txt == ["v=spf1 -all"]
    assert records.aaaa == []
    assert records.cname is None


def test_collect_dns_records_degrades_on_failure():
    resolver = FakeResolver({("x.test", "A"): ["1.2.3.4"]}, fail={("x.test", "MX")})
    records = collect_dns_records("x.test", resolver)
    assert records.a == ["1.2.3.4"]
    assert records.mx == []  # failure degraded to empty, didn't raise


def test_collect_dns_records_cname_takes_first():
    resolver = FakeResolver({("a.test", "CNAME"): ["target.test", "other.test"]})
    assert collect_dns_records("a.test", resolver).cname == "target.test"


# --- RDAP age ---------------------------------------------------------------


def test_parse_rdap_age_computes_days():
    rdap = {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}
    age = parse_rdap_age(rdap, now=dt.date(2020, 1, 31))
    assert age.registered_on == dt.date(2020, 1, 1)
    assert age.age_days == 30


def test_parse_rdap_age_extracts_registrar():
    rdap = {
        "events": [{"eventAction": "registration", "eventDate": "2021-06-15"}],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar LLC"]]],
            }
        ],
    }
    age = parse_rdap_age(rdap, now=dt.date(2021, 6, 25))
    assert age.age_days == 10
    assert age.registrar == "Example Registrar LLC"


def test_parse_rdap_age_handles_missing():
    assert parse_rdap_age(None).age_days is None
    assert parse_rdap_age({"events": []}).registered_on is None


def test_parse_rdap_age_never_negative():
    rdap = {"events": [{"eventAction": "registration", "eventDate": "2099-01-01T00:00:00Z"}]}
    assert parse_rdap_age(rdap, now=dt.date(2020, 1, 1)).age_days == 0


# --- Cymru ASN --------------------------------------------------------------


def test_parse_cymru_origin():
    info = parse_cymru_origin("13335 | 1.1.1.0/24 | US | arin | 2010-07-14")
    assert info.asn == 13335
    assert info.prefix == "1.1.1.0/24"
    assert info.country == "US"
    assert info.registry == "arin"


def test_parse_cymru_as_name():
    assert parse_cymru_as_name("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US") == "CLOUDFLARENET, US"


def test_lookup_asn_end_to_end():
    resolver = FakeResolver(
        {
            ("1.1.1.1.origin.asn.cymru.com", "TXT"): ["13335 | 1.1.1.0/24 | US | arin | 2010-07-14"],
            ("AS13335.asn.cymru.com", "TXT"): ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"],
        }
    )
    info = lookup_asn("1.1.1.1", resolver)
    assert info.asn == 13335
    assert info.as_name == "CLOUDFLARENET, US"
    assert info.country == "US"


def test_lookup_asn_rejects_non_ipv4():
    assert lookup_asn("not-an-ip", FakeResolver({})).asn is None


# --- signals ----------------------------------------------------------------


def _intel(age_days: int | None, *, mx: list[str] | None = None, asn: AsnInfo | None = None) -> DomainIntel:
    return DomainIntel(
        host="example.com",
        registrable="example.com",
        age=DomainAge(registered_on=None, age_days=age_days),
        dns=DnsRecords(a=["1.2.3.4"], mx=mx or []),
        asn=asn or AsnInfo(asn=None),
    )


def test_domain_signals_flags_young_domain():
    ids = {s["id"]: s for s in domain_signals(_intel(5))}
    assert ids["young_domain"]["weight"] == "malicious"
    assert "no_mx" in ids  # no MX records present


def test_domain_signals_established_domain_is_benign():
    sigs = {s["id"]: s for s in domain_signals(_intel(800, mx=["mail.example.com"]))}
    assert sigs["established_domain"]["weight"] == "benign"
    assert "no_mx" not in sigs


def test_domain_signals_unknown_age():
    ids = {s["id"] for s in domain_signals(_intel(None, mx=["mail.example.com"]))}
    assert "domain_age_unknown" in ids


def test_domain_signals_includes_hosting():
    asn = AsnInfo(asn=13335, as_name="CLOUDFLARENET, US", country="US")
    sigs = {s["id"]: s for s in domain_signals(_intel(800, mx=["m"], asn=asn))}
    assert "hosting_asn" in sigs
    assert "CLOUDFLARENET" in sigs["hosting_asn"]["detail"]


# --- orchestrator -----------------------------------------------------------


def test_collect_domain_intel_wires_collectors():
    resolver = FakeResolver(
        {
            ("example.com", "A"): ["93.184.216.34"],
            ("example.com", "MX"): ["mail.example.com"],
            ("34.216.184.93.origin.asn.cymru.com", "TXT"): ["15133 | 93.184.216.0/24 | US | arin | 2008"],
            ("AS15133.asn.cymru.com", "TXT"): ["15133 | US | arin | 2008 | EDGECAST, US"],
        }
    )
    rdap = FakeRdap({"events": [{"eventAction": "registration", "eventDate": "1995-08-13T00:00:00Z"}]})
    intel = collect_domain_intel("example.com", resolver=resolver, rdap=rdap, now=dt.date(2025, 1, 1))
    assert intel.registrable == "example.com"
    assert intel.dns.a == ["93.184.216.34"]
    assert intel.age.registered_on == dt.date(1995, 8, 13)
    assert intel.asn.as_name == "EDGECAST, US"
