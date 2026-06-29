"""Domain intelligence collectors (Phase 1 item 2).

Given a submitted URL's host, gather three classic phishing signals:

- **Domain age** via RDAP (the modern, JSON successor to WHOIS). Freshly
  registered domains are a strong phishing indicator — most malicious domains are
  used within days of registration.
- **DNS records** (A / AAAA / MX / NS / TXT / CNAME). A domain with no MX, or one
  whose nameservers/TXT look thrown-together, is suspicious.
- **ASN / hosting** via Team Cymru's DNS-based origin lookup — which network
  actually hosts the resolved IP (useful context + bulletproof-host flagging later).

Network access is abstracted behind small Protocols (:class:`Resolver`,
:class:`RdapClient`) so the parsing/scoring logic is pure and unit-testable
without touching the network. All real network egress for an *IP* must still pass
through :mod:`app.url_guard` before connecting; this module only resolves a
hostname's metadata (RDAP servers and Cymru are fixed, trusted endpoints).
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Protocol

# ---------------------------------------------------------------------------
# Registrable-domain extraction
# ---------------------------------------------------------------------------

# A small set of common multi-label public suffixes. This is NOT the full Public
# Suffix List (that lands as a vendored dataset later); it covers the frequent
# ccTLD second levels so "foo.co.uk" yields "foo.co.uk", not "co.uk".
_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "com.au", "net.au", "org.au", "gov.au", "edu.au",
        "co.nz", "co.za", "co.jp", "or.jp", "ne.jp",
        "com.br", "com.cn", "com.mx", "com.tr", "com.sg",
    }
)


def registrable_domain(host: str) -> str | None:
    """Best-effort registrable ("eTLD+1") domain for a hostname.

    Returns ``None`` for IP literals or hosts with too few labels. Uses the small
    multi-label suffix set above, otherwise falls back to the last two labels.
    """
    host = host.strip().rstrip(".").lower()
    if not host or _looks_like_ip(host):
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+", host)) or ":" in host


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DnsRecords:
    """Resolved DNS records for a host (empty lists when absent)."""

    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    cname: str | None = None


@dataclass(frozen=True)
class DomainAge:
    """Registration date + computed age for a registrable domain."""

    registered_on: dt.date | None
    age_days: int | None
    registrar: str | None = None


@dataclass(frozen=True)
class AsnInfo:
    """Autonomous-system / hosting context for an IP."""

    asn: int | None
    prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    as_name: str | None = None


# ---------------------------------------------------------------------------
# Network abstractions (injectable for tests)
# ---------------------------------------------------------------------------


class Resolver(Protocol):
    """Resolve a DNS record type to a list of string answers."""

    def resolve(self, qname: str, rdtype: str) -> list[str]: ...


class RdapClient(Protocol):
    """Fetch an RDAP domain object as a parsed JSON dict, or None if unavailable."""

    def fetch_domain(self, domain: str) -> dict | None: ...


# ---------------------------------------------------------------------------
# DNS collection
# ---------------------------------------------------------------------------

_DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def collect_dns_records(host: str, resolver: Resolver) -> DnsRecords:
    """Query the common record types for ``host`` via ``resolver``.

    A failed lookup for one type degrades to an empty result for that type rather
    than aborting the whole collection.
    """
    answers: dict[str, list[str]] = {}
    for rdtype in _DNS_TYPES:
        try:
            answers[rdtype] = resolver.resolve(host, rdtype)
        except Exception:  # noqa: BLE001 — any resolver error → "no records"
            answers[rdtype] = []

    cname_list = answers.get("CNAME") or []
    return DnsRecords(
        a=answers.get("A", []),
        aaaa=answers.get("AAAA", []),
        mx=answers.get("MX", []),
        ns=answers.get("NS", []),
        txt=answers.get("TXT", []),
        cname=cname_list[0] if cname_list else None,
    )


# ---------------------------------------------------------------------------
# RDAP domain-age parsing
# ---------------------------------------------------------------------------


def _parse_rdap_date(value: str) -> dt.date | None:
    """Parse an RDAP ISO-8601 ``eventDate`` (e.g. ``2021-04-05T12:00:00Z``)."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(text).date()
    except ValueError:
        # Some registries emit a bare date.
        try:
            return dt.date.fromisoformat(text[:10])
        except ValueError:
            return None


def parse_rdap_age(rdap: dict | None, *, now: dt.date | None = None) -> DomainAge:
    """Extract the registration date + age (days) from an RDAP domain object."""
    today = now or dt.datetime.now(dt.UTC).date()
    if not rdap:
        return DomainAge(registered_on=None, age_days=None)

    registered_on: dt.date | None = None
    for event in rdap.get("events", []) or []:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if isinstance(raw, str):
                registered_on = _parse_rdap_date(raw)
            break

    registrar = _rdap_registrar(rdap)

    if registered_on is None:
        return DomainAge(registered_on=None, age_days=None, registrar=registrar)

    age_days = max(0, (today - registered_on).days)
    return DomainAge(registered_on=registered_on, age_days=age_days, registrar=registrar)


def _rdap_registrar(rdap: dict) -> str | None:
    """Pull the registrar name from RDAP entities, if present."""
    for entity in rdap.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            name = _vcard_fn(vcard)
            if name:
                return name
    return None


def _vcard_fn(vcard: object) -> str | None:
    """Extract the ``fn`` (formatted name) value from a jCard array."""
    if not isinstance(vcard, list) or len(vcard) != 2:
        return None
    props = vcard[1]
    if not isinstance(props, list):
        return None
    for prop in props:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            value = prop[3]
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


# ---------------------------------------------------------------------------
# ASN / hosting (Team Cymru DNS format)
# ---------------------------------------------------------------------------


def parse_cymru_origin(txt: str) -> AsnInfo:
    """Parse a Team Cymru origin TXT record.

    Format: ``"AS | BGP Prefix | CC | Registry | Allocated"`` e.g.
    ``"13335 | 1.1.1.0/24 | US | arin | 2010-07-14"``. The first field can be
    multiple ASNs separated by spaces; we take the first.
    """
    fields = [f.strip() for f in txt.strip().strip('"').split("|")]
    asn: int | None = None
    if fields and fields[0]:
        first_asn = fields[0].split()[0] if fields[0].split() else ""
        if first_asn.isdigit():
            asn = int(first_asn)
    return AsnInfo(
        asn=asn,
        prefix=fields[1] if len(fields) > 1 and fields[1] else None,
        country=fields[2] if len(fields) > 2 and fields[2] else None,
        registry=fields[3] if len(fields) > 3 and fields[3] else None,
    )


def parse_cymru_as_name(txt: str) -> str | None:
    """Parse a Team Cymru AS-name TXT record.

    Format: ``"AS | CC | Registry | Allocated | AS Name"`` e.g.
    ``"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"``.
    """
    fields = [f.strip() for f in txt.strip().strip('"').split("|")]
    if len(fields) >= 5 and fields[4]:
        return fields[4]
    return None


def lookup_asn(ip: str, resolver: Resolver) -> AsnInfo:
    """Resolve the ASN/hosting info for an IPv4 address via Cymru DNS."""
    octets = ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return AsnInfo(asn=None)

    reversed_ip = ".".join(reversed(octets))
    try:
        origin_txt = resolver.resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
    except Exception:  # noqa: BLE001
        return AsnInfo(asn=None)
    if not origin_txt:
        return AsnInfo(asn=None)

    info = parse_cymru_origin(origin_txt[0])
    if info.asn is None:
        return info

    as_name: str | None = None
    try:
        name_txt = resolver.resolve(f"AS{info.asn}.asn.cymru.com", "TXT")
        if name_txt:
            as_name = parse_cymru_as_name(name_txt[0])
    except Exception:  # noqa: BLE001
        as_name = None

    return AsnInfo(
        asn=info.asn,
        prefix=info.prefix,
        country=info.country,
        registry=info.registry,
        as_name=as_name,
    )


# ---------------------------------------------------------------------------
# Signal synthesis
# ---------------------------------------------------------------------------

# A domain younger than this (days) is a strong phishing indicator.
YOUNG_DOMAIN_DAYS = 30
# Younger than this is worth a softer note.
NEW_DOMAIN_DAYS = 90


@dataclass(frozen=True)
class DomainIntel:
    """Aggregated domain intelligence for one host."""

    host: str
    registrable: str | None
    age: DomainAge
    dns: DnsRecords
    asn: AsnInfo


def domain_signals(intel: DomainIntel) -> list[dict[str, str]]:
    """Turn collected intel into Signal-shaped dicts (id/label/weight/detail).

    Returns plain dicts so this module stays free of the FastAPI schema import;
    the caller maps them onto :class:`app.schemas.Signal`.
    """
    out: list[dict[str, str]] = []
    age = intel.age

    if age.age_days is not None:
        if age.age_days < YOUNG_DOMAIN_DAYS:
            out.append(
                {
                    "id": "young_domain",
                    "label": "Very recently registered domain",
                    "weight": "malicious",
                    "detail": (
                        f"The domain was registered {age.age_days} day(s) ago; "
                        "most phishing domains are used within weeks of registration."
                    ),
                }
            )
        elif age.age_days < NEW_DOMAIN_DAYS:
            out.append(
                {
                    "id": "new_domain",
                    "label": "Newly registered domain",
                    "weight": "malicious",
                    "detail": f"The domain is only {age.age_days} days old.",
                }
            )
        else:
            out.append(
                {
                    "id": "established_domain",
                    "label": "Established domain",
                    "weight": "benign",
                    "detail": f"The domain has existed for {age.age_days} days.",
                }
            )
    else:
        out.append(
            {
                "id": "domain_age_unknown",
                "label": "Domain age unknown",
                "weight": "info",
                "detail": "No registration date was available via RDAP for this domain.",
            }
        )

    if not intel.dns.mx and intel.registrable:
        out.append(
            {
                "id": "no_mx",
                "label": "No mail (MX) records",
                "weight": "info",
                "detail": "The domain has no MX records — common for throwaway phishing domains.",
            }
        )

    if intel.asn.asn is not None:
        host_label = intel.asn.as_name or f"AS{intel.asn.asn}"
        out.append(
            {
                "id": "hosting_asn",
                "label": "Hosting network",
                "weight": "info",
                "detail": (
                    f"Resolved IP is hosted on {host_label}"
                    + (f" ({intel.asn.country})" if intel.asn.country else "")
                    + "."
                ),
            }
        )

    return out


# ---------------------------------------------------------------------------
# Default network-backed implementations (deps imported lazily)
# ---------------------------------------------------------------------------


class DnspythonResolver:
    """:class:`Resolver` backed by ``dnspython`` with a bounded timeout."""

    def __init__(self, *, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def resolve(self, qname: str, rdtype: str) -> list[str]:
        import dns.resolver  # lazy: keeps the module importable without dnspython

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self._timeout
        resolver.timeout = self._timeout
        try:
            answers = resolver.resolve(qname, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.DNSException:
            return []

        out: list[str] = []
        for rdata in answers:
            if rdtype == "MX":
                out.append(str(rdata.exchange).rstrip("."))
            elif rdtype == "TXT":
                # dnspython returns TXT as quoted byte chunks; join them.
                out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            else:
                out.append(str(rdata).rstrip("."))
        return out


class HttpxRdapClient:
    """:class:`RdapClient` using the rdap.org redirector (follows to the registry)."""

    def __init__(self, *, timeout: float = 8.0) -> None:
        self._timeout = timeout

    def fetch_domain(self, domain: str) -> dict | None:
        import httpx  # lazy

        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = httpx.get(
                url,
                follow_redirects=True,
                timeout=self._timeout,
                headers={"Accept": "application/rdap+json"},
            )
        except httpx.HTTPError:
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else None


def collect_domain_intel(
    host: str,
    *,
    resolver: Resolver | None = None,
    rdap: RdapClient | None = None,
    now: dt.date | None = None,
) -> DomainIntel:
    """Run all domain collectors for ``host`` and return aggregated intel.

    Pass custom ``resolver``/``rdap`` for tests; defaults hit the network.
    Failures in any single collector degrade to empty/unknown rather than raising.
    """
    resolver = resolver or DnspythonResolver()
    rdap = rdap or HttpxRdapClient()

    dns_records = collect_dns_records(host, resolver)

    registrable = registrable_domain(host)
    if registrable:
        age = parse_rdap_age(rdap.fetch_domain(registrable), now=now)
    else:
        age = DomainAge(registered_on=None, age_days=None)

    asn = lookup_asn(dns_records.a[0], resolver) if dns_records.a else AsnInfo(asn=None)

    return DomainIntel(
        host=host,
        registrable=registrable,
        age=age,
        dns=dns_records,
        asn=asn,
    )
