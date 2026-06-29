"""TLS/SSL certificate inspection (Phase 1 item 3).

Given a submitted URL's host, inspect the certificate served on the TLS port and
surface classic phishing/abuse signals:

- **Expired / not-yet-valid** certificates — a live site serving an out-of-window
  cert is a strong red flag.
- **Hostname / SAN mismatch** — the host isn't covered by the certificate's
  Subject Alternative Names (or CN fallback): the cert was issued for something
  else, a hallmark of hastily-assembled phishing infrastructure.
- **Self-signed** certificates — no trusted CA vouches for the identity.
- **Freshly issued** certificates — paired with a young domain, a cert minted days
  ago adds to the risk picture.

The certificate fetch is abstracted behind a small :class:`TlsFetcher` Protocol so
the parsing/scoring logic is pure and unit-testable without opening a socket. The
default fetcher uses the standard library ``ssl`` module (no extra dependency) and
returns the same parsed-dict shape as :meth:`ssl.SSLSocket.getpeercert`, so the
parser can be exercised directly with crafted dicts in tests.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Protocol

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TlsCertificate:
    """The fields we care about from a parsed peer certificate."""

    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    not_before: dt.datetime | None
    not_after: dt.datetime | None
    san: list[str] = field(default_factory=list)
    self_signed: bool = False


@dataclass(frozen=True)
class TlsIntel:
    """Aggregated TLS inspection result for one host."""

    host: str
    available: bool
    certificate: TlsCertificate | None = None
    error: str | None = None


@dataclass(frozen=True)
class CertFetch:
    """What a :class:`TlsFetcher` returns: a parsed cert dict, or an error reason."""

    cert: dict | None
    error: str | None = None


class TlsFetcher(Protocol):
    """Fetch the peer certificate for ``host``:``port`` as a parsed dict."""

    def fetch_peer_cert(self, host: str, port: int) -> CertFetch: ...


# ---------------------------------------------------------------------------
# Certificate parsing (operates on the stdlib ssl getpeercert() dict shape)
# ---------------------------------------------------------------------------


def _rdn_value(name: object, key: str) -> str | None:
    """Pull a value out of an ssl-style distinguished name.

    The shape is a tuple of relative DNs, each a tuple of ``(key, value)`` pairs,
    e.g. ``((('commonName', 'example.com'),), (('organizationName', 'X'),))``.
    """
    if not isinstance(name, tuple | list):
        return None
    for rdn in name:
        if not isinstance(rdn, tuple | list):
            continue
        for attr in rdn:
            if isinstance(attr, tuple | list) and len(attr) == 2 and attr[0] == key:
                value = attr[1]
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def parse_openssl_datetime(value: str) -> dt.datetime | None:
    """Parse an OpenSSL ``notBefore``/``notAfter`` string.

    Example: ``"Jun  1 12:00:00 2024 GMT"``. These are always UTC; we strip the
    trailing ``GMT`` and attach UTC so comparisons are timezone-aware.
    """
    text = value.strip()
    if text.endswith(" GMT"):
        text = text[:-4]
    try:
        naive = dt.datetime.strptime(text, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return naive.replace(tzinfo=dt.UTC)


def _extract_san(cert: dict) -> list[str]:
    """Extract DNS Subject Alternative Names from a parsed cert dict."""
    out: list[str] = []
    for entry in cert.get("subjectAltName", ()) or ():
        if isinstance(entry, tuple | list) and len(entry) == 2 and entry[0] == "DNS":
            value = entry[1]
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
    return out


def parse_peer_cert(cert: dict) -> TlsCertificate:
    """Parse the dict returned by ``ssl.SSLSocket.getpeercert()``."""
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    subject_cn = _rdn_value(subject, "commonName")
    issuer_cn = _rdn_value(issuer, "commonName")
    issuer_org = _rdn_value(issuer, "organizationName")

    not_before = None
    if isinstance(cert.get("notBefore"), str):
        not_before = parse_openssl_datetime(cert["notBefore"])
    not_after = None
    if isinstance(cert.get("notAfter"), str):
        not_after = parse_openssl_datetime(cert["notAfter"])

    # Self-signed: subject and issuer are byte-for-byte identical.
    self_signed = bool(subject) and subject == issuer

    return TlsCertificate(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        not_before=not_before,
        not_after=not_after,
        san=_extract_san(cert),
        self_signed=self_signed,
    )


# ---------------------------------------------------------------------------
# Hostname / SAN matching
# ---------------------------------------------------------------------------


def _host_matches_pattern(host: str, pattern: str) -> bool:
    """RFC 6125-style match, supporting a single leftmost ``*`` wildcard label."""
    host = host.strip().rstrip(".").lower()
    pattern = pattern.strip().rstrip(".").lower()
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if not host.endswith(suffix):
            return False
        left = host[: -len(suffix)]
        # A wildcard matches exactly one label — never an empty or dotted prefix.
        return left != "" and "." not in left
    return host == pattern


def host_matches_cert(host: str, cert: TlsCertificate) -> bool:
    """Does ``host`` match the certificate's SANs (or CN when no SANs exist)?"""
    names = cert.san or ([cert.subject_cn] if cert.subject_cn else [])
    return any(_host_matches_pattern(host, name) for name in names if name)


# ---------------------------------------------------------------------------
# Signal synthesis
# ---------------------------------------------------------------------------

# A certificate issued more recently than this (days) is "freshly issued".
FRESH_CERT_DAYS = 7


def tls_signals(intel: TlsIntel, *, now: dt.datetime | None = None) -> list[dict[str, str]]:
    """Turn TLS intel into Signal-shaped dicts (id/label/weight/detail)."""
    moment = now or dt.datetime.now(dt.UTC)
    out: list[dict[str, str]] = []

    if not intel.available or intel.certificate is None:
        out.append(
            {
                "id": "tls_unavailable",
                "label": "No HTTPS certificate",
                "weight": "info",
                "detail": (
                    "Could not retrieve a TLS certificate for this host"
                    + (f" ({intel.error})" if intel.error else "")
                    + " — the site may be HTTP-only."
                ),
            }
        )
        return out

    cert = intel.certificate
    valid_window = True

    if cert.not_after is not None and cert.not_after < moment:
        valid_window = False
        out.append(
            {
                "id": "tls_expired",
                "label": "Expired TLS certificate",
                "weight": "malicious",
                "detail": f"The certificate expired on {cert.not_after.date().isoformat()}.",
            }
        )
    if cert.not_before is not None and cert.not_before > moment:
        valid_window = False
        out.append(
            {
                "id": "tls_not_yet_valid",
                "label": "Certificate not yet valid",
                "weight": "malicious",
                "detail": f"The certificate is not valid until {cert.not_before.date().isoformat()}.",
            }
        )

    if cert.self_signed:
        out.append(
            {
                "id": "tls_self_signed",
                "label": "Self-signed certificate",
                "weight": "malicious",
                "detail": "The certificate is self-signed; no trusted authority vouches for it.",
            }
        )

    if not host_matches_cert(intel.host, cert):
        covered = ", ".join(cert.san) if cert.san else (cert.subject_cn or "unknown")
        out.append(
            {
                "id": "tls_san_mismatch",
                "label": "Hostname not covered by certificate",
                "weight": "malicious",
                "detail": f"'{intel.host}' is not covered by the certificate (covers: {covered}).",
            }
        )

    if cert.not_before is not None:
        age_days = (moment - cert.not_before).days
        if 0 <= age_days < FRESH_CERT_DAYS:
            out.append(
                {
                    "id": "tls_recently_issued",
                    "label": "Recently issued certificate",
                    "weight": "info",
                    "detail": f"The certificate was issued {age_days} day(s) ago.",
                }
            )

    # Only call it healthy when nothing above flagged it.
    if valid_window and not cert.self_signed and host_matches_cert(intel.host, cert):
        issuer = cert.issuer_org or cert.issuer_cn or "a trusted CA"
        out.append(
            {
                "id": "tls_valid",
                "label": "Valid TLS certificate",
                "weight": "benign",
                "detail": f"Served a valid certificate issued by {issuer}.",
            }
        )

    return out


# ---------------------------------------------------------------------------
# Default network-backed fetcher (stdlib ssl; no extra dependency)
# ---------------------------------------------------------------------------


class StdlibTlsFetcher:
    """:class:`TlsFetcher` using the standard library ``ssl`` module.

    Uses a verifying context so the returned :meth:`getpeercert` dict is populated.
    Verification failures (self-signed, expired, name mismatch) are reported as an
    error string rather than a parsed cert; the connection-level signal
    (``tls_unavailable``) still flags the host. A future increment can capture the
    raw cert on verify-failure for richer reporting.
    """

    def __init__(self, *, timeout: float = 8.0) -> None:
        self._timeout = timeout

    def fetch_peer_cert(self, host: str, port: int) -> CertFetch:
        import socket
        import ssl

        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            return CertFetch(cert=cert if isinstance(cert, dict) else None)
        except ssl.SSLError as exc:
            return CertFetch(cert=None, error=f"TLS error: {exc.reason or exc}")
        except (OSError, TimeoutError) as exc:  # connection refused, DNS, timeout
            return CertFetch(cert=None, error=str(exc))


def collect_tls_intel(
    host: str,
    *,
    port: int = 443,
    fetcher: TlsFetcher | None = None,
    now: dt.datetime | None = None,  # noqa: ARG001 — reserved for symmetry/future use
) -> TlsIntel:
    """Fetch and parse the TLS certificate for ``host``.

    Pass a custom ``fetcher`` for tests; the default opens a real TLS connection.
    Any failure degrades to ``available=False`` with an error reason rather than
    raising.
    """
    fetcher = fetcher or StdlibTlsFetcher()
    result = fetcher.fetch_peer_cert(host, port)
    if result.cert is None:
        return TlsIntel(host=host, available=False, error=result.error)
    return TlsIntel(host=host, available=True, certificate=parse_peer_cert(result.cert))
