"""Tests for the Phase 1 TLS/SSL certificate inspector.

All certificate fetches are faked, so these run offline and deterministically.
Certificate dicts mirror the shape of ``ssl.SSLSocket.getpeercert()``.
"""

from __future__ import annotations

import datetime as dt

from app.tls_intel import (
    CertFetch,
    TlsCertificate,
    TlsIntel,
    collect_tls_intel,
    host_matches_cert,
    parse_openssl_datetime,
    parse_peer_cert,
    tls_signals,
)

NOW = dt.datetime(2024, 6, 15, 12, 0, 0, tzinfo=dt.UTC)


def _cert_dict(
    *,
    cn: str = "example.com",
    san: tuple[str, ...] = ("example.com", "www.example.com"),
    not_before: str = "Jun  1 00:00:00 2024 GMT",
    not_after: str = "Sep  1 00:00:00 2024 GMT",
    issuer_cn: str = "R3",
    issuer_org: str = "Let's Encrypt",
    self_signed: bool = False,
) -> dict:
    subject = ((("commonName", cn),),)
    issuer = subject if self_signed else ((("commonName", issuer_cn),), (("organizationName", issuer_org),))
    return {
        "subject": subject,
        "issuer": issuer,
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": tuple(("DNS", name) for name in san),
    }


class FakeFetcher:
    def __init__(self, result: CertFetch):
        self._result = result

    def fetch_peer_cert(self, host: str, port: int) -> CertFetch:
        return self._result


def _signal_ids(intel: TlsIntel) -> set[str]:
    return {s["id"] for s in tls_signals(intel, now=NOW)}


# --- parsing ---------------------------------------------------------------


def test_parse_openssl_datetime():
    assert parse_openssl_datetime("Jun  1 12:00:00 2024 GMT") == dt.datetime(
        2024, 6, 1, 12, 0, 0, tzinfo=dt.UTC
    )
    assert parse_openssl_datetime("garbage") is None


def test_parse_peer_cert_extracts_fields():
    cert = parse_peer_cert(_cert_dict())
    assert cert.subject_cn == "example.com"
    assert cert.issuer_org == "Let's Encrypt"
    assert cert.san == ["example.com", "www.example.com"]
    assert cert.not_after == dt.datetime(2024, 9, 1, tzinfo=dt.UTC)
    assert cert.self_signed is False


def test_parse_peer_cert_detects_self_signed():
    cert = parse_peer_cert(_cert_dict(self_signed=True))
    assert cert.self_signed is True


# --- SAN / hostname matching ----------------------------------------------


def test_host_matches_exact_and_wildcard():
    cert = parse_peer_cert(_cert_dict(san=("example.com", "*.example.com")))
    assert host_matches_cert("example.com", cert)
    assert host_matches_cert("mail.example.com", cert)
    # Wildcard covers exactly one label — not nested subdomains or the bare apex.
    assert not host_matches_cert("a.b.example.com", cert)
    assert not host_matches_cert("evil.com", cert)


def test_host_matches_falls_back_to_cn_without_san():
    cert = TlsCertificate(
        subject_cn="only-cn.com",
        issuer_cn="CA",
        issuer_org="CA",
        not_before=None,
        not_after=None,
        san=[],
    )
    assert host_matches_cert("only-cn.com", cert)
    assert not host_matches_cert("other.com", cert)


# --- signals ---------------------------------------------------------------


def test_valid_cert_yields_benign_signal():
    intel = TlsIntel(host="example.com", available=True, certificate=parse_peer_cert(_cert_dict()))
    ids = _signal_ids(intel)
    assert "tls_valid" in ids
    assert "tls_san_mismatch" not in ids


def test_expired_cert_flagged_malicious():
    cert = parse_peer_cert(_cert_dict(not_after="May  1 00:00:00 2024 GMT"))
    intel = TlsIntel(host="example.com", available=True, certificate=cert)
    ids = _signal_ids(intel)
    assert "tls_expired" in ids
    assert "tls_valid" not in ids


def test_not_yet_valid_cert_flagged():
    cert = parse_peer_cert(_cert_dict(not_before="Sep  1 00:00:00 2024 GMT"))
    intel = TlsIntel(host="example.com", available=True, certificate=cert)
    assert "tls_not_yet_valid" in _signal_ids(intel)


def test_san_mismatch_flagged():
    cert = parse_peer_cert(_cert_dict(cn="legit.com", san=("legit.com",)))
    intel = TlsIntel(host="phish.example", available=True, certificate=cert)
    ids = _signal_ids(intel)
    assert "tls_san_mismatch" in ids
    assert "tls_valid" not in ids


def test_self_signed_flagged():
    cert = parse_peer_cert(_cert_dict(self_signed=True))
    intel = TlsIntel(host="example.com", available=True, certificate=cert)
    assert "tls_self_signed" in _signal_ids(intel)


def test_recently_issued_flagged():
    cert = parse_peer_cert(_cert_dict(not_before="Jun 12 00:00:00 2024 GMT"))
    intel = TlsIntel(host="example.com", available=True, certificate=cert)
    assert "tls_recently_issued" in _signal_ids(intel)


def test_unavailable_yields_info_signal():
    intel = TlsIntel(host="example.com", available=False, error="connection refused")
    ids = _signal_ids(intel)
    assert ids == {"tls_unavailable"}


# --- collector orchestration ----------------------------------------------


def test_collect_tls_intel_parses_when_cert_present():
    fetcher = FakeFetcher(CertFetch(cert=_cert_dict()))
    intel = collect_tls_intel("example.com", fetcher=fetcher)
    assert intel.available is True
    assert intel.certificate is not None
    assert intel.certificate.subject_cn == "example.com"


def test_collect_tls_intel_handles_fetch_error():
    fetcher = FakeFetcher(CertFetch(cert=None, error="timed out"))
    intel = collect_tls_intel("example.com", fetcher=fetcher)
    assert intel.available is False
    assert intel.error == "timed out"
    assert intel.certificate is None
