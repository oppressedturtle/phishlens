"""Tests for the SSRF guard + URL normalizer (Phase 1 collector foundation).

The SSRF cases are the security-critical ones: each asserts that a hostile or
internal target is rejected *before* any network egress. DNS is monkeypatched so
the tests are hermetic (no real lookups) and can exercise the rebinding path.
"""

from __future__ import annotations

import socket

import pytest

from app import url_guard
from app.url_guard import (
    InvalidUrlError,
    SsrfError,
    assert_public_url,
    normalize_url,
)

# --- normalization -------------------------------------------------------------


def test_normalize_adds_scheme_and_default_port() -> None:
    n = normalize_url("example.com/login")
    assert n.scheme == "http"
    assert n.host == "example.com"
    assert n.port == 80
    assert n.path == "/login"
    assert n.origin == "http://example.com"


def test_normalize_lowercases_host_and_keeps_nondefault_port() -> None:
    n = normalize_url("HTTPS://Example.COM:8443/x")
    assert n.host == "example.com"
    assert n.port == 8443
    assert n.origin == "https://example.com:8443"


def test_normalize_idna_encodes_unicode_host() -> None:
    # Unicode 'paypal' with a Cyrillic 'а' would IDNA-encode to an xn-- host.
    n = normalize_url("http://pаypal.com")
    assert n.host.startswith("xn--")


@pytest.mark.parametrize("bad", ["", "   ", "ftp://x.com", "file:///etc/passwd", "javascript:alert(1)"])
def test_normalize_rejects_bad_input(bad: str) -> None:
    with pytest.raises(InvalidUrlError):
        normalize_url(bad)


# --- SSRF guard: literal and numeric IP forms (no DNS needed) -------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://0.0.0.0/",
        "http://[::1]/",  # IPv6 loopback
        "http://[fe80::1]/",  # IPv6 link-local
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6 loopback
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f.0.0.1/",  # hex-octet 127.0.0.1
        "http://metadata.google.internal/",
    ],
)
def test_blocks_internal_targets(url: str) -> None:
    with pytest.raises(SsrfError):
        assert_public_url(url, resolve=False)


def test_allows_public_ip_literal() -> None:
    normalized, ips = assert_public_url("http://1.1.1.1/", resolve=False)
    assert normalized.host == "1.1.1.1"
    assert ips == ["1.1.1.1"]


# --- SSRF guard: DNS resolution + rebinding defense ----------------------------


def _patch_resolution(monkeypatch: pytest.MonkeyPatch, addresses: list[str]) -> None:
    def fake_getaddrinfo(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (addr, port)) for addr in addresses]

    monkeypatch.setattr(url_guard.socket, "getaddrinfo", fake_getaddrinfo)


def test_resolves_and_returns_public_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolution(monkeypatch, ["93.184.216.34"])
    normalized, ips = assert_public_url("http://example.com/")
    assert normalized.host == "example.com"
    assert ips == ["93.184.216.34"]


def test_blocks_when_any_resolved_ip_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    # DNS-rebinding style: one public + one internal answer → must reject.
    _patch_resolution(monkeypatch, ["93.184.216.34", "169.254.169.254"])
    with pytest.raises(SsrfError):
        assert_public_url("http://rebind.example/")


def test_unresolvable_host_raises_ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise socket.gaierror("nxdomain")

    monkeypatch.setattr(url_guard.socket, "getaddrinfo", boom)
    with pytest.raises(SsrfError):
        assert_public_url("http://does-not-exist.example/")
