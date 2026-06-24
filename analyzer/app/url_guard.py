"""URL normalization + SSRF guard (Phase 1, collector foundation).

PhishLens analyzes URLs that *strangers submit*. The moment we resolve or fetch
one of those, we hand an attacker a request originating from our own network —
the classic Server-Side Request Forgery (SSRF) primitive used to reach cloud
metadata endpoints (``169.254.169.254``), internal admin panels, or localhost
services. This module is the chokepoint every later URL collector (domain age,
TLS inspection, redirect following) must go through before touching the network.

Design:
- **Scheme allowlist** — only ``http`` / ``https``. No ``file:``, ``gopher:``,
  ``ftp:``, ``data:``, etc.
- **Host normalization** — IDNA-encode (so homographs/unicode can't smuggle a
  different host past the checks), lowercase, and coerce numeric host forms
  (decimal/hex/octal IPv4 like ``2130706433`` or ``0x7f.1``) to their real IP so
  they can't bypass literal-IP checks.
- **Address validation** — reject loopback, private (RFC1918), link-local
  (incl. the cloud metadata range), CGNAT/shared, reserved, multicast and
  unspecified addresses, for both IPv4 and IPv6 (unwrapping IPv4-mapped IPv6).
- **Resolve-and-validate** — resolve the hostname and validate *every* answer,
  returning the pinned IPs so a caller can connect to a vetted address rather
  than re-resolving (a DNS-rebinding defense).

Nothing here fetches or renders content; it only decides whether an address is a
safe, public destination and hands back the vetted IPs.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

DEFAULT_PORTS = {"http": 80, "https": 443}

# Hostnames that must never be resolved/fetched regardless of what they resolve
# to (defense in depth alongside the IP checks).
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
    }
)


class UrlGuardError(ValueError):
    """Base class for URL rejection — invalid input or an SSRF risk."""


class InvalidUrlError(UrlGuardError):
    """The input is not a well-formed http(s) URL we can normalize."""


class SsrfError(UrlGuardError):
    """The URL resolves to a non-public/forbidden address (SSRF risk)."""


@dataclass(frozen=True)
class NormalizedUrl:
    """A parsed, scheme-checked, host-normalized URL."""

    scheme: str
    host: str  # ASCII (IDNA-encoded), lowercased
    port: int
    path: str

    @property
    def origin(self) -> str:
        """`scheme://host[:port]` with the default port omitted."""
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


def _parse_int_token(token: str) -> int:
    """Parse one host token as int, honouring 0x (hex) and leading-0 (octal)."""
    lowered = token.lower()
    if lowered.startswith("0x"):
        return int(token, 16)
    if token.startswith("0") and token != "0":
        return int(token, 8)
    return int(token, 10)


def _coerce_numeric_host_to_ip(host: str) -> ipaddress.IPv4Address | None:
    """Interpret a fully-numeric host (decimal/hex/octal) as an IPv4 address.

    Browsers accept ``http://2130706433`` and ``http://0x7f.0.0.1`` as
    ``127.0.0.1``. ``ipaddress.ip_address`` does not, so an attacker could use
    these forms to dodge a naive literal-IP check. We replicate ``inet_aton``
    semantics enough to unmask them; non-numeric hosts return ``None``.
    """
    parts = host.split(".")
    try:
        if len(parts) == 1:
            return ipaddress.IPv4Address(_parse_int_token(parts[0]))
        if len(parts) == 4:
            octets = [_parse_int_token(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(bytes(octets))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if `ip` is anything other than a normal public address."""
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) and re-check as IPv4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped

    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Belt-and-suspenders: anything not globally routable is out. `is_global`
    # also catches CGNAT/shared space on older Pythons where `is_private` didn't.
    return not ip.is_global


def normalize_url(raw: str) -> NormalizedUrl:
    """Parse and normalize a submitted URL, or raise :class:`InvalidUrlError`.

    Does not perform DNS resolution or SSRF checks — call
    :func:`assert_public_url` for that.
    """
    if not raw or not raw.strip():
        raise InvalidUrlError("Empty URL.")

    candidate = raw.strip()
    # Treat a bare "example.com/path" as http:// so users can paste loosely.
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise InvalidUrlError(f"Unsupported scheme '{parts.scheme}'. Only http/https are allowed.")

    if parts.hostname is None or parts.hostname == "":
        raise InvalidUrlError("URL has no host.")

    host = parts.hostname.lower()
    # IDNA-encode unicode/IDN hosts so later string checks see the real ASCII
    # host. Fall back to the raw host if it is already ASCII or un-encodable.
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Keep the lowercased host; it may still be a valid IP literal.
        pass

    try:
        port = parts.port if parts.port is not None else DEFAULT_PORTS[scheme]
    except ValueError as exc:  # out-of-range port in the URL
        raise InvalidUrlError("Invalid port in URL.") from exc

    return NormalizedUrl(scheme=scheme, host=host, port=port, path=parts.path or "/")


def _resolve_host(host: str, port: int) -> list[str]:
    """Resolve `host` to a list of unique IP strings, or raise SsrfError."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfError(f"Host '{host}' could not be resolved.") from exc

    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    if not seen:
        raise SsrfError(f"Host '{host}' resolved to no addresses.")
    return seen


def assert_public_url(raw: str, *, resolve: bool = True) -> tuple[NormalizedUrl, list[str]]:
    """Normalize, then verify the URL points at a public address.

    Returns the :class:`NormalizedUrl` plus the list of vetted IPs the host
    resolves to (pin these when connecting to defend against DNS rebinding).

    :raises InvalidUrlError: malformed / disallowed-scheme URL.
    :raises SsrfError: the host is blocklisted, a forbidden IP literal, or
        resolves to any non-public address.
    """
    normalized = normalize_url(raw)
    host = normalized.host

    if host in BLOCKED_HOSTNAMES:
        raise SsrfError(f"Host '{host}' is blocklisted.")

    # If the host is (or decodes to) an IP literal, validate it directly — no DNS.
    literal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        literal_ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal_ip = _coerce_numeric_host_to_ip(host)

    if literal_ip is not None:
        if _is_forbidden_ip(literal_ip):
            raise SsrfError(f"Address {literal_ip} is not a public destination.")
        return normalized, [str(literal_ip)]

    if not resolve:
        return normalized, []

    resolved = _resolve_host(host, normalized.port)
    for addr in resolved:
        ip = ipaddress.ip_address(addr)
        if _is_forbidden_ip(ip):
            raise SsrfError(f"Host '{host}' resolves to non-public address {addr}.")
    return normalized, resolved
