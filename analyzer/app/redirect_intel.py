"""Redirect-chain following (Phase 1 item 4).

Phishing links love indirection: a shortener or a compromised host bounces the
victim through several hops before landing on the real credential-harvesting
page. To analyze where a submitted URL *actually* goes we follow the redirect
chain to its final destination — but doing that safely is the whole challenge,
because "follow this redirect" is itself an SSRF primitive (a 302 to
``http://169.254.169.254/`` would make us request cloud metadata).

Safety properties, all enforced here:

- **SSRF-guarded per hop.** Every URL — the submitted one *and* every ``Location``
  we're told to follow — is re-validated with :func:`assert_public_url` before we
  touch the network, so a redirect can never steer us at a private/internal
  address. A blocked hop stops the chain and is surfaced as a strong signal.
- **Capped.** At most :data:`MAX_REDIRECTS` hops; a longer chain stops and flags.
- **Loop-safe.** Revisiting an already-seen URL stops the chain.
- **Sandboxed / no JS.** We issue a ``HEAD`` and read only the status line and the
  ``Location`` header. No response body is read, rendered, or executed — so there
  is no JS execution and nothing fetched is ever treated as HTML.

The network hop is abstracted behind a :class:`HopFetcher` Protocol so the
following logic is pure and unit-testable offline; the default fetcher uses the
standard library (``http.client``/``ssl``, no extra dependency) and pins the
connection to the IP the guard vetted (DNS-rebinding defense).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from .url_guard import NormalizedUrl, UrlGuardError, assert_public_url

# A guard resolves+validates a URL, returning the normalized URL and vetted IPs
# (or raising :class:`UrlGuardError`). The default is the real SSRF guard; it is
# injectable so the following logic can be exercised offline.
UrlGuard = Callable[[str], "tuple[NormalizedUrl, list[str]]"]

# Follow at most this many redirects before giving up (defense against
# redirect loops / tar-pits and unbounded work).
MAX_REDIRECTS = 10

# HTTP status codes that carry a Location we follow.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


# ---------------------------------------------------------------------------
# Fetcher abstraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HopTarget:
    """A single vetted request target handed to a :class:`HopFetcher`."""

    scheme: str
    host: str
    port: int
    ip: str  # the guard-vetted IP to connect to (pin against DNS rebinding)
    request_target: str  # path (+query), always starts with "/"


@dataclass(frozen=True)
class HopResponse:
    """What a fetcher returns for one hop: a status and maybe a Location."""

    status: int
    location: str | None = None
    error: str | None = None


class HopFetcher(Protocol):
    """Issue a single non-following request and report status + Location."""

    def fetch(self, target: HopTarget) -> HopResponse: ...


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RedirectHop:
    """One step in the chain: the URL requested and where it pointed next."""

    url: str
    status: int
    location: str | None  # absolute next URL, or None at the terminal hop


@dataclass(frozen=True)
class RedirectChain:
    """The outcome of following a submitted URL's redirects."""

    start_url: str
    hops: list[RedirectHop] = field(default_factory=list)
    final_url: str | None = None
    capped: bool = False
    loop: bool = False
    blocked: str | None = None  # SSRF/invalid reason a hop was refused
    error: str | None = None  # network/fetcher error that halted the chain

    @property
    def redirect_count(self) -> int:
        """Number of redirects followed (terminal hop excluded)."""
        return sum(1 for hop in self.hops if hop.location is not None)


# ---------------------------------------------------------------------------
# Core following logic (pure; network behind the fetcher)
# ---------------------------------------------------------------------------


def _absolute(normalized: NormalizedUrl, request_target: str) -> str:
    """Reconstruct the absolute URL for a normalized URL + request target."""
    return f"{normalized.origin}{request_target}"


def _request_target(raw_url: str) -> str:
    """Extract the ``/path?query`` request target from an absolute URL string."""
    parts = urlsplit(raw_url)
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return target


def follow_redirects(
    raw_url: str,
    *,
    fetcher: HopFetcher,
    guard: UrlGuard = assert_public_url,
    max_redirects: int = MAX_REDIRECTS,
) -> RedirectChain:
    """Follow ``raw_url``'s redirect chain to its final destination, safely.

    Each hop is SSRF-validated (via ``guard``) before any network call. Stops at
    the first non-redirect response (the final destination), when a hop is
    blocked, on a loop, or once ``max_redirects`` is exceeded.
    """
    hops: list[RedirectHop] = []
    seen: set[str] = set()
    current = raw_url

    for _ in range(max_redirects + 1):
        try:
            normalized, ips = guard(current)
        except UrlGuardError as exc:
            return RedirectChain(
                start_url=raw_url, hops=hops, final_url=None, blocked=str(exc)
            )

        request_target = _request_target(current)
        absolute = _absolute(normalized, request_target)

        if absolute in seen:
            return RedirectChain(
                start_url=raw_url, hops=hops, final_url=absolute, loop=True
            )
        seen.add(absolute)

        target = HopTarget(
            scheme=normalized.scheme,
            host=normalized.host,
            port=normalized.port,
            ip=ips[0] if ips else normalized.host,
            request_target=request_target,
        )
        resp = fetcher.fetch(target)

        if resp.error is not None:
            hops.append(RedirectHop(url=absolute, status=resp.status, location=None))
            return RedirectChain(
                start_url=raw_url, hops=hops, final_url=absolute, error=resp.error
            )

        is_redirect = resp.status in _REDIRECT_STATUSES and bool(resp.location)
        if not is_redirect:
            hops.append(RedirectHop(url=absolute, status=resp.status, location=None))
            return RedirectChain(start_url=raw_url, hops=hops, final_url=absolute)

        # Resolve the (possibly relative) Location against the current URL.
        next_url = urljoin(absolute, resp.location or "")
        hops.append(RedirectHop(url=absolute, status=resp.status, location=next_url))
        current = next_url

    # Ran past the cap without reaching a terminal response.
    return RedirectChain(start_url=raw_url, hops=hops, final_url=None, capped=True)


# ---------------------------------------------------------------------------
# Signal synthesis
# ---------------------------------------------------------------------------


def _host_of(url: str | None) -> str | None:
    if not url:
        return None
    host = urlsplit(url).hostname
    return host.lower() if host else None


def _scheme_of(url: str | None) -> str | None:
    if not url:
        return None
    return (urlsplit(url).scheme or "").lower() or None


# A chain longer than this many redirects is itself suspicious.
LONG_CHAIN_THRESHOLD = 3


def redirect_signals(chain: RedirectChain) -> list[dict[str, str]]:
    """Turn a :class:`RedirectChain` into Signal-shaped dicts."""
    out: list[dict[str, str]] = []

    # A redirect steered us at a non-public address — a strong abuse signal.
    if chain.blocked is not None:
        out.append(
            {
                "id": "redirect_blocked",
                "label": "Redirect to a forbidden address",
                "weight": "malicious",
                "detail": (
                    "A redirect in the chain pointed at a non-public or invalid "
                    f"address and was refused ({chain.blocked})."
                ),
            }
        )
        return out

    if chain.error is not None:
        out.append(
            {
                "id": "redirect_error",
                "label": "Redirect chain could not be resolved",
                "weight": "info",
                "detail": f"Following the redirect chain failed: {chain.error}.",
            }
        )

    if chain.capped:
        out.append(
            {
                "id": "redirect_excessive",
                "label": "Excessive redirects",
                "weight": "malicious",
                "detail": (
                    f"The chain did not terminate within {MAX_REDIRECTS} redirects, "
                    "a common cloaking/tar-pit tactic."
                ),
            }
        )

    if chain.loop:
        out.append(
            {
                "id": "redirect_loop",
                "label": "Redirect loop",
                "weight": "info",
                "detail": "The redirect chain looped back to a URL it had already visited.",
            }
        )

    # Scheme downgrade (https -> http) anywhere in the chain drops TLS.
    for hop in chain.hops:
        if (
            hop.location is not None
            and _scheme_of(hop.url) == "https"
            and _scheme_of(hop.location) == "http"
        ):
            out.append(
                {
                    "id": "redirect_scheme_downgrade",
                    "label": "HTTPS downgraded to HTTP",
                    "weight": "malicious",
                    "detail": "A redirect moved the visitor from HTTPS to plain HTTP, dropping encryption.",
                }
            )
            break

    count = chain.redirect_count
    start_host = _host_of(chain.start_url)
    final_host = _host_of(chain.final_url)

    if count >= LONG_CHAIN_THRESHOLD:
        out.append(
            {
                "id": "redirect_long_chain",
                "label": "Long redirect chain",
                "weight": "info",
                "detail": f"The link passed through {count} redirects before its destination.",
            }
        )

    if count >= 1 and final_host and start_host and final_host != start_host:
        out.append(
            {
                "id": "redirect_cross_host",
                "label": "Redirects to a different host",
                "weight": "info",
                "detail": (
                    f"The submitted link on '{start_host}' ultimately lands on "
                    f"'{final_host}'."
                ),
            }
        )

    # Nothing notable, a clean single-response destination.
    if not out and count == 0:
        out.append(
            {
                "id": "redirect_none",
                "label": "No redirects",
                "weight": "benign",
                "detail": "The link resolved directly with no redirects.",
            }
        )

    return out


# ---------------------------------------------------------------------------
# Default network-backed fetcher (stdlib; no extra dependency)
# ---------------------------------------------------------------------------


class StdlibHopFetcher:
    """:class:`HopFetcher` using ``http.client`` over a guard-pinned connection.

    Connects to the IP the SSRF guard vetted (not a freshly-resolved one) so a
    DNS-rebinding answer can't slip a private address in between validation and
    connect. Issues a ``HEAD`` and reads only the status line and ``Location``
    header — the response body is never read, so nothing fetched is rendered or
    executed.
    """

    def __init__(self, *, timeout: float = 8.0) -> None:
        self._timeout = timeout

    def fetch(self, target: HopTarget) -> HopResponse:
        import http.client
        import socket
        import ssl

        try:
            raw = socket.create_connection((target.ip, target.port), timeout=self._timeout)
        except OSError as exc:
            return HopResponse(status=0, error=f"connection failed: {exc}")

        conn: http.client.HTTPConnection
        try:
            if target.scheme == "https":
                context = ssl.create_default_context()
                # Verify the certificate for the real hostname, not the pinned IP.
                sock = context.wrap_socket(raw, server_hostname=target.host)
                conn = http.client.HTTPSConnection(
                    target.host, target.port, timeout=self._timeout
                )
                conn.sock = sock
            else:
                conn = http.client.HTTPConnection(
                    target.host, target.port, timeout=self._timeout
                )
                conn.sock = raw

            conn.request("HEAD", target.request_target, headers={"Host": target.host})
            resp = conn.getresponse()
            location = resp.getheader("Location")
            # Drain nothing — HEAD has no body; just close.
            return HopResponse(status=resp.status, location=location)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            return HopResponse(status=0, error=f"request failed: {exc}")
        finally:
            try:
                conn.close()  # type: ignore[possibly-undefined]
            except Exception:
                raw.close()
