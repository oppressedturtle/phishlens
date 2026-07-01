"""Tests for the Phase 1 redirect-chain follower.

All network hops are faked with :class:`FakeFetcher`, so these run offline and
deterministically. The SSRF guard (``assert_public_url``) runs for real, so the
blocked-hop tests exercise the actual defense.
"""

from __future__ import annotations

import functools
import ipaddress

from app.redirect_intel import (
    MAX_REDIRECTS,
    HopResponse,
    HopTarget,
    RedirectChain,
    RedirectHop,
    follow_redirects,
    redirect_signals,
)
from app.url_guard import (
    BLOCKED_HOSTNAMES,
    NormalizedUrl,
    _coerce_numeric_host_to_ip,
    assert_public_url,
    normalize_url,
)


def fake_guard(raw: str) -> tuple[NormalizedUrl, list[str]]:
    """Test guard: real SSRF decision for IP literals / blocked hosts; a fake
    public IP for example hostnames (which don't resolve via real DNS).

    This keeps the metadata/SSRF test exercising the *real* guard (IP literals
    need no DNS) while letting the following logic run fully offline.
    """
    normalized = normalize_url(raw)
    host = normalized.host
    try:
        ipaddress.ip_address(host.strip("[]"))
        literal = True
    except ValueError:
        literal = _coerce_numeric_host_to_ip(host) is not None
    if literal or host in BLOCKED_HOSTNAMES:
        return assert_public_url(raw)  # real decision, no DNS required
    return normalized, ["93.184.216.34"]


# All following tests use the offline fake guard by default.
follow_redirects = functools.partial(follow_redirects, guard=fake_guard)


class FakeFetcher:
    """Maps ``scheme://host[:port]/target`` -> HopResponse; else 200 terminal."""

    def __init__(self, responses: dict[str, HopResponse]) -> None:
        self._responses = responses
        self.calls: list[HopTarget] = []

    def fetch(self, target: HopTarget) -> HopResponse:
        self.calls.append(target)
        if target.port in (80, 443):
            origin = f"{target.scheme}://{target.host}"
        else:
            origin = f"{target.scheme}://{target.host}:{target.port}"
        key = f"{origin}{target.request_target}"
        return self._responses.get(key, HopResponse(status=200))


def _ids(chain: RedirectChain) -> set[str]:
    return {s["id"] for s in redirect_signals(chain)}


def test_no_redirects_direct_200():
    fetcher = FakeFetcher({"https://good.example/": HopResponse(status=200)})
    chain = follow_redirects("https://good.example/", fetcher=fetcher)
    assert chain.final_url == "https://good.example/"
    assert chain.redirect_count == 0
    assert not chain.capped and not chain.loop and chain.blocked is None
    assert len(chain.hops) == 1
    assert _ids(chain) == {"redirect_none"}


def test_follows_single_redirect_to_final():
    fetcher = FakeFetcher(
        {
            "https://sho.rt/abc": HopResponse(status=301, location="https://dest.example/landing"),
            "https://dest.example/landing": HopResponse(status=200),
        }
    )
    chain = follow_redirects("https://sho.rt/abc", fetcher=fetcher)
    assert chain.final_url == "https://dest.example/landing"
    assert chain.redirect_count == 1
    assert [h.status for h in chain.hops] == [301, 200]
    # different host -> cross-host signal
    assert "redirect_cross_host" in _ids(chain)


def test_relative_location_is_resolved():
    fetcher = FakeFetcher(
        {
            "https://host.example/a": HopResponse(status=302, location="/b"),
            "https://host.example/b": HopResponse(status=200),
        }
    )
    chain = follow_redirects("https://host.example/a", fetcher=fetcher)
    assert chain.final_url == "https://host.example/b"
    assert chain.hops[0].location == "https://host.example/b"
    # same host, single redirect -> no cross-host, no long-chain
    assert _ids(chain) == set()  # neither notable nor "none" (count>=1)


def test_query_string_preserved_in_request_target():
    fetcher = FakeFetcher({"https://host.example/search?q=1": HopResponse(status=200)})
    chain = follow_redirects("https://host.example/search?q=1", fetcher=fetcher)
    assert chain.final_url == "https://host.example/search?q=1"
    assert fetcher.calls[0].request_target == "/search?q=1"


def test_long_chain_flagged():
    responses = {}
    for i in range(4):
        responses[f"https://host.example/{i}"] = HopResponse(
            status=302, location=f"https://host.example/{i + 1}"
        )
    responses["https://host.example/4"] = HopResponse(status=200)
    fetcher = FakeFetcher(responses)
    chain = follow_redirects("https://host.example/0", fetcher=fetcher)
    assert chain.redirect_count == 4
    assert "redirect_long_chain" in _ids(chain)


def test_cap_exceeded_sets_capped():
    # Every hop redirects to a *new* URL forever -> never terminates.
    class Endless:
        def fetch(self, target: HopTarget) -> HopResponse:
            n = int(target.request_target.strip("/"))
            return HopResponse(status=302, location=f"https://host.example/{n + 1}")

    chain = follow_redirects("https://host.example/0", fetcher=Endless(), max_redirects=5)
    assert chain.capped is True
    assert chain.final_url is None
    assert "redirect_excessive" in _ids(chain)


def test_loop_detected():
    fetcher = FakeFetcher(
        {
            "https://host.example/a": HopResponse(status=302, location="https://host.example/b"),
            "https://host.example/b": HopResponse(status=302, location="https://host.example/a"),
        }
    )
    chain = follow_redirects("https://host.example/a", fetcher=fetcher)
    assert chain.loop is True
    assert "redirect_loop" in _ids(chain)


def test_ssrf_guarded_hop_is_blocked():
    # A redirect that points at the cloud metadata endpoint must be refused,
    # and the fetcher must never be called for that hop.
    fetcher = FakeFetcher(
        {
            "https://evil.example/go": HopResponse(
                status=302, location="http://169.254.169.254/latest/meta-data/"
            ),
        }
    )
    chain = follow_redirects("https://evil.example/go", fetcher=fetcher)
    assert chain.blocked is not None
    assert chain.final_url is None
    # Only the first (public) hop was ever fetched; the metadata hop was refused.
    assert len(fetcher.calls) == 1
    assert _ids(chain) == {"redirect_blocked"}


def test_scheme_downgrade_flagged():
    fetcher = FakeFetcher(
        {
            "https://host.example/a": HopResponse(status=301, location="http://host.example/a"),
            "http://host.example/a": HopResponse(status=200),
        }
    )
    chain = follow_redirects("https://host.example/a", fetcher=fetcher)
    assert "redirect_scheme_downgrade" in _ids(chain)


def test_fetcher_error_halts_chain():
    fetcher = FakeFetcher(
        {"https://host.example/": HopResponse(status=0, error="connection failed")}
    )
    chain = follow_redirects("https://host.example/", fetcher=fetcher)
    assert chain.error == "connection failed"
    assert "redirect_error" in _ids(chain)


def test_redirect_hop_dataclass_shape():
    hop = RedirectHop(url="https://x/", status=200, location=None)
    assert hop.url == "https://x/" and hop.status == 200 and hop.location is None


def test_max_redirects_default_constant():
    assert MAX_REDIRECTS == 10
