"""Baseline lexical analysis.

This is the Phase 0 skeleton: a small set of real, working lexical heuristics
that produce structured `Signal`s and a heuristic score. It deliberately does
NOT fetch the URL (that is the SSRF-guarded Phase 1 work) or run the ML
classifier (Phase 4) — it only inspects the submitted string. Later phases swap
the scoring internals while keeping this function's contract identical.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlsplit

from .schemas import (
    AnalyzeRequest,
    Signal,
    SubmissionKind,
    Verdict,
    band_for_score,
)

# Commonly-impersonated brands (non-exhaustive starter list). A display name
# claiming one of these while sending from an unrelated domain is a red flag.
IMPERSONATED_BRANDS = {
    "paypal", "apple", "microsoft", "amazon", "google", "netflix",
    "facebook", "instagram", "bank", "chase", "wellsfargo", "coinbase",
    "dhl", "fedex", "ups", "docusign", "dropbox", "linkedin",
}

# TLDs disproportionately abused for phishing (non-exhaustive starter list).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "country",
    "kim", "work", "click", "link", "rest",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def _shannon_entropy(text: str) -> float:
    """Shannon entropy (bits/char) — high entropy hints at random/DGA hosts."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _analyze_url(raw: str) -> tuple[float, list[Signal]]:
    signals: list[Signal] = []
    weight = 0.0

    parts = urlsplit(raw.strip() if "://" in raw else f"http://{raw.strip()}")
    host = (parts.hostname or "").lower()
    if not host:
        signals.append(
            Signal(id="unparsable", label="Unparsable URL", weight="info",
                   detail="Could not extract a hostname from the input.")
        )
        return 0.0, signals

    # Credential prefix trick: http://user@evil.com
    if "@" in parts.netloc:
        weight += 0.35
        signals.append(
            Signal(id="at_trick", label="'@' in authority", weight="malicious",
                   detail="The URL uses an '@', which can hide the real destination host.")
        )

    # Raw IP host instead of a domain.
    if _IPV4.match(host):
        weight += 0.3
        signals.append(
            Signal(id="ip_host", label="IP-literal host", weight="malicious",
                   detail="The host is a raw IP address rather than a domain name.")
        )

    # Punycode / IDN homograph.
    if "xn--" in host:
        weight += 0.3
        signals.append(
            Signal(id="punycode", label="Punycode/IDN host", weight="malicious",
                   detail="The host uses punycode, a common homograph-spoofing technique.")
        )

    # Excessive sub-domain depth.
    labels = host.split(".")
    if len(labels) >= 5:
        weight += 0.15
        signals.append(
            Signal(id="subdomain_depth", label="Deep sub-domain nesting", weight="malicious",
                   detail=f"The host has {len(labels)} labels; phishing often buries a brand in sub-domains.")
        )

    # Suspicious TLD.
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        weight += 0.15
        signals.append(
            Signal(id="risky_tld", label=f"Risky TLD .{tld}", weight="malicious",
                   detail=f"The .{tld} TLD is disproportionately used for abuse.")
        )

    # Very long URL.
    if len(raw) > 100:
        weight += 0.1
        signals.append(
            Signal(id="long_url", label="Unusually long URL", weight="malicious",
                   detail=f"The URL is {len(raw)} characters; long URLs often obscure intent.")
        )

    # High-entropy host (random-looking domains).
    entropy = _shannon_entropy(host.replace(".", ""))
    if entropy > 3.5 and len(host) > 12:
        weight += 0.1
        signals.append(
            Signal(id="high_entropy", label="High-entropy host", weight="malicious",
                   detail=f"Host entropy is {entropy:.2f} bits/char, suggesting an algorithmically generated domain.")
        )

    if not signals:
        signals.append(
            Signal(id="no_lexical_flags", label="No lexical red flags", weight="benign",
                   detail="No obvious lexical phishing indicators in the URL. Deeper signals run in later phases.")
        )

    # Squash the accumulated weight into a calibrated-feeling [0,1] score.
    score = 1.0 - math.exp(-weight)
    return score, signals


def _analyze_email(raw: str) -> tuple[float, list[Signal]]:
    signals: list[Signal] = []
    weight = 0.0

    urls = _URL_RE.findall(raw)
    if urls:
        signals.append(
            Signal(id="contains_links", label=f"{len(urls)} link(s) found", weight="info",
                   detail="The message contains links; each will run through the URL pipeline in Phase 3.")
        )
        # Score the riskiest embedded URL as a baseline proxy.
        url_scores = [_analyze_url(u)[0] for u in urls[:10]]
        weight += max(url_scores) * 0.6

    # Display-name spoofing: "Brand Support <random@unrelated.tld>".
    from_match = re.search(r"^From:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
    if from_match:
        from_value = from_match.group(1)
        addr = re.search(r"<([^>]+)>", from_value)
        display = re.sub(r"<[^>]+>", "", from_value).strip().strip('"').lower()
        if addr and display:
            real_domain = addr.group(1).split("@")[-1].lower()
            # A brand named in the display name but absent from the real domain.
            impersonated = next(
                (b for b in IMPERSONATED_BRANDS
                 if b in display and b not in real_domain),
                None,
            )
            if impersonated:
                weight += 0.25
                signals.append(
                    Signal(id="display_mismatch", label="Display-name mismatch", weight="malicious",
                           detail=f"The From name claims '{impersonated}' but the sending domain is '{real_domain}'.")
                )

    if not signals:
        signals.append(
            Signal(id="no_email_flags", label="No header red flags", weight="benign",
                   detail="No obvious spoofing indicators in headers. Full SPF/DKIM/DMARC checks land in Phase 3.")
        )

    score = 1.0 - math.exp(-weight)
    return score, signals


def analyze(request: AnalyzeRequest) -> Verdict:
    """Run baseline analysis on a submission and return a structured verdict."""
    if request.kind is SubmissionKind.URL:
        assert request.url is not None  # guaranteed by AnalyzeRequest validation
        score, signals = _analyze_url(request.url)
    else:
        assert request.email is not None
        score, signals = _analyze_email(request.email)

    return Verdict(
        kind=request.kind,
        score=round(score, 4),
        band=band_for_score(score),
        signals=signals,
        explanation=None,
    )
