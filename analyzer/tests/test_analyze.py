"""Tests for the analyzer service: schema validation, heuristics, and /analyze."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.analyzer import analyze
from app.main import app
from app.schemas import AnalyzeRequest, RiskBand, SubmissionKind

client = TestClient(app)


def test_health() -> None:
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_requires_exactly_one_input() -> None:
    # Neither provided.
    res = client.post("/analyze", json={})
    assert res.status_code == 422
    # Both provided.
    res = client.post("/analyze", json={"url": "http://a.com", "email": "x"})
    assert res.status_code == 422


def test_benign_url_scores_low() -> None:
    verdict = analyze(AnalyzeRequest(url="https://github.com/login"))
    assert verdict.kind is SubmissionKind.URL
    assert verdict.band is RiskBand.SAFE
    assert verdict.score < 0.4


def test_at_trick_and_ip_host_flagged() -> None:
    verdict = analyze(AnalyzeRequest(url="http://paypal.com@198.51.100.7/login"))
    ids = {s.id for s in verdict.signals}
    assert "at_trick" in ids
    assert "ip_host" in ids
    assert verdict.score >= 0.4


def test_punycode_flagged() -> None:
    verdict = analyze(AnalyzeRequest(url="https://xn--80ak6aa92e.com/secure"))
    assert any(s.id == "punycode" for s in verdict.signals)


def test_analyze_endpoint_url() -> None:
    res = client.post("/analyze", json={"url": "http://example.com"})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"]["kind"] == "url"
    assert "analyzer_version" in body


def test_email_display_name_mismatch() -> None:
    raw = (
        'From: "PayPal Support" <attacker@random-mailer.tk>\n'
        "Subject: Verify your account\n\n"
        "Click http://paypal.com@198.51.100.7/verify now."
    )
    verdict = analyze(AnalyzeRequest(email=raw))
    ids = {s.id for s in verdict.signals}
    assert verdict.kind is SubmissionKind.EMAIL
    assert "display_mismatch" in ids
    assert "contains_links" in ids
    assert verdict.score >= 0.4
