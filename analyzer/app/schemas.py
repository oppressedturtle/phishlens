"""Typed request/response schemas for the analyzer service.

These pydantic models are the stable contract between the Next.js web app and
this microservice. Signal collectors (Phase 1+) and the ML classifier (Phase 4)
populate the same shapes, so the API surface stays constant as internals grow.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class SubmissionKind(str, Enum):
    """What the user submitted for analysis."""

    URL = "url"
    EMAIL = "email"


class RiskBand(str, Enum):
    """Human-facing risk band. Thresholds mirror the web app's risk.ts."""

    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"


# Inclusive lower bounds on a 0–1 score. Kept in sync with web/src/lib/risk.ts.
CAUTION_THRESHOLD = 0.4
DANGER_THRESHOLD = 0.75


def band_for_score(score: float) -> RiskBand:
    """Map a calibrated [0,1] probability to a risk band."""
    s = min(1.0, max(0.0, score))
    if s >= DANGER_THRESHOLD:
        return RiskBand.DANGER
    if s >= CAUTION_THRESHOLD:
        return RiskBand.CAUTION
    return RiskBand.SAFE


class AnalyzeRequest(BaseModel):
    """A submission to analyze. Exactly one of `url` or `email` must be set."""

    url: str | None = Field(
        default=None,
        max_length=2048,
        description="A suspicious URL to analyze.",
    )
    email: str | None = Field(
        default=None,
        max_length=1_000_000,
        description="A raw .eml message to analyze.",
    )

    @model_validator(mode="after")
    def exactly_one_input(self) -> AnalyzeRequest:
        provided = [v for v in (self.url, self.email) if v not in (None, "")]
        if len(provided) != 1:
            raise ValueError("Provide exactly one of `url` or `email`.")
        return self

    @property
    def kind(self) -> SubmissionKind:
        return SubmissionKind.URL if self.url else SubmissionKind.EMAIL


class Signal(BaseModel):
    """A single observed risk indicator contributing to the verdict."""

    id: str = Field(description="Stable signal identifier, e.g. 'ip_host'.")
    label: str = Field(description="Short human-readable name.")
    # How this signal moves the needle: malicious / benign / informational.
    weight: Literal["malicious", "benign", "info"]
    detail: str = Field(description="Plain-language explanation of the finding.")


class Verdict(BaseModel):
    """The analyzer's structured assessment of a submission."""

    kind: SubmissionKind
    score: float = Field(ge=0.0, le=1.0, description="Calibrated phishing probability.")
    band: RiskBand
    signals: list[Signal] = Field(default_factory=list)
    # Filled by the AI explanation layer (Phase 5); skeleton returns None.
    explanation: str | None = None


class AnalyzeResponse(BaseModel):
    """Top-level /analyze response envelope."""

    verdict: Verdict
    analyzer_version: str
