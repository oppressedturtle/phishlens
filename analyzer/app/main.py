"""FastAPI entrypoint for the PhishLens analyzer service."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .analyzer import analyze
from .schemas import AnalyzeRequest, AnalyzeResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishlens.analyzer")

app = FastAPI(
    title="PhishLens Analyzer",
    version=__version__,
    description="Scores phishing risk for submitted URLs and emails.",
)

# The Next.js web app is the only intended caller; tighten origins via env later.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness/readiness probe."""
    return {"status": "ok", "version": __version__}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_submission(request: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a URL or raw email and return a structured verdict.

    Input is validated by `AnalyzeRequest` (exactly one of url/email). No
    network fetch happens here — only lexical analysis of the submitted string.
    """
    verdict = analyze(request)
    logger.info("analyzed kind=%s band=%s score=%.3f", verdict.kind.value,
                verdict.band.value, verdict.score)
    return AnalyzeResponse(verdict=verdict, analyzer_version=__version__)
