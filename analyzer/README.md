# PhishLens Analyzer Service

FastAPI microservice that scores phishing risk for submitted **URLs** and **emails**.
The Next.js web app calls this service; it returns a structured `Verdict` (score,
risk band, and the individual signals behind the decision).

> **Phase 0 skeleton.** This implements the stable `/analyze` contract plus a set
> of real baseline *lexical* heuristics. It does **not** fetch submitted URLs — that
> is the SSRF-guarded work of Phase 1 — nor run the ML classifier (Phase 4). Later
> phases swap the scoring internals while keeping the API identical.

## Endpoints

- `GET /health` → `{ "status": "ok", "version": "0.1.0" }`
- `POST /analyze` → body `{ "url": "..." }` **or** `{ "email": "<raw .eml>" }`
  (exactly one). Returns `AnalyzeResponse` with a `verdict`.

## Run locally

```bash
cd analyzer
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

Interactive docs at `http://localhost:8000/docs`.

## Test & lint

```bash
pytest          # unit + endpoint tests
ruff check .    # lint
```

## Example

```bash
curl -s localhost:8000/analyze -H 'content-type: application/json' \
  -d '{"url":"http://paypal.com@198.51.100.7/login"}' | jq
```
