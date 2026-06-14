# PhishLens — Progress Log

## 2026-06-08 — Project kickoff
- Added to the autonomous build pipeline (security project, builds in rotation).
- Defined 8-phase roadmap; defensive framing with SSRF-guarded fetching as a first-class concern.
- Foundation committed: README, MIT LICENSE, .gitignore. Public repo created.
- **Next:** Phase 0 — Next.js + Tailwind app, FastAPI analyzer skeleton, Postgres/Prisma, Redis, Docker Compose.

## 2026-06-10 — Phase 0: Next.js web app scaffold
- Scaffolded the web app under `web/` (leaving room for the Python `analyzer/` service):
  Next.js 14 App Router, TypeScript (strict, `noUncheckedIndexedAccess`), Tailwind 3 with a
  PhishLens "lens" cyan palette + safe/caution/danger verdict accents, ESLint + Prettier.
- SSR-safe light/dark theming (provider + no-flash inline script + toggle), sticky SiteHeader,
  metadata template, and a home page: defensive submit shell (read-only/sandboxed note) plus a
  signal-capabilities overview (URL signals, lexical heuristics, email forensics, ML+explanation).
- Domain core: pure `risk.ts` (`riskBand`/`presentRisk`) mapping a 0–1 model probability to
  safe/caution/danger bands + label/colour/percent, with clamping — fully unit-tested.
- Verified: typecheck ✓, eslint ✓ (0 warnings), `next build` ✓ (static prerender), vitest 6/6 ✓.
- **Roadmap:** Phase 0 — 1/5 (web scaffold done).
- **Next:** Phase 0 item 2 — Python FastAPI analyzer skeleton (`/analyze`) with pydantic schemas.

## 2026-06-14 — Phase 0 item 2: FastAPI analyzer service skeleton
- Stood up the Python analyzer microservice under `analyzer/` (FastAPI + pydantic v2):
  `GET /health` and `POST /analyze`.
- **Typed contract** (`app/schemas.py`): `AnalyzeRequest` (exactly one of `url`/`email`,
  enforced by a model validator), `Signal` (id/label/weight/detail), `Verdict`
  (kind/score/band/signals/explanation), `AnalyzeResponse`. `RiskBand` thresholds mirror
  the web app's `risk.ts` (caution ≥0.4, danger ≥0.75) so verdicts read consistently end-to-end.
- **Baseline heuristics** (`app/analyzer.py`) — real, working lexical analysis (no network
  fetch yet — that's the SSRF-guarded Phase 1): `@`-authority trick, IP-literal host, punycode/IDN,
  deep sub-domain nesting, risky TLDs, over-long URLs, high-entropy (DGA-like) hosts; for emails:
  link extraction (scored via the URL path), and brand display-name vs sending-domain mismatch.
  Weights are squashed to a [0,1] score via `1 − e^(−Σw)`.
- **Tests** (`tests/test_analyze.py`): 7 passing — health, exactly-one-input 422s, benign URL
  scores SAFE, `@`+IP and punycode flagged, `/analyze` envelope, email display-name mismatch.
- Tooling: `requirements.txt` / `requirements-dev.txt`, `pyproject.toml` (pytest + ruff config),
  `analyzer/README.md`. Verified: **pytest 7/7 ✓**, **ruff ✓** (clean).
- **Roadmap:** Phase 0 — 2/5.
- **Next:** Phase 0 item 3 — Postgres + Prisma (submissions/verdicts/signals) + Redis;
  then Docker Compose wiring web + analyzer + postgres + redis.
