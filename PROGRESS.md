# PhishLens — Progress Log

## 2026-06-22 — Phase 0 item 4: Docker Compose + Dockerfiles + CI stub

- **`analyzer/Dockerfile`** — multi-stage Python 3.12-slim: builder stage compiles wheels,
  runtime stage installs offline as a non-root `app` user. `PYTHONUNBUFFERED`, EXPOSE 8000,
  HEALTHCHECK hitting `/health`, runs uvicorn. `+ .dockerignore`.
- **`web/Dockerfile`** — multi-stage Next.js standalone build: `deps` (npm ci) → `builder`
  (`prisma generate` + `next build`) → minimal non-root `runtime` copying only `.next/standalone`
  + `.next/static`. Added `output: "standalone"` to `next.config.mjs`. openssl installed for
  Prisma. HEALTHCHECK on `/`. `+ .dockerignore`.
- **`docker-compose.yml`** (repo root) — `web` + `analyzer` + `postgres:16-alpine` +
  `redis:7-alpine`. Healthchecks on every service; `web` waits on postgres/redis healthy +
  analyzer started; service-name DNS wiring (`postgres`, `redis`, `analyzer`); named volumes;
  host ports overridable via env. `+ .env.example`.
- **`.github/workflows/ci.yml`** — three jobs: **web** (npm ci → prisma generate → lint →
  typecheck → format → test → build), **analyzer** (ruff + pytest), **docker** (buildx builds
  both images with GHA cache). Concurrency cancel-in-progress.
- **Verified locally:** `docker compose config` valid; both images build clean; full stack
  `docker compose up --wait` → all 4 containers **healthy**; `web` returns HTTP 200, analyzer
  `/health` returns ok. (DB migration still deferred until first schema-touching feature.)
- **Roadmap:** Phase 0 — 4/5.
- **Next:** Phase 0 item 5 — root README + MIT LICENSE + .gitignore polish (LICENSE/.gitignore
  already present; finalize root README with architecture + run instructions) → closes Phase 0.

## 2026-06-22 — Phase 0 item 3: Postgres + Prisma + Redis foundation (web)

- Added the data layer to `web/` (Prisma 7.8, driver-adapter `@prisma/adapter-pg`):
  - **`prisma/schema.prisma`** — full analysis domain modelled up front so later phases only
    add fields/relations: `Submission` (URL|EMAIL input, normalizedUrl, status, ipHash for
    abuse control, error) → one `Verdict` (calibrated score 0–1, RiskLevel, confidence,
    AI explanation, modelVersion) + many `Signal` (category/severity/key/value/weight).
    Enums: SubmissionType, SubmissionStatus, RiskLevel, SignalCategory, SignalSeverity.
    Cascade deletes + hot-path composite indexes (`ipHash,createdAt`; `status,createdAt`;
    `submissionId,category`).
  - **`prisma.config.ts`** — Prisma 7 config; DATABASE_URL provided here (not in schema).
  - **`src/lib/db.ts`** — PrismaClient singleton via pg Pool + PrismaPg adapter (hot-reload safe).
  - **`src/lib/redis.ts`** — ioredis singleton (globalThis pattern) + `ping()` healthcheck helper.
  - **`src/lib/env.ts`** — Zod env validation (DATABASE_URL, REDIS_URL, ANALYZER_URL, NODE_ENV);
    throws a descriptive error at startup on misconfig. All env reads go through this module.
  - **`src/lib/rate-limit.ts`** — atomic Redis sliding-window limiter (single Lua script, no
    TOCTOU), fails open on Redis outage. + 4 unit tests.
  - `.env.example` (committed) + local `.env` (gitignored); generated client gitignored.
  - npm scripts: `db:generate`, `db:migrate`, `db:studio`.
- Verified: `prisma validate` ✓, `prisma generate` ✓, `tsc --noEmit` ✓, `vitest` 10/10 ✓,
  `next lint` ✓ (0 warnings). `prisma migrate` deferred (no live DB until Compose lands).
- **Roadmap:** Phase 0 — 3/5.
- **Next:** Phase 0 item 4 — Docker Compose (web + analyzer + postgres + redis), Dockerfiles, CI stub.

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
