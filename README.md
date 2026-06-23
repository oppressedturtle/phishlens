# PhishLens 🔍

Paste a suspicious **URL or email** → PhishLens gathers signals, scores the risk with a machine-learning classifier, and an AI explains *why* in plain language.

> **Defensive security tool** — built to **protect** users from phishing. URL fetching is sandboxed and SSRF-guarded. Portfolio project, work in progress.

## What it does

- **Signal collection** — domain age (WHOIS/RDAP), DNS/ASN, TLS cert, redirect chain, page content (login-form detection, brand impersonation), URL lexical tricks (punycode, typosquatting, entropy)
- **Email analysis** — header forensics, SPF/DKIM/DMARC, sender spoofing, link + attachment risk
- **ML verdict** — a scikit-learn classifier returns a calibrated phishing probability
- **AI explanation** — an LLM turns the evidence into a clear "here's why this is risky" narrative with a recommended action

## Architecture

PhishLens is two services behind one UI: a **Next.js** web app (UI, persistence, orchestration) and a **Python FastAPI** analyzer microservice (signal collection + ML scoring). Postgres stores submissions/verdicts/signals; Redis handles caching and rate limiting.

```
                ┌──────────────────────────────────────────────┐
   browser ───▶ │  web  (Next.js · TypeScript · Tailwind) :3000 │
                │   • submit URL/email, render verdict + reasons│
                │   • Prisma ──▶ Postgres   • cache/RL ──▶ Redis│
                └───────────────┬──────────────────────────────┘
                                │  POST /analyze (internal)
                                ▼
                ┌──────────────────────────────────────────────┐
                │ analyzer (FastAPI · scikit-learn) :8000       │
                │   • SSRF-guarded signal collectors            │
                │   • feature extraction → ML phishing score    │
                └───────────────┬──────────────────────────────┘
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
        Postgres :5432                        Redis :6379
   (submissions, verdicts, signals)     (response cache, rate limits)
```

## Quick start

Everything is containerized — the whole stack comes up with one command.

```bash
# 1. Configure (defaults work out of the box for local dev)
cp .env.example .env

# 2. Build + start web, analyzer, postgres, redis (waits for healthchecks)
docker compose up --build --wait

# 3. Open the app
open http://localhost:3000        # analyzer health: http://localhost:8000/health
```

| Service    | URL / port              | Role                                   |
| ---------- | ----------------------- | -------------------------------------- |
| `web`      | http://localhost:3000   | Next.js UI + API + orchestration       |
| `analyzer` | http://localhost:8000   | FastAPI signal collection + ML scoring |
| `postgres` | `localhost:5432`        | submissions / verdicts / signals       |
| `redis`    | `localhost:6379`        | response cache + rate limiting         |

Ports are overridable via `WEB_PORT` / `ANALYZER_PORT` / `POSTGRES_PORT` / `REDIS_PORT` in `.env`.

## Local development

```bash
# Web app (Next.js)
cd web && npm install && npm run dev          # lint · typecheck · test · build via package.json scripts

# Analyzer (FastAPI)
cd analyzer && pip install -r requirements-dev.txt   # runtime deps + ruff · pytest
uvicorn app.main:app --reload --port 8000
```

CI (GitHub Actions) runs on every push/PR: web lint + typecheck + format + test + build, analyzer ruff + pytest, and Docker image builds for both services.

## Repository layout

```
phishlens/
├── web/              Next.js app (App Router, TypeScript, Tailwind, Prisma)
├── analyzer/         FastAPI ML microservice (scikit-learn, pydantic schemas)
├── docker-compose.yml  full local stack (web + analyzer + postgres + redis)
├── ROADMAP.md        phased build plan
└── PROGRESS.md       running build log
```

## Security note

The analyzer fetches user-submitted URLs, so SSRF defense is first-class: internal/private IPs and cloud metadata endpoints are blocked, only `http(s)` is allowed, redirects are capped, and fetched content is **never** rendered as HTML.

## Status

Active build. See [`ROADMAP.md`](./ROADMAP.md) for the phase plan and [`PROGRESS.md`](./PROGRESS.md) for the running log.

## License

MIT — see [`LICENSE`](./LICENSE).
