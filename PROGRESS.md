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
