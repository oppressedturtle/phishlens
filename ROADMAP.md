# PhishLens — Roadmap

**Stack:** Next.js (App Router) · TypeScript · Tailwind · Python FastAPI (ML microservice) · scikit-learn · Postgres · Prisma · Redis
**Goal:** Production-grade phishing analyzer. Paste a URL or raw email → it gathers signals, scores risk with an ML classifier, and an AI explains *why* in plain language. Portfolio-quality: tested, containerized, CI'd, deploy-ready.
**Repo visibility:** public — Yanis's portfolio.

> **Defensive tool.** Analyzes suspicious URLs/emails to protect users. Fetching of submitted URLs is sandboxed and SSRF-guarded (no internal network access, no JS execution, no rendering of fetched content).

Each roadmap item is a self-contained increment the coder agent completes in one session, then commits + pushes. Work in order; skip ahead only if blocked.

## Phase 0 — Foundation
- [x] Next.js + TypeScript + Tailwind app, base layout, ESLint/Prettier
- [x] Python FastAPI analyzer service skeleton (`/analyze`), typed schemas (pydantic)
- [x] Postgres + Prisma (submissions, verdicts, signals), Redis (cache/rate limit)
- [x] Docker Compose (web + analyzer + postgres + redis), Dockerfiles, CI stub
- [x] Root README, MIT LICENSE, .gitignore

## Phase 1 — URL signal collectors (SSRF-guarded)
- [ ] URL normalize/parse; block private/internal IPs + metadata endpoints (SSRF defense)
- [ ] Domain age (WHOIS/RDAP), DNS records, ASN/hosting lookup
- [ ] TLS/SSL certificate inspection (issuer, age, SAN mismatch)
- [ ] Redirect-chain follow (capped, sandboxed, no JS), final-destination analysis

## Phase 2 — URL/content heuristics
- [ ] Lexical features: punycode/IDN homographs, `@` tricks, length, entropy, sub-domain depth, TLD risk
- [ ] Typosquat/lookalike detection (Levenshtein vs known-brand list)
- [ ] Safe page fetch (no JS exec): detect credential/login forms, external form actions, obfuscated JS, brand impersonation cues

## Phase 3 — Email analysis
- [ ] Parse raw `.eml`; header analysis; SPF/DKIM/DMARC result evaluation
- [ ] Sender spoofing / display-name mismatch detection
- [ ] Extract + score links (reuse URL pipeline), attachment risk flags

## Phase 4 — ML classifier
- [ ] Feature vector from all signals; scikit-learn model (e.g. gradient boosting)
- [ ] Train/eval on public phishing/benign feature datasets; report precision/recall/ROC
- [ ] Model versioning + inference endpoint; calibrated probability output

## Phase 5 — AI explanation layer
- [ ] LLM takes signals + score → plain-language narrative ("why this looks like phishing")
- [ ] Confidence + recommended action; never auto-trusts, always shows evidence

## Phase 6 — App UX & API
- [ ] Submit form (URL or paste email), verdict card, signal breakdown, history
- [ ] Public API + API keys, per-key rate limiting, abuse controls
- [ ] Dashboard: recent verdicts, stats

## Phase 7 — Hardening & Tests
- [ ] Unit/integration tests (web + analyzer), SSRF guard tests, classifier eval gate
- [ ] E2E (Playwright): submit known-bad + known-good → correct verdict
- [ ] GitHub Actions CI: lint, typecheck, pytest, build

## Phase 8 — Deploy-Ready
- [ ] Multi-stage builds, env docs, deploy guide, polished README w/ screenshots + architecture

## SECURITY PHASE
Full audit. **Top risk: SSRF** in the URL fetchers — verify internal-IP/metadata blocking, scheme allowlist, redirect cap, DNS-rebinding defense. Plus: XSS (never render fetched content as HTML), input validation, dependency CVEs, secrets, rate limiting, API authz. Document in `SECURITY.md`.

## QA PHASE
Full stack up via Docker Compose, run all tests + E2E, verify URL + email flows on sample data, confirm SSRF guards hold. Log in `PROGRESS.md`.

## SHIP PHASE
Push final commits/tags to the **public** repo, verify CI, tag `v1.0.0`, notify Yanis.
