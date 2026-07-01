# PhishLens — Progress Log

## 2026-07-01 — Phase 1 item 4: redirect-chain follow (SSRF-guarded, capped, no JS)

Built **`analyzer/app/redirect_intel.py`** — follows a submitted URL's redirect chain to its final
destination. This completes Phase 1's URL signal collectors. Following redirects is itself an SSRF
primitive (a 302 to `169.254.169.254` would make *us* fetch cloud metadata), so safety is the point:

- **SSRF-guarded per hop.** Every URL — the submitted one and every `Location` — passes through the
  real `assert_public_url` guard *before* any network call, so a redirect can never steer us at a
  private/internal/metadata address. A blocked hop halts the chain and becomes a `malicious` signal.
- **Capped** at 10 hops (`MAX_REDIRECTS`), **loop-safe** (revisiting a URL stops), and **sandboxed**:
  it issues a `HEAD` and reads only the status line + `Location` header — no body is ever read,
  rendered, or executed (no JS). Relative Locations are resolved; the guard-vetted IP is pinned
  (DNS-rebinding defense) and the default fetcher verifies TLS against the real hostname.
- **Signals:** `redirect_blocked` (SSRF hop refused), `redirect_excessive` (cap hit),
  `redirect_loop`, `redirect_scheme_downgrade` (https→http), `redirect_long_chain` (≥3),
  `redirect_cross_host`, `redirect_error`, and `redirect_none` (clean direct resolve).
- Same architecture as the other collectors: pure following logic with the network behind an
  injectable `HopFetcher` Protocol (+ injectable guard), stdlib default fetcher, no new deps.

**Tests (`test_redirect_intel.py`, 12 cases):** direct-200, single + relative redirect, query-string
preservation, long chain, cap-exceeded, loop, **real-guard SSRF block on a metadata redirect** (and
asserts the malicious hop is never fetched), scheme downgrade, fetcher-error halt. All offline.

**Verification (all green):** `ruff check` ✓ · **pytest 77/77** (12 new) ✓.

**Roadmap:** Phase 1 ✅ **complete** (all 4 URL collectors done). **Next:** Phase 2 item 1 — lexical
URL heuristics (punycode/IDN homographs, `@` tricks, length, entropy, sub-domain depth, TLD risk),
then wire the domain/TLS/redirect collectors into the SSRF-guarded `/analyze` flow.


## 2026-06-29 (b) — Phase 1 item 3: TLS/SSL certificate inspection

Built **`analyzer/app/tls_intel.py`** — inspects the certificate served on a host's TLS port and
turns it into phishing signals. Same shape as the domain collectors: pure parsing/scoring with the
network hidden behind an injectable `TlsFetcher` Protocol, so everything is offline-testable.

- **Parsing** (`parse_peer_cert`) works on the `ssl.SSLSocket.getpeercert()` dict shape — subject/
  issuer CN + org, `notBefore`/`notAfter` (OpenSSL date parser → tz-aware UTC), DNS SANs, and a
  self-signed check (subject == issuer).
- **Hostname/SAN matching** (`host_matches_cert`) is RFC 6125-style with single-label `*` wildcard
  support (a wildcard matches one label, never the apex or a dotted prefix), falling back to CN when
  no SANs are present.
- **Signals** (`tls_signals`): `tls_expired` / `tls_not_yet_valid` / `tls_self_signed` /
  `tls_san_mismatch` (all `malicious`), `tls_recently_issued` (info, <7d), `tls_valid` (benign, only
  when nothing flags), and `tls_unavailable` (info) when no cert could be fetched (HTTP-only/refused).
- **Default fetcher** `StdlibTlsFetcher` uses only the standard library `ssl` + `socket` (bounded
  timeout) — **no new dependency**. Verify-failures surface as a reason string; capturing the raw
  cert on verify-failure for richer reporting is left for a later increment.

**Tests (`tests/test_tls_intel.py`, 14):** date parsing, field extraction, self-signed detection,
exact + wildcard SAN matching (incl. nested-subdomain rejection), CN fallback, and one case per
signal, plus collector orchestration (cert present / fetch error). **ruff clean; pytest 65/65**
(14 new). No code wired into `/analyze` yet.

**Roadmap:** Phase 1 now 3/4. **NEXT:** Phase 1 item 4 — redirect-chain follow (capped, sandboxed,
no JS), then wire domain + TLS + redirect collectors into the SSRF-guarded `/analyze` flow.


## 2026-06-29 — Phase 1 item 2: domain age (RDAP) + DNS records + ASN/hosting

Built the **domain-intelligence collectors** (`analyzer/app/domain_intel.py`) — three classic
phishing signals gathered from a submitted URL's host:

- **Domain age via RDAP** (the JSON successor to WHOIS): parses the `registration` event +
  registrar from an RDAP domain object and computes age in days (clamped ≥ 0). Default client
  uses the `rdap.org` redirector (follows to the authoritative registry).
- **DNS records** (A/AAAA/MX/NS/TXT/CNAME): per-type lookup that **degrades to empty on failure**
  rather than aborting; TXT chunks joined, MX/CNAME trailing dots stripped.
- **ASN / hosting via Team Cymru** DNS origin lookup (reversed-octet `origin.asn.cymru.com` →
  `AS<n>.asn.cymru.com`), parsing the pipe-delimited ASN / prefix / country / registry / AS-name.
- **`registrable_domain`** eTLD+1 helper with a small multi-label-suffix set (co.uk, com.au, …).
- **`domain_signals`** turns intel into Signal-shaped dicts: `young_domain` (<30d, malicious),
  `new_domain` (<90d), `established_domain` (benign), `no_mx`, `domain_age_unknown`, `hosting_asn`.
- **`collect_domain_intel`** orchestrates all three, degrading per-collector on failure.

**Design:** all network access is behind injectable `Resolver` / `RdapClient` Protocols, with
default impls (`DnspythonResolver`, `HttpxRdapClient`) that **import their deps lazily**, so the
module imports and the whole test suite run offline. Added `dnspython==2.7.0` + `httpx==0.27.2`
to runtime `requirements.txt` for the Docker/CI environment.

**Verification (all green, offline):** `ruff check` ✓ · **pytest 51/51** (19 new, all network faked) ✓.

**Roadmap:** Phase 1 — 2/4. **Next:** Phase 1 item 3 — TLS/SSL certificate inspection (issuer,
age, SAN mismatch), then wiring these collectors into the live SSRF-guarded `/analyze` flow.


## 2026-06-24 — Phase 1 item 1: URL normalize/parse + SSRF guard

Built the **SSRF chokepoint** every later URL collector (domain age, TLS inspection,
redirect-follow) must pass through before any network egress — the top-listed risk in the
roadmap's security phase. New `analyzer/app/url_guard.py` (pure stdlib, no new deps):

- **`normalize_url()`** — scheme allowlist (**http/https only** — no file:/gopher:/data:/etc.),
  bare-host → `http://` coercion, host lowercasing, **IDNA encoding** (so unicode/IDN homographs
  are resolved to their real ASCII host before any check), default-port fill, `origin` helper.
- **`assert_public_url()`** — the guard. Blocks loopback, RFC1918 private, link-local (incl. the
  **`169.254.169.254` cloud-metadata** range), CGNAT/shared, reserved, multicast and unspecified
  addresses for **both IPv4 and IPv6** (unwrapping IPv4-mapped IPv6 like `::ffff:127.0.0.1`).
- **Numeric-host unmasking** — decimal/hex/octal IPv4 forms (`http://2130706433`, `http://0x7f.0.0.1`
  → `127.0.0.1`) are coerced to real IPs so they can't dodge the literal-IP checks.
- **Resolve-and-validate** — resolves the host and validates **every** answer, rejecting if *any*
  resolves internal (DNS-rebinding defense), and returns the vetted IPs so a caller can pin them.
- Hostname blocklist (`localhost`, `metadata`, `metadata.google.internal`) as defense in depth.

**Tests — `tests/test_url_guard.py` (25 cases):** normalization (scheme/port/IDNA/bad-input), and
the security-critical SSRF matrix — loopback, private, metadata, IPv6 link-local, IPv4-mapped IPv6,
decimal/hex IP literals all rejected; a public literal allowed; and DNS monkeypatched to prove the
**rebinding** case (public + internal answer) and unresolvable hosts both reject.

**Verification:** `ruff check .` ✓ · `pytest` **32/32** (25 new) ✓. (Hermetic — DNS mocked.)

**Roadmap:** Phase 1 — 1/4 (item 1 ✅). **Next:** item 2 — domain age (WHOIS/RDAP), DNS records,
ASN/hosting lookup, built on top of this guard.

**Also — fixed long-standing red CI:** the web job's `npm run format` step had been failing since
Phase 0 item 4 (no `.prettierignore`, so the **generated Prisma client** was being format-checked,
plus several hand-written files violated the style). Added `web/.prettierignore` (excludes
`src/generated/`) and ran `prettier --write` across `web/src`. Web job now clean: lint ✓ ·
typecheck ✓ · format ✓ · vitest 10/10 ✓ · `next build` ✓.

## 2026-06-23 — Phase 0 item 5: finalized root README → PHASE 0 COMPLETE

Expanded the thin root README into a portfolio-quality landing doc (LICENSE + .gitignore were
already present). Added:

- **Architecture diagram** (ASCII) showing the web ↔ analyzer split and the Postgres/Redis
  backing services with their roles.
- **Quick start** — one-command `docker compose up --build --wait`, plus a service/port table
  (web :3000, analyzer :8000, postgres :5432, redis :6379) noting the `*_PORT` overrides.
- **Local development** — accurate per-service commands (web npm scripts; analyzer
  `pip install -r requirements-dev.txt` + uvicorn `app.main:app`), verified against the actual
  `web/package.json` scripts and `analyzer/requirements-dev.txt`.
- **Repository layout** and a CI summary.

Phase 0 (Foundation) is now fully checked. **Next:** Phase 1 — URL signal collectors with
SSRF-guarded URL normalize/parse (block private/internal IPs + cloud metadata endpoints).


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
