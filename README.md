# PhishLens 🔍

Paste a suspicious **URL or email** → PhishLens gathers signals, scores the risk with a machine-learning classifier, and an AI explains *why* in plain language.

> Defensive security tool — built to **protect** users from phishing. URL fetching is sandboxed and SSRF-guarded. Portfolio project, work in progress.

## What it does
- **Signal collection** — domain age (WHOIS/RDAP), DNS/ASN, TLS cert, redirect chain, page content (login-form detection, brand impersonation), URL lexical tricks (punycode, typosquatting, entropy)
- **Email analysis** — header forensics, SPF/DKIM/DMARC, sender spoofing, link + attachment risk
- **ML verdict** — scikit-learn classifier returns a calibrated phishing probability
- **AI explanation** — an LLM turns the evidence into a clear "here's why this is risky" narrative with a recommended action

## Stack
Next.js (App Router) · TypeScript · Tailwind · Python FastAPI + scikit-learn (ML microservice) · Postgres + Prisma · Redis · Docker · GitHub Actions

## Security note
The analyzer fetches user-submitted URLs, so SSRF defense is first-class: internal/private IPs and cloud metadata endpoints are blocked, only http(s) is allowed, redirects are capped, and fetched content is **never** rendered as HTML.

## Status
See [`ROADMAP.md`](./ROADMAP.md) and [`PROGRESS.md`](./PROGRESS.md).

## License
MIT — see [`LICENSE`](./LICENSE).
