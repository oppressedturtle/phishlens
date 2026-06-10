const SIGNALS = [
  {
    name: 'URL signals',
    blurb: 'Domain age, DNS, TLS certs, redirect chains — SSRF-guarded.',
  },
  {
    name: 'Lexical heuristics',
    blurb: 'Punycode/IDN homographs, typosquats, entropy, risky TLDs.',
  },
  {
    name: 'Email forensics',
    blurb: 'SPF/DKIM/DMARC, sender spoofing, embedded link scoring.',
  },
  {
    name: 'ML + explanation',
    blurb: 'A classifier scores risk; an AI explains why in plain language.',
  },
];

export default function HomePage() {
  return (
    <div className="space-y-12">
      <section className="text-center">
        <h1 className="text-4xl font-extrabold tracking-tight sm:text-5xl">
          See through <span className="text-brand-500">phishing</span>.
        </h1>
        <p className="text-muted mx-auto mt-4 max-w-xl text-lg">
          Paste a suspicious URL or raw email. PhishLens gathers signals, scores
          the risk, and explains the verdict — so you know exactly why.
        </p>
      </section>

      <section className="border-app bg-card mx-auto max-w-xl rounded-2xl border p-5 shadow-sm">
        <label
          htmlFor="submission"
          className="text-sm font-medium text-fg"
        >
          URL or raw email
        </label>
        <textarea
          id="submission"
          name="submission"
          rows={4}
          disabled
          placeholder="https://secure-login.example.com/verify  —  or paste an entire .eml"
          className="border-app mt-2 w-full resize-none rounded-lg border bg-transparent px-3 py-2 text-sm text-fg placeholder:text-muted focus:border-brand-500 focus:outline-none"
        />
        <div className="mt-3 flex items-center justify-between">
          <span className="text-muted text-xs">
            Analysis is read-only and sandboxed — submitted links are never
            rendered or executed.
          </span>
          <button
            type="button"
            disabled
            className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white opacity-60"
          >
            Analyze
          </button>
        </div>
        <p className="text-muted mt-2 text-xs italic">
          The analyzer service arrives in Phase 1 — this is the Phase 0 shell.
        </p>
      </section>

      <section className="grid gap-4 sm:grid-cols-2">
        {SIGNALS.map((s) => (
          <article
            key={s.name}
            className="border-app bg-card rounded-xl border p-5"
          >
            <h2 className="font-semibold text-brand-500">{s.name}</h2>
            <p className="text-muted mt-1 text-sm">{s.blurb}</p>
          </article>
        ))}
      </section>
    </div>
  );
}
