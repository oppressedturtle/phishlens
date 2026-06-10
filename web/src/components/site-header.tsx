import Link from 'next/link';

import { ThemeToggle } from './theme-toggle';

export function SiteHeader() {
  return (
    <header className="border-app bg-card/80 sticky top-0 z-40 border-b backdrop-blur">
      <div className="mx-auto flex h-14 max-w-4xl items-center justify-between gap-4 px-4">
        <Link href="/" className="flex items-center gap-2 font-bold">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-brand-500 text-sm text-white">
            🔎
          </span>
          <span className="text-fg">
            Phish<span className="text-brand-500">Lens</span>
          </span>
        </Link>
        <nav className="flex items-center gap-3 text-sm">
          <a
            href="https://github.com/oppressedturtle/phishlens"
            target="_blank"
            rel="noreferrer"
            className="text-muted hover:text-fg"
          >
            GitHub
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
