import type { Metadata } from 'next';

import './globals.css';
import { SiteHeader } from '@/components/site-header';
import { ThemeProvider, themeNoFlashScript } from '@/components/theme-provider';

export const metadata: Metadata = {
  title: {
    default: 'PhishLens',
    template: '%s · PhishLens',
  },
  description:
    'PhishLens — paste a URL or email and get an explained phishing risk verdict.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeNoFlashScript }} />
      </head>
      <body className="min-h-screen">
        <ThemeProvider>
          <SiteHeader />
          <main className="mx-auto max-w-4xl px-4 py-10">{children}</main>
        </ThemeProvider>
      </body>
    </html>
  );
}
