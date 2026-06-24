'use client';

import { useTheme } from './theme-provider';

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
      title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
      className="border-app text-fg inline-flex h-9 w-9 items-center justify-center rounded-lg border transition-colors hover:bg-brand-500/10"
    >
      <span aria-hidden="true" className="text-base">
        {isDark ? '☀️' : '🌙'}
      </span>
    </button>
  );
}
