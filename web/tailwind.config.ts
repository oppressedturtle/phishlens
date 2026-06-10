import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // PhishLens brand: a vigilant cyan/teal "lens".
        brand: {
          50: '#ecfeff',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#06b6d4',
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
        },
        // Verdict accents.
        risk: {
          safe: '#16a34a',
          caution: '#d97706',
          danger: '#dc2626',
        },
      },
    },
  },
  plugins: [],
};

export default config;
